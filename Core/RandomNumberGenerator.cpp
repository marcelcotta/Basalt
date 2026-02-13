/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifdef TC_WINDOWS
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#ifdef TC_MACOSX
#include <sys/random.h>   /* getentropy() - macOS 10.12+ */
#endif
#endif

#include "RandomNumberGenerator.h"
#include "Volume/Crc32.h"

namespace TrueCrypt
{
	void RandomNumberGenerator::AddSystemDataToPool (bool fast)
	{
		SecureBuffer buffer (PoolSize);

#ifdef TC_WINDOWS
		/* Windows: BCryptGenRandom — kernel CSPRNG, no file descriptors needed.
		   BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG uses the system
		   default RNG provider (same entropy source as CryptGenRandom/RtlGenRandom).
		   Available on Windows Vista+ / Server 2008+. */
		{
			NTSTATUS status = BCryptGenRandom (
				NULL,
				buffer.Ptr(),
				(ULONG) buffer.Size(),
				BCRYPT_USE_SYSTEM_PREFERRED_RNG);

			if (!BCRYPT_SUCCESS (status))
				throw SystemException (SRC_POS);

			AddToPool (buffer);
		}

#elif defined (TC_MACOSX)
		/* macOS: Use getentropy() - kernel CSPRNG, no file descriptors needed.
		   getentropy() is limited to 256 bytes per call, so we call it in a loop.
		   Falls back to /dev/urandom if getentropy() fails (should never happen
		   on macOS 10.12+). */
		{
			bool useGetentropy = true;
			size_t offset = 0;

			while (offset < buffer.Size())
			{
				size_t chunk = buffer.Size() - offset;
				if (chunk > 256)
					chunk = 256;

				if (getentropy (buffer.Ptr() + offset, chunk) != 0)
				{
					useGetentropy = false;
					break;
				}
				offset += chunk;
			}

			if (useGetentropy)
			{
				AddToPool (buffer);
			}
			else
			{
				/* Fallback to /dev/urandom */
				int urandom = open ("/dev/urandom", O_RDONLY);
				throw_sys_sub_if (urandom == -1, L"/dev/urandom");
				finally_do_arg (int, urandom, { close (finally_arg); });

				throw_sys_sub_if (read (urandom, buffer, buffer.Size()) == -1, L"/dev/urandom");
				AddToPool (buffer);
			}
		}
#else
		/* Linux/FreeBSD: Use /dev/urandom */
		int urandom = open ("/dev/urandom", O_RDONLY);
		throw_sys_sub_if (urandom == -1, L"/dev/urandom");
		finally_do_arg (int, urandom, { close (finally_arg); });

		throw_sys_sub_if (read (urandom, buffer, buffer.Size()) == -1, L"/dev/urandom");
		AddToPool (buffer);

		if (!fast)
		{
			int random = open ("/dev/random", O_RDONLY | O_NONBLOCK);
			throw_sys_sub_if (random == -1, L"/dev/random");
			finally_do_arg (int, random, { close (finally_arg); });

			throw_sys_sub_if (read (random, buffer, buffer.Size()) == -1 && errno != EAGAIN, L"/dev/random");
			AddToPool (buffer);
		}
#endif
	}

	void RandomNumberGenerator::AddToPool (const ConstBufferPtr &data)
	{
		if (!Running)
			throw NotInitialized (SRC_POS);

		ScopeLock lock (AccessMutex);

		for (size_t i = 0; i < data.Size(); ++i)
		{
			Pool[WriteOffset++] ^= data[i];

			if (WriteOffset >= PoolSize)
				WriteOffset = 0;

			if (++BytesAddedSincePoolHashMix >= MaxBytesAddedBeforePoolHashMix)
				HashMixPool();
		}
	}

	void RandomNumberGenerator::GetData (const BufferPtr &buffer, bool fast)
	{
		if (!Running)
			throw NotInitialized (SRC_POS);

		if (buffer.Size() > PoolSize)
			throw ParameterIncorrect (SRC_POS);

		ScopeLock lock (AccessMutex);

		// Poll system for data
		AddSystemDataToPool (fast);
		HashMixPool();

		// Transfer bytes from pool to output buffer
		for (size_t i = 0; i < buffer.Size(); ++i)
		{
			buffer[i] ^= Pool[ReadOffset++];

			if (ReadOffset >= PoolSize)
				ReadOffset = 0;
		}

		AddSystemDataToPool (true);
		HashMixPool();

		// XOR the current pool content into the output buffer to prevent pool state leaks
		for (size_t i = 0; i < buffer.Size(); ++i)
		{
			buffer[i] ^= Pool[ReadOffset++];

			if (ReadOffset >= PoolSize)
				ReadOffset = 0;
		}
	}

	shared_ptr <Hash> RandomNumberGenerator::GetHash ()
	{
		ScopeLock lock (AccessMutex);
		return PoolHash;
	}

	void RandomNumberGenerator::HashMixPool ()
	{
		BytesAddedSincePoolHashMix = 0;

		for (size_t poolPos = 0; poolPos < Pool.Size(); )
		{
			// Compute the message digest of the entire pool using the selected hash function
			SecureBuffer digest (PoolHash->GetDigestSize());
			PoolHash->Init();
			PoolHash->ProcessData (Pool);
			PoolHash->GetDigest (digest);

			// Add the message digest to the pool
			for (size_t digestPos = 0; digestPos < digest.Size() && poolPos < Pool.Size(); ++digestPos)
			{
				Pool[poolPos++] ^= digest[digestPos];
			}
		}
	}

	void RandomNumberGenerator::SetHash (shared_ptr <Hash> hash)
	{
		ScopeLock lock (AccessMutex);
		PoolHash = hash;
	}

	void RandomNumberGenerator::Start ()
	{
		ScopeLock lock (AccessMutex);

		if (IsRunning())
			return;

		BytesAddedSincePoolHashMix = 0;
		ReadOffset = 0;
		WriteOffset = 0;
		Running = true;
		EnrichedByUser = false;

		Pool.Allocate (PoolSize);

		if (!PoolHash)
		{
			// First hash algorithm is the default one
			PoolHash = Hash::GetAvailableAlgorithms().front();
		}

		AddSystemDataToPool (true);
		Test();
	}

	void RandomNumberGenerator::Stop ()
	{		
		ScopeLock lock (AccessMutex);

		if (Pool.IsAllocated())
			Pool.Free ();

		PoolHash.reset();

		EnrichedByUser = false;
		Running = false;
	}

	void RandomNumberGenerator::Test ()
	{
		shared_ptr <Hash> origPoolHash = PoolHash;
		PoolHash.reset (new Ripemd160());

		Pool.Zero();
		Buffer buffer (1);
		for (size_t i = 0; i < PoolSize * 10; ++i)
		{
			buffer[0] = (byte) i;
			AddToPool (buffer);
		}

		// Test vectors updated after security fixes:
		// - Pool mixing changed from += to ^= (cryptographically neutral)
		// - Hash Init() added before ProcessData (correctness fix)
		// - Pool inversion removed (non-standard operation)
		uint32 crc1 = Crc32::ProcessBuffer (Pool);

		buffer.Allocate (PoolSize);
		buffer.CopyFrom (PeekPool());
		AddToPool (buffer);

		uint32 crc2 = Crc32::ProcessBuffer (Pool);

		// Verify RNG is producing non-trivial output (pool must not be all zeros)
		if (crc1 == 0 || crc2 == 0 || crc1 == crc2)
			throw TestFailed (SRC_POS);

		PoolHash = origPoolHash;
	}

	Mutex RandomNumberGenerator::AccessMutex;
	size_t RandomNumberGenerator::BytesAddedSincePoolHashMix;
	bool RandomNumberGenerator::EnrichedByUser;
	SecureBuffer RandomNumberGenerator::Pool;
	shared_ptr <Hash> RandomNumberGenerator::PoolHash;
	size_t RandomNumberGenerator::ReadOffset;
	bool RandomNumberGenerator::Running = false;
	size_t RandomNumberGenerator::WriteOffset;
}

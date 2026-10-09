/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Crc32.h"
#include "EncryptionModeXTS.h"
#include "Pkcs5Kdf.h"
#include "Pkcs5Kdf.h"
#include "VolumeHeader.h"
#include "VolumeException.h"
#include "Common/Crypto.h"
#include <algorithm>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

namespace Basalt
{
	namespace
	{
		// Derives the header keys of several PBKDF2 KDFs on all CPU cores. PBKDF2
		// output blocks are independent, so every (KDF, block) pair is a job. Jobs
		// are taken in KDF order, so the first KDF's key is complete first and can
		// be tested while the others are still being derived.
		class ParallelPbkdf2
		{
		public:
			ParallelPbkdf2 (const vector <shared_ptr <Pkcs5Kdf> > &kdfs, const VolumePassword &password, const ConstBufferPtr &salt, size_t keySize)
				: Kdfs (kdfs), Password (password), Salt (salt), KeySize (keySize)
			{
				for (size_t i = 0; i < Kdfs.size(); i++)
				{
					size_t blockSize = Kdfs[i]->GetPbkdf2BlockSize();
					int blocks = (int) ((KeySize + blockSize - 1) / blockSize);

					Keys.push_back (shared_ptr <SecureBuffer> (new SecureBuffer (KeySize)));
					BlocksLeft.push_back (blocks);

					for (int b = 1; b <= blocks; b++)
						Jobs.push_back (make_pair (i, b));
				}

				size_t threadCount = std::min <size_t> (Jobs.size(), std::max (1u, std::thread::hardware_concurrency()));
				for (size_t t = 0; t < threadCount; t++)
				{
					try
					{
						Threads.push_back (std::thread (&ParallelPbkdf2::Work, this));
					}
					catch (...)
					{
						break;
					}
				}

				if (Threads.empty())
					Work();
			}

			~ParallelPbkdf2 ()
			{
				{
					std::lock_guard <std::mutex> lock (Mutex);
					Cancel = true;
				}

				for (auto &t : Threads)
					t.join();
			}

			// Waits until the key of Kdfs[i] is complete.
			ConstBufferPtr GetKey (size_t i)
			{
				std::unique_lock <std::mutex> lock (Mutex);
				Done.wait (lock, [&] { return BlocksLeft[i] == 0 || Error; });

				if (Error)
					std::rethrow_exception (Error);

				return ConstBufferPtr (Keys[i]->Ptr(), Keys[i]->Size());
			}

		private:
			ParallelPbkdf2 (const ParallelPbkdf2 &);
			ParallelPbkdf2 &operator= (const ParallelPbkdf2 &);

			void Work ()
			{
				SecureBuffer block (64);	// largest PBKDF2 block (SHA-512, Whirlpool)

				while (true)
				{
					pair <size_t, int> job;
					{
						std::lock_guard <std::mutex> lock (Mutex);
						if (Cancel || NextJob >= Jobs.size())
							return;
						job = Jobs[NextJob++];
					}

					size_t blockSize = Kdfs[job.first]->GetPbkdf2BlockSize();
					try
					{
						Kdfs[job.first]->DerivePbkdf2Block (block.GetRange (0, blockSize), Password, Salt, job.second);
					}
					catch (...)
					{
						std::lock_guard <std::mutex> lock (Mutex);
						if (!Error)
							Error = std::current_exception();
						Cancel = true;
						Done.notify_all();
						return;
					}

					size_t offset = (size_t) (job.second - 1) * blockSize;
					size_t length = std::min (blockSize, KeySize - offset);

					std::lock_guard <std::mutex> lock (Mutex);
					Keys[job.first]->GetRange (offset, length).CopyFrom (block.GetRange (0, length));
					if (--BlocksLeft[job.first] == 0)
						Done.notify_all();
				}
			}

			const vector <shared_ptr <Pkcs5Kdf> > &Kdfs;
			const VolumePassword &Password;
			const ConstBufferPtr Salt;
			const size_t KeySize;

			vector <shared_ptr <SecureBuffer> > Keys;
			vector <int> BlocksLeft;
			vector <pair <size_t, int> > Jobs;
			size_t NextJob = 0;
			bool Cancel = false;
			std::exception_ptr Error;

			std::mutex Mutex;
			std::condition_variable Done;
			vector <std::thread> Threads;
		};
	}

	VolumeHeader::VolumeHeader (uint32 size)
	{
		Init();
		HeaderSize = size;
		EncryptedHeaderDataSize = size - EncryptedHeaderDataOffset;
	}

	VolumeHeader::~VolumeHeader ()
	{
		Init();
	}

	void VolumeHeader::Init ()
	{
		VolumeKeyAreaCrc32 = 0;
		VolumeCreationTime = 0;
		HeaderCreationTime = 0;
		mVolumeType = VolumeType::Unknown;
		HiddenVolumeDataSize = 0;
		VolumeDataSize = 0;
		EncryptedAreaStart = 0;
		EncryptedAreaLength = 0;
		Flags = 0;
		SectorSize = 0;
	}

	void VolumeHeader::Create (const BufferPtr &headerBuffer, VolumeHeaderCreationOptions &options)
	{
		if (options.DataKey.Size() != options.EA->GetKeySize() * 2 || options.Salt.Size() != GetSaltSize())
			throw ParameterIncorrect (SRC_POS);

		headerBuffer.Zero();

		HeaderVersion = CurrentHeaderVersion;
		RequiredMinProgramVersion = CurrentRequiredMinProgramVersion;

		DataAreaKey.Zero();
		DataAreaKey.CopyFrom (options.DataKey);

		VolumeCreationTime = 0;
		HiddenVolumeDataSize = (options.Type == VolumeType::Hidden ? options.VolumeDataSize : 0);
		VolumeDataSize = options.VolumeDataSize;

		EncryptedAreaStart = options.VolumeDataStart;
		EncryptedAreaLength = options.VolumeDataSize;

		SectorSize = options.SectorSize;

		if (SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
			|| SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
			|| SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			throw ParameterIncorrect (SRC_POS);
		}

		EA = options.EA;
		shared_ptr <EncryptionMode> mode (new EncryptionModeXTS ());
		EA->SetMode (mode);

		EncryptNew (headerBuffer, options.Salt, options.HeaderKey, options.Kdf);
	}

	bool VolumeHeader::Decrypt (const ConstBufferPtr &encryptedData, const VolumePassword &password, const Pkcs5KdfList &keyDerivationFunctions, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes)
	{
		if (password.Size() < 1)
			throw PasswordEmpty (SRC_POS);

		ConstBufferPtr salt (encryptedData.GetRange (SaltOffset, SaltSize));
		SecureBuffer header (EncryptedHeaderDataSize);
		SecureBuffer headerKey (GetLargestSerializedKeySize());

		auto tryHeaderKey = [&] (const ConstBufferPtr &key, const shared_ptr <Pkcs5Kdf> &pkcs5) -> bool
		{
			for (auto mode : encryptionModes)
			{
				if (typeid (*mode) != typeid (EncryptionModeXTS))
					mode->SetKey (key.GetRange (0, mode->GetKeySize()));

				for (auto ea : encryptionAlgorithms)
				{
					if (!ea->IsModeSupported (mode))
						continue;

					if (typeid (*mode) == typeid (EncryptionModeXTS))
					{
						ea->SetKey (key.GetRange (0, ea->GetKeySize()));

						mode = mode->GetNew();
						mode->SetKey (key.GetRange (ea->GetKeySize(), ea->GetKeySize()));
					}
					else
					{
						ea->SetKey (key.GetRange (LegacyEncryptionModeKeyAreaSize, ea->GetKeySize()));
					}

					ea->SetMode (mode);

					header.CopyFrom (encryptedData.GetRange (EncryptedHeaderDataOffset, EncryptedHeaderDataSize));
					ea->Decrypt (header);

					if (Deserialize (header, ea, mode))
					{
						EA = ea;
						Pkcs5 = pkcs5;
						return true;
					}
				}
			}
			return false;
		};

		vector <shared_ptr <Pkcs5Kdf> > kdfs (keyDerivationFunctions.begin(), keyDerivationFunctions.end());

		for (size_t i = 0; i < kdfs.size(); )
		{
			if (!kdfs[i]->IsPbkdf2())
			{
				// Argon2id: memory-hard and multi-threaded itself
				kdfs[i]->DeriveKey (headerKey, password, salt);
				if (tryHeaderKey (headerKey, kdfs[i]))
					return true;
				i++;
				continue;
			}

			// A run of PBKDF2 KDFs: derive their keys in parallel, test them in order
			size_t end = i;
			while (end < kdfs.size() && kdfs[end]->IsPbkdf2())
				end++;

			vector <shared_ptr <Pkcs5Kdf> > run (kdfs.begin() + i, kdfs.begin() + end);
			ParallelPbkdf2 derivation (run, password, salt, headerKey.Size());

			for (size_t r = 0; r < run.size(); r++)
			{
				if (tryHeaderKey (derivation.GetKey (r), run[r]))
					return true;
			}

			i = end;
		}

		return false;
	}

	bool VolumeHeader::Deserialize (const ConstBufferPtr &header, shared_ptr <EncryptionAlgorithm> &ea, shared_ptr <EncryptionMode> &mode)
	{
		if (header.Size() != EncryptedHeaderDataSize)
			throw ParameterIncorrect (SRC_POS);

		// Accept TrueCrypt ("TRUE"), VeraCrypt ("VERA"), and Basalt ("BSLT") volumes
		bool validMagic =
			(header[0] == 'T' && header[1] == 'R' && header[2] == 'U' && header[3] == 'E') ||
			(header[0] == 'V' && header[1] == 'E' && header[2] == 'R' && header[3] == 'A') ||
			(header[0] == 'B' && header[1] == 'S' && header[2] == 'L' && header[3] == 'T');

		if (!validMagic)
			return false;

		size_t offset = 4;
		HeaderVersion =	DeserializeEntry <uint16> (header, offset);

		if (HeaderVersion < MinAllowedHeaderVersion)
			return false;

		if (HeaderVersion > CurrentHeaderVersion)
			throw HigherVersionRequired (SRC_POS);

		if (HeaderVersion >= 4
			&& Crc32::ProcessBuffer (header.GetRange (0, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
			!= DeserializeEntryAt <uint32> (header, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
		{
			return false;
		}

		RequiredMinProgramVersion = DeserializeEntry <uint16> (header, offset);

		// Note: The original TrueCrypt checked RequiredMinProgramVersion against
		// Version::Number() here. This check is removed because:
		// 1. Basalt uses a fresh version line (1.x = 0x01xx) that is numerically
		//    below TrueCrypt's (0x06xx-0x07xx), making the comparison meaningless.
		// 2. The HeaderVersion check above (line 154) already guards against
		//    genuinely incompatible header format changes.
		// 3. If magic, header version, and CRC all pass, we can read the header.

		VolumeKeyAreaCrc32 = DeserializeEntry <uint32> (header, offset);
		VolumeCreationTime = DeserializeEntry <uint64> (header, offset);
		HeaderCreationTime = DeserializeEntry <uint64> (header, offset);
		HiddenVolumeDataSize = DeserializeEntry <uint64> (header, offset);
		mVolumeType = (HiddenVolumeDataSize != 0 ? VolumeType::Hidden : VolumeType::Normal);
		VolumeDataSize = DeserializeEntry <uint64> (header, offset);
		EncryptedAreaStart = DeserializeEntry <uint64> (header, offset);
		EncryptedAreaLength = DeserializeEntry <uint64> (header, offset);
		Flags = DeserializeEntry <uint32> (header, offset);

		SectorSize = DeserializeEntry <uint32> (header, offset);
		if (HeaderVersion < 5)
			SectorSize = TC_SECTOR_SIZE_LEGACY;

		if (SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
			|| SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
			|| SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			throw ParameterIncorrect (SRC_POS);
		}

#if !(defined (TC_WINDOWS) || defined (TC_LINUX))
		if (SectorSize != TC_SECTOR_SIZE_LEGACY)
			throw UnsupportedSectorSize (SRC_POS);
#endif

		offset = DataAreaKeyOffset;

		if (VolumeKeyAreaCrc32 != Crc32::ProcessBuffer (header.GetRange (offset, DataKeyAreaMaxSize)))
			return false;

		DataAreaKey.CopyFrom (header.GetRange (offset, DataKeyAreaMaxSize));
		
		ea = ea->GetNew();
		mode = mode->GetNew();
		
		if (typeid (*mode) == typeid (EncryptionModeXTS))
		{
			ea->SetKey (header.GetRange (offset, ea->GetKeySize()));
			mode->SetKey (header.GetRange (offset + ea->GetKeySize(), ea->GetKeySize()));
		}
		else
		{
			mode->SetKey (header.GetRange (offset, mode->GetKeySize()));
			ea->SetKey (header.GetRange (offset + LegacyEncryptionModeKeyAreaSize, ea->GetKeySize()));
		}

		ea->SetMode (mode);

		return true;
	}

	template <typename T>
	T VolumeHeader::DeserializeEntry (const ConstBufferPtr &header, size_t &offset) const
	{
		offset += sizeof (T);

		if (offset > header.Size())
			throw ParameterIncorrect (SRC_POS);

		return Endian::Big (*reinterpret_cast<const T *> (header.Get() + offset - sizeof (T)));
	}

	template <typename T>
	T VolumeHeader::DeserializeEntryAt (const ConstBufferPtr &header, const size_t &offset) const
	{
		if (offset > header.Size())
			throw ParameterIncorrect (SRC_POS);

		return Endian::Big (*reinterpret_cast<const T *> (header.Get() + offset));
	}

	void VolumeHeader::EncryptNew (const BufferPtr &newHeaderBuffer, const ConstBufferPtr &newSalt, const ConstBufferPtr &newHeaderKey, shared_ptr <Pkcs5Kdf> newPkcs5Kdf)
	{
		if (newHeaderBuffer.Size() != HeaderSize || newSalt.Size() != SaltSize)
			throw ParameterIncorrect (SRC_POS);

		shared_ptr <EncryptionMode> mode = EA->GetMode()->GetNew();
		shared_ptr <EncryptionAlgorithm> ea = EA->GetNew();

		if (typeid (*mode) == typeid (EncryptionModeXTS))
		{
			mode->SetKey (newHeaderKey.GetRange (EA->GetKeySize(), EA->GetKeySize()));
			ea->SetKey (newHeaderKey.GetRange (0, ea->GetKeySize()));
		}
		else
		{
			mode->SetKey (newHeaderKey.GetRange (0, mode->GetKeySize()));
			ea->SetKey (newHeaderKey.GetRange (LegacyEncryptionModeKeyAreaSize, ea->GetKeySize()));
		}

		ea->SetMode (mode);

		newHeaderBuffer.CopyFrom (newSalt);

		BufferPtr headerData = newHeaderBuffer.GetRange (EncryptedHeaderDataOffset, EncryptedHeaderDataSize);
		Serialize (headerData);
		ea->Encrypt (headerData);

		if (newPkcs5Kdf)
			Pkcs5 = newPkcs5Kdf;
	}

	size_t VolumeHeader::GetLargestSerializedKeySize ()
	{
		size_t largestKey = EncryptionAlgorithm::GetLargestKeySize (EncryptionAlgorithm::GetAvailableAlgorithms());
		
		// XTS mode requires the same key size as the encryption algorithm.
		// Legacy modes may require larger key than XTS.
		if (LegacyEncryptionModeKeyAreaSize + largestKey > largestKey * 2)
			return LegacyEncryptionModeKeyAreaSize + largestKey;

		return largestKey * 2;
	}

	void VolumeHeader::Serialize (const BufferPtr &header) const
	{
		if (header.Size() != EncryptedHeaderDataSize)
			throw ParameterIncorrect (SRC_POS);

		header.Zero();

		header[0] = 'B';
		header[1] = 'S';
		header[2] = 'L';
		header[3] = 'T';
		size_t offset = 4;

		header.GetRange (DataAreaKeyOffset, DataAreaKey.Size()).CopyFrom (DataAreaKey);

		uint16 headerVersion = CurrentHeaderVersion;
		SerializeEntry (headerVersion, header, offset);
		SerializeEntry (RequiredMinProgramVersion, header, offset);
		SerializeEntry (Crc32::ProcessBuffer (header.GetRange (DataAreaKeyOffset, DataKeyAreaMaxSize)), header, offset);

		uint64 reserved64 = 0;
		SerializeEntry (reserved64, header, offset);
		SerializeEntry (reserved64, header, offset);

		SerializeEntry (HiddenVolumeDataSize, header, offset);
		SerializeEntry (VolumeDataSize, header, offset);
		SerializeEntry (EncryptedAreaStart, header, offset);
		SerializeEntry (EncryptedAreaLength, header, offset);
		SerializeEntry (Flags, header, offset);

		if (SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
			|| SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
			|| SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0)
		{
			throw ParameterIncorrect (SRC_POS);
		}

		SerializeEntry (SectorSize, header, offset);

		offset = TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC;
		SerializeEntry (Crc32::ProcessBuffer (header.GetRange (0, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC)), header, offset);
	}

	template <typename T>
	void VolumeHeader::SerializeEntry (const T &entry, const BufferPtr &header, size_t &offset) const
	{
		offset += sizeof (T);

		if (offset > header.Size())
			throw ParameterIncorrect (SRC_POS);

		*reinterpret_cast<T *> (header.Get() + offset - sizeof (T)) = Endian::Big (entry);
	}

	void VolumeHeader::SetSize (uint32 headerSize)
	{
		HeaderSize = headerSize;
		EncryptedHeaderDataSize = HeaderSize - EncryptedHeaderDataOffset;
	}
}

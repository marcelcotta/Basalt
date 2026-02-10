/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Common/Pkcs5.h"
#include "Common/Argon2Kdf.h"
#include "Pkcs5Kdf.h"
#include "VolumePassword.h"

namespace TrueCrypt
{
	Pkcs5Kdf::Pkcs5Kdf ()
	{
	}

	Pkcs5Kdf::~Pkcs5Kdf ()
	{
	}

	void Pkcs5Kdf::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt) const
	{
		DeriveKey (key, password, salt, GetIterationCount());
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetAlgorithm (const wstring &name, bool allowLegacy)
	{
		for (const auto &kdf : GetAvailableAlgorithms())
		{
			if (kdf->GetName() == name && (allowLegacy ? kdf->IsLegacy() : !kdf->IsLegacy()))
				return kdf;
		}
		throw ParameterIncorrect (SRC_POS);
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetAlgorithm (const Hash &hash, bool allowLegacy)
	{
		for (const auto &kdf : GetAvailableAlgorithms())
		{
			if (typeid (*kdf->GetHash()) == typeid (hash) && (allowLegacy ? kdf->IsLegacy() : !kdf->IsLegacy()))
				return kdf;
		}

		throw ParameterIncorrect (SRC_POS);
	}

	Pkcs5KdfList Pkcs5Kdf::GetAvailableAlgorithms ()
	{
		Pkcs5KdfList l;

		// Legacy KDFs first (fast match for existing TrueCrypt volumes)
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacRipemd160_Legacy ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha512_Legacy ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacWhirlpool_Legacy ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha1_Legacy ()));

		// Modern KDFs (high iteration counts for new volumes)
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacRipemd160 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha512 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacWhirlpool ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha1 ()));

		// Memory-hard KDF last (expensive to try during mount brute-force,
		// but PBKDF2 volumes are matched above before reaching this point)
		l.push_back (shared_ptr <Pkcs5Kdf> (new KdfArgon2id ()));

		return l;
	}

	void Pkcs5Kdf::ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		if (key.Size() < 1 || password.Size() < 1 || salt.Size() < 1 || iterationCount < 1)
			throw ParameterIncorrect (SRC_POS);
	}

	// --- Argon2id KDF implementation (RFC 9106, m=256MB, t=3, p=4) ---

	void KdfArgon2id::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		int rc = derive_key_argon2id (
			(char *) password.DataPtr(), (int) password.Size(),
			(char *) salt.Get(), (int) salt.Size(),
			(char *) key.Get(), (int) key.Size());
		if (rc != 0)
			throw ParameterIncorrect (SRC_POS);  // Typically ARGON2_MEMORY_ALLOCATION_ERROR
	}

	// --- Modern KDF implementations ---

	void Pkcs5HmacRipemd160::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_ripemd160 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacSha1::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha1 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacSha512::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha512 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacWhirlpool::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_whirlpool ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	// --- Legacy KDF implementations ---

	void Pkcs5HmacRipemd160_Legacy::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_ripemd160 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacRipemd160_1000::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_ripemd160 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacSha512_Legacy::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha512 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacWhirlpool_Legacy::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_whirlpool ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}

	void Pkcs5HmacSha1_Legacy::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		derive_key_sha1 ((char *) password.DataPtr(), (int) password.Size(), (char *) salt.Get(), (int) salt.Size(), iterationCount, (char *) key.Get(), (int) key.Size());
	}
}

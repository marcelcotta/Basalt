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

namespace Basalt
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

		// Legacy KDFs first (near-zero cost, fast match for TrueCrypt 7.1a volumes)
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha512_Legacy ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacRipemd160_Legacy ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacWhirlpool_Legacy ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha1_Legacy ()));

		// Argon2id: Basalt default (Max first — new volumes use this)
		l.push_back (shared_ptr <Pkcs5Kdf> (new KdfArgon2idMax ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new KdfArgon2id ()));

		// Modern PBKDF2: SHA-512 first (TC/VC default), then remaining
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha512 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacWhirlpool ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacRipemd160 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha1 ()));

		return l;
	}

	void Pkcs5Kdf::ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		if (key.Size() < 1 || password.Size() < 1 || salt.Size() < 1 || iterationCount < 1)
			throw ParameterIncorrect (SRC_POS);
	}

	// --- Argon2id KDF implementations (RFC 9106) ---

	// Standard: m=512 MB, t=4, p=4
	void KdfArgon2id::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		int rc = derive_key_argon2id (
			(char *) password.DataPtr(), (int) password.Size(),
			(char *) salt.Get(), (int) salt.Size(),
			(char *) key.Get(), (int) key.Size());
		if (rc != 0)
			throw ParameterIncorrect (SRC_POS);
	}

	// Maximum Security: m=1 GB, t=4, p=8
	void KdfArgon2idMax::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		int rc = derive_key_argon2id_max (
			(char *) password.DataPtr(), (int) password.Size(),
			(char *) salt.Get(), (int) salt.Size(),
			(char *) key.Get(), (int) key.Size());
		if (rc != 0)
			throw ParameterIncorrect (SRC_POS);
	}

	// --- Modern PBKDF2 implementations ---

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

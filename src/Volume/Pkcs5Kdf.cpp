/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Common/Pkcs5.h"
#include "Common/Argon2Kdf.h"
#include "Pkcs5Kdf.h"
#include "VolumeInfo.h"
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
			if (kdf->IsOpenOnly())
				continue;

			if (kdf->GetName() == name && (allowLegacy ? kdf->IsLegacy() : !kdf->IsLegacy()))
				return kdf;
		}
		throw ParameterIncorrect (SRC_POS);
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetAlgorithm (const Hash &hash, bool allowLegacy)
	{
		for (const auto &kdf : GetAvailableAlgorithms())
		{
			if (kdf->IsOpenOnly())
				continue;

			if (typeid (*kdf->GetHash()) == typeid (hash) && (allowLegacy ? kdf->IsLegacy() : !kdf->IsLegacy()))
				return kdf;
		}

		throw ParameterIncorrect (SRC_POS);
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetUpgradeTarget (const VolumeInfo &volume, bool upgradeCurrentPbkdf2)
	{
		shared_ptr <Pkcs5Kdf> target = GetUpgradeTarget (volume.Pkcs5PrfName, (int) volume.Pkcs5IterationCount, upgradeCurrentPbkdf2);

		// TrueCrypt <= 5.x format: required program version below 6.0
		if (target && !target->IsPbkdf2() && volume.Type == VolumeType::Hidden && volume.MinRequiredProgramVersion < 0x600)
			return shared_ptr <Pkcs5Kdf>();

		return target;
	}

	shared_ptr <Pkcs5Kdf> Pkcs5Kdf::GetUpgradeTarget (const wstring &name, int iterationCount, bool upgradeCurrentPbkdf2)
	{
		// A mounted volume reports its KDF by name and iteration count; together
		// they identify the KDF (legacy and modern PBKDF2 share names).
		for (const auto &kdf : GetAvailableAlgorithms())
		{
			if (kdf->GetName() != name || kdf->GetIterationCount() != iterationCount)
				continue;

			if (kdf->IsPbkdf2())
			{
				if (kdf->IsLegacy() || upgradeCurrentPbkdf2)
					return GetAlgorithm (L"Argon2id-Max");
				return shared_ptr <Pkcs5Kdf>();
			}

			// Argon2id: only the pre-RFC 9106 variants of Basalt <= 1.1.x
			if (kdf->IsOpenOnly())
				return GetAlgorithm (*kdf->GetHash());

			return shared_ptr <Pkcs5Kdf>();
		}

		return shared_ptr <Pkcs5Kdf>();
	}

	Pkcs5KdfList Pkcs5Kdf::FilterByHint (const Pkcs5KdfList &kdfs, const wstring &hint)
	{
		if (hint.empty())
			return kdfs;

		Pkcs5KdfList l;
		for (const auto &kdf : kdfs)
		{
			wstring name = kdf->GetName();
			bool match;

			if (hint == L"PBKDF2")
				match = kdf->IsPbkdf2();
			else if (hint == L"Argon2id" || hint == L"Argon2id-Max")
				match = name == hint || name == hint + L" (legacy)";
			else
				throw ParameterIncorrect (SRC_POS);

			if (match)
				l.push_back (kdf);
		}
		return l;
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

		// Modern PBKDF2 (VeraCrypt): SHA-512 first (TC/VC default), then remaining.
		// Consecutive PBKDF2 KDFs are derived in parallel (VolumeHeader::Decrypt).
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha512 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacWhirlpool ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacRipemd160 ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new Pkcs5HmacSha1 ()));

		// Open-only pre-RFC 9106 Argon2id of Basalt <= 1.1.x, last: these volumes
		// are upgraded to standard Argon2id on mount.
		l.push_back (shared_ptr <Pkcs5Kdf> (new KdfArgon2idMaxLegacy ()));
		l.push_back (shared_ptr <Pkcs5Kdf> (new KdfArgon2idLegacy ()));

		return l;
	}

	size_t Pkcs5Kdf::GetPbkdf2BlockSize () const
	{
		shared_ptr <Hash> hash = GetHash();
		const Hash &h = *hash;

		if (typeid (h) == typeid (Sha512) || typeid (h) == typeid (Whirlpool)
			|| typeid (h) == typeid (Ripemd160) || typeid (h) == typeid (Sha1))
		{
			return hash->GetDigestSize();
		}

		return 0;
	}

	void Pkcs5Kdf::DerivePbkdf2Block (const BufferPtr &block, const VolumePassword &password, const ConstBufferPtr &salt, int blockNumber) const
	{
		shared_ptr <Hash> hash = GetHash();
		const Hash &h = *hash;
		int iterations = GetIterationCount();

		if (block.Size() != GetPbkdf2BlockSize() || blockNumber < 1)
			throw ParameterIncorrect (SRC_POS);

		ValidateParameters (block, password, salt, iterations);

		char *pwd = (char *) password.DataPtr();
		int pwdLen = (int) password.Size();
		char *s = (char *) salt.Get();
		int saltLen = (int) salt.Size();
		char *u = (char *) block.Get();

		// Same blocks as derive_key_*(), which concatenates them
		if (typeid (h) == typeid (Sha512))
			derive_u_sha512 (pwd, pwdLen, s, saltLen, iterations, u, blockNumber);
		else if (typeid (h) == typeid (Whirlpool))
			derive_u_whirlpool (pwd, pwdLen, s, saltLen, iterations, u, blockNumber);
		else if (typeid (h) == typeid (Ripemd160))
			derive_u_ripemd160 (pwd, pwdLen, s, saltLen, iterations, u, blockNumber);
		else if (typeid (h) == typeid (Sha1))
			derive_u_sha1 (pwd, pwdLen, s, saltLen, iterations, u, blockNumber);
		else
			throw NotApplicable (SRC_POS);
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

	// --- Open-only Argon2id variants of Basalt <= 1.1.x ---

	void KdfArgon2idLegacy::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		int rc = derive_key_argon2id_legacy (
			(char *) password.DataPtr(), (int) password.Size(),
			(char *) salt.Get(), (int) salt.Size(),
			(char *) key.Get(), (int) key.Size());
		if (rc != 0)
			throw ParameterIncorrect (SRC_POS);
	}

	void KdfArgon2idMaxLegacy::DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const
	{
		ValidateParameters (key, password, salt, iterationCount);
		int rc = derive_key_argon2id_max_legacy (
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

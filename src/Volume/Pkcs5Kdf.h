/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Encryption_Pkcs5
#define TC_HEADER_Encryption_Pkcs5

#include "Platform/Platform.h"
#include "Hash.h"
#include "VolumePassword.h"

namespace Basalt
{
	class Pkcs5Kdf;
	typedef list < shared_ptr <Pkcs5Kdf> > Pkcs5KdfList;

	class Pkcs5Kdf
	{
	public:
		virtual ~Pkcs5Kdf ();

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt) const;
		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const = 0;
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const wstring &name, bool allowLegacy = false);
		static shared_ptr <Pkcs5Kdf> GetAlgorithm (const Hash &hash, bool allowLegacy = false);
		static Pkcs5KdfList GetAvailableAlgorithms ();
		static shared_ptr <Pkcs5Kdf> GetUpgradeTarget (const wstring &name, int iterationCount);
		// Restricts the KDFs tried when opening a volume. Hint: empty (all),
		// "Argon2id-Max" or "Argon2id" (each including its pre-RFC variant), "PBKDF2".
		static Pkcs5KdfList FilterByHint (const Pkcs5KdfList &kdfs, const wstring &hint);
		virtual shared_ptr <Hash> GetHash () const = 0;
		virtual int GetIterationCount () const = 0;
		virtual wstring GetName () const = 0;
		virtual bool IsDeprecated () const { return GetHash()->IsDeprecated(); }
		virtual bool IsLegacy () const { return false; }
		// Open-only KDFs are tried when opening volumes but are never selected
		// for creating headers (GetAlgorithm skips them).
		virtual bool IsOpenOnly () const { return false; }

		// PBKDF2 output consists of independent blocks of the PRF's digest size,
		// which can be derived in parallel (VolumeHeader::Decrypt). 0 for other
		// KDFs (Argon2id).
		size_t GetPbkdf2BlockSize () const;
		bool IsPbkdf2 () const { return GetPbkdf2BlockSize() != 0; }
		// Derives PBKDF2 block 'blockNumber' (1-based, GetPbkdf2BlockSize() bytes).
		void DerivePbkdf2Block (const BufferPtr &block, const VolumePassword &password, const ConstBufferPtr &salt, int blockNumber) const;

	protected:
		Pkcs5Kdf ();

		void ValidateParameters (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;

	private:
		Pkcs5Kdf (const Pkcs5Kdf &);
		Pkcs5Kdf &operator= (const Pkcs5Kdf &);
	};

	// --- Modern KDFs (high iteration counts for new volumes) ---

	class Pkcs5HmacRipemd160 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacRipemd160 () { }
		virtual ~Pkcs5HmacRipemd160 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Ripemd160); }
		virtual int GetIterationCount () const { return 655331; }
		virtual wstring GetName () const { return L"HMAC-RIPEMD-160"; }

	private:
		Pkcs5HmacRipemd160 (const Pkcs5HmacRipemd160 &);
		Pkcs5HmacRipemd160 &operator= (const Pkcs5HmacRipemd160 &);
	};

	class Pkcs5HmacSha512 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha512 () { }
		virtual ~Pkcs5HmacSha512 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha512); }
		virtual int GetIterationCount () const { return 500000; }
		virtual wstring GetName () const { return L"HMAC-SHA-512"; }

	private:
		Pkcs5HmacSha512 (const Pkcs5HmacSha512 &);
		Pkcs5HmacSha512 &operator= (const Pkcs5HmacSha512 &);
	};

	class Pkcs5HmacWhirlpool : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacWhirlpool () { }
		virtual ~Pkcs5HmacWhirlpool () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Whirlpool); }
		virtual int GetIterationCount () const { return 500000; }
		virtual wstring GetName () const { return L"HMAC-Whirlpool"; }

	private:
		Pkcs5HmacWhirlpool (const Pkcs5HmacWhirlpool &);
		Pkcs5HmacWhirlpool &operator= (const Pkcs5HmacWhirlpool &);
	};

	class Pkcs5HmacSha1 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha1 () { }
		virtual ~Pkcs5HmacSha1 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha1); }
		virtual int GetIterationCount () const { return 500000; }
		virtual wstring GetName () const { return L"HMAC-SHA-1"; }

	private:
		Pkcs5HmacSha1 (const Pkcs5HmacSha1 &);
		Pkcs5HmacSha1 &operator= (const Pkcs5HmacSha1 &);
	};

	// --- Memory-hard KDF (Argon2id, RFC 9106) ---

	class KdfArgon2id : public Pkcs5Kdf
	{
	public:
		KdfArgon2id () { }
		virtual ~KdfArgon2id () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Argon2idHash); }
		virtual int GetIterationCount () const { return 4; } // t_cost (passes)
		virtual wstring GetName () const { return L"Argon2id"; }
		virtual bool IsDeprecated () const { return false; }

	private:
		KdfArgon2id (const KdfArgon2id &);
		KdfArgon2id &operator= (const KdfArgon2id &);
	};

	// Argon2id Maximum Security: m=1 GB, t=4, p=8
	class KdfArgon2idMax : public Pkcs5Kdf
	{
	public:
		KdfArgon2idMax () { }
		virtual ~KdfArgon2idMax () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Argon2idMaxHash); }
		virtual int GetIterationCount () const { return 4; }  // t_cost
		virtual wstring GetName () const { return L"Argon2id-Max"; }
		virtual bool IsDeprecated () const { return false; }

	private:
		KdfArgon2idMax (const KdfArgon2idMax &);
		KdfArgon2idMax &operator= (const KdfArgon2idMax &);
	};

	// --- Open-only Argon2id variants of Basalt <= 1.1.x ---
	// Those versions used a compression function that deviates from RFC 9106.
	// These classes reproduce it so that existing volumes can be opened and
	// upgraded to the standard KDF; they are never used for new headers.

	class KdfArgon2idLegacy : public Pkcs5Kdf
	{
	public:
		KdfArgon2idLegacy () { }
		virtual ~KdfArgon2idLegacy () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Argon2idHash); }
		virtual int GetIterationCount () const { return 4; }
		virtual wstring GetName () const { return L"Argon2id (legacy)"; }
		virtual bool IsDeprecated () const { return true; }
		virtual bool IsLegacy () const { return true; }
		virtual bool IsOpenOnly () const { return true; }

	private:
		KdfArgon2idLegacy (const KdfArgon2idLegacy &);
		KdfArgon2idLegacy &operator= (const KdfArgon2idLegacy &);
	};

	class KdfArgon2idMaxLegacy : public Pkcs5Kdf
	{
	public:
		KdfArgon2idMaxLegacy () { }
		virtual ~KdfArgon2idMaxLegacy () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Argon2idMaxHash); }
		virtual int GetIterationCount () const { return 4; }
		virtual wstring GetName () const { return L"Argon2id-Max (legacy)"; }
		virtual bool IsDeprecated () const { return true; }
		virtual bool IsLegacy () const { return true; }
		virtual bool IsOpenOnly () const { return true; }

	private:
		KdfArgon2idMaxLegacy (const KdfArgon2idMaxLegacy &);
		KdfArgon2idMaxLegacy &operator= (const KdfArgon2idMaxLegacy &);
	};

	// --- Legacy KDFs (original TrueCrypt iteration counts for opening old volumes) ---

	class Pkcs5HmacRipemd160_Legacy : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacRipemd160_Legacy () { }
		virtual ~Pkcs5HmacRipemd160_Legacy () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Ripemd160); }
		virtual int GetIterationCount () const { return 2000; }
		virtual wstring GetName () const { return L"HMAC-RIPEMD-160"; }
		virtual bool IsLegacy () const { return true; }

	private:
		Pkcs5HmacRipemd160_Legacy (const Pkcs5HmacRipemd160_Legacy &);
		Pkcs5HmacRipemd160_Legacy &operator= (const Pkcs5HmacRipemd160_Legacy &);
	};

	class Pkcs5HmacRipemd160_1000 : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacRipemd160_1000 () { }
		virtual ~Pkcs5HmacRipemd160_1000 () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Ripemd160); }
		virtual int GetIterationCount () const { return 1000; }
		virtual wstring GetName () const { return L"HMAC-RIPEMD-160"; }
		virtual bool IsLegacy () const { return true; }

	private:
		Pkcs5HmacRipemd160_1000 (const Pkcs5HmacRipemd160_1000 &);
		Pkcs5HmacRipemd160_1000 &operator= (const Pkcs5HmacRipemd160_1000 &);
	};

	class Pkcs5HmacSha512_Legacy : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha512_Legacy () { }
		virtual ~Pkcs5HmacSha512_Legacy () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha512); }
		virtual int GetIterationCount () const { return 1000; }
		virtual wstring GetName () const { return L"HMAC-SHA-512"; }
		virtual bool IsLegacy () const { return true; }

	private:
		Pkcs5HmacSha512_Legacy (const Pkcs5HmacSha512_Legacy &);
		Pkcs5HmacSha512_Legacy &operator= (const Pkcs5HmacSha512_Legacy &);
	};

	class Pkcs5HmacWhirlpool_Legacy : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacWhirlpool_Legacy () { }
		virtual ~Pkcs5HmacWhirlpool_Legacy () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Whirlpool); }
		virtual int GetIterationCount () const { return 1000; }
		virtual wstring GetName () const { return L"HMAC-Whirlpool"; }
		virtual bool IsLegacy () const { return true; }

	private:
		Pkcs5HmacWhirlpool_Legacy (const Pkcs5HmacWhirlpool_Legacy &);
		Pkcs5HmacWhirlpool_Legacy &operator= (const Pkcs5HmacWhirlpool_Legacy &);
	};

	class Pkcs5HmacSha1_Legacy : public Pkcs5Kdf
	{
	public:
		Pkcs5HmacSha1_Legacy () { }
		virtual ~Pkcs5HmacSha1_Legacy () { }

		virtual void DeriveKey (const BufferPtr &key, const VolumePassword &password, const ConstBufferPtr &salt, int iterationCount) const;
		virtual shared_ptr <Hash> GetHash () const { return shared_ptr <Hash> (new Sha1); }
		virtual int GetIterationCount () const { return 2000; }
		virtual wstring GetName () const { return L"HMAC-SHA-1"; }
		virtual bool IsLegacy () const { return true; }

	private:
		Pkcs5HmacSha1_Legacy (const Pkcs5HmacSha1_Legacy &);
		Pkcs5HmacSha1_Legacy &operator= (const Pkcs5HmacSha1_Legacy &);
	};
}

#endif // TC_HEADER_Encryption_Pkcs5

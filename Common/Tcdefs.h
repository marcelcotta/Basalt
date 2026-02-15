/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef TCDEFS_H
#define TCDEFS_H

#define TC_APP_NAME						"Basalt"

// Version displayed to user
#define VERSION_STRING					"1.0"

// Version number to compare against driver
#define VERSION_NUM						0x0100

// Release date
#define TC_STR_RELEASE_DATE				"February 10, 2025"
#define TC_RELEASE_DATE_YEAR			2025
#define TC_RELEASE_DATE_MONTH			2

#define BYTES_PER_KB                    1024LL
#define BYTES_PER_MB                    1048576LL
#define BYTES_PER_GB                    1073741824LL
#define BYTES_PER_TB                    1099511627776LL
#define BYTES_PER_PB                    1125899906842624LL

// --- Integer types ---

#ifdef _MSC_VER

typedef __int8 int8;
typedef __int16 int16;
typedef __int32 int32;
typedef unsigned __int8 byte;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;

typedef unsigned __int64	TC_LARGEST_COMPILER_UINT;
typedef __int64 int64;
typedef unsigned __int64 uint64;

#else // !_MSC_VER

#include <inttypes.h>
#include <limits.h>

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t byte;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

#if UCHAR_MAX != 0xffU
#error UCHAR_MAX != 0xff
#endif
#define __int8 char

#if USHRT_MAX != 0xffffU
#error USHRT_MAX != 0xffff
#endif
#define __int16 short

#if UINT_MAX != 0xffffffffU
#error UINT_MAX != 0xffffffff
#endif
#define __int32 int

typedef uint64 TC_LARGEST_COMPILER_UINT;

// Don't redefine BOOL when compiling Objective-C/C++ — ObjC defines
// typedef bool BOOL in <objc/objc.h> and our #define would conflict.
#if !defined(__OBJC__)
#define BOOL int
#endif
#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#endif // !_MSC_VER

#define TC_INT_TYPES_DEFINED

// Integer types required by Cryptolib
typedef unsigned __int8 uint_8t;
typedef unsigned __int16 uint_16t;
typedef unsigned __int32 uint_32t;
typedef uint64 uint_64t;

typedef union
{
	struct
	{
		unsigned __int32 LowPart;
		unsigned __int32 HighPart;
	};
	uint64 Value;

} UINT64_STRUCT;

// --- Fatal exception (null-pointer dereference for crash dump) ---
#define TC_THROW_FATAL_EXCEPTION	*(char *) 0 = 0

// --- Stringification ---
#ifndef TC_TO_STRING
#	define TC_TO_STRING2(n) #n
#	define TC_TO_STRING(n) TC_TO_STRING2(n)
#endif

// --- Secure memory wipe ---
#ifdef _WIN32
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; RtlSecureZeroMemory (mem, size); while (burnc--) *burnm++ = 0; } while (0)
#else
/* Use memset_s() - C11 Annex K, guaranteed not to be optimized away.
   Available on macOS 10.9+, and most C11-compliant platforms. */
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>
#define burn(mem,size) memset_s((mem), (size), 0, (size))
#endif

// SECURITY: FAST_ERASE64 delegates to burn() which uses memset_s().
// memset_s() (C11 Annex K) is the only standards-compliant way to
// ensure the wipe is not optimized away.
#define FAST_ERASE64(mem,size) burn((mem),(size))

// Avoid conflict with macOS <mach/error.h> which #defines ERR_SUCCESS
#ifdef ERR_SUCCESS
#undef ERR_SUCCESS
#endif

enum
{
	/* WARNING: ADD ANY NEW CODES AT THE END (DO NOT INSERT THEM BETWEEN EXISTING). DO *NOT* DELETE ANY
	EXISTING CODES! Changing these values or their meanings may cause incompatibility with other versions. */

	ERR_SUCCESS								= 0,
	ERR_OS_ERROR							= 1,
	ERR_OUTOFMEMORY							= 2,
	ERR_PASSWORD_WRONG						= 3,
	ERR_VOL_FORMAT_BAD						= 4,
	ERR_DRIVE_NOT_FOUND						= 5,
	ERR_FILES_OPEN							= 6,
	ERR_VOL_SIZE_WRONG						= 7,
	ERR_COMPRESSION_NOT_SUPPORTED			= 8,
	ERR_PASSWORD_CHANGE_VOL_TYPE			= 9,
	ERR_PASSWORD_CHANGE_VOL_VERSION			= 10,
	ERR_VOL_SEEKING							= 11,
	ERR_VOL_WRITING							= 12,
	ERR_FILES_OPEN_LOCK						= 13,
	ERR_VOL_READING							= 14,
	ERR_DRIVER_VERSION						= 15,
	ERR_NEW_VERSION_REQUIRED				= 16,
	ERR_CIPHER_INIT_FAILURE					= 17,
	ERR_CIPHER_INIT_WEAK_KEY				= 18,
	ERR_SELF_TESTS_FAILED					= 19,
	ERR_SECTOR_SIZE_INCOMPATIBLE			= 20,
	ERR_VOL_ALREADY_MOUNTED					= 21,
	ERR_NO_FREE_DRIVES						= 22,
	ERR_FILE_OPEN_FAILED					= 23,
	ERR_VOL_MOUNT_FAILED					= 24,
	DEPRECATED_ERR_INVALID_DEVICE			= 25,
	ERR_ACCESS_DENIED						= 26,
	ERR_MODE_INIT_FAILED					= 27,
	ERR_DONT_REPORT							= 28,
	ERR_ENCRYPTION_NOT_COMPLETED			= 29,
	ERR_PARAMETER_INCORRECT					= 30,
	ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG	= 31,
	ERR_NONSYS_INPLACE_ENC_INCOMPLETE		= 32,
	ERR_USER_ABORT							= 33
};

#endif 	// #ifndef TCDEFS_H

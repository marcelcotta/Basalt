#
# Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#

OBJS :=
OBJS += Cipher.o
OBJS += EncryptionAlgorithm.o
OBJS += EncryptionMode.o
OBJS += EncryptionModeCBC.o
OBJS += EncryptionModeLRW.o
OBJS += EncryptionModeXTS.o
OBJS += EncryptionTest.o
OBJS += EncryptionThreadPool.o
OBJS += Hash.o
OBJS += Keyfile.o
OBJS += Pkcs5Kdf.o
OBJS += Volume.o
OBJS += VolumeException.o
OBJS += VolumeHeader.o
OBJS += VolumeInfo.o
OBJS += VolumeLayout.o
OBJS += VolumePassword.o

ifeq "$(CPU_ARCH)" "x86"
	OBJS += ../Crypto/Aes_x86.o
	OBJS += ../Crypto/Aes_hw_cpu.o
	ifeq "$(PLATFORM)" "MacOSX"
		OBJS += ../Crypto/Aescrypt.o
	endif
else ifeq "$(CPU_ARCH)" "x64"
	OBJS += ../Crypto/Aes_x64.o
	OBJS += ../Crypto/Aes_hw_cpu.o
else
	OBJS += ../Crypto/Aescrypt.o
	# ARM64 hardware AES via NEON intrinsics (not assembly, works with NOASM=1)
	# Use TARGET_ARCH if set (for cross-compilation), else detect via uname -m
	REAL_ARCH := $(or $(TARGET_ARCH),$(shell uname -m))
	ifneq (,$(filter arm64 aarch64,$(REAL_ARCH)))
		OBJS += ../Crypto/Aes_hw_cpu_arm.o
	endif
endif

OBJS += ../Crypto/Aeskey.o
OBJS += ../Crypto/Aestab.o
OBJS += ../Crypto/Blowfish.o
OBJS += ../Crypto/Cast.o
OBJS += ../Crypto/Des.o
OBJS += ../Crypto/Rmd160.o
OBJS += ../Crypto/Serpent.o
OBJS += ../Crypto/Sha1.o
OBJS += ../Crypto/Sha2.o
OBJS += ../Crypto/Twofish.o
OBJS += ../Crypto/Whirlpool.o

OBJS += ../Crypto/Argon2/argon2.o
OBJS += ../Crypto/Argon2/core.o
OBJS += ../Crypto/Argon2/blake2b.o
OBJS += ../Crypto/Argon2/ref.o
OBJS += ../Crypto/Argon2/thread.o

OBJS += ../Common/Crc.o
OBJS += ../Common/Endian.o
OBJS += ../Common/GfMul.o
OBJS += ../Common/Pkcs5.o
OBJS += ../Common/Argon2Kdf.o
OBJS += ../Common/SecurityToken.o

VolumeLibrary: Volume.a

include $(BUILD_INC)/Makefile.inc

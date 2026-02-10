#
# Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#

#------ Command line arguments ------
# DEBUG:		Disable optimizations and enable debugging checks
# DEBUGGER:		Enable debugging information for use by debuggers
# NOASM:		Exclude modules requiring assembler
# NOSTRIP:		Do not strip release binary
# NOTEST:		Do not test release binary
# VERBOSE:		Enable verbose messages
# TARGET_ARCH:	Override target architecture for cross-compilation (arm64 or x86_64)


#------ Targets ------
# libTrueCryptCore	Build the core static library (no UI dependency)
# cli			Build standalone command-line tool
# clean			Remove build artifacts


#------ Build configuration ------

export APPNAME := basalt
export BASE_DIR := $(CURDIR)
export BUILD_INC := $(BASE_DIR)/Build/Include

export AR ?= ar
export CC ?= gcc
export CXX ?= g++
export AS := nasm
export RANLIB ?= ranlib

export CFLAGS := -Wall
export CXXFLAGS := -Wall -Wno-unused-parameter
C_CXX_FLAGS := -MMD -D__STDC_WANT_LIB_EXT1__=1 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES -I$(BASE_DIR) -I$(BASE_DIR)/Crypto
export ASFLAGS := -Ox -D __GNUC__
export LFLAGS :=
ifneq "$(shell uname -s)" "Darwin"
export LIBS := -ldl
else
export LIBS :=
endif

export PKG_CONFIG_PATH ?= /usr/local/lib/pkgconfig


export TC_BUILD_CONFIG := Release

ifeq "$(origin DEBUG)" "command line"
	ifneq "$(DEBUG)" "0"
		TC_BUILD_CONFIG := Debug
	endif
endif

ifdef PKCS11_INC
	C_CXX_FLAGS += -I$(PKCS11_INC)
endif

ifneq "$(origin VERBOSE)" "command line"
	MAKEFLAGS += -s
endif


#------ Release configuration ------

ifeq "$(TC_BUILD_CONFIG)" "Release"

	C_CXX_FLAGS += -O2 -fno-strict-aliasing  # Do not enable strict aliasing

else

#------ Debug configuration ------

	C_CXX_FLAGS += -DDEBUG
	CXXFLAGS += -fno-default-inline -Wno-unused-function -Wno-unused-variable

endif


#------ Debugger configuration ------

ifeq "$(origin DEBUGGER)" "command line"
	C_CXX_FLAGS += -ggdb
endif


#------ Platform configuration ------

export PLATFORM := "Unknown"
export PLATFORM_UNSUPPORTED := 0

export CPU_ARCH ?= unknown
export TARGET_ARCH ?=

ARCH = $(shell uname -p)
ifeq "$(ARCH)" "unknown"
	ARCH = $(shell uname -m)
endif

ifneq (,$(filter i386 i486 i586 i686 x86,$(ARCH)))
	CPU_ARCH = x86
	ASM_OBJ_FORMAT = elf32
else ifneq (,$(filter x86_64 x86-64 amd64 x64,$(ARCH)))
	CPU_ARCH = x64
	ASM_OBJ_FORMAT = elf64
else ifneq (,$(filter arm64 aarch64,$(ARCH)))
	CPU_ARCH = arm64
endif

ifeq "$(origin NOASM)" "command line"
	CPU_ARCH = unknown
endif

ifeq "$(CPU_ARCH)" "x86"
	C_CXX_FLAGS += -D TC_ARCH_X86
else ifeq "$(CPU_ARCH)" "x64"
	C_CXX_FLAGS += -D TC_ARCH_X64
endif


#------ Linux configuration ------

ifeq "$(shell uname -s)" "Linux"

	PLATFORM := Linux
	C_CXX_FLAGS += -DTC_UNIX -DTC_LINUX
	CXXFLAGS += -std=c++14 -Wno-deprecated-declarations

	ifeq "$(TC_BUILD_CONFIG)" "Release"
		C_CXX_FLAGS += -fdata-sections -ffunction-sections
		LFLAGS += -Wl,--gc-sections

		ifneq "$(shell ld --help 2>&1 | grep sysv | wc -l)" "0"
			LFLAGS += -Wl,--hash-style=sysv
		endif
	endif

endif


#------ Mac OS X configuration ------

ifeq "$(shell uname -s)" "Darwin"

	PLATFORM := MacOSX
	APPNAME := Basalt

	TC_OSX_SDK ?= $(shell xcrun --show-sdk-path)

	C_CXX_FLAGS += -DTC_UNIX -DTC_BSD -DTC_MACOSX -mmacosx-version-min=11.0 -isysroot $(TC_OSX_SDK)
	CXXFLAGS += -std=c++14 -stdlib=libc++ -Wno-deprecated-declarations
	LFLAGS += -mmacosx-version-min=11.0 -Wl,-syslibroot,$(TC_OSX_SDK) -stdlib=libc++

	ASM_OBJ_FORMAT = macho64
	ASFLAGS += --prefix _

	ifeq "$(TC_BUILD_CONFIG)" "Release"

		export DISABLE_PRECOMPILED_HEADERS := 1

		S := $(C_CXX_FLAGS)
		C_CXX_FLAGS = $(subst -MMD,,$(S))

		C_CXX_FLAGS += -g
		LFLAGS += -Wl,-dead_strip

	endif

endif


#------ FreeBSD configuration ------

ifeq "$(shell uname -s)" "FreeBSD"

	PLATFORM := FreeBSD
	PLATFORM_UNSUPPORTED := 1
	C_CXX_FLAGS += -DTC_UNIX -DTC_BSD -DTC_FREEBSD

endif


#------ Solaris configuration ------

ifeq "$(shell uname -s)" "SunOS"

	PLATFORM := Solaris
	PLATFORM_UNSUPPORTED := 1
	C_CXX_FLAGS += -DTC_UNIX -DTC_SOLARIS

endif


#------ Common configuration ------

CFLAGS := $(C_CXX_FLAGS) $(CFLAGS) $(TC_EXTRA_CFLAGS)
CXXFLAGS := $(C_CXX_FLAGS) $(CXXFLAGS) $(TC_EXTRA_CXXFLAGS)
ASFLAGS += -f $(ASM_OBJ_FORMAT)
LFLAGS := $(LFLAGS) $(TC_EXTRA_LFLAGS)


#------ Project build ------

CORE_DIRS := Platform Volume Driver/Fuse Core

.PHONY: libTrueCryptCore cli clean

#------ Core library (no UI dependency) ------

CORE_ARCHIVES := \
	$(BASE_DIR)/Platform/Platform.a \
	$(BASE_DIR)/Volume/Volume.a \
	$(BASE_DIR)/Driver/Fuse/Driver.a \
	$(BASE_DIR)/Core/Core.a

libTrueCryptCore:
	@for DIR in $(CORE_DIRS); do \
		PROJ=$$(echo $$DIR | cut -d/ -f1); \
		$(MAKE) -C $$DIR -f $$PROJ.make NAME=$$PROJ || exit $$?; \
	done
	@echo "Creating libTrueCryptCore.a..."
ifeq "$(shell uname -s)" "Darwin"
	libtool -static -o $(BASE_DIR)/libTrueCryptCore.a $(CORE_ARCHIVES)
else
	rm -f $(BASE_DIR)/libTrueCryptCore.a
	$(eval TMPDIR_AR := $(shell mktemp -d))
	@for archive in $(CORE_ARCHIVES); do \
		cd $(TMPDIR_AR) && $(AR) x $$archive; \
	done
	$(AR) rcs $(BASE_DIR)/libTrueCryptCore.a $(TMPDIR_AR)/*.o
	$(RANLIB) $(BASE_DIR)/libTrueCryptCore.a
	rm -rf $(TMPDIR_AR)
endif


#------ Standalone CLI (no UI dependency) ------

cli: libTrueCryptCore
	$(MAKE) -C CLI -f CLI.make APPNAME=basalt-cli


#------ Clean ------

clean:
	@for DIR in $(CORE_DIRS); do \
		PROJ=$$(echo $$DIR | cut -d/ -f1); \
		$(MAKE) -C $$DIR -f $$PROJ.make NAME=$$PROJ clean 2>/dev/null || true; \
	done
	$(MAKE) -C CLI -f CLI.make clean 2>/dev/null || true
	rm -f $(BASE_DIR)/libTrueCryptCore.a

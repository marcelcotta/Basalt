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

#------ Targets ------
# libBasaltCore		Build the core static library (no UI dependency)
# cli			Build standalone command-line tool
# clean			Remove build artifacts


#------ Build configuration ------

export APPNAME := basalt
export BASE_DIR := $(CURDIR)
export BUILD_INC := $(BASE_DIR)/Build/Include
export SRC_DIR := $(BASE_DIR)/src

export AR ?= ar
export CC ?= gcc
export CXX ?= g++
export AS := nasm
export RANLIB ?= ranlib

export CFLAGS := -Wall
export CXXFLAGS := -Wall -Wno-unused-parameter -Wno-potentially-evaluated-expression
C_CXX_FLAGS := -MMD -D__STDC_WANT_LIB_EXT1__=1 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES -I$(BASE_DIR)/src -I$(BASE_DIR)/src/Crypto
export ASFLAGS := -Ox -D __GNUC__
export LFLAGS :=
export LIBS :=

export PKG_CONFIG_PATH ?= /usr/local/lib/pkgconfig


export TC_BUILD_CONFIG := Release

ifeq "$(origin DEBUG)" "command line"
	ifneq "$(DEBUG)" "0"
		TC_BUILD_CONFIG := Debug
	endif
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

export CPU_ARCH ?= unknown

ARCH = $(shell uname -m)

ifneq (,$(filter x86_64 x86-64 amd64 x64,$(ARCH)))
	CPU_ARCH = x64
else ifneq (,$(filter arm64 aarch64,$(ARCH)))
	CPU_ARCH = arm64
endif

ifeq "$(origin NOASM)" "command line"
	CPU_ARCH = unknown
endif

ifeq "$(CPU_ARCH)" "x64"
	C_CXX_FLAGS += -D TC_ARCH_X64
endif


#------ macOS configuration ------

export PLATFORM := MacOSX
export PLATFORM_UNSUPPORTED := 0
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


#------ Common configuration ------

CFLAGS := $(C_CXX_FLAGS) $(CFLAGS) $(TC_EXTRA_CFLAGS)
CXXFLAGS := $(C_CXX_FLAGS) $(CXXFLAGS) $(TC_EXTRA_CXXFLAGS)
ASFLAGS += -f $(ASM_OBJ_FORMAT)
LFLAGS := $(LFLAGS) $(TC_EXTRA_LFLAGS)


#------ Project build ------

CORE_DIRS := Platform Volume Fuse Core

.PHONY: libBasaltCore cli clean darwinfuse

#------ DarwinFUSE (NFSv4 userspace FUSE) ------

DARWINFUSE_LIB := $(SRC_DIR)/DarwinFUSE/libdarwinfuse.a

darwinfuse: $(DARWINFUSE_LIB)

$(DARWINFUSE_LIB):
	$(MAKE) -C $(SRC_DIR)/DarwinFUSE TC_BUILD_CONFIG=$(TC_BUILD_CONFIG)

#------ Core library (no UI dependency) ------

CORE_ARCHIVES := \
	$(SRC_DIR)/Platform/Platform.a \
	$(SRC_DIR)/Volume/Volume.a \
	$(SRC_DIR)/Fuse/Fuse.a \
	$(SRC_DIR)/Core/Core.a

libBasaltCore: $(DARWINFUSE_LIB)
	@for DIR in $(CORE_DIRS); do \
		$(MAKE) -C $(SRC_DIR)/$$DIR -f $$DIR.make NAME=$$DIR || exit $$?; \
	done
	@echo "Creating libBasaltCore.a..."
	libtool -static -o $(BASE_DIR)/libBasaltCore.a $(CORE_ARCHIVES)


#------ Standalone CLI (no UI dependency) ------

cli: libBasaltCore
	$(MAKE) -C CLI -f CLI.make APPNAME=basalt-cli


#------ Clean ------

clean:
	@for DIR in $(CORE_DIRS); do \
		$(MAKE) -C $(SRC_DIR)/$$DIR -f $$DIR.make NAME=$$DIR clean 2>/dev/null || true; \
	done
	$(MAKE) -C CLI -f CLI.make clean 2>/dev/null || true
	$(MAKE) -C $(SRC_DIR)/DarwinFUSE clean 2>/dev/null || true
	rm -f $(BASE_DIR)/libBasaltCore.a

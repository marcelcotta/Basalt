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
# gui			Build Qt6 GUI (uses CMake for Qt6 deps)
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

.PHONY: libTrueCryptCore cli gui clean darwinfuse

#------ DarwinFUSE (macOS only — NFSv4 FUSE replacement) ------

ifeq "$(shell uname -s)" "Darwin"
DARWINFUSE_LIB := $(BASE_DIR)/DarwinFUSE/libdarwinfuse.a

darwinfuse: $(DARWINFUSE_LIB)

$(DARWINFUSE_LIB):
	$(MAKE) -C $(BASE_DIR)/DarwinFUSE TC_BUILD_CONFIG=$(TC_BUILD_CONFIG)
endif

#------ Core library (no UI dependency) ------

CORE_ARCHIVES := \
	$(BASE_DIR)/Platform/Platform.a \
	$(BASE_DIR)/Volume/Volume.a \
	$(BASE_DIR)/Driver/Fuse/Driver.a \
	$(BASE_DIR)/Core/Core.a

ifeq "$(shell uname -s)" "Darwin"
libTrueCryptCore: $(DARWINFUSE_LIB)
endif

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


#------ Qt6 GUI (uses CMake — handles Qt6 dependency) ------

gui:
	@echo "Building Basalt Qt6 GUI via CMake..."
ifeq "$(TC_BUILD_CONFIG)" "Release"
	cmake -B build_gui -DCMAKE_BUILD_TYPE=Release -DBASALT_BUILD_GUI=ON 2>&1 | tail -5
else
	cmake -B build_gui -DCMAKE_BUILD_TYPE=Debug -DBASALT_BUILD_GUI=ON 2>&1 | tail -5
endif
	cmake --build build_gui --target basalt-gui -- -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
	@echo "GUI binary: build_gui/bin/basalt-gui"


#------ Qt6 GUI for Windows (cross-compile from macOS via MinGW + aqtinstall) ------

gui-windows:
	@echo "Cross-compiling Basalt Qt6 GUI for Windows..."
	@if [ ! -d qt6-win-mingw ]; then \
		echo "ERROR: Qt6 for Windows/MinGW not found."; \
		echo "  Install: pip install aqtinstall"; \
		echo "  Then:    aqt install-qt windows desktop 6.10.2 win64_mingw --outputdir qt6-win-mingw"; \
		exit 1; \
	fi
ifeq "$(TC_BUILD_CONFIG)" "Release"
	cmake -B build_wingui -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-qt6.cmake -DBASALT_BUILD_GUI=ON -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -5
else
	cmake -B build_wingui -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-qt6.cmake -DBASALT_BUILD_GUI=ON -DCMAKE_BUILD_TYPE=Debug 2>&1 | tail -5
endif
	cmake --build build_wingui --target basalt-gui -- -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
	@echo "Windows GUI binary: build_wingui/bin/basalt-gui.exe"
	@echo "Run 'make deploy-windows' to create a distributable folder with all DLLs."

deploy-windows: gui-windows
	@echo "Packaging Basalt for Windows..."
	@QT_DIR=$$(find qt6-win-mingw -path "*/mingw_64" -type d | head -1) && \
	rm -rf dist/windows && mkdir -p dist/windows/platforms && \
	cp build_wingui/bin/basalt-gui.exe dist/windows/ && \
	cp build_wingui/bin/basalt-cli.exe dist/windows/ 2>/dev/null; \
	cp "$$QT_DIR/bin/Qt6Core.dll" dist/windows/ && \
	cp "$$QT_DIR/bin/Qt6Gui.dll" dist/windows/ && \
	cp "$$QT_DIR/bin/Qt6Widgets.dll" dist/windows/ && \
	cp "$$QT_DIR/bin/libgcc_s_seh-1.dll" dist/windows/ && \
	cp "$$QT_DIR/bin/libstdc++-6.dll" dist/windows/ && \
	cp "$$QT_DIR/bin/libwinpthread-1.dll" dist/windows/ && \
	cp "$$QT_DIR/plugins/platforms/qwindows.dll" dist/windows/platforms/ && \
	echo "Done: dist/windows/ ($$(ls dist/windows/*.{exe,dll} 2>/dev/null | wc -l | tr -d ' ') files)" && \
	du -sh dist/windows/


#------ Clean ------

clean:
	@for DIR in $(CORE_DIRS); do \
		PROJ=$$(echo $$DIR | cut -d/ -f1); \
		$(MAKE) -C $$DIR -f $$PROJ.make NAME=$$PROJ clean 2>/dev/null || true; \
	done
	$(MAKE) -C CLI -f CLI.make clean 2>/dev/null || true
ifeq "$(shell uname -s)" "Darwin"
	$(MAKE) -C $(BASE_DIR)/DarwinFUSE clean 2>/dev/null || true
endif
	rm -rf $(BASE_DIR)/build_gui
	rm -f $(BASE_DIR)/libTrueCryptCore.a

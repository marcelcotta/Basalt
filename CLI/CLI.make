#
# Copyright (c) 2024-2026 Basalt contributors. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#
# Standalone CLI — links against libTrueCryptCore.a, no wxWidgets dependency.
#

OBJS :=
OBJS += main.o
OBJS += CLICallback.o

CXXFLAGS += -I$(BASE_DIR)/CLI -I$(BASE_DIR)/src -I$(BASE_DIR)/src/Crypto

#------ FUSE configuration ------

ifeq "$(shell uname -s)" "Darwin"
    FUSE_LIBS = $(BASE_DIR)/src/DarwinFUSE/libdarwinfuse.a
else
    FUSE_LIBS = $(shell pkg-config fuse --libs)
endif

#------ C++ standard library (libc++ on macOS, libstdc++ on Linux) ------

ifeq "$(shell uname -s)" "Darwin"
CXX_STDLIB := -lc++
else
CXX_STDLIB := -lstdc++ -lpthread
endif

#------ Core library ------

CORE_LIB = $(BASE_DIR)/libBasaltCore.a

#------ Executable ------

APPNAME := basalt-cli

$(APPNAME): $(CORE_LIB) $(OBJS)
	@echo Linking $@
	$(CXX) -o $(APPNAME) $(LFLAGS) $(OBJS) $(CORE_LIB) $(FUSE_LIBS) $(LIBS) $(CXX_STDLIB)

ifeq "$(TC_BUILD_CONFIG)" "Release"
ifndef NOSTRIP
	strip $(APPNAME)
endif

ifndef NOTEST
	./$(APPNAME) --test >/dev/null || exit 1
endif
endif

clean:
	@echo Cleaning CLI
	rm -f $(APPNAME) $(OBJS) $(OBJS:.o=.d)

%.o: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Dependencies
-include $(OBJS:.o=.d)

#
# DarwinFUSE — Userspace NFSv4 FUSE replacement for macOS
# Builds libdarwinfuse.a (static library, pure C, no external dependencies)
#

CC ?= cc
AR ?= ar
RANLIB ?= ranlib

CFLAGS += -Wall -Wextra -Wno-unused-parameter -std=c11 \
          -I$(CURDIR)/include -I$(CURDIR)/src \
          -D_FILE_OFFSET_BITS=64

ifeq "$(TC_BUILD_CONFIG)" "Release"
    CFLAGS += -O2
else
    CFLAGS += -g
endif

SRCS := \
	src/nfs4_xdr.c \
	src/rpc.c \
	src/nfs4_server.c \
	src/nfs4_ops.c \
	src/darwinfuse.c

OBJS := $(SRCS:.c=.o)

LIB := libdarwinfuse.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	@echo "  AR    $@"
	$(AR) rcs $@ $(OBJS)
	$(RANLIB) $@

%.o: %.c
	@echo "  CC    $<"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning DarwinFUSE"
	rm -f $(OBJS) $(OBJS:.o=.d) $(LIB)

-include $(OBJS:.o=.d)

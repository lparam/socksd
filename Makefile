MAJOR = 0
MINOR = 2
PATCH = 1
NAME = socksd

ifdef O
ifeq ("$(origin O)", "command line")
BUILD_DIR := $(O)
endif
endif

ifneq ($(BUILD_DIR),)
saved-output := $(BUILD_DIR)

# Attempt to create a output directory.
$(shell [ -d ${BUILD_DIR} ] || mkdir -p ${BUILD_DIR})

# Verify if it was successful.
BUILD_DIR := $(shell cd $(BUILD_DIR) && /bin/pwd)
$(if $(BUILD_DIR),,$(error output directory "$(saved-output)" does not exist))
endif # ifneq ($(BUILD_DIR),)

OBJTREE		:= $(if $(BUILD_DIR),$(BUILD_DIR),$(CURDIR))
SRCTREE		:= $(CURDIR)
TOPDIR		:= $(SRCTREE)
export TOPDIR SRCTREE OBJTREE

#########################################################################

ifdef HOST
CROSS_COMPILE = $(HOST)-
endif

# for OpenWrt
ifdef CROSS
CROSS_COMPILE = $(CROSS)
HOST = $(patsubst %-,%,$(CROSS_COMPILE))
ifneq (,$(findstring openwrt,$(CROSS_COMPILE)))
OPENWRT = 1
endif
endif

ifdef CROSS_COMPILE
CPPFLAGS = -DCROSS_COMPILE
endif

CFLAGS = \
	-Os	\
	-g \
	-std=gnu99 \
	-Wall \
	$(PLATFORM_CFLAGS)

CFLAGS += -fomit-frame-pointer -fdata-sections -ffunction-sections

EXTRA_CFLAGS =

#########################################################################

CPPFLAGS += -Isrc
CPPFLAGS += -I3rd/libuv/include -I3rd/udns

LDFLAGS = -Wl,--gc-sections

LIBS += -pthread -ldl -lrt
LIBS += 3rd/libuv/.libs/libuv.a 3rd/udns/libudns.a

LDFLAGS += $(LIBS)

#########################################################################
include $(TOPDIR)/config.mk
#########################################################################

all: libuv udns socksd

3rd/libuv/autogen.sh:
	$(Q)git submodule update --init

3rd/libuv/Makefile: | 3rd/libuv/autogen.sh
	$(Q)cd 3rd/libuv && ./autogen.sh && ./configure --host=$(HOST) LDFLAGS= && $(MAKE)

libuv: 3rd/libuv/Makefile

3rd/udns/configure:
	$(Q)git submodule update --init

3rd/udns/Makefile: | 3rd/udns/configure
	$(Q)cd 3rd/udns && ./configure && $(MAKE)

udns: 3rd/udns/Makefile

socksd: \
	src/util.o \
	src/logger.o \
	src/resolver.o \
	src/consumer.o \
	src/dispatcher.o \
	src/daemon.o \
	src/signal.o \
	src/cache.o \
	src/md5.o \
	src/udprelay.o \
	src/client.o \
	src/remote.o \
	src/main.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)

clean:
	@find $(OBJTREE) -type f \
	\( -name '*.bak' -o -name '*~' \
	-o -name '*.o' -o -name '*.tmp' \) -print \
	| xargs rm -f
	@rm -f socksd

distclean: clean
	$(Q)cd 3rd/libuv && make distclean
	$(Q)cd 3rd/udns && make distclean

install:
	$(Q)cp socksd /usr/local/bin

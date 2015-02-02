#
# (C) Copyright 2000-2015
# Ken <ken.i18n@gmail.com>
#

MAJOR = 0
MINOR = 1
PATCH = 0
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

ifdef CROSS
CROSS_COMPILE = $(CROSS)
endif

CFLAGS = \
	-Os	\
	-std=gnu99 \
	-Wall \
	$(PLATFORM_CFLAGS)

# CFLAGS += -g

EXTRA_CFLAGS =

#########################################################################

CPPFLAGS += -Isrc
CPPFLAGS += -I3rd/libuv/include -I3rd/udns

LDFLAGS = -Wl,-E
LDFLAGS += -pthread -ldl -lrt
LDFLAGS += -L3rd/libuv/.libs -luv -L3rd/udns -ludns

#########################################################################
include $(TOPDIR)/config.mk
#########################################################################

all: libuv udns socksd

3rd/libuv/autogen.sh:
	git submodule update --init

3rd/libuv/Makefile: | 3rd/libuv/autogen.sh
	@cd 3rd/libuv && ./autogen.sh && ./configure && $(MAKE)

libuv: 3rd/libuv/Makefile

udns:
	@cd 3rd/udns && ./configure && make

socksd: \
	src/util.o \
	src/resolver.o \
	src/consumer.o \
	src/dispatcher.o \
	src/client.o \
	src/remote.o \
	src/main.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)

clean:
	@find $(OBJTREE) -type f \
	\( -name '*.bak' -o -name '*~' \
	-o -name '*.o' -o -name '*.tmp' \) -print \
	| xargs rm -f

distclean: clean
	@cd 3rd/libuv && make distclean
	@cd 3rd/udns && make distclean

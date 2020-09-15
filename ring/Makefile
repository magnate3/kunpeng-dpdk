ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = dpdk_test


INC += $(wildcard include/*.h)

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)/include -I/usr/local/include

EXTRA_CFLAGS += -O3 -Wfatal-errors

include $(RTE_SDK)/mk/rte.extapp.mk
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
Q = @
endif

LESSONS = $(wildcard basic*) $(wildcard packet*) $(wildcard tracing??-*)
# LESSONS += advanced03-AF_XDP
LESSONS_CLEAN = $(addsuffix _clean,$(LESSONS))

.PHONY: clean clobber distclean $(LESSONS) $(LESSONS_CLEAN)

all: lib $(LESSONS)
clean: $(LESSONS_CLEAN)
	@echo; echo common; $(MAKE) -C common clean
	@echo; echo lib; $(MAKE) -C lib clean

lib: config.mk check_submodule
	@echo; echo $@; $(MAKE) -C $@

$(LESSONS):
	@echo; echo $@; $(MAKE) -C $@

$(LESSONS_CLEAN):
	@echo; echo $@; $(MAKE) -C $(subst _clean,,$@) clean

config.mk: configure
	@sh configure

clobber:
	@touch config.mk
	$(Q)$(MAKE) clean
	$(Q)rm -f config.mk

distclean:	clobber

check_submodule:
	@if [ -d .git ] && `git submodule status lib/libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\


ifneq ($(srcdir),)
VPATH = $(srcdir)
else
srcdir=$(shell pwd)
endif
CFLAGS = -O2 -g
DWZ_VERSION := $(shell cat $(srcdir)/VERSION)
override CFLAGS += -Wall -W -D_FILE_OFFSET_BITS=64 \
	-DDWZ_VERSION='"$(DWZ_VERSION)"' $(shell cat $(srcdir)/COPYRIGHT_YEARS)
prefix = /usr
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
datarootdir = $(prefix)/share
mandir = $(datarootdir)/man
OBJECTS = dwz.o hashtab.o sha1.o dwarfnames.o
dwz: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ -lelf
install: dwz
	install -D dwz $(DESTDIR)$(bindir)/dwz
	install -D -m 644 $(srcdir)/dwz.1 $(DESTDIR)$(mandir)/man1/dwz.1
clean:
	rm -f $(OBJECTS) *~ core* dwz $(TEST_EXECS) $(DWZ_TEST_SOURCES) \
	  dwz.log dwz.sum
	rm -Rf testsuite-bin tmp.*

PWD:=$(shell pwd -P)

TEST_SRC = $(srcdir)/testsuite/dwz.tests
TEST_EXECS_DWARF_ASM = no-multifile-prop invalid-dw-at-stmt-list-encoding
TEST_EXECS_x86_64 = py-section-script dw2-skip-prologue \
	implptr-64bit-d2o4a8r8t0 varval
TEST_EXECS = hello dwz-for-test min two-typedef start hello-gold-gdb-index \
	start-gold hello-gnu-pubnames $(TEST_EXECS_DWARF_ASM) \
	$(TEST_EXECS_$(UNAME)) odr-struct odr-class odr-union odr-struct-ns \
	odr-class-ns odr-union-ns odr-loc def-decl

UNAME:=$(shell uname -p)

hello:
	$(CC) $(TEST_SRC)/hello.c -o $@ -g

hello-gnu-pubnames:
	$(CC) $(TEST_SRC)/hello.c -o $@ -g -ggnu-pubnames || touch $@

dw2-skip-prologue:
	$(CC) $(TEST_SRC)/dw2-skip-prologue.S $(TEST_SRC)/dw2-skip-prologue.c \
	  -DINLINED -DPTRBITS=64 -o $@ || touch $@

py-section-script:
	$(CC) $(TEST_SRC)/py-section-script.s -o $@ -g || touch $@

DWZ_TEST_SOURCES := $(patsubst %.o,%-for-test.c,$(OBJECTS))

%-for-test.c: %.c
	sed 's/__GNUC__/NOT_DEFINED/' $< > $@

dwz-for-test: $(DWZ_TEST_SOURCES)
	$(CC) $(DWZ_TEST_SOURCES) -O2 -g -lelf -o $@ -Wall -W -DDEVEL \
	  -D_FILE_OFFSET_BITS=64 -DDWZ_VERSION='"for-test"' -I$(srcdir) \
	  $(shell cat $(srcdir)/COPYRIGHT_YEARS)

min:
	$(CC) $(TEST_SRC)/min.c $(TEST_SRC)/min-2.c -o $@ -g

two-typedef:
	$(CC) $(TEST_SRC)/two-typedef.c $(TEST_SRC)/two-typedef-2.c \
	  -I $(TEST_SRC) -o $@ -g

start:
	$(CC) $(TEST_SRC)/start.c -o $@ -g -nostdlib

start-gold:
	$(CC) $(TEST_SRC)/start.c -fuse-ld=gold -o $@ -g -nostdlib || touch $@

implptr-64bit-d2o4a8r8t0:
	$(CC) $(TEST_SRC)/implptr-64bit-d2o4a8r8t0.S $(TEST_SRC)/main.c \
	  -o $@ -g || touch $@

hello-gold-gdb-index:
	$(CC) $(TEST_SRC)/hello.c -g -fuse-ld=gold -Wl,--gdb-index -o $@ \
	    || touch $@

varval:
	$(CC) $(TEST_SRC)/varval.c $(TEST_SRC)/varval.S -g -o $@ || touch $@

POINTER_SIZE:=$(shell $(CC) $(TEST_SRC)/pointer-size.c -o pointer-size; \
	./pointer-size; \
	rm -f ./pointer-size)

TEMP_ASM_FILES=$(addsuffix -dw.S, $(TEST_EXECS_DWARF_ASM))
.INTERMEDIATE: $(TEMP_ASM_FILES)

$(TEMP_ASM_FILES): %-dw.S: $(TEST_SRC)/../lib/%.exp
	export POINTER_SIZE=$(POINTER_SIZE); \
	  export DEJAGNU=$(DEJAGNU); \
	  runtest --tool=dwz -srcdir $(srcdir)/testsuite/ lib/$*.exp

$(TEST_EXECS_DWARF_ASM): %: %-dw.S
	$(CC) $(TEST_SRC)/main.c $< -o $@

odr-struct:
	$(CXX) $(TEST_SRC)/odr.cc $(TEST_SRC)/odr-2.cc -I$(TEST_SRC) -o $@ -g \
	  -DKIND=struct

odr-class:
	$(CXX) $(TEST_SRC)/odr.cc $(TEST_SRC)/odr-2.cc -I$(TEST_SRC) -o $@ -g \
	  -DKIND=class

odr-union:
	$(CXX) $(TEST_SRC)/odr.cc $(TEST_SRC)/odr-2.cc -I$(TEST_SRC) -o $@ -g \
	  -DKIND=union

odr-struct-ns:
	$(CXX) $(TEST_SRC)/odr.cc $(TEST_SRC)/odr-2.cc -I$(TEST_SRC) -o $@ -g \
	  -DKIND=struct -DNAMESPACE=1

odr-class-ns:
	$(CXX) $(TEST_SRC)/odr.cc $(TEST_SRC)/odr-2.cc -I$(TEST_SRC) -o $@ -g \
	  -DKIND=class -DNAMESPACE=1

odr-union-ns:
	$(CXX) $(TEST_SRC)/odr.cc $(TEST_SRC)/odr-2.cc -I$(TEST_SRC) -o $@ -g \
	  -DKIND=union -DNAMESPACE=1

odr-loc:
	$(CXX) $(TEST_SRC)/odr-loc.cc $(TEST_SRC)/odr-loc-2.cc -I$(TEST_SRC) \
	  -o $@ -g


def-decl:
	$(CXX) $(TEST_SRC)/decl.c $(TEST_SRC)/def.c $(TEST_SRC)/def2.c -I$(TEST_SRC) \
	  -o $@ -g

# On some systems we need to set and export DEJAGNU to suppress
# WARNING: Couldn't find the global config file.
DEJAGNU ?= /dev/null

check: dwz $(TEST_EXECS)
	mkdir -p testsuite-bin
	cd testsuite-bin; ln -sf $(PWD)/dwz .
	export DEJAGNU=$(DEJAGNU); \
	export PATH=$(PWD)/testsuite-bin:$$PATH; export LC_ALL=C; \
	runtest --tool=dwz -srcdir $(srcdir)/testsuite $(RUNTESTFLAGS)
	rm -Rf testsuite-bin $(TEST_EXECS) $(DWZ_TEST_SOURCES)

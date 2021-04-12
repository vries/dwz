ifneq ($(srcdir),)
VPATH = $(srcdir)
else
srcdir=$(shell pwd)
endif

CFLAGS = -O2 -g
DWZ_VERSION := $(shell cat $(srcdir)/VERSION)
CFLAGS_VERSION = -DDWZ_VERSION='"$(DWZ_VERSION)"'
CFLAGS_COPYRIGHT = $(shell cat $(srcdir)/COPYRIGHT_YEARS)
CFLAGS_COMMON = -Wall -W -D_FILE_OFFSET_BITS=64
override CFLAGS += $(CFLAGS_COMMON) $(CFLAGS_VERSION) $(CFLAGS_COPYRIGHT)

prefix = /usr
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
datarootdir = $(prefix)/share
mandir = $(datarootdir)/man
OBJECTS = args.o dwz.o hashtab.o pool.o sha1.o dwarfnames.o
LIBS=-lelf
dwz: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
args.o: native.o
args.o: CFLAGS_FOR_SOURCE = \
	-DNATIVE_ENDIAN_VAL=$(NATIVE_ENDIAN_VAL) \
	-DNATIVE_POINTER_SIZE=$(NATIVE_POINTER_SIZE)
NATIVE_ENDIAN=$(shell readelf -h native.o \
	| grep Data \
	| sed 's/.*, //;s/ endian//')
NATIVE_ENDIAN_LITTLE=$(findstring $(NATIVE_ENDIAN),$(findstring little,$(NATIVE_ENDIAN)))
NATIVE_ENDIAN_BIG=$(findstring $(NATIVE_ENDIAN),$(findstring big,$(NATIVE_ENDIAN)))
NATIVE_ENDIAN_VAL=$(if $(NATIVE_ENDIAN_LITTLE),ELFDATA2LSB,$(if $(NATIVE_ENDIAN_BIG),ELFDATA2MSB,ELFDATANONE))
NATIVE_POINTER_SIZE=$(shell readelf -wi native.o \
	| grep "Pointer Size:" \
	| sed 's/.*: *//')
%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(CFLAGS_FOR_SOURCE)
install: dwz
	install -D dwz $(DESTDIR)$(bindir)/dwz
	install -D -m 644 $(srcdir)/dwz.1 $(DESTDIR)$(mandir)/man1/dwz.1
clean:
	rm -f $(OBJECTS) *~ core* dwz $(TEST_EXECS) $(DWZ_TEST_OBJECTS) \
	  dwz.log dwz.sum native.o
	rm -Rf testsuite-bin tmp.*
native.o: native.c
	$(CC) -o $@ $< -c -g

PWD:=$(shell pwd -P)

TEST_SRC = $(srcdir)/testsuite/dwz.tests
TEST_EXECS_DWARF_ASM = no-multifile-prop invalid-dw-at-stmt-list-encoding \
		       unavailable-dwarf-piece
TEST_EXECS_x86_64 = py-section-script dw2-skip-prologue \
	implptr-64bit-d2o4a8r8t0 varval
TEST_EXECS = hello dwz-for-test min two-typedef start hello-gold-gdb-index \
	start-gold hello-gnu-pubnames $(TEST_EXECS_DWARF_ASM) \
	$(TEST_EXECS_$(UNAME)) odr-struct odr-class odr-union odr-struct-ns \
	odr-class-ns odr-union-ns odr-loc def-decl cycle

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

DWZ_TEST_OBJECTS := $(patsubst %.o,%-for-test.o,$(OBJECTS))
dwz-for-test: $(DWZ_TEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	rm -f $(DWZ_TEST_OBJECTS)
args-for-test.o: CFLAGS_FOR_SOURCE = \
	-DNATIVE_ENDIAN_VAL=$(NATIVE_ENDIAN_VAL) \
	-DNATIVE_POINTER_SIZE=$(NATIVE_POINTER_SIZE)
$(DWZ_TEST_OBJECTS): %-for-test.o : %.c
	$(CC) $< -o $@ -c \
	  -DUSE_GNUC=0 -DDEVEL \
	  -O2 -g \
	  $(CFLAGS_COMMON) \
	  -DDWZ_VERSION='"for-test"' \
	  $(CFLAGS_COPYRIGHT) \
	  $(CFLAGS_FOR_SOURCE)

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

$(filter-out no-multifile-prop unavailable-dwarf-piece, $(TEST_EXECS_DWARF_ASM)): %: %-dw.S
	$(CC) $(TEST_SRC)/main.c $< -o $@

# Fails to compile on riscv64: Error: non-constant .uleb128 is not supported.
no-multifile-prop unavailable-dwarf-piece: %: %-dw.S
	$(CC) $(TEST_SRC)/main.c $< -o $@ || true

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
	$(CXX) $(TEST_SRC)/decl.cc $(TEST_SRC)/def.cc $(TEST_SRC)/def2.cc \
	  -I$(TEST_SRC) -o $@ -g

cycle:
	$(CC) $(TEST_SRC)/cycle.c -o $@ -g

# On some systems we need to set and export DEJAGNU to suppress
# WARNING: Couldn't find the global config file.
DEJAGNU ?= /dev/null

VALGRIND_OPTIONS = -q --error-exitcode=99

check check-valgrind: dwz $(TEST_EXECS)
	mkdir -p testsuite-bin
	cd testsuite-bin; \
	  if [ "$@" = "check" ]; then \
	    ln -sf $(PWD)/dwz .; \
	  else \
	    echo "valgrind $(VALGRIND_OPTIONS) $(PWD)/dwz \"\$$@\"" > dwz; \
	    chmod +x dwz; \
	  fi
	export DEJAGNU=$(DEJAGNU); \
	export PATH=$(PWD)/testsuite-bin:$$PATH; export LC_ALL=C; \
	runtest --tool=dwz -srcdir $(srcdir)/testsuite $(RUNTESTFLAGS)
	rm -Rf testsuite-bin $(TEST_EXECS) $(DWZ_TEST_OBJECTS)

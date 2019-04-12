ifneq ($(srcdir),)
VPATH = $(srcdir)
else
srcdir=$(shell pwd)
endif
CFLAGS = -O2 -g
DWZ_VERSION := $(shell cat $(srcdir)/VERSION)
override CFLAGS += -Wall -W -D_FILE_OFFSET_BITS=64 -DDWZ_VERSION='"$(DWZ_VERSION)"'
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
	install -D -m 644 dwz.1 $(DESTDIR)$(mandir)/man1/dwz.1
clean:
	rm -f $(OBJECTS) *~ core* dwz

PWD:=$(shell pwd -P)

TEST_SRC = $(srcdir)/testsuite/dwz.tests
TEST_EXECS = hello dw2-restrict py-section-script dwz-for-test min two-typedef

hello:
	$(CC) $(TEST_SRC)/hello.c -o $@ -g

dw2-restrict:
	$(CC) $(TEST_SRC)/dw2-restrict.S -o $@ || touch $@

py-section-script:
	$(CC) $(TEST_SRC)/py-section-script.s -o $@ -g || touch $@

DWZ_TEST_SOURCES := $(patsubst %.o,%-for-test.c,$(OBJECTS))

%-for-test.c: %.c
	sed 's/__GNUC__/NOT_DEFINED/' $< > $@

dwz-for-test: $(DWZ_TEST_SOURCES)
	$(CC) $(DWZ_TEST_SOURCES) -O2 -g -lelf -o $@ -Wall -W -DDEVEL \
	  -D_FILE_OFFSET_BITS=64 -DDWZ_VERSION='"for-test"' -I$(srcdir)

min:
	$(CC) $(TEST_SRC)/min.c $(TEST_SRC)/min-2.c -o $@ -g

two-typedef:
	$(CC) $(TEST_SRC)/two-typedef.c $(TEST_SRC)/two-typedef-2.c \
	  -I $(TEST_SRC) -o $@ -g

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

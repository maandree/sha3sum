.NONPOSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

LIBEXECDIR = $(PREFIX)/$(LIBEXEC)

BIN =\
	keccaksum\
	keccak-224sum\
	keccak-256sum\
	keccak-384sum\
	keccak-512sum\
	sha3sum\
	sha3-224sum\
	sha3-256sum\
	sha3-384sum\
	sha3-512sum\
	rawshake128sum\
	rawshake256sum\
	rawshake512sum\
	shake128sum\
	shake256sum\
	shake512sum

MAN1 = $(BIN:=.1)
HDR = arg.h common.h

keccaksum = Keccak[]
keccak-224sum = Keccak-224
keccak-256sum = Keccak-256
keccak-384sum = Keccak-384
keccak-512sum = Keccak-512
sha3sum = SHA3
sha3-224sum = SHA3-224
sha3-256sum = SHA3-256
sha3-384sum = SHA3-384
sha3-512sum = SHA3-512
rawshake128sum = RawSHAKE128
rawshake256sum = RawSHAKE256
rawshake512sum = RawSHAKE512
shake128sum = SHAKE128
shake256sum = SHAKE256
shake512sum = SHAKE512


all: $(BIN) $(MAN1)
mcb: sha3sum-mcb $(MAN1)

sha3sum-mcb.c: commands.h

%: %.o common.o
	$(CC) -o $@ $< common.o $(LDFLAGS)

%.o: %.c $(HDR)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

%.bo: %.c $(HDR)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) \
	-Dmain="main_$$(printf '%s\n' $* | tr - _)(int, char *[]); int main_$$(printf '%s\n' $* | tr - _)"

%.1: xsum.man
	u=$$(printf '%s\n' $* | tr a-z A-Z); \
	if test $* = sha3sum; then \
		sed -e 's/xsum/$*/g' -e 's/XSUM/'"$$u"'/g' -e 's/Xsum/$($*)/g' -e 's/^\\# ONLY SHA3: //' < xsum.man > $@; \
	else \
		sed -e 's/xsum/$*/g' -e 's/XSUM/'"$$u"'/g' -e 's/Xsum/$($*)/g' -e '/^\\# ONLY SHA3: /d' < xsum.man > $@; \
	fi

commands.h: Makefile
	(printf '%s' '#define LIST_COMMANDS(_)' && printf '\\\n\t_(%s)' $(BIN) && printf '\n') \
	| sed 's/_(\(.*\))/_("\1", main_\1)/' | sed 's/\(main_.*\)-/\1_/' > $@

sha3sum-mcb: sha3sum-mcb.o common.o $(BIN:=.bo)
	$(CC) -o $@ sha3sum-mcb.o common.o $(BIN:=.bo) $(LDFLAGS)

keccak-%sum.c:
	printf '%s\n' '#include "common.h"' 'KECCAK_MAIN($*)' > $@

sha3-%sum.c:
	printf '%s\n' '#include "common.h"' 'SHA3_MAIN($*)' > $@

rawshake%sum.c:
	printf '%s\n' '#include "common.h"' 'RAWSHAKE_MAIN($*)' > $@

shake%sum.c:
	printf '%s\n' '#include "common.h"' 'SHAKE_MAIN($*)' > $@

check: $(BIN)
	./test

install: $(BIN) $(MAN1)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man1"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum"
	cp -- $(BIN) "$(DESTDIR)$(PREFIX)/bin/"
	cp -- $(MAN1) "$(DESTDIR)$(MANPREFIX)/man1/"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum/"

install-mcb: sha3sum-mcb $(MAN1)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(LIBEXECDIR)"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man1"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum"
	set -e && cd "$(DESTDIR)$(PREFIX)/bin/" && \
	for f in $(BIN); do ln -sf -- ../$(LIBEXEC)/sha3sum "$$f"; done
	cp -- sha3sum-mcb "$(DESTDIR)$(LIBEXECDIR)/sha3sum"
	cp -- $(MAN1) "$(DESTDIR)$(MANPREFIX)/man1/"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum/"

uninstall:
	-cd -- "$(DESTDIR)$(PREFIX)/bin" && rm -f -- $(BIN)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man1" && rm -f -- $(MAN1)
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum"
	-rm -f -- "$(DESTDIR)$(LIBEXECDIR)/sha3sum"

clean:
	-rm -rf -- $(MAN1) $(BIN) sha3sum-mcb *.o *.bo *.su commands.h keccak-*sum.c sha3-*sum.c rawshake*sum.c shake*sum.c .testdir

.SUFFIXES:

.PHONY: all check install uninstall clean

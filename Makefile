.NONPOSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)


BIN =\
	keccaksum\
	keccak-224sum\
	keccak-256sum\
	keccak-384sum\
	keccak-512sum\
	sha3-224sum\
	sha3-256sum\
	sha3-384sum\
	sha3-512sum\
	rawshake256sum\
	rawshake512sum\
	shake256sum\
	shake512sum

MAN1 = $(BIN:=.1)
HDR = arg.h common.h

keccak-224sum = Keccak-224
keccak-256sum = Keccak-256
keccak-384sum = Keccak-384
keccak-512sum = Keccak-512
keccaksum = Keccak[]
sha3-224sum = SHA3-224
sha3-256sum = SHA3-256
sha3-384sum = SHA3-384
sha3-512sum = SHA3-512
rawshake256sum = RawSHAKE256
rawshake512sum = RawSHAKE512
shake256sum = SHAKE256
shake512sum = SHAKE512


all: $(BIN) $(MAN1)

%: %.o common.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HDR)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

%.1: xsum.man
	u=$$(printf '%s\n' $* | tr a-z A-Z); \
	sed -e 's/xsum/$*/g' -e 's/XSUM/'"$$u"'/g' -e 's/Xsum/$($*)/g' < xsum.man > $@

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

uninstall:
	-cd -- "$(DESTDIR)$(PREFIX)/bin" && rm -f -- $(BIN)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man1" && rm -f -- $(MAN1)
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum"

clean:
	-rm -rf -- $(MAN1) $(BIN) keccak-*sum.c sha3-*sum.c rawshake*sum.c shake*sum.c .testdir

.SUFFIXES:

.PHONY: all check install uninstall clean

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share
DOCDIR = $(DATADIR)/doc
MANDIR = $(DATADIR)/man
INFODIR = $(DATADIR)/info
LICENSEDIR = $(DATADIR)/licenses

PKGNAME = sha3sum


WARN = -Wall -Wextra -pedantic -Wdouble-promotion -Wformat=2 -Winit-self -Wmissing-include-dirs  \
       -Wtrampolines -Wfloat-equal -Wshadow -Wmissing-prototypes -Wmissing-declarations          \
       -Wredundant-decls -Wnested-externs -Winline -Wno-variadic-macros -Wswitch-default         \
       -Wpadded -Wsync-nand -Wunsafe-loop-optimizations -Wcast-align -Wstrict-overflow           \
       -Wdeclaration-after-statement -Wundef -Wbad-function-cast -Wcast-qual -Wlogical-op        \
       -Wstrict-prototypes -Wold-style-definition -Wpacked -Wvector-operation-performance        \
       -Wunsuffixed-float-constants -Wsuggest-attribute=const -Wsuggest-attribute=noreturn       \
       -Wsuggest-attribute=pure -Wsuggest-attribute=format -Wnormalized=nfkc

LDOPTIMISE =
COPTIMISE = -O3

FLAGS = $(WARN) -std=gnu99


KECCAK_CMDS = keccak-224sum keccak-256sum keccak-384sum keccak-512sum keccaksum
SHA3_CMDS = sha3-224sum sha3-256sum sha3-384sum sha3-512sum
RAWSHAKE_CMDS = rawshake256sum rawshake512sum
SHAKE_CMDS = shake256sum shake512sum

CMDS = $(KECCAK_CMDS) $(SHA3_CMDS) $(RAWSHAKE_CMDS) $(SHAKE_CMDS)

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



.PHONY: all
all: command man


.PHONY: command
command: $(foreach C,$(CMDS),bin/$(C))

bin/%: obj/%.o obj/common.o
	@mkdir -p bin
	$(CC) $(FLAGS) $(LDOPTIMISE) -o $@ $^ $(LDFLAGS) -lkeccak -largparser

obj/%.o: src/%.c src/*.h
	@mkdir -p obj
	$(CC) $(FLAGS) $(COPTIMISE) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)



.PHONY: man
man: $(foreach C,$(CMDS),bin/$(C).1)

bin/%.1: xsum.texman
	@mkdir -p bin
	cat $< | sed -e 's/xsum/$*/g' -e 's/XSUM/$($*)/g' | texman > $@


.PHONY: install
install: install-command install-copyright install-man


.PHONY: install-command
install-command: install-keccak install-sha3 install-rawshake install-shake

.PHONY: install-keccak
install-keccak: $(foreach C,$(KECCAK_CMDS),install-$(C))

.PHONY: install-sha3
install-sha3: $(foreach C,$(SHA3_CMDS),install-$(C))

.PHONY: install-rawshake
install-rawshake: $(foreach C,$(RAWSHAKE_CMDS),install-$(C))

.PHONY: install-shake
install-shake: $(foreach C,$(SHAKE_CMDS),install-$(C))

.PHONY: install-%sum
install-%sum: bin/%sum
	install -dm755 -- "$(DESTDIR)$(BINDIR)"
	install -m755 -- $< "$(DESTDIR)$(BINDIR)/$*sum"


.PHONY: install-copyright
install-copyright: install-license

.PHONY: install-license
install-license:
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644 -- LICENSE "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"


.PHONY: install-man
install-man: install-keccak-man install-sha3-man install-rawshake-man install-shake-man

.PHONY: install-keccak-man
install-keccak-man: $(foreach C,$(KECCAK_CMDS),install-$(C)-man)

.PHONY: install-sha3-man
install-sha3-man: $(foreach C,$(SHA3_CMDS),install-$(C)-man)

.PHONY: install-rawshake-man
install-rawshake-man: $(foreach C,$(RAWSHAKE_CMDS),install-$(C)-man)

.PHONY: install-shake-man
install-shake-man: $(foreach C,$(SHAKE_CMDS),install-$(C)-man)

.PHONY: install-%sum-man
install-%sum-man: bin/%sum.1
	install -dm755 -- "$(DESTDIR)$(MANDIR)/man1"
	install -m644 -- $< "$(DESTDIR)$(MANDIR)/man1/$*sum.1"



.PHONY: uninstall
uninstall:
	-rm -- $(foreach C,$(CMDS),"$(DESTDIR)$(BINDIR)/$(C)")
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"
	-rmdir -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	-rm -- $(foreach C,$(CMDS),"$(DESTDIR)$(MANDIR)/man1/$(C).1")


.PHONY: clean
clean:
	-rm -r bin obj

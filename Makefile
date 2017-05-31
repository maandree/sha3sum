# Copyright © 2013, 2014  Mattias Andrée (maandree@member.fsf.org)
# 
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
# 
# [GNU All Permissive License]


# The package path prefix, if you want to install to another root, set DESTDIR to that root
PREFIX = /usr
# The command path excluding prefix
BIN = /bin
# The resource path excluding prefix
DATA = /share
# The command path including prefix
BINDIR = $(PREFIX)$(BIN)
# The resource path including prefix
DATADIR = $(PREFIX)$(DATA)
# The generic documentation path including prefix
DOCDIR = $(DATADIR)/doc
# The man page documentation path including prefix
MANDIR = $(DATADIR)/man
# The info manual documentation path including prefix
INFODIR = $(DATADIR)/info
# The license base path including prefix
LICENSEDIR = $(DATADIR)/licenses

# The name of the package as it should be installed
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



.PHONY: default
default: command shell info

.PHONY: all
all: command shell doc


.PHONY: command
command: $(foreach C,$(CMDS),bin/$(C))

bin/%: obj/%.o obj/common.o
	@mkdir -p bin
	$(CC) $(FLAGS) $(LDOPTIMISE) -o $@ $^ $(LDFLAGS) -lkeccak -largparser

obj/%.o: src/%.c src/*.h
	@mkdir -p obj
	$(CC) $(FLAGS) $(COPTIMISE) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)


.PHONY: shell
shell: bash zsh fish

.PHONY: bash
bash: $(foreach C,$(CMDS),bin/$(C).bash)

.PHONY: zsh
zsh: $(foreach C,$(CMDS),bin/$(C).zsh)

.PHONY: fish
fish: $(foreach C,$(CMDS),bin/$(C).fish)

bin/%.bash: src/completion
	@mkdir -p bin
	auto-auto-complete bash --output $@ --source $< command=$*

bin/%.zsh: src/completion
	@mkdir -p bin
	auto-auto-complete zsh --output $@ --source $< command=$*

bin/%.fish: src/completion
	@mkdir -p bin
	auto-auto-complete fish --output $@ --source $< command=$*


.PHONY: doc
doc: man info pdf dvi ps

.PHONY: man
man: $(foreach C,$(CMDS),bin/$(C).1)

bin/%.1: doc/xsum.texman
	@mkdir -p bin
	cat $< | sed -e 's/xsum/$*/g' -e 's/XSUM/$($*)/g' | texman > $@


.PHONY: info
info: bin/sha3sum.info
bin/%.info: doc/%.texinfo doc/fdl.texinfo
	@mkdir -p obj/info bin
	cd obj/info ; makeinfo ../../$<
	mv obj/info/$*.info bin/$*.info

.PHONY: pdf
pdf: bin/sha3sum.pdf
bin/%.pdf: doc/%.texinfo doc/fdl.texinfo
	@mkdir -p obj/pdf bin
	cd obj/pdf/ ; yes X | texi2pdf ../../$<
	mv obj/pdf/$*.pdf bin/$*.pdf

.PHONY: dvi
dvi: bin/sha3sum.dvi
bin/%.dvi: doc/%.texinfo doc/fdl.texinfo
	@mkdir -p obj/dvi bin
	cd obj/dvi ; yes X | $(TEXI2DVI) ../../$<
	mv obj/dvi/$*.dvi bin/$*.dvi

.PHONY: ps
ps: bin/sha3sum.ps
bin/%.ps: doc/%.texinfo doc/fdl.texinfo
	@mkdir -p obj/ps bin
	cd obj/ps ; yes X | texi2pdf --ps ../../$<
	mv obj/ps/$*.ps bin/$*.ps



.PHONY: install
install: install-base install-shell install-info

.PHONY: install-all
install-all: install-base install-shell install-doc

.PHONY: install-base
install-base: install-command install-copyright


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
install-copyright: install-copying install-license

.PHONY: install-copying
install-copying:
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644 -- COPYING "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/COPYING"

.PHONY: install-license
install-license:
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644 -- LICENSE "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"


.PHONY: install-shell
install-shell: install-bash install-fish install-zsh

.PHONY: install-keccak-shell
install-keccak-shell: install-keccak-bash install-keccak-fish install-keccak-zsh

.PHONY: install-sha3-shell
install-sha3-shell: install-sha3-bash install-sha3-fish install-sha3-zsh

.PHONY: install-rawshake-shell
install-rawshake-shell: install-rawshake-bash install-rawshake-fish install-rawshake-zsh

.PHONY: install-shake-shell
install-shake-shell: install-shake-bash install-shake-fish install-shake-zsh

.PHONY: install-bash
install-bash: install-keccak-bash install-sha3-bash install-rawshake-bash install-shake-bash

.PHONY: install-fish
install-fish: install-keccak-fish install-sha3-fish install-rawshake-fish install-shake-fish

.PHONY: install-zsh
install-zsh: install-keccak-zsh install-sha3-zsh install-rawshake-zsh install-shake-zsh

.PHONY: install-keccak-bash
install-keccak-bash: $(foreach C,$(KECCAK_CMDS),install-$(C)-bash)

.PHONY: install-keccak-fish
install-keccak-fish: $(foreach C,$(KECCAK_CMDS),install-$(C)-fish)

.PHONY: install-keccak-zsh
install-keccak-zsh: $(foreach C,$(KECCAK_CMDS),install-$(C)-zsh)

.PHONY: install-sha3-bash
install-sha3-bash: $(foreach C,$(SHA3_CMDS),install-$(C)-bash)

.PHONY: install-sha3-fish
install-sha3-fish: $(foreach C,$(SHA3_CMDS),install-$(C)-fish)

.PHONY: install-sha3-zsh
install-sha3-zsh: $(foreach C,$(SHA3_CMDS),install-$(C)-zsh)

.PHONY: install-rawshake-bash
install-rawshake-bash: $(foreach C,$(RAWSHAKE_CMDS),install-$(C)-bash)

.PHONY: install-rawshake-fish
install-rawshake-fish: $(foreach C,$(RAWSHAKE_CMDS),install-$(C)-fish)

.PHONY: install-rawshake-zsh
install-rawshake-zsh: $(foreach C,$(RAWSHAKE_CMDS),install-$(C)-zsh)

.PHONY: install-shake-bash
install-shake-bash: $(foreach C,$(SHAKE_CMDS),install-$(C)-bash)

.PHONY: install-shake-fish
install-shake-fish: $(foreach C,$(SHAKE_CMDS),install-$(C)-fish)

.PHONY: install-shake-zsh
install-shake-zsh: $(foreach C,$(SHAKE_CMDS),install-$(C)-zsh)

.PHONY: install-%sum-bash
install-%sum-bash: bin/$*sum.bash
	install -dm755 -- "$(DESTDIR)$(DATADIR)/bash-completion/completions"
	install -m644 -- $< "$(DESTDIR)$(DATADIR)/bash-completion/completions/$*sum"

.PHONY: install-%sum-fish
install-%sum-fish: bin/$*sum.fish
	install -dm755 -- "$(DESTDIR)$(DATADIR)/fish/completions"
	install -m644 -- $< "$(DESTDIR)$(DATADIR)/fish/completions/$*sum.fish"

.PHONY: install-%sum-zsh
install-%sum-zsh: bin/$*sum.zsh
	install -dm755 -- "$(DESTDIR)$(DATADIR)/zsh/site-functions"
	install -m644 -- $< "$(DESTDIR)$(DATADIR)/zsh/site-functions/_$*sum"


.PHONY: install-doc
install-doc: install-man install-info install-pdf install-dvi install-ps

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

.PHONY: install-info
install-info: bin/sha3sum.info
	install -dm755 -- "$(DESTDIR)$(INFODIR)"
	install -m644 -- $< "$(DESTDIR)$(INFODIR)/$(PKGNAME).info"

.PHONY: install-pdf
install-pdf: bin/sha3sum.pdf
	install -dm755 -- "$(DESTDIR)$(DOCDIR)"
	install -m644 -- $< "$(DESTDIR)$(DOCDIR)/$(PKGNAME).pdf"

.PHONY: install-dvi
install-dvi: bin/sha3sum.dvi
	install -dm755 -- "$(DESTDIR)$(DOCDIR)"
	install -m644 -- $< "$(DESTDIR)$(DOCDIR)/$(PKGNAME).dvi"

.PHONY: install-ps
install-ps: bin/sha3sum.ps
	install -dm755 -- "$(DESTDIR)$(DOCDIR)"
	install -m644 -- $< "$(DESTDIR)$(DOCDIR)/$(PKGNAME).ps"



.PHONY: uninstall
uninstall:
	-rm -- $(foreach C,$(CMDS),"$(DESTDIR)$(BINDIR)/$(C)")
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/COPYING"
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"
	-rmdir -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	-rm -- $(foreach C,$(CMDS),"$(DESTDIR)$(DATADIR)/bash-completion/completions/$(C)")
	-rm -- $(foreach C,$(CMDS),"$(DESTDIR)$(DATADIR)/fish/completions/$(C).fish")
	-rm -- $(foreach C,$(CMDS),"$(DESTDIR)$(DATADIR)/zsh/site-functions/_$(C)")
	-rm -- $(foreach C,$(CMDS),"$(DESTDIR)$(MANDIR)/man1/$(C).1")
	-rm -- "$(DESTDIR)$(INFODIR)/$(PKGNAME).info"
	-rm -- "$(DESTDIR)$(DOCDIR)/$(PKGNAME).pdf"
	-rm -- "$(DESTDIR)$(DOCDIR)/$(PKGNAME).dvi"
	-rm -- "$(DESTDIR)$(DOCDIR)/$(PKGNAME).ps"



.PHONY: clean
clean:
	-rm -r bin obj


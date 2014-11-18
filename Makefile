# Copyright © 2013, 2014  Mattias Andrée (maandree@member.fsf.org)
# 
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
# 
# [GNU All Permissive License]


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


CMDS = keccak-224sum keccak-256sum keccak-384sum keccak-512sum keccaksum  \
       sha3-224sum sha3-256sum sha3-384sum sha3-512sum                    \
       rawshake256sum rawshake512sum shake256sum shake512sum

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
	$(CC) $(FLAGS) $(LDOPTIMISE) -lkeccak -largparser -o $@ $^ $(LDFLAGS)

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
	@mkdir -p obj bin
	cd obj ; makeinfo ../$<
	mv obj/$*.info bin/$*.info

.PHONY: pdf
pdf: bin/sha3sum.pdf
bin/%.pdf: doc/%.texinfo doc/fdl.texinfo
	@mkdir -p obj bin
	cd obj ; yes X | texi2pdf ../$<
	mv obj/$*.pdf bin/$*.pdf

.PHONY: dvi
dvi: bin/sha3sum.dvi
bin/%.dvi: doc/%.texinfo doc/fdl.texinfo
	@mkdir -p obj bin
	cd obj ; yes X | $(TEXI2DVI) ../$<
	mv obj/$*.dvi bin/$*.dvi

.PHONY: ps
ps: bin/sha3sum.ps
bin/%.ps: doc/%.texinfo doc/fdl.texinfo
	@mkdir -p obj bin
	cd obj ; yes X | texi2pdf --ps ../$<
	mv obj/$*.ps bin/$*.ps



.PHONY: clean
clean:
	-rm -r bin obj


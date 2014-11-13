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



.PHONY: all
all: $(foreach C,$(CMDS),bin/$(C))


bin/%: obj/%.o obj/common.o
	@mkdir -p bin
	$(CC) $(FLAGS) $(LDOPTIMISE) -lkeccak -largparser -o $@ $^ $(LDFLAGS)

obj/%.o: src/%.c src/*.h
	@mkdir -p obj
	$(CC) $(FLAGS) $(COPTIMISE) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)


.PHONY: clean
clean:
	-rm -r bin obj


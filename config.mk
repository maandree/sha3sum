PREFIX    = /usr/local
MANPREFIX = $(PREFIX)/share/man
LIBEXEC   = libexec

WARN = -pedantic -Wdouble-promotion -Wformat=2 -Winit-self -Wmissing-include-dirs          \
       -Wtrampolines -Wfloat-equal -Wshadow -Wmissing-prototypes -Wmissing-declarations    \
       -Wredundant-decls -Wnested-externs -Winline -Wno-variadic-macros -Wswitch-default   \
       -Wpadded -Wsync-nand -Wunsafe-loop-optimizations -Wcast-align -Wstrict-overflow     \
       -Wdeclaration-after-statement -Wundef -Wbad-function-cast -Wcast-qual -Wlogical-op  \
       -Wstrict-prototypes -Wold-style-definition -Wpacked -Wvector-operation-performance  \
       -Wunsuffixed-float-constants -Wsuggest-attribute=const -Wsuggest-attribute=noreturn \
       -Wsuggest-attribute=pure -Wsuggest-attribute=format -Wnormalized=nfkc

CFLAGS   = -std=c99 -Wall -Wextra $(WARN) -O3
CPPFLAGS =
LDFLAGS  = -s -lkeccak

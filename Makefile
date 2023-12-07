.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

LIBEXECDIR = $(PREFIX)/$(LIBEXEC)


BIN_GENERIC =\
	keccaksum\
	sha3sum\

BIN_SPECIFIC =\
	keccak-224sum\
	keccak-256sum\
	keccak-384sum\
	keccak-512sum\
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

BIN = $(BIN_GENERIC) $(BIN_SPECIFIC)
MAN1 = $(BIN:=.1)
HDR = arg.h common.h


all: $(BIN) $(MAN1)
mcb: sha3sum-mcb $(MAN1)

sha3sum-mcb.o: commands.h
$(BIN:=.o): $(HDR)
$(BIN:=.bo): $(HDR)
$(BIN): common.o

.o:
	$(CC) -o $@ $@.o common.o $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.c.bo:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) \
	-Dmain="main_$$(printf '%s\n' $* | tr - _)(int, char *[]); int main_$$(printf '%s\n' $* | tr - _)"

$(MAN1): xsum.man algorithm-map
	set -e; \
	f="$$(printf '%s\n' "$@" | sed 's/\.1$$//')"; \
	u="$$(printf '%s\n' "$$f" | tr a-z A-Z)"; \
	a="$$(sed -n 's/^'"$$f"'[[:space:]]*=[[:space:]]*//p' < algorithm-map | sed 's/[[:space:]]*$$//')"; \
	if test "$$f" = sha3sum; then \
		sed -e "s/xsum/$$f/g" -e "s/XSUM/$$u/g" -e "s/Xsum/$$a/g" -e 's/^\\# ONLY SHA3: //' < xsum.man > $@; \
	else \
		sed -e "s/xsum/$$f/g" -e "s/XSUM/$$u/g" -e "s/Xsum/$$a/g" -e '/^\\# ONLY SHA3: /d' < xsum.man > $@; \
	fi

commands.h: Makefile
	(printf '%s' '#define LIST_COMMANDS(_)' && printf '\\\n\t_(%s)' $(BIN) && printf '\n') \
	| sed 's/_(\(.*\))/_("\1", main_\1)/' | sed 's/\(main_.*\)-/\1_/' > $@

sha3sum-mcb: sha3sum-mcb.o common.o $(BIN:=.bo)
	$(CC) -o $@ sha3sum-mcb.o common.o $(BIN:=.bo) $(LDFLAGS)

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
	for f in $(BIN); do ln -sf -- ../$(LIBEXEC)/sha3sum "$$f" || exit 1; done
	cp -- sha3sum-mcb "$(DESTDIR)$(LIBEXECDIR)/sha3sum"
	cp -- $(MAN1) "$(DESTDIR)$(MANPREFIX)/man1/"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum/"

uninstall:
	-cd -- "$(DESTDIR)$(PREFIX)/bin" && rm -f -- $(BIN)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man1" && rm -f -- $(MAN1)
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/sha3sum"
	-rm -f -- "$(DESTDIR)$(LIBEXECDIR)/sha3sum"

clean:
	-rm -rf -- $(MAN1) $(BIN) sha3sum-mcb *.o *.bo *.su commands.h .testdir
	-rm -rf -- keccak-*sum.c sha3-*sum.c rawshake*sum.c shake*sum.c

$(BIN_SPECIFIC:=.c):
	+@set -e; \
		f="$$(\
			set -e; \
			sed -n 's/^\([a-z][a-z0-9-]*\)%\([^:]*\):.*$$/\1 \2/p' < unportable.mk | while read start end; do \
				end="$$(printf '%s\n' "$$end" | sed 's/\./\\\./g')"; \
				x="$$(printf '%s\n' '$@' | sed -n 's/^'"$$start"'\(.*\)'"$$end"'$$/\1/p')"; \
				if test -n "$$x"; then \
					printf '%s\n' "$$x"; \
					break; \
				fi; \
			done; \
		)"; \
		if test -z "$$f"; then \
			printf 'No rule to make target %s\n' "$@" >&2; \
			exit 1; \
		fi; \
		sed "/^[a-z]/s/%/$$f/g" < unportable.mk | sed 's/\$$\*/'"$$f/g" | $(MAKE) -f - "$@"

.SUFFIXES:
.SUFFIXES: .c .o .bo

.PHONY: all mcb check install install-mcb uninstall clean

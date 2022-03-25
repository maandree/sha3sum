/* See LICENSE file for copyright and license details. */
#include "common.h"
#include "arg.h"

#include <sys/stat.h>
#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



/**
 * Storage for binary hash
 */
static void *restrict hashsum = NULL;

/**
 * Storage for hexadecimal hash
 */
static char *restrict hexsum = NULL;

/**
 * `argv[0]` from `main`
 */
char *argv0;



static void
usage(void)
{
	fprintf(stderr, "usage: %s [-u | -l | -b | -c] [-R rate] [-C capacity] "
	                "[-N output-size] [-S state-size] [-W word-size] "
	                "[-Z squeeze-count] [-vxz] [file ...]\n", argv0);
	exit(2);
}

static void
user_error(const char *text)
{
	fprintf(stderr, "%s: %s\n", argv0, text);
	exit(2);
}

static void *
emalloc(size_t n)
{
	void *r = malloc(n);
	if (!r) {
		perror(argv0);
		exit(2);
	}
	return r;
}

static void *
erealloc(void *ptr, size_t n)
{
	if (!(ptr = realloc(ptr, n))) {
		perror(argv0);
		exit(2);
	}
	return ptr;
}

static void
eperror(void)
{
	perror(argv0);
	exit(2);
}


/**
 * Convert `struct libkeccak_generalised_spec` to `struct libkeccak_spec` and check for errors
 * 
 * @param  gspec  See libkeccak_degeneralise_spec(3)
 * @param  spec   See libkeccak_degeneralise_spec(3)
 */
static void
make_spec(struct libkeccak_generalised_spec *restrict gspec, struct libkeccak_spec *restrict spec)
{
#define case /* fall through */ case
#define default /* fall through */ default
#define TEST(CASE, STR) case LIBKECCAK_GENERALISED_SPEC_ERROR_##CASE: user_error(STR)
	switch (libkeccak_degeneralise_spec(gspec, spec)) {
	case 0:
		break;
	TEST (STATE_NONPOSITIVE,                    "the state size must be positive");
	TEST (STATE_TOO_LARGE,                      "the state size is too large, may not exceed 1600");
	TEST (STATE_MOD_25,                         "the state size must be a multiple of 25");
	TEST (WORD_NONPOSITIVE,                     "the word size must be positive");
	TEST (WORD_TOO_LARGE,                       "the word size is too large, may not exceed 64");
	TEST (STATE_WORD_INCOHERENCY,               "the state size must be exactly 25 times the word size");
	TEST (CAPACITY_NONPOSITIVE,                 "the capacity must be positive");
	TEST (CAPACITY_MOD_8,                       "the capacity must be a multiple of 8");
	TEST (BITRATE_NONPOSITIVE,                  "the rate must be positive");
	TEST (BITRATE_MOD_8,                        "the rate must be a multiple of 8");
	TEST (OUTPUT_NONPOSITIVE,                   "the output size must be positive");
	TEST (STATE_BITRATE_CAPACITY_INCONSISTENCY, "the sum of the rate and capacity must equal"
	                                            " the state size (25 times the word size)");
	default:
		user_error("unknown error in algorithm parameters");
	}
#undef TEST

#define TEST(CASE, STR) case LIBKECCAK_SPEC_ERROR_##CASE: user_error(STR)
	switch (libkeccak_spec_check(spec)) {
	case 0:
		break;
	TEST (BITRATE_NONPOSITIVE,  "the rate size must be positive");
	TEST (BITRATE_MOD_8,        "the rate must be a multiple of 8");
	TEST (CAPACITY_NONPOSITIVE, "the capacity must be positive");
	TEST (CAPACITY_MOD_8,       "the capacity must be a multiple of 8");
	TEST (OUTPUT_NONPOSITIVE,   "the output size must be positive");
	TEST (STATE_TOO_LARGE,      "the state size is too large, may not exceed 1600");
	TEST (STATE_MOD_25,         "the state size must be a multiple of 25");
	TEST (WORD_NON_2_POTENT,    "the word size must be a power of 2");
	TEST (WORD_MOD_8,           "the word size must be a multiple of 8");
	default:
		user_error("unknown error in algorithm parameters");
	}
#undef TEST
#undef default
#undef case
}


/**
 * Calculate a Keccak-family hashsum of a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd      The file descriptor of the file to hash
 * @param   state   The hashing state, should not be initialised (memory leak otherwise)
 * @param   spec    Specifications for the hashing algorithm
 * @param   suffix  The data suffix, see `libkeccak_digest`
 * @param   hash    Output array for the hashsum, have an allocation size of
 *                  at least `(spec->output / 8) * sizeof(char)`, may be `NULL`
 * @return          Zero on success, -1 on error
 */
static int
generalised_sum_fd_hex(int fd, struct libkeccak_state *restrict state,
                       const struct libkeccak_spec *restrict spec,
                       const char *restrict suffix, void *restrict hash)
{
	ssize_t got;
	struct stat attr;
	size_t blksize = 4096, r, w;
	unsigned char *restrict chunk;
	unsigned char even = 1, buf = 0, c;

	if (libkeccak_state_initialise(state, spec) < 0)
		return -1;

	if (!fstat(fd, &attr) && attr.st_blksize > 0)
		blksize = (size_t)(attr.st_blksize);

	chunk = alloca(blksize);

	for (;;) {
		got = read(fd, chunk, blksize);
		if (got < 0)
			return -1;
		if (!got)
			break;
		r = w = 0;
		while (r < (size_t)got) {
			c = chunk[r++];
			if (isxdigit(c)) {
				buf = (unsigned char)((buf << 4) | ((c & 15) + (c > '9' ? 9 : 0)));
				if ((even ^= 1))
					chunk[w++] = buf;
			} else if (!isspace(c)) {
				user_error("file is malformated");
			}
		}
		if (libkeccak_fast_update(state, chunk, w) < 0)
			return -1;
	}

	if (!even)
		user_error("file is malformated");

	return libkeccak_fast_digest(state, NULL, 0, 0, suffix, hash);
}


/**
 * Calculate the checksum of a file and store it in the global variable `hashsum`
 * 
 * @param   filename  The file to hash
 * @param   spec      Hashing parameters
 * @param   squeezes  The number of squeezes to perform
 * @param   suffix    The message suffix
 * @param   hex       Whether to use hexadecimal input rather than binary
 * @return            An appropriate exit value
 */
static int
hash(const char *restrict filename, const struct libkeccak_spec *restrict spec,
     long int squeezes, const char *restrict suffix, int hex)
{
	static size_t length = 0;
	struct libkeccak_state state;
	int fd;

	if (!length) {
		length = (size_t)((spec->output + 7) / 8);
		hashsum = emalloc(length * sizeof(char));
 		hexsum = emalloc((length * 2 + 1) * sizeof(char));
	}

	filename = strcmp(filename, "-") ? filename : "/dev/stdin";
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return 1;
		eperror();
	}

	if ((hex ? generalised_sum_fd_hex : libkeccak_generalised_sum_fd)
	    (fd, &state, spec, suffix, squeezes > 1 ? NULL : hashsum))
		eperror();
	close(fd);

	if (squeezes > 2)
		libkeccak_fast_squeeze(&state, squeezes - 2);
	if (squeezes > 1)
		libkeccak_squeeze(&state, hashsum);
	libkeccak_state_fast_destroy(&state);

	return 0;
}


/**
 * Check that file has a reported checksum, `bad_found` will be
 * updated if the file is missing or incorrect
 * 
 * @param   spec          Hashing parameters
 * @param   squeezes      The number of squeezes to perform
 * @param   suffix        The message suffix
 * @param   hex           Whether to use hexadecimal input rather than binary
 * @param   filename      The file to check
 * @param   correct_hash  The expected checksum (any form of hexadecimal)
 * @return                An appropriate exit value
 */
static int
check(const struct libkeccak_spec *restrict spec, long int squeezes, const char *restrict suffix,
      int hex, const char *restrict filename, const char *restrict correct_hash)
{
	size_t length = (size_t)((spec->output + 7) / 8);

	if (access(filename, F_OK) || hash(filename, spec, squeezes, suffix, hex)) {
		printf("%s: Missing\n", filename);
		return 1;
	}

	libkeccak_unhex(hexsum, correct_hash);
	if (memcmp(hexsum, hashsum, length)) {
		printf("%s: Fail\n", filename);
		return 1;
	} else {
		printf("%s: OK\n", filename);
		return 0;
	}
}


/**
 * Check checksums from a file
 * 
 * @param   filename  The file to hash
 * @param   spec      Hashing parameters
 * @param   squeezes  The number of squeezes to perform
 * @param   suffix    The message suffix
 * @param   style     (unused)
 * @param   hex       Whether to use hexadecimal input rather than binary
 * @param   nuls      Whether lines end with NUL instead of LF,
 *                    and parsing should be less lax
 * @return            An appropriate exit value
 */
static int
check_checksums(const char *restrict filename, const struct libkeccak_spec *restrict spec,
                long int squeezes, const char *restrict suffix, enum representation style, int hex, int nuls)
{
	struct stat attr;
	size_t blksize = 4096;
	size_t size = 4096;
	size_t ptr = 0;
	ssize_t got;
	char *buf;
	int fd = -1;
	int ret = 0;
	int stage;
	size_t hash_start = 0, hash_end = 0;
	size_t file_start = 0, file_end = 0;
	char *hash;
	char *file;
	size_t hash_n;
	char c;

	fd = open(strcmp(filename, "-") ? filename : "/dev/stdin", O_RDONLY);
	if (fd < 0)
		eperror();

	if (!fstat(fd, &attr)) {
		if (attr.st_blksize > 0)
			blksize = (size_t)(attr.st_blksize);
		if (attr.st_size > 0)
			size = (size_t)(attr.st_size);
	}

	size = size > blksize ? size : blksize;
	buf = emalloc(size);

	for (;;) {
		if (ptr + blksize > size)
			buf = erealloc(buf, size <<= 1);

		got = read(fd, &buf[ptr], blksize);
		if (got < 0)
			eperror();
		if (!got)
			break;
		ptr += (size_t)got;
	}
	if (ptr == size)
		buf = erealloc(buf, size + 1);
	size = ptr;
	close(fd), fd = -1;
	buf[size++] = nuls ? '\0' : '\n';

	for (ptr = 0, stage = 0; ptr < size; ptr++) {
		c = buf[ptr];
		if (!nuls) {
			if (stage == 0) {
				if (isxdigit(c))
					;
				else if (c == ' ' || c == '\t')
					hash_end = ptr, stage++;
				else if (c == '\n' || c == '\f' || c == '\r')
					hash_end = ptr, stage = 3;
				else
					user_error("file is malformated");
			} else if (stage == 1) {
				if (c == '\n' || c == '\f' || c == '\r')
					stage = 3;
				else if (c != ' ' && c != '\t')
					file_start = ptr, stage++;
			} else if (stage == 2) {
				if (c == '\n' || c == '\f' || c == '\r')
					file_end = ptr, stage++;
			}
		} else {
			if (stage == 0) {
				if (c == ' ')
					hash_end = ptr, stage++;
				else if (c == '\0')
					hash_end = ptr, stage = 3;
				else if (!isxdigit(c))
					user_error("file is malformated");
			} else if (stage == 1) {
				if (c == ' ')
					file_start = ptr + 1, stage++;
				else
					user_error("file is malformated");
			} else if (stage == 2) {
				if (c == '\0')
					file_end = ptr, stage++;
			}
		}

		if (stage == 3) {
			if ((hash_start == hash_end) != (file_start == file_end))
				user_error("file is malformated");
			if (hash_start != hash_end) {
				hash = buf + hash_start;
				file = buf + file_start;
				hash_n = hash_end - hash_start;
				buf[hash_end] = '\0';
				buf[file_end] = '\0';
				if (hash_n % 2)
					user_error("file is malformated");
				if (hash_n / 2 != (size_t)((spec->output + 7) / 8))
					user_error("algorithm parameter mismatch");
				ret |= check(spec, squeezes, suffix, hex, file, hash);
			}
			stage = 0;
			hash_start = hash_end = file_start = file_end = ptr + 1;
		}
	}

	if (stage)
		user_error("file is malformated");

	free(buf);
	return ret;

	(void) style;
}


/**
 * Print the checksum of a file
 * 
 * @param   filename  The file to hash
 * @param   spec      Hashing parameters
 * @param   squeezes  The number of squeezes to perform
 * @param   suffix    The message suffix
 * @param   style     How the hashes shall be represented
 * @param   hex       Whether to use hexadecimal input rather than binary
 * @param   nuls      Whether lines end with NUL instead of LF
 * @return            An appropriate exit value
 */
static int
print_checksum(const char *restrict filename, const struct libkeccak_spec *restrict spec,
               long int squeezes, const char *restrict suffix, enum representation style, int hex, int nuls)
{
	size_t p = 0, n = (size_t)((spec->output + 7) / 8);
	ssize_t w;

	if (hash(filename, spec, squeezes, suffix, hex)) {
		fprintf(stderr, "%s: %s: %s\n", argv0, filename, strerror(errno));
		return 1;
	}

	if (style == REPRESENTATION_UPPER_CASE) {
		libkeccak_behex_upper(hexsum, hashsum, n);
		printf("%s  %s%c", hexsum, filename, nuls ? '\0' : '\n');
	} else if (style == REPRESENTATION_LOWER_CASE) {
		libkeccak_behex_lower(hexsum, hashsum, n);
		printf("%s  %s%c", hexsum, filename, nuls ? '\0' : '\n');
	} else {
		fflush(stdout);
		for (; p < n; p += (size_t)w)
			if ((w = write(STDOUT_FILENO, &((unsigned char *)hashsum)[p], n - p)) < 0)
				eperror();
	}

	return 0;
}


/**
 * Parse the command line and calculate the hashes of the selected files
 * 
 * @param   argc    The first argument from `main`
 * @param   argv    The second argument from `main`
 * @param   gspec   The default algorithm parameters
 * @param   suffix  Message suffix
 * @param   with_a  Whether the -a option should be recognised (but ignored)
 * @return          An appropriate exit value
 */
int
run(int argc, char *argv[], struct libkeccak_generalised_spec *restrict gspec, const char *restrict suffix, int with_a)
{
	enum representation style = REPRESENTATION_LOWER_CASE;
	int verbose = 0, hex = 0, check = 0, nuls = 0;
	long int squeezes = 1;
	int (*fun)(const char *restrict filename, const struct libkeccak_spec *restrict spec,
	           long int squeezes, const char *restrict suffix, enum representation style, int hex, int nuls);
	struct libkeccak_spec spec;
	int r = 0;

	/* Note: when options are added or removed, also update sha3sum.c */
	ARGBEGIN {
	case 'R':
		gspec->bitrate = atol(EARGF(usage()));
		break;
	case 'C':
		gspec->capacity = atol(EARGF(usage()));
		break;
	case 'N':
	case 'O':
		gspec->output = atol(EARGF(usage()));
		break;
	case 'S':
	case 'B':
		gspec->state_size = atol(EARGF(usage()));
		break;
	case 'W':
		gspec->word_size = atol(EARGF(usage()));
		break;
	case 'Z':
		squeezes = atol(EARGF(usage()));
		break;
	case 'u':
		style = REPRESENTATION_UPPER_CASE;
		break;
	case 'l':
		style = REPRESENTATION_LOWER_CASE;
		break;
	case 'b':
		style = REPRESENTATION_BINARY;
		break;
	case 'c':
		check = 1;
		break;
	case 'v':
		verbose = 1;
		break;
	case 'x':
		hex = 1;
		break;
	case 'z':
		nuls = 1;
		break;
	case 'a':
		if (!with_a)
			usage();
		(void) EARGF(usage());
		break;
	default:
		usage();
	} ARGEND;
	/* -cz has been added because the sha1sum, sha256sum, &c have
	 * it, but I ignore the other crap, mostly because not all
	 * implemention have them and binary vs text mode is stupid. */

	fun = check ? check_checksums : print_checksum;

	make_spec(gspec, &spec);
	if (squeezes <= 0)
		user_error("the squeeze count most be positive");

	if (verbose) {
		fprintf(stderr,        "rate: %li\n", gspec->bitrate);
		fprintf(stderr,    "capacity: %li\n", gspec->capacity);
		fprintf(stderr, "output size: %li\n", gspec->output);
		fprintf(stderr,  "state size: %li\n", gspec->state_size);
		fprintf(stderr,   "word size: %li\n", gspec->word_size);
		fprintf(stderr,    "squeezes: %li\n", squeezes);
		fprintf(stderr,      "suffix: %s\n",  suffix ? suffix : "");
	}

	if (!*argv)
		r = fun("-", &spec, squeezes, suffix, style, hex, nuls);
	for (; *argv; argv++)
		r |= fun(*argv, &spec, squeezes, suffix, style, hex, nuls);

	free(hashsum);
	free(hexsum);
	return r;
}

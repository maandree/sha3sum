/* See LICENSE file for copyright and license details. */
#include "common.h"
#include "arg.h"

#include <sys/stat.h>
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



#define USER_ERROR(string)\
	(fprintf(stderr, "%s: %s\n", argv0, string), 1)



/**
 * Storage for binary hash
 */
static char *restrict hashsum = NULL;

/**
 * Storage for hexadecimal hash
 */
static char *restrict hexsum = NULL;

/**
 * Storage for binary version of expected checksum
 */
#define correct_binary  hexsum

/**
 * Whether a mismatch has been found or if a file was missing
 */
static int bad_found = 0;

/**
 * `argv[0]` from `main`
 */
char *argv0;



/**
 * Print usage information and exit
 */
static void
usage(void)
{
	fprintf(stderr, "usage: %s [-u  | -l | -b | -c] [-R rate] [-C capacity] "
	                "[(-N | -O) output-size] [(-S | -B) state-size] [-W word-size] "
	                "[-Z squeeze-count] [-vx] [file ...]", argv0);
	exit(1);
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
generalised_sum_fd_hex(int fd, libkeccak_state_t *restrict state,
                       const libkeccak_spec_t *restrict spec,
                       const char *restrict suffix, char *restrict hash)
{
	ssize_t got;
	struct stat attr;
	size_t blksize = 4096, r_ptr = 0, w_ptr = 0;
	char *restrict chunk;
	char even = 1, buf = 0, c;

	if (libkeccak_state_initialise(state, spec) < 0)
		return -1;

	if (fstat(fd, &attr) == 0)
		if (attr.st_blksize > 0)
			blksize = (size_t)(attr.st_blksize);

	chunk = alloca(blksize);

	for (;;) {
		got = read(fd, chunk, blksize);
		if (got < 0) return -1;
		if (!got)    break;
		while (r_ptr < (size_t)got) {
			if (c = chunk[r_ptr++], c <= ' ')
				continue;
			buf = (buf << 4) | ((c & 15) + (c > '9' ? 9 : 0));
			if ((even ^= 1))
				chunk[w_ptr++] = buf;
		}
		if (libkeccak_fast_update(state, chunk, w_ptr) < 0)
			return -1;
	}

	return libkeccak_fast_digest(state, NULL, 0, 0, suffix, hash);
}


/**
 * Convert `libkeccak_generalised_spec_t` to `libkeccak_spec_t` and check for errors
 * 
 * @param   gspec  See `libkeccak_degeneralise_spec` 
 * @param   spec   See `libkeccak_degeneralise_spec` 
 * @return         Zero on success, an appropriate exit value on error
 */
static int
make_spec(libkeccak_generalised_spec_t *restrict gspec, libkeccak_spec_t *restrict spec)
{
	int r;

#define TEST(CASE, STR) case LIBKECCAK_GENERALISED_SPEC_ERROR_##CASE: return USER_ERROR(STR)
	if (r = libkeccak_degeneralise_spec(gspec, spec), r) {
		switch (r) {
		TEST (STATE_NONPOSITIVE,      "the state size must be positive");
		TEST (STATE_TOO_LARGE,        "the state size is too large, may not exceed 1600");
		TEST (STATE_MOD_25,           "the state size must be a multiple of 25");
		TEST (WORD_NONPOSITIVE,       "the word size must be positive");
		TEST (WORD_TOO_LARGE,         "the word size is too large, may not exceed 64");
		TEST (STATE_WORD_INCOHERENCY, "the state size must be exactly 25 times the word size");
		TEST (CAPACITY_NONPOSITIVE,   "the capacity must be positive");
		TEST (CAPACITY_MOD_8,         "the capacity must be a multiple of 8");
		TEST (BITRATE_NONPOSITIVE,    "the rate must be positive");
		TEST (BITRATE_MOD_8,          "the rate must be a multiple of 8");
		TEST (OUTPUT_NONPOSITIVE,     "the output size must be positive");
		default:
			return USER_ERROR("unknown error in algorithm parameters");
		}
	}
#undef TEST

#define TEST(CASE, STR) case LIBKECCAK_SPEC_ERROR_##CASE: return USER_ERROR(STR)
	if (r = libkeccak_spec_check(spec), r) {
		switch (r) {
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
			return USER_ERROR("unknown error in algorithm parameters");
		}
	}
#undef TEST

	return 0;
}


/**
 * Calculate the checksum of a file and store it in the global variable `hashsum`
 * 
 * @param   filename        The file to hash
 * @param   spec            Hashing parameters
 * @param   squeezes        The number of squeezes to perform
 * @param   suffix          The message suffix
 * @param   hex             Whether to use hexadecimal input rather than binary
 * @return                  Zero on success, an appropriate exit value on error
 */
static int
hash(const char *restrict filename, const libkeccak_spec_t *restrict spec,
     long squeezes, const char *restrict suffix, int hex)
{
	libkeccak_state_t state;
	size_t length;
	int r, fd;

	length = (size_t)((spec->output + 7) / 8);

	if (!hashsum && (hashsum = malloc(length * sizeof(char)), !hashsum))
		return perror(argv0), 2;

	if (!hexsum && (hexsum = malloc((length * 2 + 1) * sizeof(char)), !hexsum))
		return perror(argv0), 2;

	if (fd = open(strcmp(filename, "-") ? filename : "/dev/stdin", O_RDONLY), fd < 0)
		return r = (errno != ENOENT), perror(argv0), r + 1;

	if ((hex == 0 ? libkeccak_generalised_sum_fd : generalised_sum_fd_hex)
	    (fd, &state, spec, suffix, squeezes > 1 ? NULL : hashsum))
		return perror(argv0), close(fd), libkeccak_state_fast_destroy(&state), 2;
	close(fd);

	if (squeezes > 2) libkeccak_fast_squeeze(&state, squeezes - 2);
	if (squeezes > 1) libkeccak_squeeze(&state, hashsum);
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
 * @return                Zero on success, an appropriate exit value on error
 */
static int
check(const libkeccak_spec_t *restrict spec, long squeezes, const char *restrict suffix,
      int hex, const char *restrict filename, const char *restrict correct_hash)
{
	size_t length = (size_t)((spec->output + 7) / 8);
	int r;

	if (access(filename, F_OK)) {
		bad_found = 1;
		printf("%s: %s\n", filename, "Missing");
		return 0;
	}

	if ((r = hash(filename, spec, squeezes, suffix, hex)))
		return r;

	libkeccak_unhex(correct_binary, correct_hash);
	if ((r = memcmp(correct_binary, hashsum, length)))
		bad_found = 1;
	printf("%s: %s\n", filename, !r ? "OK" : "Fail");

	return 0;
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
 * @return            Zero on success, an appropriate exit value on error
 */
static int
check_checksums(const char *restrict filename, const libkeccak_spec_t *restrict spec,
                long squeezes, const char *restrict suffix, enum representation style, int hex)
{
	struct stat attr;
	size_t blksize = 4096;
	size_t size = 4096;
	size_t ptr = 0;
	ssize_t got;
	char *buf = NULL;
	char *new;
	int fd = -1, rc = 2, stage, r;
	size_t hash_start = 0, hash_end = 0;
	size_t file_start = 0, file_end = 0;
	char *hash;
	char *file;
	size_t hash_n;
	char c;

	if (fd = open(strcmp(filename, "-") ? filename : "/dev/stdin", O_RDONLY), fd < 0)
		goto pfail;

	if (fstat(fd, &attr) == 0) {
		if (attr.st_blksize > 0) blksize = (size_t)(attr.st_blksize);
		if (attr.st_size    > 0) size    = (size_t)(attr.st_size);
	}

	size = size > blksize ? size : blksize;
	if (buf = malloc(size), buf == NULL)
		goto pfail;

	for (;;) {
		if (ptr + blksize < size) {
			if (new = realloc(buf, size <<= 1), new == NULL)
				goto pfail;
			buf = new;
		}

		got = read(fd, buf + ptr, blksize);
		if      (got < 0)  goto pfail;
		else if (got == 0) break;
		else               ptr += (size_t)got;
	}
	if (ptr == size) {
		if (new = realloc(buf, size + 1), new == NULL)
			goto pfail;
		buf = new;
	}
	size = ptr;
	close(fd), fd = -1;
	buf[size++] = '\n';

	for (ptr = 0, stage = 0; ptr < size; ptr++) {
		c = buf[ptr];
		if (stage == 0) {
			if      (('0' <= c) && (c <= '9'));
			else if (('a' <= c) && (c <= 'f'));
			else if (('A' <= c) && (c <= 'F'));
			else if ((c == ' ') || (c == '\t')) {
				hash_end = ptr, stage++;
			} else if ((c == '\n') || (c == '\f') || (c == '\r')) {
				hash_end = ptr, stage = 3;
			} else {
				rc = USER_ERROR("file is malformated");
				goto fail;
			}
		} else if (stage == 1) {
			if ((c == '\n') || (c == '\f') || (c == '\r'))
				stage = 3;
			else if ((c != ' ') && (c != '\t'))
				file_start = ptr, stage++;
		} else if (stage == 2) {
			if ((c == '\n') || (c == '\f') || (c == '\r'))
				file_end = ptr, stage++;
		}

		if (stage == 3) {
			if ((hash_start == hash_end) != (file_start == file_end)) {
				rc = USER_ERROR("file is malformated");
				goto fail;
			}
			if (hash_start != hash_end) {
				hash = buf + hash_start;
				file = buf + file_start;
				hash_n = hash_end - hash_start;
				buf[hash_end] = '\0';
				buf[file_end] = '\0';
				if (hash_n % 2) {
					rc = USER_ERROR("file is malformated");
					goto fail;
				}
				if (hash_n / 2 != (size_t)((spec->output + 7) / 8)) {
					rc = USER_ERROR("algorithm parameter mismatch");
					goto fail;
				}
				if ((r = check(spec, squeezes, suffix, hex, file, hash))) {
					rc = r;
					goto fail;
				}
			}
			stage = 0;
			hash_start = hash_end = file_start = file_end = ptr + 1;
		}
	}

	if (stage) {
		rc = USER_ERROR("file is malformated");
		goto fail;
	}

	free(buf);
	return 0;

pfail:
	perror(argv0);
fail:
	free(buf);
	if (fd >= 0)
		close(fd);
	return rc;

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
 * @return            Zero on success, an appropriate exit value on error
 */
static int
print_checksum(const char *restrict filename, const libkeccak_spec_t *restrict spec,
               long squeezes, const char *restrict suffix, enum representation style, int hex)
{
	size_t length = (size_t)((spec->output + 7) / 8);
	int r;
	size_t ptr = 0;
	ssize_t wrote;

	if ((r = hash(filename, spec, squeezes, suffix, hex)))
		return r;

	if (style == REPRESENTATION_UPPER_CASE) {
		libkeccak_behex_upper(hexsum, hashsum, length);
		printf("%s  %s\n", hexsum, filename);
	} else if (style == REPRESENTATION_LOWER_CASE) {
		libkeccak_behex_lower(hexsum, hashsum, length);
		printf("%s  %s\n", hexsum, filename);
	} else {
		fflush(stdout);
		while (length - ptr) {
			wrote = write(STDOUT_FILENO, hashsum, length - ptr);
			if (wrote <= 0)
				return perror(argv0), 2;
			ptr += (size_t)wrote;
		}
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
 * @return          An appropriate exit value
 */
int
run(int argc, char *argv[], libkeccak_generalised_spec_t *restrict gspec, const char *restrict suffix)
{
	enum representation style = REPRESENTATION_UPPER_CASE;
	int verbose = 0;
	int hex = 0;
	int check = 0;
	long int squeezes = 1;
	int (*fun)(const char *restrict filename, const libkeccak_spec_t *restrict spec,
	           long squeezes, const char *restrict suffix, enum representation style, int hex);
	libkeccak_spec_t spec;
	int r;

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
	case 'x':
		hex = 1;
		break;
	case 'v':
		verbose = 1;
		break;
	default:
		usage();
	} ARGEND;
	/* -c has been added because the sha1sum, sha256sum &c have
	 * it, but I ignore the other crap, mostly because not all
	 * implemention have them and binary vs text mode is stupid. */

	fun = check ? check_checksums : print_checksum;

	if ((r = make_spec(gspec, &spec)))
		goto done;

	if (squeezes <= 0) {
		r = USER_ERROR("the squeeze count most be positive");
		goto done;
	}

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
		r = fun("-", &spec, squeezes, suffix, style, hex);
	for (; *argv; argv++)
		if ((r = fun(*argv, &spec, squeezes, suffix, style, hex)))
			break;

done:
	free(hashsum);
	free(hexsum);
	return r ? r : bad_found;
}

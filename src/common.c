/**
 * sha3sum – SHA-3 (Keccak) checksum calculator
 * 
 * Copyright © 2013, 2014  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "common.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <alloca.h>



#ifndef STDIN_PATH
# ifndef DEVDIR
#  define DEVDIR  "/dev"
# endif
# define STDIN_PATH  DEVDIR "/stdin"
#endif



#define USER_ERROR(string) 				\
  (fprintf(stderr, "%s: %s.\n", execname, string), 1)

#define ADD(arg, desc, ...)								\
  (arg ? args_add_option(args_new_argumented(NULL, arg, 0, __VA_ARGS__, NULL), desc)	\
       : args_add_option(args_new_argumentless(NULL, 0, __VA_ARGS__, NULL), desc))

#define LAST(arg)					\
  (args_opts_get(arg)[args_opts_get_count(arg) - 1])



/**
 * Storage for binary hash
 */
static char* restrict hashsum = NULL;

/**
 * Storage for hexadecimal hash
 */
static char* restrict hexsum = NULL;

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
static char* execname;



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
__attribute__((nonnull(2, 3)))
static int generalised_sum_fd_hex(int fd, libkeccak_state_t* restrict state,
				  const libkeccak_spec_t* restrict spec,
				  const char* restrict suffix, char* restrict hash)
{
  ssize_t got;
  struct stat attr;
  size_t blksize = 4096, r_ptr = 0, w_ptr = 0;
  char* restrict chunk;
  char even = 1, buf = 0, c;
  
  if (libkeccak_state_initialise(state, spec) < 0)
    return -1;
  
  if (fstat(fd, &attr) == 0)
    if (attr.st_blksize > 0)
      blksize = (size_t)(attr.st_blksize);
  
  chunk = alloca(blksize);
  
  for (;;)
    {
      got = read(fd, chunk, blksize);
      if (got < 0)   return -1;
      if (got == 0)  break;
      while (r_ptr < (size_t)got)
	{
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
static int make_spec(libkeccak_generalised_spec_t* restrict gspec, libkeccak_spec_t* restrict spec)
{
  int r;
  
#define TEST(CASE, STR)  case LIBKECCAK_GENERALISED_SPEC_ERROR_##CASE:  return USER_ERROR(STR)
  if (r = libkeccak_degeneralise_spec(gspec, spec), r)
    switch (r)
      {
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
#undef TEST
  
#define TEST(CASE, STR)  case LIBKECCAK_SPEC_ERROR_##CASE:  return USER_ERROR(STR)
  if (r = libkeccak_spec_check(spec), r)
    switch (r)
      {
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
static int hash(const char* restrict filename, const libkeccak_spec_t* restrict spec,
		long squeezes, const char* restrict suffix, int hex)
{
  libkeccak_state_t state;
  size_t length;
  int r, fd;
  
  length = (size_t)((spec->output + 7) / 8);
  
  if (hashsum == NULL)
    if (hashsum = malloc(length * sizeof(char)), hashsum == NULL)
      return perror(execname), 2;
  
  if (hexsum == NULL)
    if (hexsum = malloc((length * 2 + 1) * sizeof(char)), hexsum == NULL)
      return perror(execname), 2;
  
  if (fd = open(strcmp(filename, "-") ? filename : STDIN_PATH, O_RDONLY), fd < 0)
    return r = (errno != ENOENT), perror(execname), r + 1;
  
  if ((hex == 0 ? libkeccak_generalised_sum_fd : generalised_sum_fd_hex)
      (fd, &state, spec, suffix, squeezes > 1 ? NULL : hashsum))
    return perror(execname), close(fd), libkeccak_state_fast_destroy(&state), 2;
  close(fd);
  
  if (squeezes > 2)  libkeccak_fast_squeeze(&state, squeezes - 2);
  if (squeezes > 1)  libkeccak_squeeze(&state, hashsum);
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
static int check(const libkeccak_spec_t* restrict spec, long squeezes, const char* restrict suffix,
		 int hex, const char* restrict filename, const char* restrict correct_hash)
{
  size_t length = (size_t)((spec->output + 7) / 8);
  int r;
  
  if (access(filename, F_OK))
    {
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
 * @param   filename        The file to hash
 * @param   spec            Hashing parameters
 * @param   squeezes        The number of squeezes to perform
 * @param   suffix          The message suffix
 * @param   representation  (unused)
 * @param   hex             Whether to use hexadecimal input rather than binary
 * @return                  Zero on success, an appropriate exit value on error
 */
static int check_checksums(const char* restrict filename, const libkeccak_spec_t* restrict spec,
			   long squeezes, const char* restrict suffix, int representation, int hex)
{
  struct stat attr;
  size_t blksize = 4096;
  size_t size = 4096;
  size_t ptr = 0;
  ssize_t got;
  char* buf = NULL;
  char* new;
  int fd = -1, rc = 2, stage, r;
  size_t hash_start = 0, hash_end = 0;
  size_t file_start = 0, file_end = 0;
  char* hash;
  char* file;
  size_t hash_n;
  
  if (fd = open(strcmp(filename, "-") ? filename : STDIN_PATH, O_RDONLY), fd < 0)
    goto pfail;
  
  if (fstat(fd, &attr) == 0)
    {
      if (attr.st_blksize > 0)  blksize = (size_t)(attr.st_blksize);
      if (attr.st_size    > 0)  size    = (size_t)(attr.st_size);
    }
  
  size = size > blksize ? size : blksize;
  if (buf = malloc(size), buf == NULL)
    goto pfail;
  
  for (;;)
    {
      if (ptr + blksize < size)
	{
	  if (new = realloc(buf, size <<= 1), new == NULL)
	    goto pfail;
	  buf = new;
	}
      
      got = read(fd, buf + ptr, blksize);
      if      (got < 0)   goto pfail;
      else if (got == 0)  break;
      else                ptr += (size_t)got;
    }
  if (ptr == size)
    {
      if (new = realloc(buf, size + 1), new == NULL)
	goto pfail;
      buf = new;
    }
  size = ptr;
  close(fd), fd = -1;
  buf[size++] = '\n';
  
  for (ptr = 0, stage = 0; ptr < size; ptr++)
    {
      char c = buf[ptr];
      if (stage == 0)
	{
	  if      (('0' <= c) && (c <= '9'));
	  else if (('a' <= c) && (c <= 'f'));
	  else if (('A' <= c) && (c <= 'F'));
	  else if ((c == ' ') || (c == '\t'))
	    hash_end = ptr, stage++;
	  else if ((c == '\n') || (c == '\f') || (c == '\r'))
	    hash_end = ptr, stage = 3;
	  else
	    {
	      rc = USER_ERROR("file is malformated");
	      goto fail;
	    }
	}
      else if (stage == 1)
	{
	  if ((c == '\n') || (c == '\f') || (c == '\r'))
	    stage = 3;
	  else if ((c != ' ') && (c != '\t'))
	    file_start = ptr, stage++;
	}
      else if (stage == 2)
	{
	  if ((c == '\n') || (c == '\f') || (c == '\r'))
	    file_end = ptr, stage++;
	}
      
      if (stage == 3)
	{
	  if ((hash_start == hash_end) != (file_start == file_end))
	    {
	      rc = USER_ERROR("file is malformated");
	      goto fail;
	    }
	  if (hash_start != hash_end)
	    {
	      hash = buf + hash_start;
	      file = buf + file_start;
	      hash_n = hash_end - hash_start;
	      buf[hash_end] = '\0';
	      buf[file_end] = '\0';
	      if (hash_n % 2)
		{
		  rc = USER_ERROR("file is malformated");
		  goto fail;
		}
	      if (hash_n / 2 != (size_t)((spec->output + 7) / 8))
		{
		  rc = USER_ERROR("algorithm parameter mismatch");
		  goto fail;
		}
	      if ((r = check(spec, squeezes, suffix, hex, file, hash)))
		{
		  rc = r;
		  goto fail;
		}
	    }
	  stage = 0;
	  hash_start = hash_end = file_start = file_end = ptr + 1;
	}
    }
  
  if (stage)
    {
      rc = USER_ERROR("file is malformated");
      goto fail;
    }
  
  free(buf);
  return 0;
  
 pfail:
  perror(execname);
 fail:
  free(buf);
  if (fd >= 0)
    close(fd);
  return rc;
  
  (void) representation;
}


/**
 * Print the checksum of a file
 * 
 * @param   filename        The file to hash
 * @param   spec            Hashing parameters
 * @param   squeezes        The number of squeezes to perform
 * @param   suffix          The message suffix
 * @param   representation  Either of `REPRESENTATION_BINARY`, `REPRESENTATION_UPPER_CASE`
 *                          and `REPRESENTATION_LOWER_CASE`
 * @param   hex             Whether to use hexadecimal input rather than binary
 * @return                  Zero on success, an appropriate exit value on error
 */
static int print_checksum(const char* restrict filename, const libkeccak_spec_t* restrict spec,
			  long squeezes, const char* restrict suffix, int representation, int hex)
{
  size_t length = (size_t)((spec->output + 7) / 8);
  int r;
  
  if ((r = hash(filename, spec, squeezes, suffix, hex)))
    return r;
  
  if (representation == REPRESENTATION_UPPER_CASE)
    {
      libkeccak_behex_upper(hexsum, hashsum, length);
      printf("%s  %s\n", hexsum, filename);
    }
  else if (representation == REPRESENTATION_LOWER_CASE)
    {
      libkeccak_behex_lower(hexsum, hashsum, length);
      printf("%s  %s\n", hexsum, filename);
    }
  else
    {
      size_t ptr = 0;
      ssize_t wrote;
      fflush(stdout);
      while (length - ptr)
	{
	  wrote = write(STDOUT_FILENO, hashsum, length - ptr);
	  if (wrote <= 0)
	    return perror(execname), 2;
	  ptr += (size_t)wrote;
	}
    }
  
  return 0;
}


/**
 * Cleanup allocations
 */
static inline void cleanup(void)
{
  free(hashsum), hashsum = NULL;
  free(hexsum), hexsum = NULL;
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
int run(int argc, char* argv[], libkeccak_generalised_spec_t* restrict gspec, const char* restrict suffix)
{
  int r, verbose = 0, presentation = REPRESENTATION_UPPER_CASE, hex = 0, check = 0;
  long squeezes = 1;
  size_t i;
  libkeccak_spec_t spec;
  int (*fun)(const char* restrict filename, const libkeccak_spec_t* restrict spec,
	     long squeezes, const char* restrict suffix, int representation, int hex);
  
  execname = *argv;
  
  ADD(NULL,       "Display option summary", "-h", "--help");
  ADD("RATE",     "Select rate",            "-R", "--bitrate", "--rate");
  ADD("CAPACITY", "Select capacity",        "-C", "--capacity");
  ADD("SIZE",     "Select output size",     "-N", "-O", "--output-size", "--output");
  ADD("SIZE",     "Select state size",      "-S", "-B", "--state-size", "--state");
  ADD("SIZE",     "Select word size",       "-W", "--word-size", "--word");
  ADD("COUNT",    "Select squeeze count",   "-Z", "--squeezes");
  ADD(NULL,       "Use upper-case output",  "-u", "--upper", "--uppercase", "--upper-case");
  ADD(NULL,       "Use lower-case output",  "-l", "--lower", "--lowercase", "--lower-case");
  ADD(NULL,       "Use binary output",      "-b", "--binary");
  ADD(NULL,       "Use hexadecimal input",  "-x", "--hex", "--hex-input");
  ADD(NULL,       "Check checksums",        "-c", "--check");
  ADD(NULL,       "Be verbose",             "-v", "--verbose");
  /* --check has been added because the sha1sum, sha256sum &c have it,
   * but I ignore the other crap, mostly because not all implemention
   * have them and binary vs text mode is stupid. */
  
  args_parse(argc, argv);
  
  if (args_opts_used("-h"))  return args_help(0), args_dispose(), 0;
  if (args_opts_used("-R"))  gspec->bitrate    = atol(LAST("-R"));
  if (args_opts_used("-C"))  gspec->capacity   = atol(LAST("-C"));
  if (args_opts_used("-N"))  gspec->output     = atol(LAST("-N"));
  if (args_opts_used("-S"))  gspec->state_size = atol(LAST("-S"));
  if (args_opts_used("-W"))  gspec->word_size  = atol(LAST("-W"));
  if (args_opts_used("-Z"))  squeezes          = atol(LAST("-Z"));
  if (args_opts_used("-u"))  presentation      = REPRESENTATION_UPPER_CASE;
  if (args_opts_used("-l"))  presentation      = REPRESENTATION_LOWER_CASE;
  if (args_opts_used("-b"))  presentation      = REPRESENTATION_BINARY;
  if (args_opts_used("-x"))  hex               = 1;
  if (args_opts_used("-c"))  check             = 1;
  if (args_opts_used("-v"))  verbose           = 1;
  
  fun = check ? check_checksums : print_checksum;
  
  if ((r = make_spec(gspec, &spec)))
      goto done;
  
  if (squeezes <= 0)
    {
      r = USER_ERROR("the squeeze count most be positive");
      goto done;
    }
  
  if (verbose)
    {
      fprintf(stderr,        "rate: %li\n", gspec->bitrate);
      fprintf(stderr,    "capacity: %li\n", gspec->capacity);
      fprintf(stderr, "output size: %li\n", gspec->output);
      fprintf(stderr,  "state size: %li\n", gspec->state_size);
      fprintf(stderr,   "word size: %li\n", gspec->word_size);
      fprintf(stderr,    "squeezes: %li\n", squeezes);
      fprintf(stderr,      "suffix: %s\n",  suffix ? suffix : "");
    }
  
  if (args_files_count == 0)
    r = fun("-", &spec, squeezes, suffix, presentation, hex);
  else
    for (i = 0; i < (size_t)args_files_count; i++)
      if ((r = fun(args_files[i], &spec, squeezes, suffix, presentation, hex)))
	break;
  
 done:
  args_dispose();
  cleanup();
  return r ? r : bad_found;
}


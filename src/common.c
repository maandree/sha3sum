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



#define USER_ERROR(string)  \
  (fprintf(stderr, "%s: %s.\n", execname, string), 1)


#define ADD(arg, desc, ...)  \
  (arg ? args_add_option(args_new_argumented(NULL, arg, 0, __VA_ARGS__, NULL), desc)  \
       : args_add_option(args_new_argumentless(NULL, 0, __VA_ARGS__, NULL), desc))



/**
 * Storage for binary hash
 */
static char* restrict hashsum = NULL;

/**
 * Storage for hexadecimal hash
 */
static char* restrict hexsum = NULL;



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
	  buf = (buf << 4) | ((c & 15) + (c > '9' ? 0 : 0));
	  if ((even ^= 1))
	    chunk[w_ptr++] = buf;
	}
      if (libkeccak_fast_update(state, chunk, w_ptr) < 0)
	return -1;
    }
  
  return libkeccak_fast_digest(state, NULL, 0, 0, suffix, hash);
}


/**
 * Print the checksum of a file
 * 
 * @param   filename        The file to hash
 * @param   gspec           Hashing parameters
 * @param   squeezes        The number of squeezes to perform
 * @param   suffix          The message suffix
 * @param   representation  Either of `REPRESENTATION_BINARY`, `REPRESENTATION_UPPER_CASE`
 *                          and `REPRESENTATION_LOWER_CASE`
 * @param   hex             Whether to use hexadecimal input rather than binary
 * @param   verbose         Whether to print the hashing parameters
 * @param   execname        `argv[0]` from `main`
 * @return                  Zero on succes, an appropriate exit value on error
 */
int print_checksum(const char* restrict filename, libkeccak_generalised_spec_t* restrict gspec,
		   long squeezes, const char* restrict suffix, int representation, int hex,
		   int verbose, const char* restrict execname)
{
  libkeccak_spec_t spec;
  libkeccak_state_t state;
  int r, fd;
  size_t length;
  
  if (r = libkeccak_degeneralise_spec(gspec, &spec), r)
    switch (r)
      {	
      case LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_NONPOSITIVE:
	return USER_ERROR("the state size must be positive");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_TOO_LARGE:
	return USER_ERROR("the state size is too large, may not exceed 1600");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_MOD_25:
	return USER_ERROR("the state size must be a multiple of 25");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_NONPOSITIVE:
	return USER_ERROR("the word size must be positive");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_WORD_TOO_LARGE:
	return USER_ERROR("the word size is too large, may not exceed 64");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_STATE_WORD_INCOHERENCY:
	return USER_ERROR("the state size must be exactly 25 times the word size");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_NONPOSITIVE:
	return USER_ERROR("the capacity must be positive");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_CAPACITY_MOD_8:
	return USER_ERROR("the capacity must be a multiple of 8");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_NONPOSITIVE:
	return USER_ERROR("the rate must be positive");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_BITRATE_MOD_8:
	return USER_ERROR("the rate must be a multiple of 8");
      case LIBKECCAK_GENERALISED_SPEC_ERROR_OUTPUT_NONPOSITIVE:
	return USER_ERROR("the output size must be positive");
      default:
	return USER_ERROR("unknown error in algorithm parameters");
    }
  
  if (r = libkeccak_spec_check(&spec), r)
    switch (r)
      {
      case LIBKECCAK_SPEC_ERROR_BITRATE_NONPOSITIVE:
	return USER_ERROR("the rate size must be positive");
      case LIBKECCAK_SPEC_ERROR_BITRATE_MOD_8:
	return USER_ERROR("the rate must be a multiple of 8");
      case LIBKECCAK_SPEC_ERROR_CAPACITY_NONPOSITIVE:
	return USER_ERROR("the capacity must be positive");
      case LIBKECCAK_SPEC_ERROR_CAPACITY_MOD_8:
	return USER_ERROR("the capacity must be a multiple of 8");
      case LIBKECCAK_SPEC_ERROR_OUTPUT_NONPOSITIVE:
	return USER_ERROR("the output size must be positive");
      case LIBKECCAK_SPEC_ERROR_STATE_TOO_LARGE:
	return USER_ERROR("the state size is too large, may not exceed 1600");
      case LIBKECCAK_SPEC_ERROR_STATE_MOD_25:
	return USER_ERROR("the state size must be a multiple of 25");
      case LIBKECCAK_SPEC_ERROR_WORD_NON_2_POTENT:
	return USER_ERROR("the word size must be a power of 2");
      case LIBKECCAK_SPEC_ERROR_WORD_MOD_8:
	return USER_ERROR("the word size must be a multiple of 8");
      default:
	return USER_ERROR("unknown error in algorithm parameters");
      }
  
  if (squeezes <= 0)
    return USER_ERROR("the squeeze count be be positive");
  
  if (verbose)
    {
      fprintf(stderr,        "rate: %li\n", gspec->bitrate);
      fprintf(stderr,    "capacity: %li\n", gspec->capacity);
      fprintf(stderr, "output size: %li\n", gspec->output);
      fprintf(stderr,  "state size: %li\n", gspec->state_size);
      fprintf(stderr,   "word size: %li\n", gspec->word_size);
      fprintf(stderr,    "squeezes: %li\n", squeezes);
    }
  
  length = (size_t)((spec.output + 7) / 8);
  
  if (hashsum == NULL)
    if (hashsum = malloc(length * sizeof(char)), hashsum == NULL)
      return perror(execname), 2;
  
  if ((hexsum == NULL) && (representation != REPRESENTATION_BINARY))
    if (hexsum = malloc((length * 2 + 1) * sizeof(char)), hexsum == NULL)
      return perror(execname), 2;
  
  if (fd = open(strcmp(filename, "-") ? filename : STDIN_PATH, O_RDONLY), fd < 0)
    return r = (errno != ENOENT), perror(execname), r + 1;
  
  if ((hex == 0 ? libkeccak_generalised_sum_fd : generalised_sum_fd_hex)
      (fd, &state, &spec, suffix, squeezes > 1 ? NULL : hashsum))
    return perror(execname), close(fd), libkeccak_state_fast_destroy(&state), 2;
  close(fd);
  
  if (squeezes > 2)  libkeccak_fast_squeeze(&state, squeezes - 2);
  if (squeezes > 1)  libkeccak_squeeze(&state, hashsum);
  libkeccak_state_fast_destroy(&state);
  
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
 * @param   spec    The default algorithm parameters
 * @param   suffix  Message suffix
 * @return          An appropriate exit value
 */
int run(int argc, char* argv[], libkeccak_generalised_spec_t* restrict spec, const char* restrict suffix)
{
  int r, verbose = 0, presentation = REPRESENTATION_UPPER_CASE, hex = 0;
  long squeezes = 1;
  size_t i;
  
  ADD(NULL,       "Display option summary", "-h", "--help");
  ADD("RATE",     "Select rate",            "-r", "--bitrate", "--rate");
  ADD("CAPACITY", "Select capacity",        "-c", "--capacity");
  ADD("SIZE",     "Select output size",     "-n", "-o", "--output-size", "--output");
  ADD("SIZE",     "Select state size",      "-s", "-b", "--state-size", "--state");
  ADD("SIZE",     "Select word size",       "-w", "--word-size", "--word");
  ADD("COUNT",    "Select squeeze count",   "-z", "--squeezes");
  ADD(NULL,       "Use upper-case output",  "-U", "--upper", "--uppercase", "--upper-case");
  ADD(NULL,       "Use lower-case output",  "-L", "--lower", "--lowercase", "--lower-case");
  ADD(NULL,       "Use binary output",      "-B", "--binary");
  ADD(NULL,       "Use hexadecimal input",  "-X", "--hex", "--hex-input");
  ADD(NULL,       "Be verbose",             "-V", "--verbose");
  
  args_parse(argc, argv);
  
  /* TODO stricter parsing */
  if (args_opts_used("-h"))  return args_help(0), 0;
  if (args_opts_used("-r"))  spec->bitrate    = atol(args_opts_get("-r")[0]);
  if (args_opts_used("-c"))  spec->capacity   = atol(args_opts_get("-c")[0]);
  if (args_opts_used("-n"))  spec->output     = atol(args_opts_get("-n")[0]);
  if (args_opts_used("-s"))  spec->state_size = atol(args_opts_get("-s")[0]);
  if (args_opts_used("-w"))  spec->word_size  = atol(args_opts_get("-w")[0]);
  if (args_opts_used("-z"))  squeezes         = atol(args_opts_get("-z")[0]);
  if (args_opts_used("-U"))  presentation     = REPRESENTATION_UPPER_CASE;
  if (args_opts_used("-L"))  presentation     = REPRESENTATION_LOWER_CASE;
  if (args_opts_used("-B"))  presentation     = REPRESENTATION_BINARY;
  if (args_opts_used("-X"))  hex              = 1;
  if (args_opts_used("-V"))  verbose          = 1;
  
  if (args_files_count == 0)
    r = print_checksum("-", spec, squeezes, suffix, presentation, hex, verbose, *argv);
  else
    for (i = 0; i < (size_t)args_files_count; i++, verbose = 0)
      if ((r = print_checksum(args_files[i], spec, squeezes, suffix, presentation, hex, verbose, *argv)))
	break;
  
  args_dispose();
  cleanup();
  return r;
}


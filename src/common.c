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



#ifndef STDIN_PATH
# ifndef DEVDIR
#  define DEVDIR  "/dev"
# endif
# define STDIN_PATH  DEVDIR "/stdin"
#endif



#define USER_ERROR(string)  \
  (fprintf(stderr, "%s: %s.\n", execname, string), 1)



static char* restrict hashsum = NULL;
static char* restrict hexsum = NULL;



/**
 * Print the checksum of a file
 * 
 * @param   filename        The file to hash
 * @param   gspec           Hashing parameters
 * @param   squeezes        The number of squeezes to perform
 * @param   suffix          The message suffix
 * @param   representation  Either of `REPRESENTATION_BINARY`, `REPRESENTATION_UPPER_CASE`
 *                          and `REPRESENTATION_LOWER_CASE`
 * @param   verbose         Whether to print the hashing parameters
 * @param   execname        `argv[0]` from `main`
 * @return                  Zero on succes, an appropriate exit value on error
 */
int print_checksum(const char* restrict filename, libkeccak_generalised_spec_t* restrict gspec,
		   long squeezes, const char* restrict suffix, int representation, int verbose,
		   const char* restrict execname)
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
      return perror(execname), free(hashsum), 2;
  
  if (fd = open(strcmp(filename, "-") ? filename : STDIN_PATH, O_RDONLY), fd < 0)
    return r = (errno != ENOENT), perror(execname), free(hashsum), free(hexsum), r + 1;
  
  if (libkeccak_generalised_sum_fd(fd, &state, &spec, suffix, squeezes > 1 ? NULL : hashsum))
    return perror(execname), close(fd), libkeccak_state_fast_destroy(&state), free(hashsum), free(hexsum), 2;
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
      for (;;)
	{
	  wrote = write(STDOUT_FILENO, hashsum, length - ptr);
	  if (wrote <= 0)
	    return perror(execname), 2;
	  ptr += (size_t)wrote;
	}
    }
  
  return 0;
}


void cleanup(void)
{
  free(hashsum), hashsum = NULL;
  free(hexsum), hexsum = NULL;
}

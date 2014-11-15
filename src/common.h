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
#ifndef SHA3SUM_COMMON_H
#define SHA3SUM_COMMON_H 1


#include <libkeccak.h>
#include <argparser.h>


#define libkeccak_spec_keccak    libkeccak_spec_sha3
#define LIBKECCAK_KECCAK_SUFFIX  ""



/**
 * Wrapper for `run` that also initialises the command line parser
 * 
 * @param  algo    The name of the hashing algorithm, must be a string literal
 * @param  prog    The name of program, must be a string literal
 * @param  suffix  The message suffix
 */
#define RUN(algo, prog, suffix)					\
  (args_init(algo " checksum calculator",			\
	     prog " [options...] [--] [files...]", NULL,	\
	     NULL, 1, 0, args_standard_abbreviations),		\
   run(argc, argv, &spec, suffix))



/**
 * Print the checksum in binary
 */
#define REPRESENTATION_BINARY  0

/**
 * Print the checksum in upper case hexadecimal
 */
#define REPRESENTATION_UPPER_CASE  1

/**
 * Print the checksum in lower case hexadecimal
 */
#define REPRESENTATION_LOWER_CASE  2



/**
 * Parse the command line and calculate the hashes of the selected files
 * 
 * @param   argc    The first argument from `main`
 * @param   argv    The second argument from `main`
 * @param   gspec   The default algorithm parameters
 * @param   suffix  Message suffix
 * @return          An appropriate exit value
 */
int run(int argc, char* argv[], libkeccak_generalised_spec_t* restrict gspec, const char* restrict suffix);


#endif


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
 * Print the checksum of a file
 * 
 * @param   filename        The file to hash
 * @param   gspec           Hashing parameters
 * @param   squeezes        The  number of squeezes to perform
 * @param   suffix          The message suffix
 * @param   representation  Either of `REPRESENTATION_BINARY`, `REPRESENTATION_UPPER_CASE`
 *                          and `REPRESENTATION_LOWER_CASE`
 * @param   verbose         Whether to print the hashing parameters
 * @param   execname        `argv[0]` from `main`
 * @return                  Zero on succes, an appropriate exit value on error
 */
int print_checksum(const char* restrict filename, libkeccak_generalised_spec_t* restrict gspec,
		   long squeezes, const char* restrict suffix, int representation, int verbose,
		   const char* restrict execname);


void cleanup(void);


#endif


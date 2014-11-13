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

#include <stdlib.h>

#include <argparser.h>


#define ADD(arg, desc, ...)  \
  args_add_option(args_new_argumented(NULL, arg, 0, __VA_ARGS__, NULL), desc)


int main(int argc, char* argv[])
{
  libkeccak_generalised_spec_t spec;
  long squeezes = 1;
  int r, verbose = 1;
  size_t i;
  
  libkeccak_generalised_spec_initialise(&spec);
  
  args_init("Keccak checksum calculator",
	    "keccaksum [options...] [--] [files...]", NULL,
	    NULL, 1, 0, args_standard_abbreviations);
  
  ADD("RATE",     "Select rate",          "-r", "--bitrate", "--rate");
  ADD("CAPACITY", "Select capacity",      "-c", "--capacity");
  ADD("SIZE",     "Select output size",   "-n", "-o", "--output-size", "--output");
  ADD("SIZE",     "Select state size",    "-s", "-b", "--state-size", "--state");
  ADD("SIZE",     "Select word size",     "-w", "--word-size", "--word");
  ADD("COUNT",    "Select squeeze count", "-z", "--squeezes");
  /* TODO more options */
  
  args_parse(argc, argv);
  
  /* TODO stricter parsing */
  
  if (args_opts_used("-r"))  spec.bitrate    = atol(*(args_opts_get("-r")));
  if (args_opts_used("-c"))  spec.capacity   = atol(*(args_opts_get("-c")));
  if (args_opts_used("-n"))  spec.output     = atol(*(args_opts_get("-n")));
  if (args_opts_used("-s"))  spec.state_size = atol(*(args_opts_get("-s")));
  if (args_opts_used("-w"))  spec.word_size  = atol(*(args_opts_get("-w")));
  if (args_opts_used("-z"))  squeezes        = atol(*(args_opts_get("-z")));
  
  if (args_files_count == 0)
    r = print_checksum("-", &spec, squeezes, "", REPRESENTATION_UPPER_CASE, verbose, *argv);
  else
    for (i = 0; i < args_files_count; i++, verbose = 0)
      if ((r = print_checksum(args_files[i], &spec, squeezes, "", REPRESENTATION_UPPER_CASE, verbose, *argv)))
	break;
  
  args_dispose();
  cleanup();
  return r;
}


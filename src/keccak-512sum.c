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



int main(int argc, char* argv[])
{
  libkeccak_generalised_spec_t spec;
  libkeccak_generalised_spec_initialise(&spec);
  libkeccak_spec_keccak((libkeccak_spec_t*)&spec, 512);
  return RUN("Keccak", "keccak-512sum", LIBKECCAK_KECCAK_SUFFIX);
}


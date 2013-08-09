/**
 * sha3sum – SHA-3 (Keccak) checksum calculator
 * 
 * Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)
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
#include <stdlib.h>



/**
 * Initialise Keccak sponge
 * 
 * @param  bitrate   The bitrate
 * @param  capacity  The capacity
 * @param  output    The output size
 */
extern void initialise(long bitrate, long capacity, long output);


/**
 * Dispose of the Keccak sponge
 */
extern void dispose();


/**
 * Absorb the more of the message message to the Keccak sponge
 * 
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message
 */
extern void update(char* msg, long msglen);


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param   msg         The rest of the message, may be {@code null}
 * @param   msglen      The length of the partial message
 * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
 * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
 */
extern char* digest(char* msg, long msglen, long withReturn);


/**
 * Force some rounds of Keccak-f
 * 
 * @param  times  The number of rounds
 */
extern void simpleSqueeze(long times);


/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  times  The number of digests
 */
extern void fastSqueeze(long times);


/**
 * Squeeze out another digest
 * 
 * @return  The hash sum
 */
extern char* squeeze();


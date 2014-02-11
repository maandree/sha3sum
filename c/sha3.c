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
#include "sha3.h"


#ifdef WITH_C99
  #define static_inline static inline
#else
  #define static_inline inline
#endif

#define null 0
#define true 1
#define false 0



/**
 * Round contants
 */
#ifdef WITH_C99
static const llong RC[] = {
  0x0000000000000001LL, 0x0000000000008082LL, 0x800000000000808ALL, 0x8000000080008000LL,
  0x000000000000808BLL, 0x0000000080000001LL, 0x8000000080008081LL, 0x8000000000008009LL,
  0x000000000000008ALL, 0x0000000000000088LL, 0x0000000080008009LL, 0x000000008000000ALL,
  0x000000008000808BLL, 0x800000000000008BLL, 0x8000000000008089LL, 0x8000000000008003LL,
  0x8000000000008002LL, 0x8000000000000080LL, 0x000000000000800ALL, 0x800000008000000ALL,
  0x8000000080008081LL, 0x8000000000008080LL, 0x0000000080000001LL, 0x8000000080008008LL};
#else
static const llong RC[] = {
  0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
  0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
  0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
  0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
  0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
  0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
#endif

/**
 * Keccak-f round temporary
 */
static llong B[25];

/**
 * Keccak-f round temporary
 */
static llong C[5];


/**
 * The bitrate
 */
static long r = 0;

/**
 * The capacity
 */
static long c = 0;

/**
 * The output size
 */
static long n = 0;

/**
 * The state size
 */
static long b = 0;

/**
 * The word size
 */
static long w = 0;

/**
 * The word mask
 */
static llong wmod = 0;

/**
 * ℓ, the binary logarithm of the word size
 */
static long l = 0;

/**
 * 12 + 2ℓ, the number of rounds
 */
static long nr = 0;


/**
 * The current state
 */
static llong* S = null;

/**
 * Left over water to fill the sponge with at next update
 */
static byte* M = null;

/**
 * Pointer for {@link #M}
 */
static long mptr = 0;

/**
 * Size of {@link #M}
 */
static long mlen = 0;



/**
 * Gets the smallest, in value, of the arguments
 * 
 * @param   X  The first candidate
 * @param   Y  The second candidate
 * @return     The lowest candidate
 */
#define min(X, Y)  ((X) < (Y) ? (X) : (Y))



/**
 * Copy an array segment into an array in start to end order
 * 
 * @param  src     The source array
 * @param  soff    The source array offset
 * @param  dest    The destination array
 * @param  doff    The destination array offset
 * @param  length  The number of elements to copy
 */
static_inline void sha3_arraycopy(byte* src, long soff, byte* dest, long doff, long length)
{
  long i;
  src += soff;
  dest += doff;
  
  #define __(X)  dest[X] = src[X]
  #define __0  *dest = *src
  #define __1  __(0x01)
  #define __2  __(0x02); __(0x03)
  #define __3  __(0x04); __(0x05); __(0x06); __(0x07)
  #define __4  __(0x08); __(0x09); __(0x0A); __(0x0B); __(0x0C); __(0x0D); __(0x0E); __(0x0F)
  #define __5  __(0x10); __(0x11); __(0x12); __(0x13); __(0x14); __(0x15); __(0x16); __(0x17); __(0x18); __(0x19); __(0x1A); __(0x1B); __(0x1C); __(0x1D); __(0x1E); __(0x1F)
  #define __6  __(0x20); __(0x21); __(0x22); __(0x23); __(0x24); __(0x25); __(0x26); __(0x27); __(0x28); __(0x29); __(0x2A); __(0x2B); __(0x2C); __(0x2D); __(0x2E); __(0x2F); \
               __(0x30); __(0x31); __(0x32); __(0x33); __(0x34); __(0x35); __(0x36); __(0x37); __(0x38); __(0x39); __(0x3A); __(0x3B); __(0x3C); __(0x3D); __(0x3E); __(0x3F)
  #define __7  __(0x40); __(0x41); __(0x42); __(0x43); __(0x44); __(0x45); __(0x46); __(0x47); __(0x48); __(0x49); __(0x4A); __(0x4B); __(0x4C); __(0x4D); __(0x4E); __(0x4F); \
               __(0x50); __(0x51); __(0x52); __(0x53); __(0x54); __(0x55); __(0x56); __(0x57); __(0x58); __(0x59); __(0x5A); __(0x5B); __(0x5C); __(0x5D); __(0x5E); __(0x5F); \
               __(0x60); __(0x61); __(0x62); __(0x63); __(0x64); __(0x65); __(0x66); __(0x67); __(0x68); __(0x69); __(0x6A); __(0x6B); __(0x6C); __(0x6D); __(0x6E); __(0x6F); \
               __(0x70); __(0x71); __(0x72); __(0x73); __(0x74); __(0x75); __(0x76); __(0x77); __(0x78); __(0x79); __(0x7A); __(0x7B); __(0x7C); __(0x7D); __(0x7E); __(0x7F)
  #define __8  __(0x80); __(0x81); __(0x82); __(0x83); __(0x84); __(0x85); __(0x86); __(0x87); __(0x88); __(0x89); __(0x8A); __(0x8B); __(0x8C); __(0x8D); __(0x8E); __(0x8F); \
               __(0x90); __(0x91); __(0x92); __(0x93); __(0x94); __(0x95); __(0x96); __(0x97); __(0x98); __(0x99); __(0x9A); __(0x9B); __(0x9C); __(0x9D); __(0x9E); __(0x9F); \
               __(0xA0); __(0xA1); __(0xA2); __(0xA3); __(0xA4); __(0xA5); __(0xA6); __(0xA7); __(0xA8); __(0xA9); __(0xAA); __(0xAB); __(0xAC); __(0xAD); __(0xAE); __(0xAF); \
               __(0xB0); __(0xB1); __(0xB2); __(0xB3); __(0xB4); __(0xB5); __(0xB6); __(0xB7); __(0xB8); __(0xB9); __(0xBA); __(0xBB); __(0xBC); __(0xBD); __(0xBE); __(0xBF); \
               __(0xC0); __(0xC1); __(0xC2); __(0xC3); __(0xC4); __(0xC5); __(0xC6); __(0xC7); __(0xC8); __(0xC9); __(0xCA); __(0xCB); __(0xCC); __(0xCD); __(0xCE); __(0xCF); \
               __(0xD0); __(0xD1); __(0xD2); __(0xD3); __(0xD4); __(0xD5); __(0xD6); __(0xD7); __(0xD8); __(0xD9); __(0xDA); __(0xDB); __(0xDC); __(0xDD); __(0xDE); __(0xDF); \
               __(0xE0); __(0xE1); __(0xE2); __(0xE3); __(0xE4); __(0xE5); __(0xE6); __(0xE7); __(0xE8); __(0xE9); __(0xEA); __(0xEB); __(0xEC); __(0xED); __(0xEE); __(0xEF); \
               __(0xF0); __(0xF1); __(0xF2); __(0xF3); __(0xF4); __(0xF5); __(0xF6); __(0xF7); __(0xF8); __(0xF9); __(0xFA); __(0xFB); __(0xFC); __(0xFD); __(0xFE); __(0xFF)
  
  if ((length & 15))
    {
      if ((length &   1))  {  __0;   src += 1;  dest += 1;  }
      if ((length &   2))  {  __0;  __1;   src += 2;  dest += 2;  }
      if ((length &   4))  {  __0;  __1;  __2;   src += 4;  dest += 4;  }
      if ((length &   8))  {  __0;  __1;  __2;  __3;   src += 8;  dest += 8;  }
    }
  if ((length & 240))
    {
      if ((length &  16))  {  __0;  __1;  __2;  __3;  __4;   src += 16;  dest += 16;  }
      if ((length &  32))  {  __0;  __1;  __2;  __3;  __4;  __5;   src += 32;  dest += 32;  }
      if ((length &  64))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;   src += 64;  dest += 64;  }
      if ((length & 128))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;   src += 128;  dest += 128;  }
    }
  length &= ~255;
  for (i = 0; i < length; i += 256)
    {
      __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;  __8;   src += 256;  dest += 256;
    }
  
  #undef __8
  #undef __7
  #undef __6
  #undef __5
  #undef __4
  #undef __3
  #undef __2
  #undef __1
  #undef __0
  #undef __
}


/**
 * Copy an array segment into an array in end to start order
 * 
 * @param  src     The source array
 * @param  soff    The source array offset
 * @param  dest    The destination array
 * @param  doff    The destination array offset
 * @param  length  The number of elements to copy
 */
static_inline void sha3_revarraycopy(byte* src, long soff, byte* dest, long doff, long length)
{
  long copyi;
  for (copyi = length - 1; copyi >= 0; copyi--)
    dest[copyi + doff] = src[copyi + soff];
}


/**
 * Rotate a word
 * 
 * @param   X:llong  The value to rotate
 * @param   N:long   Rotation steps, may not be 0
 * @return   :llong  The value rotated
 */
#define rotate(X, N)  ((((X) >> (w - ((N) % w))) + ((X) << ((N) % w))) & wmod)


/**
 * Rotate a 64-bit word
 * 
 * @param   X:llong  The value to rotate
 * @param   N:long   Rotation steps, may not be 0
 * @return   :llong  The value rotated
 */
#define rotate64(X, N)  ((llong)((ullong)(X) >> (64 - (N))) + ((X) << (N)))


/**
 * Binary logarithm
 * 
 * @param   x  The value of which to calculate the binary logarithm
 * @return     The binary logarithm
 */
static_inline long sha3_lb(long x)
{
  long rc = 0;
  if ((x & 0xFF00) != 0)  { rc +=  8;  x >>=  8; }
  if ((x & 0x00F0) != 0)  { rc +=  4;  x >>=  4; }
  if ((x & 0x000C) != 0)  { rc +=  2;  x >>=  2; }
  if ((x & 0x0002) != 0)    rc +=  1;
  return rc;
}


/**
 * Perform one round of computation
 * 
 * @param  A   The current state
 * @param  rc  Round constant
 */
static void sha3_keccakFRound(llong* restrict A, llong rc)
{
  llong da, db, dc, dd, de;
  
  /* θ step (step 1 and 2 of 3) */
  #define __C(I, J0, J1, J2, J3, J4)  C[I] = (A[J0] ^ A[J1]) ^ (A[J2] ^ A[J3]) ^ A[J4]
  __C(0,   0,  1,  2,  3,  4);
  __C(1,   5,  6,  7,  8,  9);
  __C(2,  10, 11, 12, 13, 14);
  __C(3,  15, 16, 17, 18, 19);
  __C(4,  20, 21, 22, 23, 24);
  #undef __C
  
  da = C[4] ^ rotate64(C[1], 1);
  dd = C[2] ^ rotate64(C[4], 1);
  db = C[0] ^ rotate64(C[2], 1);
  de = C[3] ^ rotate64(C[0], 1);
  dc = C[1] ^ rotate64(C[3], 1);
  
  if (w == 64)
    {
      /* ρ and π steps, with last two part of θ */
      #define __B(Bi, Ai, Dv, R)  B[Bi] = rotate64(A[Ai] ^ Dv, R)
      B[0] = A[0] ^ da;     __B( 1, 15, dd, 28);  __B( 2,  5, db,  1);  __B( 3, 20, de, 27);  __B( 4, 10, dc, 62);
      __B( 5,  6, db, 44);  __B( 6, 21, de, 20);  __B( 7, 11, dc,  6);  __B( 8,  1, da, 36);  __B( 9, 16, dd, 55);
      __B(10, 12, dc, 43);  __B(11,  2, da,  3);  __B(12, 17, dd, 25);  __B(13,  7, db, 10);  __B(14, 22, de, 39);
      __B(15, 18, dd, 21);  __B(16,  8, db, 45);  __B(17, 23, de,  8);  __B(18, 13, dc, 15);  __B(19,  3, da, 41);
      __B(20, 24, de, 14);  __B(21, 14, dc, 61);  __B(22,  4, da, 18);  __B(23, 19, dd, 56);  __B(24,  9, db,  2);
      #undef __B
    }
  else
    {
      /* ρ and π steps, with last two part of θ */
      #define __B(Bi, Ai, Dv, R)  B[Bi] = rotate(A[Ai] ^ Dv, R)
      B[0] = A[0] ^ da;     __B( 1, 15, dd, 28);  __B( 2,  5, db,  1);  __B( 3, 20, de, 27);  __B( 4, 10, dc, 62);
      __B( 5,  6, db, 44);  __B( 6, 21, de, 20);  __B( 7, 11, dc,  6);  __B( 8,  1, da, 36);  __B( 9, 16, dd, 55);
      __B(10, 12, dc, 43);  __B(11,  2, da,  3);  __B(12, 17, dd, 25);  __B(13,  7, db, 10);  __B(14, 22, de, 39);
      __B(15, 18, dd, 21);  __B(16,  8, db, 45);  __B(17, 23, de,  8);  __B(18, 13, dc, 15);  __B(19,  3, da, 41);
      __B(20, 24, de, 14);  __B(21, 14, dc, 61);  __B(22,  4, da, 18);  __B(23, 19, dd, 56);  __B(24,  9, db,  2);
      #undef __B
    }
  
  /* ξ step */
  #define __A(X, X5, X10)  A[X] = B[X] ^ ((~(B[X5])) & B[X10])
  __A( 0,  5, 10);  __A( 1,  6, 11);  __A( 2,  7, 12);  __A( 3,  8, 13);  __A( 4,  9, 14);
  __A( 5, 10, 15);  __A( 6, 11, 16);  __A( 7, 12, 17);  __A( 8, 13, 18);  __A( 9, 14, 19);
  __A(10, 15, 20);  __A(11, 16, 21);  __A(12, 17, 22);  __A(13, 18, 23);  __A(14, 19, 24);
  __A(15, 20,  0);  __A(16, 21,  1);  __A(17, 22,  2);  __A(18, 23,  3);  __A(19, 24,  4);
  __A(20,  0,  5);  __A(21,  1,  6);  __A(22,  2,  7);  __A(23,  3,  8);  __A(24,  4,  9);
  #undef __A
  
  /* ι step */
  A[0] ^= rc;
}


/**
 * Perform Keccak-f function
 * 
 * @param  A  The current state
 */
static void sha3_keccakF(llong* restrict A)
{
  long i;
  if (nr == 24)
    {
      sha3_keccakFRound(A, 0x0000000000000001);
      sha3_keccakFRound(A, 0x0000000000008082);
      sha3_keccakFRound(A, 0x800000000000808A);
      sha3_keccakFRound(A, 0x8000000080008000);
      sha3_keccakFRound(A, 0x000000000000808B);
      sha3_keccakFRound(A, 0x0000000080000001);
      sha3_keccakFRound(A, 0x8000000080008081);
      sha3_keccakFRound(A, 0x8000000000008009);
      sha3_keccakFRound(A, 0x000000000000008A);
      sha3_keccakFRound(A, 0x0000000000000088);
      sha3_keccakFRound(A, 0x0000000080008009);
      sha3_keccakFRound(A, 0x000000008000000A);
      sha3_keccakFRound(A, 0x000000008000808B);
      sha3_keccakFRound(A, 0x800000000000008B);
      sha3_keccakFRound(A, 0x8000000000008089);
      sha3_keccakFRound(A, 0x8000000000008003);
      sha3_keccakFRound(A, 0x8000000000008002);
      sha3_keccakFRound(A, 0x8000000000000080);
      sha3_keccakFRound(A, 0x000000000000800A);
      sha3_keccakFRound(A, 0x800000008000000A);
      sha3_keccakFRound(A, 0x8000000080008081);
      sha3_keccakFRound(A, 0x8000000000008080);
      sha3_keccakFRound(A, 0x0000000080000001);
      sha3_keccakFRound(A, 0x8000000080008008);
    }
  else
    for (i = 0; i < nr; i++)
      sha3_keccakFRound(A, RC[i] & wmod);
}


/**
 * Convert a chunk of byte:s to a word
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   ww       Word size in bytes
 * @param   off      The offset in the message
 * @return           Lane
 */
static_inline llong sha3_toLane(byte* restrict message, long msglen, long rr, long ww, long off)
{
  llong rc = 0;
  long n = min(msglen, rr), i;
  for (i = off + ww - 1; i >= off; i--)
    rc = (rc << 8) | ((i < n) ? (llong)(message[i] & 255) : 0L);
  return rc;
}


/**
 * Convert a chunk of byte:s to a 64-bit word
 * 
 * @param   message  The message
 * @param   msglen   The length of the message
 * @param   rr       Bitrate in bytes
 * @param   off      The offset in the message
 * @return           Lane
 */
static_inline llong sha3_toLane64(byte* restrict message, long msglen, long rr, long off)
{
  long n = min(msglen, rr);
  return ((off + 7 < n) ? ((llong)(message[off + 7] & 255) << 56) : 0L) |
         ((off + 6 < n) ? ((llong)(message[off + 6] & 255) << 48) : 0L) |
         ((off + 5 < n) ? ((llong)(message[off + 5] & 255) << 40) : 0L) |
         ((off + 4 < n) ? ((llong)(message[off + 4] & 255) << 32) : 0L) |
         ((off + 3 < n) ? ((llong)(message[off + 3] & 255) << 24) : 0L) |
         ((off + 2 < n) ? ((llong)(message[off + 2] & 255) << 16) : 0L) |
         ((off + 1 < n) ? ((llong)(message[off + 1] & 255) <<  8) : 0L) |
         ((off     < n) ? ((llong)(message[off    ] & 255)      ) : 0L);
}


/**
 * pad 10*1
 * 
 * @param   msg     The message to pad
 * @param   len     The length of the message
 * @param   r       The bitrate
 * @param   outlen  The length of the padded message (out parameter)
 * @return          The message padded
 */
static_inline byte* sha3_pad10star1(byte* restrict msg, long len, long r, long* restrict outlen)
{
  byte* message;
  
  long nrf = (len <<= 3) >> 3;
  long nbrf = len & 7;
  long ll = len % r;
  long i;
  
  byte b = (byte)(nbrf == 0 ? 1 : ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf)));
  
  if ((r - 8 <= ll) && (ll <= r - 2))
    {
      message = (byte*)malloc((len = nrf + 1) * sizeof(byte));
      message[nrf] = (byte)(b ^ 128);
    }
  else
    {
      byte* M;
      long N;
      len = (nrf + 1) << 3;
      len = ((len - (len % r) + (r - 8)) >> 3) + 1;
      message = (byte*)malloc(len * sizeof(byte));
      message[nrf] = b;
      N = len - nrf - 1;
      M = message + nrf + 1;
      
      #define __(X)  M[X] = 0
      #define __0  *M = 0
      #define __1  __(0x01)
      #define __2  __(0x02); __(0x03)
      #define __3  __(0x04); __(0x05); __(0x06); __(0x07)
      #define __4  __(0x08); __(0x09); __(0x0A); __(0x0B); __(0x0C); __(0x0D); __(0x0E); __(0x0F)
      #define __5  __(0x10); __(0x11); __(0x12); __(0x13); __(0x14); __(0x15); __(0x16); __(0x17); __(0x18); __(0x19); __(0x1A); __(0x1B); __(0x1C); __(0x1D); __(0x1E); __(0x1F)
      #define __6  __(0x20); __(0x21); __(0x22); __(0x23); __(0x24); __(0x25); __(0x26); __(0x27); __(0x28); __(0x29); __(0x2A); __(0x2B); __(0x2C); __(0x2D); __(0x2E); __(0x2F); \
                   __(0x30); __(0x31); __(0x32); __(0x33); __(0x34); __(0x35); __(0x36); __(0x37); __(0x38); __(0x39); __(0x3A); __(0x3B); __(0x3C); __(0x3D); __(0x3E); __(0x3F)
      #define __7  __(0x40); __(0x41); __(0x42); __(0x43); __(0x44); __(0x45); __(0x46); __(0x47); __(0x48); __(0x49); __(0x4A); __(0x4B); __(0x4C); __(0x4D); __(0x4E); __(0x4F); \
                   __(0x50); __(0x51); __(0x52); __(0x53); __(0x54); __(0x55); __(0x56); __(0x57); __(0x58); __(0x59); __(0x5A); __(0x5B); __(0x5C); __(0x5D); __(0x5E); __(0x5F); \
                   __(0x60); __(0x61); __(0x62); __(0x63); __(0x64); __(0x65); __(0x66); __(0x67); __(0x68); __(0x69); __(0x6A); __(0x6B); __(0x6C); __(0x6D); __(0x6E); __(0x6F); \
                   __(0x70); __(0x71); __(0x72); __(0x73); __(0x74); __(0x75); __(0x76); __(0x77); __(0x78); __(0x79); __(0x7A); __(0x7B); __(0x7C); __(0x7D); __(0x7E); __(0x7F)
      #define __8  __(0x80); __(0x81); __(0x82); __(0x83); __(0x84); __(0x85); __(0x86); __(0x87); __(0x88); __(0x89); __(0x8A); __(0x8B); __(0x8C); __(0x8D); __(0x8E); __(0x8F); \
                   __(0x90); __(0x91); __(0x92); __(0x93); __(0x94); __(0x95); __(0x96); __(0x97); __(0x98); __(0x99); __(0x9A); __(0x9B); __(0x9C); __(0x9D); __(0x9E); __(0x9F); \
                   __(0xA0); __(0xA1); __(0xA2); __(0xA3); __(0xA4); __(0xA5); __(0xA6); __(0xA7); __(0xA8); __(0xA9); __(0xAA); __(0xAB); __(0xAC); __(0xAD); __(0xAE); __(0xAF); \
                   __(0xB0); __(0xB1); __(0xB2); __(0xB3); __(0xB4); __(0xB5); __(0xB6); __(0xB7); __(0xB8); __(0xB9); __(0xBA); __(0xBB); __(0xBC); __(0xBD); __(0xBE); __(0xBF); \
                   __(0xC0); __(0xC1); __(0xC2); __(0xC3); __(0xC4); __(0xC5); __(0xC6); __(0xC7); __(0xC8); __(0xC9); __(0xCA); __(0xCB); __(0xCC); __(0xCD); __(0xCE); __(0xCF); \
                   __(0xD0); __(0xD1); __(0xD2); __(0xD3); __(0xD4); __(0xD5); __(0xD6); __(0xD7); __(0xD8); __(0xD9); __(0xDA); __(0xDB); __(0xDC); __(0xDD); __(0xDE); __(0xDF); \
                   __(0xE0); __(0xE1); __(0xE2); __(0xE3); __(0xE4); __(0xE5); __(0xE6); __(0xE7); __(0xE8); __(0xE9); __(0xEA); __(0xEB); __(0xEC); __(0xED); __(0xEE); __(0xEF); \
                   __(0xF0); __(0xF1); __(0xF2); __(0xF3); __(0xF4); __(0xF5); __(0xF6); __(0xF7); __(0xF8); __(0xF9); __(0xFA); __(0xFB); __(0xFC); __(0xFD); __(0xFE); __(0xFF)
      
      if ((N & 15))
	{
	  if ((N &   1))  {  __0;   M += 1;  }
	  if ((N &   2))  {  __0;  __1;   M += 2;  }
	  if ((N &   4))  {  __0;  __1;  __2;   M += 4;  }
	  if ((N &   8))  {  __0;  __1;  __2;  __3;   M += 8;  }
	}
      if ((N & 240))
	{
	  if ((N &  16))  {  __0;  __1;  __2;  __3;  __4;   M += 16;  }
	  if ((N &  32))  {  __0;  __1;  __2;  __3;  __4;  __5;   M += 32;  }
	  if ((N &  64))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;   M += 64;  }
	  if ((N & 128))  {  __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;   M += 128;  }
	}
      N &= ~255;
      for (i = 0; i < N; i += 256)
	{
	  __0;  __1;  __2;  __3;  __4;  __5;  __6;  __7;  __8;   M += 256;
	}
      
      #undef __8
      #undef __7
      #undef __6
      #undef __5
      #undef __4
      #undef __3
      #undef __2
      #undef __1
      #undef __0
      #undef __
      
      message[len - 1] = -128;
    }
  sha3_arraycopy(msg, 0, message, 0, nrf);
  
  *outlen = len;
  return message;
}


/**
 * Initialise Keccak sponge
 * 
 * @param  bitrate   The bitrate
 * @param  capacity  The capacity
 * @param  output    The output size
 */
extern void sha3_initialise(long bitrate, long capacity, long output)
{
  long i;
  
  r = bitrate;
  n = output;
  c = capacity;
  b = r + c;
  w = b / 25;
  l = sha3_lb(w);
  nr = 12 + (l << 1);
  if (w == 64)
    wmod = -1;
  else
    {
      wmod = 1;
      wmod <<= w;
      wmod--;
    }
  S = (llong*)malloc(25 * sizeof(llong));
  M = (byte*)malloc((mlen = (r * b) >> 2) * sizeof(byte));
  mptr = 0;
  
  for (i = 0; i < 25; i++)
    *(S + i) = 0;
}

/**
 * Dispose of the Keccak sponge
 */
extern void sha3_dispose()
{
  if (S != null)
    {
      free(S);
      S = null;
    }
  if (M != null)
    {
      free(M);
      M = null;
    }
}

/**
 * Absorb the more of the message message to the Keccak sponge
 * 
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message
 */
extern void sha3_update(byte* restrict msg, long msglen)
{
  long rr = r >> 3;
  long ww = w >> 3;
  long i, len;
  byte* message;
  byte* _msg;
  long nnn;
  
  if (mptr + msglen > mlen)
    M = (byte*)realloc(M, mlen = (mlen + msglen) << 1);
  sha3_arraycopy(msg, 0, M, mptr, msglen);
  len = mptr += msglen;
  len -= len % ((r * b) >> 3);
  message = (byte*)malloc(len * sizeof(byte));
  sha3_arraycopy(M, 0, message, 0, len);
  mptr -= len;
  sha3_revarraycopy(M, nnn = len, M, 0, mptr);
  _msg = message;
  
  /* Absorbing phase */
  if (ww == 8)
    for (i = 0; i < nnn; i += rr)
      {
	#define __S(Si, OFF)  S[Si] ^= sha3_toLane64(message, len, rr, OFF)
	__S( 0,   0);  __S( 5,   8);  __S(10,  16);  __S(15,  24);  __S(20,  32);
	__S( 1,  40);  __S( 6,  48);  __S(11,  56);  __S(16,  64);  __S(21,  72);
	__S( 2,  80);  __S( 7,  88);  __S(12,  96);  __S(17, 104);  __S(22, 112);
	__S( 3, 120);  __S( 8, 128);  __S(13, 136);  __S(18, 144);  __S(23, 152);
	__S( 4, 160);  __S( 9, 168);  __S(14, 176);  __S(19, 184);  __S(24, 192);
        #undef __S
	sha3_keccakF(S);
	message += rr;
	len -= rr;
      }
  else
    for (i = 0; i < nnn; i += rr)
      {
	#define __S(Si, OFF)  S[Si] ^= sha3_toLane(message, len, rr, ww, OFF * w)
	__S( 0,  0);  __S( 5,  1);  __S(10,  2);  __S(15,  3);  __S(20,  4);
	__S( 1,  5);  __S( 6,  6);  __S(11,  7);  __S(16,  8);  __S(21,  9);
	__S( 2, 10);  __S( 7, 11);  __S(12, 12);  __S(17, 13);  __S(22, 14);
	__S( 3, 15);  __S( 8, 16);  __S(13, 17);  __S(18, 18);  __S(23, 19);
	__S( 4, 20);  __S( 9, 21);  __S(14, 22);  __S(19, 23);  __S(24, 24);
        #undef __S
	sha3_keccakF(S);
	message += rr;
	len -= rr;
      }
  
  free(_msg);
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param   msg         The rest of the message, may be {@code null}
 * @param   msglen      The length of the partial message
 * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
 * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
 */
extern byte* sha3_digest(byte* restrict msg, long msglen, boolean withReturn)
{
  byte* message;
  byte* _msg;
  byte* rc;
  long rr = r >> 3, len;
  long nn = (n + 7) >> 3, olen;
  long ww = w >> 3, ni;
  long i, j = 0, ptr = 0, _;
  long nnn;
  
  if ((msg == null) || (msglen == 0))
    message = sha3_pad10star1(M, mptr, r, &len);
  else
    {
      if (mptr + msglen > mlen)
	M = (byte*)realloc(M, mlen += msglen);
      sha3_arraycopy(msg, 0, M, mptr, msglen);
      message = sha3_pad10star1(M, mptr + msglen, r, &len);
    }
  free(M);
  M = null;
  rc = (byte*)malloc(((n + 7) >> 3) * sizeof(byte));
  _msg = message;
  nnn = len;
  
  /* Absorbing phase */
  if (ww == 8)
    for (i = 0; i < nnn; i += rr)
      {
	#define __S(Si, OFF)  S[Si] ^= sha3_toLane64(message, len, rr, OFF)
	__S( 0,   0);  __S( 5,   8);  __S(10,  16);  __S(15,  24);  __S(20,  32);
	__S( 1,  40);  __S( 6,  48);  __S(11,  56);  __S(16,  64);  __S(21,  72);
	__S( 2,  80);  __S( 7,  88);  __S(12,  96);  __S(17, 104);  __S(22, 112);
	__S( 3, 120);  __S( 8, 128);  __S(13, 136);  __S(18, 144);  __S(23, 152);
	__S( 4, 160);  __S( 9, 168);  __S(14, 176);  __S(19, 184);  __S(24, 192);
        #undef __S
	sha3_keccakF(S);
	message += rr;
	len -= rr;
      }
  else
    for (i = 0; i < nnn; i += rr)
      {
	#define __S(Si, OFF)  S[Si] ^= sha3_toLane(message, len, rr, ww, OFF * w)
	__S( 0,  0);  __S( 5,  1);  __S(10,  2);  __S(15,  3);  __S(20,  4);
	__S( 1,  5);  __S( 6,  6);  __S(11,  7);  __S(16,  8);  __S(21,  9);
	__S( 2, 10);  __S( 7, 11);  __S(12, 12);  __S(17, 13);  __S(22, 14);
	__S( 3, 15);  __S( 8, 16);  __S(13, 17);  __S(18, 18);  __S(23, 19);
	__S( 4, 20);  __S( 9, 21);  __S(14, 22);  __S(19, 23);  __S(24, 24);
        #undef __S
	sha3_keccakF(S);
	message += rr;
	len -= rr;
      }
  
  free(_msg);
  
  /* Squeezing phase */
  olen = n;
  if (withReturn)
    {
      ni = min(25, rr);
      while (olen > 0)
	{
	  i = 0;
	  while ((i < ni) && (j < nn))
	    {
	      llong v = S[(i % 5) * 5 + i / 5];
	      for (_ = 0; _ < ww; _++)
		{
		  if (j < nn)
		    rc[ptr++] = (byte)v;
		  v >>= 8;
		  j += 1;
		}
	      i += 1;
	    }
	  olen -= r;
	  if (olen > 0)
	    sha3_keccakF(S);
	}
      if ((n & 7))
	rc[n >> 3] &= (1 << (n & 7)) - 1;
      
      return rc;
    }
  while ((olen -= r) > 0)
    sha3_keccakF(S);
  return null;
}


/**
 * Force some rounds of Keccak-f
 * 
 * @param  times  The number of rounds
 */
extern void sha3_simpleSqueeze(long times)
{
  long i;
  for (i = 0; i < times; i++)
    sha3_keccakF(S);
}


/**
 * Squeeze as much as is needed to get a digest a number of times
 * 
 * @param  times  The number of digests
 */
extern void sha3_fastSqueeze(long times)
{
  long i, olen;
  for (i = 0; i < times; i++)
    {
      sha3_keccakF(S); /* Last squeeze did not do a ending squeeze */
      olen = n;
      while ((olen -= r) > 0)
	sha3_keccakF(S);
    }
}


/**
 * Squeeze out another digest
 * 
 * @return  The hash sum
 */
extern byte* sha3_squeeze(void)
{
  long nn, ww, olen, i, j, ptr, ni;
  byte* rc;
  
  sha3_keccakF(S); /* Last squeeze did not do a ending squeeze */
  
  ww = w >> 3;
  rc = (byte*)malloc((nn = (n + 7) >> 3) * sizeof(byte));
  olen = n;
  j = ptr = 0;
  ni = (25 < r >> 3) ? 25 : (r >> 3);
  
  while (olen > 0)
    {
      i = 0;
      while ((i < ni) && (j < nn))
	{
	  long _, v = S[(i % 5) * 5 + i / 5];
	  for (_ = 0; _ < ww; _++)
	    {
	      if (j < nn)
		*(rc + ptr++) = (byte)v;
	      v >>= 8;
	      j += 1;
	    }
	  i += 1;
	}
      olen -= r;
      if (olen > 0)
	sha3_keccakF(S);
    }
  if (n & 7)
    rc[nn - 1] &= (1 << (n & 7)) - 1;
  
  return rc;
}


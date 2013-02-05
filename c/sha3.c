/**
 * sha3sum – SHA-3 (Keccak) checksum calculator
 * 
 * Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if __x86_64__ || __ppc64__
    #define llong long int
#else
    #define llong long long int
#endif


#define null    0
#define byte    char
#define boolean long
#define true    1
#define false   0


/**
 * Round contants
 */
static const llong RC[] = {
	    0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
	    0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
	    0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
	    0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
	    0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
	    0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};

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
 * Polonger for {@link #M}
 */
static long mptr = 0;



/**
 * Rotate a word
 * 
 * @param   x  The value to rotate
 * @param   n  Rotation steps, may not be 0
 * @return     The value rotated
 */
static llong rotate(llong x, long n)
{
  llong m;
  return ((x >> (w - (m = n % w))) + (x << m)) & wmod;
}


/**
 * Rotate a 64-bit word
 * 
 * @param   x  The value to rotate
 * @param   n  Rotation steps, may not be 0
 * @return     The value rotated
 */
static llong rotate64(llong x, long n)
{
  return (llong)((unsigned llong)x >> (w - n)) + (x << n);
}


/**
 * Binary logarithm
 * 
 * @param   x  The value of which to calculate the binary logarithm
 * @return     The binary logarithm
 */
static long lb(long x)
{
  return (((x & 0xFF00) == 0 ? 0 : 8) +
          ((x & 0xF0F0) == 0 ? 0 : 4)) +
         (((x & 0xCCCC) == 0 ? 0 : 2) +
	  ((x & 0xAAAA) == 0 ? 0 : 1));
}


/**
 * Perform one round of computation
 * 
 * @param  A   The current state
 * @param  rc  Round constant
 */
static void keccakFRound(llong* A, llong rc)
{
  /* θ step (step 1 of 3) */
  for (long i = 0, j = 0; i < 5; i++, j += 5)
    SHA3.C[i] = (A[j] ^ A[j + 1]) ^ (A[j + 2] ^ A[j + 3]) ^ A[j + 4];
  
  llong da, db, dc, dd, de;
  
  if (SHA3.w == 64)
    {
      /* ρ and π steps, with last two part of θ */
      SHA3.B[0] =               A[ 0] ^ (da = SHA3.C[4] ^ SHA3.rotate64(SHA3.C[1], 1));
      SHA3.B[1] = SHA3.rotate64(A[15] ^ (dd = SHA3.C[2] ^ SHA3.rotate64(SHA3.C[4], 1)), 28);
      SHA3.B[2] = SHA3.rotate64(A[ 5] ^ (db = SHA3.C[0] ^ SHA3.rotate64(SHA3.C[2], 1)),  1);
      SHA3.B[3] = SHA3.rotate64(A[20] ^ (de = SHA3.C[3] ^ SHA3.rotate64(SHA3.C[0], 1)), 27);
      SHA3.B[4] = SHA3.rotate64(A[10] ^ (dc = SHA3.C[1] ^ SHA3.rotate64(SHA3.C[3], 1)), 62);
      
      SHA3.B[5] = SHA3.rotate64(A[ 6] ^ db, 44);
      SHA3.B[6] = SHA3.rotate64(A[21] ^ de, 20);
      SHA3.B[7] = SHA3.rotate64(A[11] ^ dc,  6);
      SHA3.B[8] = SHA3.rotate64(A[ 1] ^ da, 36);
      SHA3.B[9] = SHA3.rotate64(A[16] ^ dd, 55);
      
      SHA3.B[10] = SHA3.rotate64(A[12] ^ dc, 43);
      SHA3.B[11] = SHA3.rotate64(A[ 2] ^ da,  3);
      SHA3.B[12] = SHA3.rotate64(A[17] ^ dd, 25);
      SHA3.B[13] = SHA3.rotate64(A[ 7] ^ db, 10);
      SHA3.B[14] = SHA3.rotate64(A[22] ^ de, 39);
      
      SHA3.B[15] = SHA3.rotate64(A[18] ^ dd, 21);
      SHA3.B[16] = SHA3.rotate64(A[ 8] ^ db, 45);
      SHA3.B[17] = SHA3.rotate64(A[23] ^ de,  8);
      SHA3.B[18] = SHA3.rotate64(A[13] ^ dc, 15);
      SHA3.B[19] = SHA3.rotate64(A[ 3] ^ da, 41);
      
      SHA3.B[20] = SHA3.rotate64(A[24] ^ de, 14);
      SHA3.B[21] = SHA3.rotate64(A[14] ^ dc, 61);
      SHA3.B[22] = SHA3.rotate64(A[ 4] ^ da, 18);
      SHA3.B[23] = SHA3.rotate64(A[19] ^ dd, 56);
      SHA3.B[24] = SHA3.rotate64(A[ 9] ^ db,  2);
    }
  else
    {
      /* ρ and π steps, with last two part of θ */
      SHA3.B[0] =             A[ 0] ^ (da = SHA3.C[4] ^ SHA3.rotate(SHA3.C[1], 1));
      SHA3.B[1] = SHA3.rotate(A[15] ^ (dd = SHA3.C[2] ^ SHA3.rotate(SHA3.C[4], 1)), 28);
      SHA3.B[2] = SHA3.rotate(A[ 5] ^ (db = SHA3.C[0] ^ SHA3.rotate(SHA3.C[2], 1)),  1);
      SHA3.B[3] = SHA3.rotate(A[20] ^ (de = SHA3.C[3] ^ SHA3.rotate(SHA3.C[0], 1)), 27);
      SHA3.B[4] = SHA3.rotate(A[10] ^ (dc = SHA3.C[1] ^ SHA3.rotate(SHA3.C[3], 1)), 62);
      
      SHA3.B[5] = SHA3.rotate(A[ 6] ^ db, 44);
      SHA3.B[6] = SHA3.rotate(A[21] ^ de, 20);
      SHA3.B[7] = SHA3.rotate(A[11] ^ dc,  6);
      SHA3.B[8] = SHA3.rotate(A[ 1] ^ da, 36);
      SHA3.B[9] = SHA3.rotate(A[16] ^ dd, 55);
      
      SHA3.B[10] = SHA3.rotate(A[12] ^ dc, 43);
      SHA3.B[11] = SHA3.rotate(A[ 2] ^ da,  3);
      SHA3.B[12] = SHA3.rotate(A[17] ^ dd, 25);
      SHA3.B[13] = SHA3.rotate(A[ 7] ^ db, 10);
      SHA3.B[14] = SHA3.rotate(A[22] ^ de, 39);
      
      SHA3.B[15] = SHA3.rotate(A[18] ^ dd, 21);
      SHA3.B[16] = SHA3.rotate(A[ 8] ^ db, 45);
      SHA3.B[17] = SHA3.rotate(A[23] ^ de,  8);
      SHA3.B[18] = SHA3.rotate(A[13] ^ dc, 15);
      SHA3.B[19] = SHA3.rotate(A[ 3] ^ da, 41);
      
      SHA3.B[20] = SHA3.rotate(A[24] ^ de, 14);
      SHA3.B[21] = SHA3.rotate(A[14] ^ dc, 61);
      SHA3.B[22] = SHA3.rotate(A[ 4] ^ da, 18);
      SHA3.B[23] = SHA3.rotate(A[19] ^ dd, 56);
      SHA3.B[24] = SHA3.rotate(A[ 9] ^ db,  2);
    }
  
  /* ξ step */
  for (long i = 0; i < 15; i++)
    A[i     ] = SHA3.B[i     ] ^ ((~(SHA3.B[i +  5])) & SHA3.B[i + 10]);
  for (long i = 0; i < 5; i++)
    {
      A[i + 15] = SHA3.B[i + 15] ^ ((~(SHA3.B[i + 20])) & SHA3.B[i     ]);
      A[i + 20] = SHA3.B[i + 20] ^ ((~(SHA3.B[i     ])) & SHA3.B[i +  5]);
    }
  
  /* ι step */
  A[0] ^= rc;
}


/**
 * Perform Keccak-f function
 * 
 * @param  A  The current state
 */
static void keccakF(llong* A)
{
  if (SHA3.nr == 24)
    for (long i = 0; i < SHA3.nr; i++)
      SHA3.keccakFRound(A, SHA3.RC[i]);
  else
    for (long i = 0; i < SHA3.nr; i++)
      SHA3.keccakFRound(A, SHA3.RC[i] & SHA3.wmod);
}


/**
 * Convert a chunk of byte:s to a word
 * 
 * @param   message  The message
 * @param   rr       Bitrate in bytes
 * @param   ww       Word size in bytes
 * @param   off      The offset in the message
 * @return           Lane
 */
static llong toLane(byte* message, long rr, long ww, long off)
{
  llong rc = 0;
  long n = Math.min(message.length, rr);
  for (long i = off + ww - 1; i >= off; i--)
    rc = (rc << 8) | ((i < n) ? (llong)(message[i] & 255) : 0L);
  return rc;
}


/**
 * Convert a chunk of byte:s to a 64-bit word
 * 
 * @param   message  The message
 * @param   rr       Bitrate in bytes
 * @param   off      The offset in the message
 * @return           Lane
 */
static llong toLane64(byte* message, long rr, long off)
{
  long n = Math.min(message.length, rr);
  return ((off + 7 < n) ? ((llong)(message[off + 7] & 255) << 56) : 0L) |
         ((off + 6 < n) ? ((llong)(message[off + 6] & 255) << 48) : 0L) |
         ((off + 5 < n) ? ((llong)(message[off + 5] & 255) << 40) : 0L) |
         ((off + 4 < n) ? ((llong)(message[off + 4] & 255) << 32) : 0L) |
         ((off + 3 < n) ? ((llong)(message[off + 3] & 255) << 24) : 0L) |
         ((off + 2 < n) ? ((llong)(message[off + 2] & 255) << 16) : 0L) |
         ((off + 1 < n) ? ((llong)(message[off + 1] & 255) <<  8) : 0L) |
         ((off < n) ? ((llong)(message[off] & 255)) : 0L);
}


/**
 * pad 10*1
 * 
 * @param   msg  The message to pad
 * @parm    len  The length of the message
 * @param   r    The bitrate
 * @return       The message padded
 */
static byte* pad10star1(byte* msg, long len, long r)
{
  long nrf = len >> 3;
  long nbrf = len & 7;
  long ll = len % r;
  
  byte b = (byte)(nbrf == 0 ? 1 : ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf)));
  
  byte* message;
  if ((r - 8 <= ll) && (ll <= r - 2))
    {
      message = new byte[len = nrf + 1];
      message[nrf] = (byte)(b ^ 128);
    }
  else
    {
      len = (nrf + 1) << 3;
      len = ((len - (len % r) + (r - 8)) >> 3) + 1;
      message = new byte[len];
      message[nrf] = b;
      //for (llong i = nrf + 1; i < len; i++)
      //    message[i + nrf] = 0;
      message[len - 1] = -128;
    }
  System.arraycopy(msg, 0, message, 0, nrf);
  
  return message;
}


/**
 * Initialise Keccak sponge
 * 
 * @param  r  The bitrate
 * @param  c  The capacity
 * @param  n  The output size
 */
extern void initialise(long r, long c, long n)
{
  SHA3.r = r;
  SHA3.c = c;
  SHA3.n = n;
  SHA3.b = r + c;
  SHA3.w = SHA3.b / 25;
  SHA3.l = SHA3.lb(SHA3.w);
  SHA3.nr = 12 + (SHA3.l << 1);
  SHA3.wmod = (1L << SHA3.w) - 1L;
  SHA3.S = new llong[25];
  SHA3.M = new byte[(SHA3.r * SHA3.b) >> 2];
  SHA3.mptr = 0;
}


/**
 * Absorb the more of the message message to the Keccak sponge
 * 
 * @param  msg  The partial message
 */
extern void update(byte* msg)
{
  update(msg, msg.length);
}


/**
 * Absorb the more of the message message to the Keccak sponge
 * 
 * @param  msg     The partial message
 * @param  msglen  The length of the partial message
 */
extern void update(byte* msg, long msglen)
{
  long rr = SHA3.r >> 3;
  long ww = SHA3.w >> 3;
  
  if (SHA3.mptr + msglen > SHA3.M.length)
    System.arraycopy(SHA3.M, 0, SHA3.M = new byte[(SHA3.M.length + msglen) << 1], 0, SHA3.mptr);
  System.arraycopy(msg, 0, SHA3.M, SHA3.mptr, msglen);
  long len = SHA3.mptr += msglen;
  len -= len % ((SHA3.r * SHA3.b) >> 3);
  byte* message;
  System.arraycopy(SHA3.M, 0, message = new byte[len], 0, len);
  System.arraycopy(SHA3.M, len, SHA3.M, 0, SHA3.mptr -= len);
  
  /* Absorbing phase */
  if (ww == 8)
    for (long i = 0; i < len; i += rr)
      {
	SHA3.S[ 0] ^= SHA3.toLane64(message, rr, i + 0);
	SHA3.S[ 5] ^= SHA3.toLane64(message, rr, i + 8);
	SHA3.S[10] ^= SHA3.toLane64(message, rr, i + 16);
	SHA3.S[15] ^= SHA3.toLane64(message, rr, i + 24);
	SHA3.S[20] ^= SHA3.toLane64(message, rr, i + 32);
	SHA3.S[ 1] ^= SHA3.toLane64(message, rr, i + 40);
	SHA3.S[ 6] ^= SHA3.toLane64(message, rr, i + 48);
	SHA3.S[11] ^= SHA3.toLane64(message, rr, i + 56);
	SHA3.S[16] ^= SHA3.toLane64(message, rr, i + 64);
	SHA3.S[21] ^= SHA3.toLane64(message, rr, i + 72);
	SHA3.S[ 2] ^= SHA3.toLane64(message, rr, i + 80);
	SHA3.S[ 7] ^= SHA3.toLane64(message, rr, i + 88);
	SHA3.S[12] ^= SHA3.toLane64(message, rr, i + 96);
	SHA3.S[17] ^= SHA3.toLane64(message, rr, i + 104);
	SHA3.S[22] ^= SHA3.toLane64(message, rr, i + 112);
	SHA3.S[ 3] ^= SHA3.toLane64(message, rr, i + 120);
	SHA3.S[ 8] ^= SHA3.toLane64(message, rr, i + 128);
	SHA3.S[13] ^= SHA3.toLane64(message, rr, i + 136);
	SHA3.S[18] ^= SHA3.toLane64(message, rr, i + 144);
	SHA3.S[23] ^= SHA3.toLane64(message, rr, i + 152);
	SHA3.S[ 4] ^= SHA3.toLane64(message, rr, i + 160);
	SHA3.S[ 9] ^= SHA3.toLane64(message, rr, i + 168);
	SHA3.S[14] ^= SHA3.toLane64(message, rr, i + 176);
	SHA3.S[19] ^= SHA3.toLane64(message, rr, i + 184);
	SHA3.S[24] ^= SHA3.toLane64(message, rr, i + 192);
	SHA3.keccakF(SHA3.S);
      }
  else
    for (long i = 0; i < len; i += rr)
      {
	SHA3.S[ 0] ^= SHA3.toLane(message, rr, ww, i +  0    );
	SHA3.S[ 5] ^= SHA3.toLane(message, rr, ww, i +      w);
	SHA3.S[10] ^= SHA3.toLane(message, rr, ww, i +  2 * w);
	SHA3.S[15] ^= SHA3.toLane(message, rr, ww, i +  3 * w);
	SHA3.S[20] ^= SHA3.toLane(message, rr, ww, i +  4 * w);
	SHA3.S[ 1] ^= SHA3.toLane(message, rr, ww, i +  5 * w);
	SHA3.S[ 6] ^= SHA3.toLane(message, rr, ww, i +  6 * w);
	SHA3.S[11] ^= SHA3.toLane(message, rr, ww, i +  7 * w);
	SHA3.S[16] ^= SHA3.toLane(message, rr, ww, i +  8 * w);
	SHA3.S[21] ^= SHA3.toLane(message, rr, ww, i +  9 * w);
	SHA3.S[ 2] ^= SHA3.toLane(message, rr, ww, i + 10 * w);
	SHA3.S[ 7] ^= SHA3.toLane(message, rr, ww, i + 11 * w);
	SHA3.S[12] ^= SHA3.toLane(message, rr, ww, i + 12 * w);
	SHA3.S[17] ^= SHA3.toLane(message, rr, ww, i + 13 * w);
	SHA3.S[22] ^= SHA3.toLane(message, rr, ww, i + 14 * w);
	SHA3.S[ 3] ^= SHA3.toLane(message, rr, ww, i + 15 * w);
	SHA3.S[ 8] ^= SHA3.toLane(message, rr, ww, i + 16 * w);
	SHA3.S[13] ^= SHA3.toLane(message, rr, ww, i + 17 * w);
	SHA3.S[18] ^= SHA3.toLane(message, rr, ww, i + 18 * w);
	SHA3.S[23] ^= SHA3.toLane(message, rr, ww, i + 19 * w);
	SHA3.S[ 4] ^= SHA3.toLane(message, rr, ww, i + 20 * w);
	SHA3.S[ 9] ^= SHA3.toLane(message, rr, ww, i + 21 * w);
	SHA3.S[14] ^= SHA3.toLane(message, rr, ww, i + 22 * w);
	SHA3.S[19] ^= SHA3.toLane(message, rr, ww, i + 23 * w);
	SHA3.S[24] ^= SHA3.toLane(message, rr, ww, i + 24 * w);
	SHA3.keccakF(SHA3.S);
      }
}
    

/**
 * Squeeze the Keccak sponge
 */
extern byte* digest()
{
  return digest(null);
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param  msg  The rest of the message
 */
extern byte* digest(byte* msg)
{
  return digest(msg, msg == null ? 0 : msg.length);
}


/**
 * Absorb the last part of the message and squeeze the Keccak sponge
 * 
 * @param  msg     The rest of the message
 * @param  msglen  The length of the partial message
 */
extern byte* digest(byte* msg, long msglen)
{
  byte* message;
  if ((msg == null) || (msglen == 0))
    message = SHA3.pad10star1(SHA3.M, SHA3.mptr, SHA3.r);
  else
    {
      if (SHA3.mptr + msglen > SHA3.M.length)
	System.arraycopy(SHA3.M, 0, SHA3.M = new byte[SHA3.M.length + msglen], 0, SHA3.mptr);
      System.arraycopy(msg, 0, SHA3.M, SHA3.mptr, msglen);
      message = SHA3.pad10star1(SHA3.M, SHA3.mptr + msglen, SHA3.r);
    }
  SHA3.M = null;
  long len = message.length;
  byte* rc = new byte[(SHA3.n + 7) >> 3];
  long ptr = 0;
  
  long rr = SHA3.r >> 3;
  long nn = SHA3.n >> 3;
  long ww = SHA3.w >> 3;
  
  /* Absorbing phase */
  if (ww == 8)
    for (long i = 0; i < len; i += rr)
      {
	SHA3.S[ 0] ^= SHA3.toLane64(message, rr, i + 0);
	SHA3.S[ 5] ^= SHA3.toLane64(message, rr, i + 8);
	SHA3.S[10] ^= SHA3.toLane64(message, rr, i + 16);
	SHA3.S[15] ^= SHA3.toLane64(message, rr, i + 24);
	SHA3.S[20] ^= SHA3.toLane64(message, rr, i + 32);
	SHA3.S[ 1] ^= SHA3.toLane64(message, rr, i + 40);
	SHA3.S[ 6] ^= SHA3.toLane64(message, rr, i + 48);
	SHA3.S[11] ^= SHA3.toLane64(message, rr, i + 56);
	SHA3.S[16] ^= SHA3.toLane64(message, rr, i + 64);
	SHA3.S[21] ^= SHA3.toLane64(message, rr, i + 72);
	SHA3.S[ 2] ^= SHA3.toLane64(message, rr, i + 80);
	SHA3.S[ 7] ^= SHA3.toLane64(message, rr, i + 88);
	SHA3.S[12] ^= SHA3.toLane64(message, rr, i + 96);
	SHA3.S[17] ^= SHA3.toLane64(message, rr, i + 104);
	SHA3.S[22] ^= SHA3.toLane64(message, rr, i + 112);
	SHA3.S[ 3] ^= SHA3.toLane64(message, rr, i + 120);
	SHA3.S[ 8] ^= SHA3.toLane64(message, rr, i + 128);
	SHA3.S[13] ^= SHA3.toLane64(message, rr, i + 136);
	SHA3.S[18] ^= SHA3.toLane64(message, rr, i + 144);
	SHA3.S[23] ^= SHA3.toLane64(message, rr, i + 152);
	SHA3.S[ 4] ^= SHA3.toLane64(message, rr, i + 160);
	SHA3.S[ 9] ^= SHA3.toLane64(message, rr, i + 168);
	SHA3.S[14] ^= SHA3.toLane64(message, rr, i + 176);
	SHA3.S[19] ^= SHA3.toLane64(message, rr, i + 184);
	SHA3.S[24] ^= SHA3.toLane64(message, rr, i + 192);
	SHA3.keccakF(SHA3.S);
      }
  else
    for (long i = 0; i < len; i += rr)
      {
	SHA3.S[ 0] ^= SHA3.toLane(message, rr, ww, i +  0    );
	SHA3.S[ 5] ^= SHA3.toLane(message, rr, ww, i +      w);
	SHA3.S[10] ^= SHA3.toLane(message, rr, ww, i +  2 * w);
	SHA3.S[15] ^= SHA3.toLane(message, rr, ww, i +  3 * w);
	SHA3.S[20] ^= SHA3.toLane(message, rr, ww, i +  4 * w);
	SHA3.S[ 1] ^= SHA3.toLane(message, rr, ww, i +  5 * w);
	SHA3.S[ 6] ^= SHA3.toLane(message, rr, ww, i +  6 * w);
	SHA3.S[11] ^= SHA3.toLane(message, rr, ww, i +  7 * w);
	SHA3.S[16] ^= SHA3.toLane(message, rr, ww, i +  8 * w);
	SHA3.S[21] ^= SHA3.toLane(message, rr, ww, i +  9 * w);
	SHA3.S[ 2] ^= SHA3.toLane(message, rr, ww, i + 10 * w);
	SHA3.S[ 7] ^= SHA3.toLane(message, rr, ww, i + 11 * w);
	SHA3.S[12] ^= SHA3.toLane(message, rr, ww, i + 12 * w);
	SHA3.S[17] ^= SHA3.toLane(message, rr, ww, i + 13 * w);
	SHA3.S[22] ^= SHA3.toLane(message, rr, ww, i + 14 * w);
	SHA3.S[ 3] ^= SHA3.toLane(message, rr, ww, i + 15 * w);
	SHA3.S[ 8] ^= SHA3.toLane(message, rr, ww, i + 16 * w);
	SHA3.S[13] ^= SHA3.toLane(message, rr, ww, i + 17 * w);
	SHA3.S[18] ^= SHA3.toLane(message, rr, ww, i + 18 * w);
	SHA3.S[23] ^= SHA3.toLane(message, rr, ww, i + 19 * w);
	SHA3.S[ 4] ^= SHA3.toLane(message, rr, ww, i + 20 * w);
	SHA3.S[ 9] ^= SHA3.toLane(message, rr, ww, i + 21 * w);
	SHA3.S[14] ^= SHA3.toLane(message, rr, ww, i + 22 * w);
	SHA3.S[19] ^= SHA3.toLane(message, rr, ww, i + 23 * w);
	SHA3.S[24] ^= SHA3.toLane(message, rr, ww, i + 24 * w);
	SHA3.keccakF(SHA3.S);
      }
  
  /* Squeezing phase */
  long olen = SHA3.n;
  long j = 0;
  long ni = Math.min(25, rr);
  while (olen > 0)
    {
      long i = 0;
      while ((i < ni) && (j < nn))
	{
	  llong v = SHA3.S[(i % 5) * 5 + i / 5];
	  for (long _ = 0; _ < ww; _++)
	    {
	      if (j < nn)
		{
		  rc[ptr] = (byte)v;
		  ptr += 1;
		}
	      v >>= 8;
	      j += 1;
	    }
	  i += 1;
	}
      olen -= SHA3.r;
      if (olen > 0)
	SHA3.keccakF(S);
    }
  return rc;
}


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
    
	
/**
 * Copy an array segment into an array
 * 
 * @param  src     The source array
 * @param  soff    The source array offset
 * @param  dest    The destination array
 * @param  doff    The destination array offset
 * @param  length  The number of elements to copy
 */
static void arraycopy(uint8[] src, int soff, uint8[] dest, int doff, int length)
{
	if (soff + length < doff)
		for (int i = 0; i < length; i++)
			dest[doff + i] = src[soff + i];
	else
		for (int i = length - 1; i >= 0; i--)
			dest[doff + i] = src[soff + i];
}

	
/**
 * Copy an array segment into an array
 * 
 * @param  src     The source array
 * @param  soff    The source array offset
 * @param  dest    The destination array
 * @param  doff    The destination array offset
 * @param  length  The number of elements to copy
 */
static void arraycopy_string(string[] src, int soff, string[] dest, int doff, int length)
{
	if (soff + length < doff)
		for (int i = 0; i < length; i++)
			dest[doff + i] = src[soff + i];
	else
		for (int i = length - 1; i >= 0; i--)
			dest[doff + i] = src[soff + i];
}


/**
 * SHA-3/Keccak hash algorithm implementation
 * 
 * @author  Mattias Andrée  <a href="mailto:maandree@member.fsf.org">maandree@member.fsf.org</a>
 */
class SHA3 : Object
{
    /**
     * Round contants
     */
    private static const int64[] RC = {
	    0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
	    0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
	    0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
	    0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
	    0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
	    0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    
    /**
     * Keccak-f round temporary
     */
    private static int64[] B = new int64[25];
    
    /**
     * Keccak-f round temporary
     */
    private static int64[] C = new int64[5];
    
    
    /**
     * The bitrate
     */
    private static int r = 0;
    
    /**
     * The capacity
     */
    private static int c = 0;
    
    /**
     * The output size
     */
    private static int n = 0;
    
    /**
     * The state size
     */
    private static int b = 0;
    
    /**
     * The word size
     */
    private static int w = 0;
    
    /**
     * The word mask
     */
    private static int64 wmod = 0;
    
    /**
     * ℓ, the binary logarithm of the word size
     */
    private static int l = 0;
    
    /**
     * 12 + 2ℓ, the number of rounds
     */
    private static int nr = 0;
    
    
    /**
     * The current state
     */
    private static int64[] S = null;
    
    /**
     * Left over water to fill the sponge with at next update
     */
    private static uint8[] M = null;
    
    /**
     * Pointer for {@link #M}
     */
    private static int mptr = 0;
    
    
    
    /**
     * Hidden constructor
     */
    private SHA3()
    {
		// Inhibit instansiation
    }
    
	
    
    /**
     * Rotate a word
     * 
     * @param   x  The value to rotate
     * @param   n  Rotation steps, may not be 0
     * @return     The value rotated
     */
    private static int64 rotate(int64 x, int n)
    {
        int64 m = n % SHA3.w;
        return (((x >> (SHA3.w - m)) & ((1 << m) - 1)) + (x << m)) & SHA3.wmod;
    }
    
    
    /**
     * Rotate a 64-bit word
     * 
     * @param   x  The value to rotate
     * @param   n  Rotation steps, may not be 0
     * @return     The value rotated
     */
    private static int64 rotate64(int64 x, int n)
    {
        return ((x >> (64 - n)) & ((1 << n) - 1)) + (x << n);
    }
    
    
    /**
     * Binary logarithm
     * 
     * @param   x  The value of which to calculate the binary logarithm
     * @return     The binary logarithm
     */
    private static int lb(int x)
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
    private static void keccakFRound(int64[] A, int64 rc)
    {
		/* θ step (step 1 of 3) */
		for (int i = 0, j = 0; i < 5; i++, j += 5)
			SHA3.C[i] = (A[j] ^ A[j + 1]) ^ (A[j + 2] ^ A[j + 3]) ^ A[j + 4];
	
		int64 da, db, dc, dd, de;
	
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
		for (int i = 0; i < 15; i++)
			A[i     ] = SHA3.B[i     ] ^ ((~(SHA3.B[i +  5])) & SHA3.B[i + 10]);
		for (int i = 0; i < 5; i++)
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
    private static void keccakF(int64[] A)
    {
        if (SHA3.nr == 24)
            for (int i = 0; i < 24; i++)
				SHA3.keccakFRound(A, SHA3.RC[i]);
        else
            for (int i = 0; i < SHA3.nr; i++)
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
    private static int64 toLane(uint8[] message, int rr, int ww, int off)
    {
		int64 rc = 0;
		int n = message.length < rr ? message.length : rr;
        for (int i = off + ww - 1; i >= off; i--)
            rc = (rc << 8) | ((i < n) ? (int64)(message[i] & 255) : 0L);
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
    private static int64 toLane64(uint8[] message, int rr, int off)
    {
		int n = message.length < rr ? message.length : rr;
        return ((off + 7 < n) ? ((int64)(message[off + 7] & 255) << 56) : 0L) |
		       ((off + 6 < n) ? ((int64)(message[off + 6] & 255) << 48) : 0L) |
			   ((off + 5 < n) ? ((int64)(message[off + 5] & 255) << 40) : 0L) |
			   ((off + 4 < n) ? ((int64)(message[off + 4] & 255) << 32) : 0L) |
			   ((off + 3 < n) ? ((int64)(message[off + 3] & 255) << 24) : 0L) |
			   ((off + 2 < n) ? ((int64)(message[off + 2] & 255) << 16) : 0L) |
			   ((off + 1 < n) ? ((int64)(message[off + 1] & 255) <<  8) : 0L) |
			   ((off     < n) ? ((int64)(message[off    ] & 255)      ) : 0L);
    }
    
    
    /**
     * pad 10*1
     * 
     * @param   msg  The message to pad
     * @parm    len  The length of the message
     * @param   r    The bitrate
     * @return       The message padded
     */
    private static uint8[] pad10star1(uint8[] msg, int len, int r)
    {
        int nrf = (len <<= 3) >> 3;
        int nbrf = len & 7;
        int ll = len % r;
        
        uint8 b = (uint8)(nbrf == 0 ? 1 : ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf)));
        
        uint8[] message;
        if ((r - 8 <= ll) && (ll <= r - 2))
		{
			message = new uint8[len = nrf + 1];
            message[nrf] = (uint8)(b ^ 128);
		}
        else
		{
			len = (nrf + 1) << 3;
			len = ((len - (len % r) + (r - 8)) >> 3) + 1;
			message = new uint8[len];
			message[nrf] = b;
			message[len - 1] = (uint8)(-128);
		}
		arraycopy(msg, 0, message, 0, nrf);
        
        return message;
    }
    
    
    /**
     * Initialise Keccak sponge
     * 
     * @param  r  The bitrate
     * @param  c  The capacity
     * @param  n  The output size
     */
    public static void initialise(int r, int c, int n)
    {
        SHA3.r = r;
        SHA3.c = c;
        SHA3.n = n;
        SHA3.b = r + c;
        SHA3.w = SHA3.b / 25;
        SHA3.l = SHA3.lb(SHA3.w);
        SHA3.nr = 12 + (SHA3.l << 1);
        SHA3.wmod = w == 64 ? -1L : (1L << SHA3.w) - 1L;
        SHA3.S = new int64[25];
        SHA3.M = new uint8[(SHA3.r * SHA3.b) >> 2];
		SHA3.mptr = 0;
    }
    
    
    /**
     * Absorb the more of the message message to the Keccak sponge
     * 
     * @param  msg     The partial message
     * @param  msglen  The length of the partial message
     */
    public static void update(uint8[] msg, int msglen)
    {
        int rr = SHA3.r >> 3;
        int ww = SHA3.w >> 3;
        
		if (SHA3.mptr + msglen > SHA3.M.length)
			arraycopy(SHA3.M, 0, SHA3.M = new uint8[(SHA3.M.length + msglen) << 1], 0, SHA3.mptr);
		arraycopy(msg, 0, SHA3.M, SHA3.mptr, msglen);
        int len = SHA3.mptr += msglen;
        len -= len % ((SHA3.r * SHA3.b) >> 3);
        uint8[] message;
		arraycopy(SHA3.M, 0, message = new uint8[len], 0, len);
		arraycopy(SHA3.M, len, SHA3.M, 0, SHA3.mptr -= len);
	
        /* Absorbing phase */
        if (ww == 8)
            for (int i = 0; i < len; i += rr)
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
			for (int i = 0; i < len; i += rr)
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
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param  msg     The rest of the message
     * @param  msglen  The length of the partial message
     */
    public static uint8[] digest(uint8[] msg, int msglen)
    {
		uint8[] message;
		if ((msg == null) || (msglen == 0))
            message = SHA3.pad10star1(SHA3.M, SHA3.mptr, SHA3.r);
		else
		{
			if (SHA3.mptr + msglen > SHA3.M.length)
				arraycopy(SHA3.M, 0, SHA3.M = new uint8[SHA3.M.length + msglen], 0, SHA3.mptr);
			arraycopy(msg, 0, SHA3.M, SHA3.mptr, msglen);
			message = SHA3.pad10star1(SHA3.M, SHA3.mptr + msglen, SHA3.r);
		}
        SHA3.M = null;
        int len = message.length;
        uint8[] rc = new uint8[(SHA3.n + 7) >> 3];
        int ptr = 0;
        
        int rr = SHA3.r >> 3;
        int nn = SHA3.n >> 3;
        int ww = SHA3.w >> 3;
        
        /* Absorbing phase */
        if (ww == 8)
            for (int i = 0; i < len; i += rr)
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
			for (int i = 0; i < len; i += rr)
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
        int olen = SHA3.n;
        int j = 0;
        int ni = 25 < rr ? 25 : rr;
        while (olen > 0)
		{
            int i = 0;
			while ((i < ni) && (j < nn))
			{
				int64 v = SHA3.S[(i % 5) * 5 + i / 5];
				for (int _ = 0; _ < ww; _++)
				{
                    if (j < nn)
					{
						rc[ptr] = (uint8)v;
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
    
}


/**
 * This is the main entry point of the program
 * 
 * @param  args  Command line arguments
 */
static int main(string[] cmdargs)
{
	string[] HEXADECA = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};
	
	string cmd = cmdargs[0];
	string[] argv = new string[cmdargs.length - 1];
	arraycopy_string(cmdargs, 1, argv, 0, argv.length);
	
	if (cmd.contains("/"))
	    cmd = cmd.substring(cmd.last_index_of("/") + 1);
	if (cmd.has_suffix(".jar"))
	    cmd = cmd.substring(0, cmd.length - 4);
	
	int _o, o = _o = 512;           /* --outputsize */
	if      (cmd == "sha3-224sum")  o = _o = 224;
	else if (cmd == "sha3-256sum")  o = _o = 256;
	else if (cmd == "sha3-384sum")  o = _o = 384;
	else if (cmd == "sha3-512sum")  o = _o = 512;
	int _s, s = _s = 1600;          /* --statesize  */
	int _r, r = _r = s - (o << 1);  /* --bitrate    */
	int _c, c = _c = s - r;         /* --capacity   */
	int _w, w = _w = s / 25;        /* --wordsize   */
	int _i, i = _i = 1;             /* --iterations */
	bool binary = false;
	
	string[] files = new string[argv.length + 1];
	int fptr = 0;
	bool dashed = false;
	string[] linger = null;
	
	string[] args = new string[argv.length + 1];
	arraycopy_string(argv, 0, args, 0, argv.length);
	for (int a = 0, an = args.length; a < an; a++)
	{   string arg = args[a];
	    if (linger != null)
	    {
			if ((linger[0] == "-h") || (linger[0] == "--help"))
			{
				stdout.printf("\n");
				stdout.printf("SHA-3/Keccak checksum calculator\n");
				stdout.printf("\n");
				stdout.printf("USAGE:	sha3sum [option...] < file\n");
				stdout.printf("	sha3sum [option...] file...\n");
				stdout.printf("\n");
				stdout.printf("\n");
				stdout.printf("OPTIONS:\n");
				stdout.printf("        -r BITRATE\n");
				stdout.printf("        --bitrate       The bitrate to use for SHA-3.           (default: %i)\n", _r);
				stdout.printf("        \n");
				stdout.printf("        -c CAPACITY\n");
				stdout.printf("        --capacity      The capacity to use for SHA-3.          (default: %i)\n", _c);
				stdout.printf("        \n");
				stdout.printf("        -w WORDSIZE\n");
				stdout.printf("        --wordsize      The word size to use for SHA-3.         (default: %i)\n", _w);
				stdout.printf("        \n");
				stdout.printf("        -o OUTPUTSIZE\n");
				stdout.printf("        --outputsize    The output size to use for SHA-3.       (default: %i)\n", _o);
				stdout.printf("        \n");
				stdout.printf("        -s STATESIZE\n");
				stdout.printf("        --statesize     The state size to use for SHA-3.        (default: %i)\n", _s);
				stdout.printf("        \n");
				stdout.printf("        -i ITERATIONS\n");
				stdout.printf("        --iterations    The number of hash iterations to run.   (default: %i)\n", _i);
				stdout.printf("        \n");
				stdout.printf("        -b\n");
				stdout.printf("        --binary        Print the checksum in binary, rather than hexadecimal.\n");
				stdout.printf("\n");
				stdout.printf("\n");
				stdout.printf("COPYRIGHT:\n");
				stdout.printf("\n");
				stdout.printf("Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)\n");
				stdout.printf("\n");
				stdout.printf("This program is free software: you can redistribute it and/or modify\n");
				stdout.printf("it under the terms of the GNU General Public License as published by\n");
				stdout.printf("the Free Software Foundation, either version 3 of the License, or\n");
				stdout.printf("(at your option) any later version.\n");
				stdout.printf("\n");
				stdout.printf("This program is distributed in the hope that it will be useful,\n");
				stdout.printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
				stdout.printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
				stdout.printf("GNU General Public License for more details.\n");
				stdout.printf("\n");
				stdout.printf("You should have received a copy of the GNU General Public License\n");
				stdout.printf("along with this program.  If not, see <http://www.gnu.org/licenses/>.\n");
				stdout.printf("\n");
				return 2;
			}
			else
			{
				if (linger[1] == null)
				{
					linger[1] = arg;
					arg = null;
				}
				if ((linger[0] == "-r") || (linger[0] == "--bitrate"))
					o = (s - (r = int.parse(linger[1]))) >> 1;
				else if ((linger[0] == "-c") || (linger[0] == "--capacity"))
					r = s - (c = int.parse(linger[1]));
				else if ((linger[0] == "-w") || (linger[0] == "--wordsize"))
					s = (w = int.parse(linger[1])) * 25;
				else if ((linger[0] == "-o") || (linger[0] == "--outputsize"))
					r = s - ((o = int.parse(linger[1])) << 1);
				else if ((linger[0] == "-s") || (linger[0] == "--statesize"))
					r = (s = int.parse(linger[1])) - (o << 1);
				else if ((linger[0] == "-i") || (linger[0] == "--iterations"))
					i = int.parse(linger[1]);
				else
				{
					stdout.printf("%s: unrecognised option: %s\n", cmd, linger[0]);
					return 1;
				}
			}
			linger = null;
			if (arg == null)
				continue;
	    }
	    if (arg == null)
			continue;
	    if (dashed)
			files[fptr++] = arg == "-" ? null : arg;
	    else if (arg == "--")
			dashed = true;
	    else if (arg == "-")
			files[fptr++] = null;
	    else if (arg.has_prefix("--"))
			if (arg.contains("="))
	            linger = new string[] { arg.substring(0, arg.index_of("=")), arg.substring(arg.index_of("=") + 1) };
			else
				if (arg == "--binary")
	                binary = true;
				else
					linger = new string[] { arg, null };
	    else if (arg.has_prefix("-"))
	    {
			arg = arg.substring(1);
			if (arg[0] == 'b')
			{
				binary = true;
				arg = arg.substring(1);
			}
			else if (arg.length == 1)
				linger = new string[] { "-" + arg, null };
			else
				linger = new string[] { "-" + arg[0].to_string(), arg.substring(1) };
	    }
		else
			files[fptr++] = arg;
	}
	
	if (fptr == 0)
	    files[fptr++] = null;
	if (i < 1)
	{
	    stderr.printf("%s: sorry, I will only do at least one iteration!\n", cmd);
	    return 3;
	}
	
	uint8[] stdin_ = null;
	bool fail = false;
	string filename;

	for (int f = 0; f < fptr; f++)
	{
		if (((filename = files[f]) == null) && (stdin_ != null))
	    {
			stdout.write(stdin_, stdin_.length); 
			continue;
	    }
	    string rc = "";
		string fn = filename == null ? "/dev/stdin" : filename;
	    FileStream file = null;
	    try
	    {
			file = FileStream.open(fn, "r");
			if (file == null)
			{
				stderr.printf("%s: cannot read file: %s\n", cmd, filename);
				fail = true;
				continue;
			}
			SHA3.initialise(r, c, o);
			int blksize = 4096; /** XXX os.stat(os.path.realpath(fn)).st_size; **/
			uint8[] chunk = new uint8[blksize];
            while (file.eof() == false)
			{
				int readn = (int)(file.read(chunk, blksize));
				SHA3.update(chunk, readn);
			}
			uint8[] bs = SHA3.digest(null, 0);
			for (int _ = 1; _ < i; _++)
			{
				SHA3.initialise(r, c, o);
				bs = SHA3.digest(bs, bs.length);
			}
			if (binary)
			{   if (filename == null)
					stdin_ = bs;
				stdout.write(bs, bs.length);
				stdout.flush();
			}
			else
			{   for (int b = 0, bn = bs.length; b < bn; b++)
				{
					rc += HEXADECA[(bs[b] >> 4) & 15];
				    rc += HEXADECA[bs[b] & 15];
				}
				rc += " " + (filename == null ? "-" : filename) + "\n";
				if (filename == null)
					stdin_ = (uint8[])(rc.to_utf8);
				stdout.printf("%s", rc);
				stdout.flush();
			}
	    }
	    catch
	    {
			stderr.printf("%s: cannot read file: %s\n", cmd, filename);
			fail = true;
	    }
	}
	
    stdout.flush();
	if (fail)
	    return 5;
	
	return 0;
}


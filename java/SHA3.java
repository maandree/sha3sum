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


/**
 * SHA-3/Keccak hash algorithm implementation
 * 
 * @author  Mattias Andrée  <a href="mailto:maandree@member.fsf.org">maandree@member.fsf.org</a>
 */
public class SHA3
{
    /**
     * Round contants
     */
    private static final long[] RC = {
	    0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
	    0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
	    0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
	    0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
	    0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
	    0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    
    /**
     * Keccak-f round temporary
     */
    private static long[] B = new long[25];
    
    /**
     * Keccak-f round temporary
     */
    private static long[] C = new long[5];
    
    
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
    private static long wmod = 0;
    
    /**
     * ℓ, the binary logarithm of the word size
     */
    private static int l = 0;
    
    /**
     * 12 + 2ℓ, the number of rounds
     */
    private static int nr = 0;
    
    
    /**
     * Message chunk that is being processes
     */
    private static byte[] message = null;
    
    /**
     * The current state
     */
    private static long[] S = null;
    
    /**
     * Left over water to fill the sponge with at next update
     */
    private static byte[] M = null;
    
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
    private static long rotate(long x, int n)
    {
        long m;
        return ((x >>> (SHA3.w - (m = n % SHA3.w))) + (x << m)) & SHA3.wmod;
    }
    
    
    /**
     * Rotate a 64-bit word
     * 
     * @param   x  The value to rotate
     * @param   n  Rotation steps, may not be 0
     * @return     The value rotated
     */
    private static long rotate64(long x, int n)
    {
        return (x >>> (64 - n)) + (x << n);
    }
    
    
    /**
     * Binary logarithm
     * 
     * @param   x  The value of which to calculate the binary logarithm
     * @return     The binary logarithm
     */
    private static int lb(int x)
    {
	int rc = 0;
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
    private static void keccakFRound(long[] A, long rc)
    {
	/* θ step (step 1 of 3) */
	for (int i = 0, j = 0; i < 5; i++, j += 5)
	    SHA3.C[i] = (A[j] ^ A[j + 1]) ^ (A[j + 2] ^ A[j + 3]) ^ A[j + 4];
	
	long da, db, dc, dd, de;
	
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
    private static void keccakF(long[] A)
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
     * @param   n       {@code Math.min(SHA3.message.length, rr) + msgoff}
     *          msgoff  The number of times to loop has run times the bitrate
     *          rr      Bitrate in bytes
     * @param   ww      Word size in bytes
     * @param   off     The offset in the message
     * @return          Lane
     */
    private static long toLane(int n, int ww, int off)
    {
	long rc = 0;
        for (int i = off + ww - 1; i >= off; i--)
            rc = (rc << 8) | ((i < n) ? (long)(SHA3.message[i] & 255) : 0L);
        return rc;
    }
    
    
    /**
     * Convert a chunk of byte:s to a 64-bit word
     * 
     * @param   n       {@code Math.min(SHA3.message.length, rr) + msgoff}
     *          msgoff  The number of times to loop has run times the bitrate
     *          rr      Bitrate in bytes
     * @param   off     The offset in the message
     * @return          Lane
     */
    private static long toLane64(int n, int off)
    {
        return ((off + 7 < n) ? ((long)(SHA3.message[off + 7] & 255) << 56) : 0L) |
	       ((off + 6 < n) ? ((long)(SHA3.message[off + 6] & 255) << 48) : 0L) |
	       ((off + 5 < n) ? ((long)(SHA3.message[off + 5] & 255) << 40) : 0L) |
	       ((off + 4 < n) ? ((long)(SHA3.message[off + 4] & 255) << 32) : 0L) |
	       ((off + 3 < n) ? ((long)(SHA3.message[off + 3] & 255) << 24) : 0L) |
	       ((off + 2 < n) ? ((long)(SHA3.message[off + 2] & 255) << 16) : 0L) |
	       ((off + 1 < n) ? ((long)(SHA3.message[off + 1] & 255) <<  8) : 0L) |
	       ((off < n) ? ((long)(SHA3.message[off] & 255)) : 0L);
    }
    
    
    /**
     * pad 10*1
     * 
     * @param   msg  The message to pad
     * @param   len  The length of the message
     * @param   r    The bitrate
     * @return       The actual length of {@link #message}
     */
    private static int pad10star1(byte[] msg, int len, int r)
    {
        int nrf = (len <<= 3) >> 3;
        int nbrf = len & 7;
        int ll = len % r;
        
        byte b = (byte)(nbrf == 0 ? 1 : ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf)));
        
        if ((r - 8 <= ll) && (ll <= r - 2))
	{
	    SHA3.message = new byte[len = nrf + 1];
            SHA3.message[nrf] = (byte)(b ^ 128);
	}
        else
	{
	    len = (nrf + 1) << 3;
	    len = ((len - (len % r) + (r - 8)) >> 3) + 1;
	    SHA3.message = new byte[len];
	    SHA3.message[nrf] = b;
	    SHA3.message[len - 1] = -128;
	}
	
	System.arraycopy(msg, 0, SHA3.message, 0, nrf);
	return len;
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
        SHA3.S = new long[25];
	if ((SHA3.M == null) || ((SHA3.r * SHA3.b) >> 2 != SHA3.M.length))
	    SHA3.M = new byte[(SHA3.r * SHA3.b) >> 2];
	SHA3.mptr = 0;
	if (SHA3.message == null)
	    SHA3.message = new byte[8 << 10];
    }
    
    
    /**
     * Free up static resources
     */
    public static void dispose()
    {
	SHA3.S = null;
	SHA3.M = null;
	SHA3.message = null;
    }
    
    
    /**
     * Absorb the more of the message message to the Keccak sponge
     * 
     * @param  msg  The partial message
     */
    public static void update(byte[] msg)
    {
	update(msg, msg.length);
    }
    
    
    /**
     * Absorb the more of the message message to the Keccak sponge
     * 
     * @param  msg     The partial message
     * @param  msglen  The length of the partial message
     */
    public static void update(byte[] msg, int msglen)
    {
        int rr = SHA3.r >> 3;
        int ww = SHA3.w >> 3;
        
	if (SHA3.mptr + msglen > SHA3.M.length)
	    System.arraycopy(SHA3.M, 0, SHA3.M = new byte[(SHA3.M.length + msglen) << 1], 0, SHA3.mptr);
	System.arraycopy(msg, 0, SHA3.M, SHA3.mptr, msglen);
        int len = SHA3.mptr += msglen;
        len -= len % ((SHA3.r * SHA3.b) >> 3);
	System.arraycopy(SHA3.M, 0, (SHA3.message.length < len) ? (SHA3.message = new byte[len]) : SHA3.message, 0, len);
	System.arraycopy(SHA3.M, len, SHA3.M, 0, SHA3.mptr -= len);
	int n = Math.min(len, rr);
	
        /* Absorbing phase */
        if (ww == 8)
            for (int i = 0; i < len; i += rr)
	    {
		SHA3.S[ 0] ^= SHA3.toLane64(n, i + 0);
		SHA3.S[ 5] ^= SHA3.toLane64(n, i + 8);
		SHA3.S[10] ^= SHA3.toLane64(n, i + 16);
                SHA3.S[15] ^= SHA3.toLane64(n, i + 24);
                SHA3.S[20] ^= SHA3.toLane64(n, i + 32);
                SHA3.S[ 1] ^= SHA3.toLane64(n, i + 40);
                SHA3.S[ 6] ^= SHA3.toLane64(n, i + 48);
                SHA3.S[11] ^= SHA3.toLane64(n, i + 56);
                SHA3.S[16] ^= SHA3.toLane64(n, i + 64);
                SHA3.S[21] ^= SHA3.toLane64(n, i + 72);
                SHA3.S[ 2] ^= SHA3.toLane64(n, i + 80);
                SHA3.S[ 7] ^= SHA3.toLane64(n, i + 88);
		SHA3.S[12] ^= SHA3.toLane64(n, i + 96);
		SHA3.S[17] ^= SHA3.toLane64(n, i + 104);
		SHA3.S[22] ^= SHA3.toLane64(n, i + 112);
		SHA3.S[ 3] ^= SHA3.toLane64(n, i + 120);
		SHA3.S[ 8] ^= SHA3.toLane64(n, i + 128);
		SHA3.S[13] ^= SHA3.toLane64(n, i + 136);
		SHA3.S[18] ^= SHA3.toLane64(n, i + 144);
		SHA3.S[23] ^= SHA3.toLane64(n, i + 152);
                SHA3.S[ 4] ^= SHA3.toLane64(n, i + 160);
                SHA3.S[ 9] ^= SHA3.toLane64(n, i + 168);
                SHA3.S[14] ^= SHA3.toLane64(n, i + 176);
                SHA3.S[19] ^= SHA3.toLane64(n, i + 184);
                SHA3.S[24] ^= SHA3.toLane64(n, i + 192);
		SHA3.keccakF(SHA3.S);
		n += rr;
	    }
        else
	    for (int i = 0; i < len; i += rr)
	    {
		SHA3.S[ 0] ^= SHA3.toLane(n, ww, i +  0    );
		SHA3.S[ 5] ^= SHA3.toLane(n, ww, i +      w);
		SHA3.S[10] ^= SHA3.toLane(n, ww, i +  2 * w);
                SHA3.S[15] ^= SHA3.toLane(n, ww, i +  3 * w);
                SHA3.S[20] ^= SHA3.toLane(n, ww, i +  4 * w);
                SHA3.S[ 1] ^= SHA3.toLane(n, ww, i +  5 * w);
                SHA3.S[ 6] ^= SHA3.toLane(n, ww, i +  6 * w);
                SHA3.S[11] ^= SHA3.toLane(n, ww, i +  7 * w);
                SHA3.S[16] ^= SHA3.toLane(n, ww, i +  8 * w);
                SHA3.S[21] ^= SHA3.toLane(n, ww, i +  9 * w);
                SHA3.S[ 2] ^= SHA3.toLane(n, ww, i + 10 * w);
                SHA3.S[ 7] ^= SHA3.toLane(n, ww, i + 11 * w);
		SHA3.S[12] ^= SHA3.toLane(n, ww, i + 12 * w);
		SHA3.S[17] ^= SHA3.toLane(n, ww, i + 13 * w);
		SHA3.S[22] ^= SHA3.toLane(n, ww, i + 14 * w);
		SHA3.S[ 3] ^= SHA3.toLane(n, ww, i + 15 * w);
		SHA3.S[ 8] ^= SHA3.toLane(n, ww, i + 16 * w);
		SHA3.S[13] ^= SHA3.toLane(n, ww, i + 17 * w);
		SHA3.S[18] ^= SHA3.toLane(n, ww, i + 18 * w);
		SHA3.S[23] ^= SHA3.toLane(n, ww, i + 19 * w);
                SHA3.S[ 4] ^= SHA3.toLane(n, ww, i + 20 * w);
                SHA3.S[ 9] ^= SHA3.toLane(n, ww, i + 21 * w);
                SHA3.S[14] ^= SHA3.toLane(n, ww, i + 22 * w);
                SHA3.S[19] ^= SHA3.toLane(n, ww, i + 23 * w);
                SHA3.S[24] ^= SHA3.toLane(n, ww, i + 24 * w);
		SHA3.keccakF(SHA3.S);
		n += rr;
	    }
    }
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @return  The hash sum
     */
    public static byte[] digest()
    {
	return digest(null, 0, true);
    }
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(boolean withReturn)
    {
	return digest(null, 0, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg  The rest of the message
     * @return       The hash sum
     */
    public static byte[] digest(byte[] msg)
    {
	return digest(msg, msg == null ? 0 : msg.length, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(byte[] msg, boolean withReturn)
    {
	return digest(msg, msg == null ? 0 : msg.length, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg     The rest of the message
     * @param   msglen  The length of the partial message
     * @return          The hash sum
     */
    public static byte[] digest(byte[] msg, int msglen)
    {
	return digest(msg, msg == null ? 0 : msg.length, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   msglen      The length of the partial message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(byte[] msg, int msglen, boolean withReturn)
    {
	int len;
        if ((msg == null) || (msglen == 0))
            len = SHA3.pad10star1(SHA3.M, SHA3.mptr, SHA3.r);
	else
	{
	    if (SHA3.mptr + msglen > SHA3.M.length)
		System.arraycopy(SHA3.M, 0, SHA3.M = new byte[SHA3.M.length + msglen], 0, SHA3.mptr);
	    System.arraycopy(msg, 0, SHA3.M, SHA3.mptr, msglen);
	    len = SHA3.pad10star1(SHA3.M, SHA3.mptr + msglen, SHA3.r);
	}
        
        int rr = SHA3.r >> 3;
        int nn = (SHA3.n + 7) >> 3;
        int ww = SHA3.w >> 3;
	
	int n = Math.min(len, rr);
        
        /* Absorbing phase */
        if (ww == 8)
            for (int i = 0; i < len; i += rr)
	    {
		SHA3.S[ 0] ^= SHA3.toLane64(n, i + 0);
		SHA3.S[ 5] ^= SHA3.toLane64(n, i + 8);
		SHA3.S[10] ^= SHA3.toLane64(n, i + 16);
                SHA3.S[15] ^= SHA3.toLane64(n, i + 24);
                SHA3.S[20] ^= SHA3.toLane64(n, i + 32);
                SHA3.S[ 1] ^= SHA3.toLane64(n, i + 40);
                SHA3.S[ 6] ^= SHA3.toLane64(n, i + 48);
                SHA3.S[11] ^= SHA3.toLane64(n, i + 56);
                SHA3.S[16] ^= SHA3.toLane64(n, i + 64);
                SHA3.S[21] ^= SHA3.toLane64(n, i + 72);
                SHA3.S[ 2] ^= SHA3.toLane64(n, i + 80);
                SHA3.S[ 7] ^= SHA3.toLane64(n, i + 88);
		SHA3.S[12] ^= SHA3.toLane64(n, i + 96);
		SHA3.S[17] ^= SHA3.toLane64(n, i + 104);
		SHA3.S[22] ^= SHA3.toLane64(n, i + 112);
		SHA3.S[ 3] ^= SHA3.toLane64(n, i + 120);
		SHA3.S[ 8] ^= SHA3.toLane64(n, i + 128);
		SHA3.S[13] ^= SHA3.toLane64(n, i + 136);
		SHA3.S[18] ^= SHA3.toLane64(n, i + 144);
		SHA3.S[23] ^= SHA3.toLane64(n, i + 152);
                SHA3.S[ 4] ^= SHA3.toLane64(n, i + 160);
                SHA3.S[ 9] ^= SHA3.toLane64(n, i + 168);
                SHA3.S[14] ^= SHA3.toLane64(n, i + 176);
                SHA3.S[19] ^= SHA3.toLane64(n, i + 184);
                SHA3.S[24] ^= SHA3.toLane64(n, i + 192);
                SHA3.keccakF(SHA3.S);
		n += rr;
	    }
        else
	    for (int i = 0; i < len; i += rr)
	    {
		SHA3.S[ 0] ^= SHA3.toLane(n, ww, i +  0    );
		SHA3.S[ 5] ^= SHA3.toLane(n, ww, i +      w);
		SHA3.S[10] ^= SHA3.toLane(n, ww, i +  2 * w);
                SHA3.S[15] ^= SHA3.toLane(n, ww, i +  3 * w);
                SHA3.S[20] ^= SHA3.toLane(n, ww, i +  4 * w);
                SHA3.S[ 1] ^= SHA3.toLane(n, ww, i +  5 * w);
                SHA3.S[ 6] ^= SHA3.toLane(n, ww, i +  6 * w);
                SHA3.S[11] ^= SHA3.toLane(n, ww, i +  7 * w);
                SHA3.S[16] ^= SHA3.toLane(n, ww, i +  8 * w);
                SHA3.S[21] ^= SHA3.toLane(n, ww, i +  9 * w);
                SHA3.S[ 2] ^= SHA3.toLane(n, ww, i + 10 * w);
                SHA3.S[ 7] ^= SHA3.toLane(n, ww, i + 11 * w);
		SHA3.S[12] ^= SHA3.toLane(n, ww, i + 12 * w);
		SHA3.S[17] ^= SHA3.toLane(n, ww, i + 13 * w);
		SHA3.S[22] ^= SHA3.toLane(n, ww, i + 14 * w);
		SHA3.S[ 3] ^= SHA3.toLane(n, ww, i + 15 * w);
		SHA3.S[ 8] ^= SHA3.toLane(n, ww, i + 16 * w);
		SHA3.S[13] ^= SHA3.toLane(n, ww, i + 17 * w);
		SHA3.S[18] ^= SHA3.toLane(n, ww, i + 18 * w);
		SHA3.S[23] ^= SHA3.toLane(n, ww, i + 19 * w);
                SHA3.S[ 4] ^= SHA3.toLane(n, ww, i + 20 * w);
                SHA3.S[ 9] ^= SHA3.toLane(n, ww, i + 21 * w);
                SHA3.S[14] ^= SHA3.toLane(n, ww, i + 22 * w);
                SHA3.S[19] ^= SHA3.toLane(n, ww, i + 23 * w);
                SHA3.S[24] ^= SHA3.toLane(n, ww, i + 24 * w);
		SHA3.keccakF(SHA3.S);
		n += rr;
	    }
        
        /* Squeezing phase */
	if (withReturn)
	{
	    byte[] rc = new byte[(SHA3.n + 7) >> 3];
	    int ptr = 0;
	    
	    int olen = SHA3.n;
	    int j = 0;
	    int ni = Math.min(25, rr);
	    while (olen > 0)
	    {
		int i = 0;
		while ((i < ni) && (j < nn))
		{
		    long v = SHA3.S[(i % 5) * 5 + i / 5];
		    for (int _ = 0; _ < ww; _++)
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
		    SHA3.keccakF(SHA3.S);
	    }
	    if ((SHA3.n & 7) != 0)
		rc[rc.length - 1] &= (1 << (SHA3.n & 7)) - 1;
	    
	    return rc;
	}
        int olen = SHA3.n;
        while ((olen -= SHA3.r) > 0)
	    SHA3.keccakF(SHA3.S);
	return null;
    }
    
    
    /**
     * Force a round of Keccak-f
     */
    public static void simpleSqueeze()
    {
	SHA3.keccakF(SHA3.S);
    }
    
    
    /**
     * Force some rounds of Keccak-f
     * 
     * @param  times  The number of rounds
     */
    public static void simpleSqueeze(int times)
    {
	for (int i = 0; i < times; i++)
	    SHA3.keccakF(SHA3.S);
    }
    
    
    /**
     * Squeeze as much as is needed to get a digest
     */
    public static void fastSqueeze()
    {
	SHA3.keccakF(SHA3.S); /* Last squeeze did not do a ending squeeze */
        int olen = SHA3.n;
        while ((olen -= SHA3.r) > 0)
	    SHA3.keccakF(SHA3.S);
    }
    
    
    /**
     * Squeeze as much as is needed to get a digest a number of times
     * 
     * @param  times  The number of digests
     */
    public static void fastSqueeze(int times)
    {
	for (int i = 0; i < times; i++)
	{
	    SHA3.keccakF(SHA3.S); /* Last squeeze did not do a ending squeeze */
	    int olen = SHA3.n;
	    while ((olen -= SHA3.r) > 0)
		SHA3.keccakF(SHA3.S);
	}
    }
    
    
    /**
     * Squeeze out another digest
     * 
     * @return  The hash sum
     */
    public static byte[] squeeze()
    {
	SHA3.keccakF(SHA3.S); /* Last squeeze did not do a ending squeeze */
	
        int nn, ww = SHA3.w >> 3;
        byte[] rc = new byte[nn = (SHA3.n + 7) >> 3];
	
        int olen = SHA3.n;
        int j = 0, ptr = 0;
        int ni = Math.min(25, SHA3.r >> 3);
        while (olen > 0)
	{
            int i = 0;
	    while ((i < ni) && (j < nn))
	    {
		long v = SHA3.S[(i % 5) * 5 + i / 5];
		for (int _ = 0; _ < ww; _++)
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
		SHA3.keccakF(SHA3.S);
	}
	if ((SHA3.n & 7) != 0)
	    rc[rc.length - 1] &= (1 << (SHA3.n & 7)) - 1;
	
        return rc;
    }
    
}

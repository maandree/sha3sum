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


/**
 * SHA-3/Keccak hash algorithm implementation with support for concurrent threads
 * 
 * @author  Mattias Andrée  <a href="mailto:maandree@member.fsf.org">maandree@member.fsf.org</a>
 */
public class ConcurrentSHA3
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
     * <p>Constructor</p>
     * <p>
     *   Do not forget to run {@link #Initialise(int, int, int)}
     * </p>
     */
    public ConcurrentSHA3()
    {
	/* Do nothing */
    }
    
    
    
    /**
     * Keccak-f round temporary
     */
    private long[] B = new long[25];
    
    /**
     * Keccak-f round temporary
     */
    private long[] C = new long[5];
    
    
    /**
     * The bitrate
     */
    private int r = 0;
    
    /**
     * The capacity
     */
    private int c = 0;
    
    /**
     * The output size
     */
    private int n = 0;
    
    /**
     * The state size
     */
    private int b = 0;
    
    /**
     * The word size
     */
    private int w = 0;
    
    /**
     * The word mask
     */
    private long wmod = 0;
    
    /**
     * ℓ, the binary logarithm of the word size
     */
    private int l = 0;
    
    /**
     * 12 + 2ℓ, the number of rounds
     */
    private int nr = 0;
    
    
    /**
     * The current state
     */
    private long[] S = null;
    
    /**
     * Left over water to fill the sponge with at next update
     */
    private byte[] M = null;
    
    /**
     * Pointer for {@link #M}
     */
    private int mptr = 0;
    
    
    
    /**
     * Rotate a word
     * 
     * @param   x  The value to rotate
     * @param   n  Rotation steps, may not be 0
     * @return     The value rotated
     */
    private long rotate(long x, int n)
    {
        long m;
        return ((x >>> (this.w - (m = n % this.w))) + (x << m)) & this.wmod;
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
    private void keccakFRound(long[] A, long rc)
    {
	/* θ step (step 1 of 3) */
	for (int i = 0, j = 0; i < 5; i++, j += 5)
	    this.C[i] = (A[j] ^ A[j + 1]) ^ (A[j + 2] ^ A[j + 3]) ^ A[j + 4];
	
	long da, db, dc, dd, de;
	
        if (this.w == 64)
	{
            /* ρ and π steps, with last two part of θ */
            this.B[0] =                         A[ 0] ^ (da = this.C[4] ^ ConcurrentSHA3.rotate64(this.C[1], 1));
            this.B[1] = ConcurrentSHA3.rotate64(A[15] ^ (dd = this.C[2] ^ ConcurrentSHA3.rotate64(this.C[4], 1)), 28);
            this.B[2] = ConcurrentSHA3.rotate64(A[ 5] ^ (db = this.C[0] ^ ConcurrentSHA3.rotate64(this.C[2], 1)),  1);
            this.B[3] = ConcurrentSHA3.rotate64(A[20] ^ (de = this.C[3] ^ ConcurrentSHA3.rotate64(this.C[0], 1)), 27);
            this.B[4] = ConcurrentSHA3.rotate64(A[10] ^ (dc = this.C[1] ^ ConcurrentSHA3.rotate64(this.C[3], 1)), 62);
            
            this.B[5] = ConcurrentSHA3.rotate64(A[ 6] ^ db, 44);
            this.B[6] = ConcurrentSHA3.rotate64(A[21] ^ de, 20);
            this.B[7] = ConcurrentSHA3.rotate64(A[11] ^ dc,  6);
            this.B[8] = ConcurrentSHA3.rotate64(A[ 1] ^ da, 36);
            this.B[9] = ConcurrentSHA3.rotate64(A[16] ^ dd, 55);
            
            this.B[10] = ConcurrentSHA3.rotate64(A[12] ^ dc, 43);
            this.B[11] = ConcurrentSHA3.rotate64(A[ 2] ^ da,  3);
            this.B[12] = ConcurrentSHA3.rotate64(A[17] ^ dd, 25);
            this.B[13] = ConcurrentSHA3.rotate64(A[ 7] ^ db, 10);
            this.B[14] = ConcurrentSHA3.rotate64(A[22] ^ de, 39);
            
            this.B[15] = ConcurrentSHA3.rotate64(A[18] ^ dd, 21);
            this.B[16] = ConcurrentSHA3.rotate64(A[ 8] ^ db, 45);
            this.B[17] = ConcurrentSHA3.rotate64(A[23] ^ de,  8);
            this.B[18] = ConcurrentSHA3.rotate64(A[13] ^ dc, 15);
            this.B[19] = ConcurrentSHA3.rotate64(A[ 3] ^ da, 41);
            
            this.B[20] = ConcurrentSHA3.rotate64(A[24] ^ de, 14);
            this.B[21] = ConcurrentSHA3.rotate64(A[14] ^ dc, 61);
            this.B[22] = ConcurrentSHA3.rotate64(A[ 4] ^ da, 18);
            this.B[23] = ConcurrentSHA3.rotate64(A[19] ^ dd, 56);
            this.B[24] = ConcurrentSHA3.rotate64(A[ 9] ^ db,  2);
	}
        else
	{
	    /* ρ and π steps, with last two part of θ */
            this.B[0] =             A[ 0] ^ (da = this.C[4] ^ this.rotate(this.C[1], 1));
            this.B[1] = this.rotate(A[15] ^ (dd = this.C[2] ^ this.rotate(this.C[4], 1)), 28);
            this.B[2] = this.rotate(A[ 5] ^ (db = this.C[0] ^ this.rotate(this.C[2], 1)),  1);
            this.B[3] = this.rotate(A[20] ^ (de = this.C[3] ^ this.rotate(this.C[0], 1)), 27);
            this.B[4] = this.rotate(A[10] ^ (dc = this.C[1] ^ this.rotate(this.C[3], 1)), 62);
            
            this.B[5] = this.rotate(A[ 6] ^ db, 44);
            this.B[6] = this.rotate(A[21] ^ de, 20);
            this.B[7] = this.rotate(A[11] ^ dc,  6);
            this.B[8] = this.rotate(A[ 1] ^ da, 36);
            this.B[9] = this.rotate(A[16] ^ dd, 55);
            
            this.B[10] = this.rotate(A[12] ^ dc, 43);
            this.B[11] = this.rotate(A[ 2] ^ da,  3);
            this.B[12] = this.rotate(A[17] ^ dd, 25);
	    this.B[13] = this.rotate(A[ 7] ^ db, 10);
            this.B[14] = this.rotate(A[22] ^ de, 39);
            
            this.B[15] = this.rotate(A[18] ^ dd, 21);
            this.B[16] = this.rotate(A[ 8] ^ db, 45);
            this.B[17] = this.rotate(A[23] ^ de,  8);
            this.B[18] = this.rotate(A[13] ^ dc, 15);
            this.B[19] = this.rotate(A[ 3] ^ da, 41);
            
            this.B[20] = this.rotate(A[24] ^ de, 14);
            this.B[21] = this.rotate(A[14] ^ dc, 61);
            this.B[22] = this.rotate(A[ 4] ^ da, 18);
            this.B[23] = this.rotate(A[19] ^ dd, 56);
            this.B[24] = this.rotate(A[ 9] ^ db,  2);
	}
	
        /* ξ step */
	for (int i = 0; i < 15; i++)
	    A[i     ] = this.B[i     ] ^ ((~(this.B[i +  5])) & this.B[i + 10]);
	for (int i = 0; i < 5; i++)
	{
	    A[i + 15] = this.B[i + 15] ^ ((~(this.B[i + 20])) & this.B[i     ]);
	    A[i + 20] = this.B[i + 20] ^ ((~(this.B[i     ])) & this.B[i +  5]);
	}
	
        /* ι step */
        A[0] ^= rc;
    }
    
    
    /**
     * Perform Keccak-f function
     * 
     * @param  A  The current state
     */
    private void keccakF(long[] A)
    {
        if (this.nr == 24)
            for (int i = 0; i < 24; i++)
		this.keccakFRound(A, ConcurrentSHA3.RC[i]);
        else
            for (int i = 0; i < this.nr; i++)
		this.keccakFRound(A, ConcurrentSHA3.RC[i] & this.wmod);
    }
    
    
    /**
     * Convert a chunk of byte:s to a word
     * 
     * @param   message  The message
     * @param   msgoff   The number of times to loop has run times the bitrate
     * @param   rr       Bitrate in bytes
     * @param   ww       Word size in bytes
     * @param   off      The offset in the message
     * @return           Lane
     */
    private static long toLane(byte[] message, int msgoff, int rr, int ww, int off)
    {
	long rc = 0;
        int n = Math.min(message.length, rr) + msgoff;
        for (int i = off + ww - 1; i >= off; i--)
            rc = (rc << 8) | ((i < n) ? (long)(message[i] & 255) : 0L);
        return rc;
    }
    
    
    /**
     * Convert a chunk of byte:s to a 64-bit word
     * 
     * @param   message  The message
     * @param   msgoff   The number of times to loop has run times the bitrate
     * @param   rr       Bitrate in bytes
     * @param   off      The offset in the message
     * @return           Lane
     */
    private static long toLane64(byte[] message, int msgoff, int rr, int off)
    {
        int n = Math.min(message.length, rr) + msgoff;
        return ((off + 7 < n) ? ((long)(message[off + 7] & 255) << 56) : 0L) |
	       ((off + 6 < n) ? ((long)(message[off + 6] & 255) << 48) : 0L) |
	       ((off + 5 < n) ? ((long)(message[off + 5] & 255) << 40) : 0L) |
	       ((off + 4 < n) ? ((long)(message[off + 4] & 255) << 32) : 0L) |
	       ((off + 3 < n) ? ((long)(message[off + 3] & 255) << 24) : 0L) |
	       ((off + 2 < n) ? ((long)(message[off + 2] & 255) << 16) : 0L) |
	       ((off + 1 < n) ? ((long)(message[off + 1] & 255) <<  8) : 0L) |
	       ((off < n) ? ((long)(message[off] & 255)) : 0L);
    }
    
    
    /**
     * pad 10*1
     * 
     * @param   msg  The message to pad
     * @parm    len  The length of the message
     * @param   r    The bitrate
     * @return       The message padded
     */
    private static byte[] pad10star1(byte[] msg, int len, int r)
    {
        int nrf = (len <<= 3) >> 3;
        int nbrf = len & 7;
        int ll = len % r;
        
        byte b = (byte)(nbrf == 0 ? 1 : ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf)));
        
        byte[] message;
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
    public void initialise(int r, int c, int n)
    {
        this.r = r;
        this.c = c;
        this.n = n;
        this.b = r + c;
        this.w = this.b / 25;
        this.l = ConcurrentSHA3.lb(this.w);
        this.nr = 12 + (this.l << 1);
        this.wmod = w == 64 ? -1L : (1L << this.w) - 1L;
        this.S = new long[25];
        this.M = new byte[(this.r * this.b) >> 2];
	this.mptr = 0;
    }
    
    
    /**
     * Absorb the more of the message message to the Keccak sponge
     * 
     * @param  msg  The partial message
     */
    public void update(byte[] msg)
    {
	this.update(msg, msg.length);
    }
    
    
    /**
     * Absorb the more of the message message to the Keccak sponge
     * 
     * @param  msg     The partial message
     * @param  msglen  The length of the partial message
     */
    public void update(byte[] msg, int msglen)
    {
        int rr = this.r >> 3;
        int ww = this.w >> 3;
        
	if (this.mptr + msglen > this.M.length)
	    System.arraycopy(this.M, 0, this.M = new byte[(this.M.length + msglen) << 1], 0, this.mptr);
	System.arraycopy(msg, 0, this.M, this.mptr, msglen);
        int len = this.mptr += msglen;
        len -= len % ((this.r * this.b) >> 3);
        byte[] message;
	System.arraycopy(this.M, 0, message = new byte[len], 0, len);
	System.arraycopy(this.M, len, this.M, 0, this.mptr -= len);
	
        /* Absorbing phase */
        if (ww == 8)
            for (int i = 0; i < len; i += rr)
	    {
		this.S[ 0] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 0);
		this.S[ 5] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 8);
		this.S[10] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 16);
                this.S[15] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 24);
                this.S[20] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 32);
                this.S[ 1] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 40);
                this.S[ 6] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 48);
                this.S[11] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 56);
                this.S[16] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 64);
                this.S[21] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 72);
                this.S[ 2] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 80);
                this.S[ 7] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 88);
		this.S[12] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 96);
		this.S[17] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 104);
		this.S[22] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 112);
		this.S[ 3] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 120);
		this.S[ 8] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 128);
		this.S[13] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 136);
		this.S[18] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 144);
		this.S[23] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 152);
                this.S[ 4] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 160);
                this.S[ 9] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 168);
                this.S[14] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 176);
                this.S[19] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 184);
                this.S[24] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 192);
		this.keccakF(this.S);
	    }
        else
	    for (int i = 0; i < len; i += rr)
	    {
		this.S[ 0] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  0    );
		this.S[ 5] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +      w);
		this.S[10] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  2 * w);
                this.S[15] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  3 * w);
                this.S[20] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  4 * w);
                this.S[ 1] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  5 * w);
                this.S[ 6] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  6 * w);
                this.S[11] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  7 * w);
                this.S[16] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  8 * w);
                this.S[21] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  9 * w);
                this.S[ 2] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 10 * w);
                this.S[ 7] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 11 * w);
		this.S[12] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 12 * w);
		this.S[17] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 13 * w);
		this.S[22] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 14 * w);
		this.S[ 3] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 15 * w);
		this.S[ 8] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 16 * w);
		this.S[13] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 17 * w);
		this.S[18] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 18 * w);
		this.S[23] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 19 * w);
                this.S[ 4] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 20 * w);
                this.S[ 9] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 21 * w);
                this.S[14] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 22 * w);
                this.S[19] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 23 * w);
                this.S[24] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 24 * w);
		this.keccakF(this.S);
	    }
    }
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @return  The hash sum
     */
    public byte[] digest()
    {
	return this.digest(null, 0, true);
    }
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public byte[] digest(boolean withReturn)
    {
	return this.digest(null, 0, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg  The rest of the message
     * @return       The hash sum
     */
    public byte[] digest(byte[] msg)
    {
	return this.digest(msg, msg == null ? 0 : msg.length, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public byte[] digest(byte[] msg, boolean withReturn)
    {
	return this.digest(msg, msg == null ? 0 : msg.length, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg     The rest of the message
     * @param   msglen  The length of the partial message
     * @return          The hash sum
     */
    public byte[] digest(byte[] msg, int msglen)
    {
	return this.digest(msg, msg == null ? 0 : msg.length, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   msglen      The length of the partial message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public byte[] digest(byte[] msg, int msglen, boolean withReturn)
    {
	byte[] message;
        if ((msg == null) || (msglen == 0))
            message = ConcurrentSHA3.pad10star1(this.M, this.mptr, this.r);
	else
	{
	    if (this.mptr + msglen > this.M.length)
		System.arraycopy(this.M, 0, this.M = new byte[this.M.length + msglen], 0, this.mptr);
	    System.arraycopy(msg, 0, this.M, this.mptr, msglen);
	    message = ConcurrentSHA3.pad10star1(this.M, this.mptr + msglen, this.r);
	}
        this.M = null;
        int len = message.length;
        
        int rr = this.r >> 3;
        int nn = (this.n + 7) >> 3;
        int ww = this.w >> 3;
        
        /* Absorbing phase */
        if (ww == 8)
            for (int i = 0; i < len; i += rr)
	    {
		this.S[ 0] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 0);
		this.S[ 5] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 8);
		this.S[10] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 16);
                this.S[15] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 24);
                this.S[20] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 32);
                this.S[ 1] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 40);
                this.S[ 6] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 48);
                this.S[11] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 56);
                this.S[16] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 64);
                this.S[21] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 72);
                this.S[ 2] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 80);
                this.S[ 7] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 88);
		this.S[12] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 96);
		this.S[17] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 104);
		this.S[22] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 112);
		this.S[ 3] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 120);
		this.S[ 8] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 128);
		this.S[13] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 136);
		this.S[18] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 144);
		this.S[23] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 152);
                this.S[ 4] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 160);
                this.S[ 9] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 168);
                this.S[14] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 176);
                this.S[19] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 184);
                this.S[24] ^= ConcurrentSHA3.toLane64(message, i, rr, i + 192);
                this.keccakF(this.S);
	    }
        else
	    for (int i = 0; i < len; i += rr)
	    {
		this.S[ 0] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  0    );
		this.S[ 5] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +      w);
		this.S[10] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  2 * w);
                this.S[15] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  3 * w);
                this.S[20] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  4 * w);
                this.S[ 1] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  5 * w);
                this.S[ 6] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  6 * w);
                this.S[11] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  7 * w);
                this.S[16] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  8 * w);
                this.S[21] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i +  9 * w);
                this.S[ 2] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 10 * w);
                this.S[ 7] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 11 * w);
		this.S[12] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 12 * w);
		this.S[17] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 13 * w);
		this.S[22] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 14 * w);
		this.S[ 3] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 15 * w);
		this.S[ 8] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 16 * w);
		this.S[13] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 17 * w);
		this.S[18] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 18 * w);
		this.S[23] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 19 * w);
                this.S[ 4] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 20 * w);
                this.S[ 9] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 21 * w);
                this.S[14] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 22 * w);
                this.S[19] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 23 * w);
                this.S[24] ^= ConcurrentSHA3.toLane(message, i, rr, ww, i + 24 * w);
		this.keccakF(this.S);
	    }
        
        /* Squeezing phase */
	if (withReturn)
	{
	    byte[] rc = new byte[(this.n + 7) >> 3];
	    int ptr = 0;
	    
	    int olen = this.n;
	    int j = 0;
	    int ni = Math.min(25, rr);
	    while (olen > 0)
	    {
		int i = 0;
		while ((i < ni) && (j < nn))
		{
		    long v = this.S[(i % 5) * 5 + i / 5];
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
		olen -= this.r;
		if (olen > 0)
		    this.keccakF(this.S);
	    }
	    if ((this.n & 7) != 0)
		rc[rc.length - 1] &= (1 << (this.n & 7)) - 1;
	    
	    return rc;
	}
        int olen = this.n;
        while ((olen -= this.r) > 0)
	    this.keccakF(this.S);
	return null;
    }
    
    
    /**
     * Force a round of Keccak-f
     */
    public void simpleSqueeze()
    {
	this.keccakF(this.S);
    }
    
    
    /**
     * Force some rounds of Keccak-f
     * 
     * @param  times  The number of rounds
     */
    public void simpleSqueeze(int times)
    {
	for (int i = 0; i < times; i++)
	    this.keccakF(this.S);
    }
    
    
    /**
     * Squeeze as much as is needed to get a digest
     */
    public void fastSqueeze()
    {
	this.keccakF(this.S); /* Last squeeze did not do a ending squeeze */
        int olen = this.n;
        while ((olen -= this.r) > 0)
	    this.keccakF(this.S);
    }
    
    
    /**
     * Squeeze as much as is needed to get a digest a number of times
     * 
     * @param  times  The number of digests
     */
    public void fastSqueeze(int times)
    {
	for (int i = 0; i < times; i++)
	{
	    this.keccakF(this.S); /* Last squeeze did not do a ending squeeze */
	    int olen = this.n;
	    while ((olen -= this.r) > 0)
		this.keccakF(this.S);
	}
    }
    
    
    /**
     * Squeeze out another digest
     * 
     * @return  The hash sum
     */
    public byte[] squeeze()
    {
	this.keccakF(this.S); /* Last squeeze did not do a ending squeeze */
	
        int nn, ww = this.w >> 3;
        byte[] rc = new byte[nn = (this.n + 7) >> 3];
	
        int olen = this.n;
        int j = 0, ptr = 0;
        int ni = Math.min(25, this.r >> 3);
        while (olen > 0)
	{
            int i = 0;
	    while ((i < ni) && (j < nn))
	    {
		long v = this.S[(i % 5) * 5 + i / 5];
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
            olen -= this.r;
	    if (olen > 0)
		this.keccakF(this.S);
	}
	if ((this.n & 7) != 0)
	    rc[rc.length - 1] &= (1 << (this.n & 7)) - 1;
	
        return rc;
    }
    
}

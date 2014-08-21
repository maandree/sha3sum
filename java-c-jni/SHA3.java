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
import java.io.*;
import java.util.*;


/**
 * SHA-3/Keccak hash algorithm implementation
 * 
 * @author  Mattias Andrée  <a href="mailto:maandree@member.fsf.org">maandree@member.fsf.org</a>
 */
public class SHA3
{
    /**
     * Suffix the message when calculating the Keccak hash sum
     */
    public static final String KECCAK_SUFFIX = "";
    
    /**
     * Suffix the message when calculating the SHA-3 hash sum
     */
    public static final String SHA3_SUFFIX = "01";
    
    /**
     * Suffix the message when calculating the RawSHAKE hash sum
     */
    public static final String RawSHAKE_SUFFIX = "11";
    
    /**
     * Suffix the message when calculating the SHAKE hash sum
     */
    public static final String SHAKE_SUFFIX = "1111";
    
    
    
    /**
     * Hidden constructor
     */
    private SHA3()
    {
	// Inhibit instansiation
    }
    

    
    /**
     * Class initialiser
     */
    static
    {
	try
	{
	    System.load((new File("./SHA3.so")).getCanonicalPath());
	}
	catch (IOException err)
	{
	    throw new Error("SHA3 library cannot be found");
	}
    }
    
    
    
    /**
     * Initialise Keccak sponge
     * 
     * @param  r  The bitrate
     * @param  c  The capacity
     * @param  n  The output size
     */
    public static native void initialise(int r, int c, int n);
    
    
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
    public static native void update(byte[] msg, int msglen);
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @return  The hash sum
     */
    public static byte[] digest()
    {
	return digest(null, 0, 0, SHA3.SHA3_SUFFIX, true);
    }
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @param   suffix  The suffix concatenate to the message
     * @return          The hash sum
     */
    public static byte[] digest(String suffix)
    {
	return digest(null, 0, 0, suffix, true);
    }
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(boolean withReturn)
    {
	return digest(null, 0, 0, SHA3.SHA3_SUFFIX, withReturn);
    }
    
    
    /**
     * Squeeze the Keccak sponge
     * 
     * @param   suffix      The suffix concatenate to the message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(String suffix, boolean withReturn)
    {
	return digest(null, 0, 0, suffix, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg  The rest of the message
     * @return       The hash sum
     */
    public static byte[] digest(byte[] msg)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, SHA3.SHA3_SUFFIX, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg     The rest of the message
     * @param   suffix  The suffix concatenate to the message
     * @return          The hash sum
     */
    public static byte[] digest(byte[] msg, String suffix)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, suffix, true);
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
	return digest(msg, msg == null ? 0 : msg.length, 0, SHA3.SHA3_SUFFIX, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   suffix      The suffix concatenate to the message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(byte[] msg, String suffix, boolean withReturn)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, suffix, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg     The rest of the message
     * @param   msglen  The length of the partial message in while bytes
     * @return          The hash sum
     */
    public static byte[] digest(byte[] msg, int msglen)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, SHA3.SHA3_SUFFIX, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg     The rest of the message
     * @param   msglen  The length of the partial message in while bytes
     * @param   suffix  The suffix concatenate to the message
     * @return          The hash sum
     */
    public static byte[] digest(byte[] msg, int msglen, String suffix)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, suffix, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg     The rest of the message
     * @param   msglen  The length of the partial message in while bytes
     * @param   bits    The number of bits at the end of the message not covered by <tt>msglen</tt>
     * @return          The hash sum
     */
    public static byte[] digest(byte[] msg, int msglen, int bits)
    {
	return digest(msg, msg == null ? 0 : msg.length, bits, SHA3.SHA3_SUFFIX, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg     The rest of the message
     * @param   msglen  The length of the partial message in while bytes
     * @param   bits    The number of bits at the end of the message not covered by <tt>msglen</tt>
     * @param   suffix  The suffix concatenate to the message
     * @return          The hash sum
     */
    public static byte[] digest(byte[] msg, int msglen, int bits, String suffix)
    {
	return digest(msg, msg == null ? 0 : msg.length, bits, suffix, true);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   msglen      The length of the partial message in while bytes
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(byte[] msg, int msglen, boolean withReturn)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, SHA3.SHA3_SUFFIX, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   msglen      The length of the partial message in while bytes
     * @param   suffix      The suffix concatenate to the message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(byte[] msg, int msglen, String suffix, boolean withReturn)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, suffix, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   msglen      The length of the partial message in while bytes
     * @param   bits        The number of bits at the end of the message not covered by <tt>msglen</tt>
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(byte[] msg, int msglen, int bits, boolean withReturn)
    {
	return digest(msg, msg == null ? 0 : msg.length, 0, SHA3.SHA3_SUFFIX, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   msglen      The length of the partial message
     * @param   bits        The number of bits at the end of the message not covered by <tt>msglen</tt>
     * @param   suffix      The suffix concatenate to the message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static byte[] digest(byte[] msg, int msglen, int bits, String suffix, boolean withReturn)
    {
	int[] suffix_ = new int[suffix.length()];
	for (int i = 0, n = suffix_.length; i < n; i++)
	    suffix_[i] = suffix.charAt(i) == '1' ? 1 : 0;
	
	return digest(msg, msglen, bits, suffix_, withReturn);
    }
    
    
    /**
     * Absorb the last part of the message and squeeze the Keccak sponge
     * 
     * @param   msg         The rest of the message
     * @param   msglen      The length of the partial message
     * @param   bits        The number of bits at the end of the message not covered by <tt>msglen</tt>
     * @param   suffix      The suffix concatenate to the message
     * @param   withReturn  Whether to return the hash instead of just do a quick squeeze phrase and return {@code null}
     * @return              The hash sum, or {@code null} if <tt>withReturn</tt> is {@code false}
     */
    public static native byte[] digest(byte[] msg, int msglen, int bits, int[] suffix, boolean withReturn);
    
    
    /**
     * Force a round of Keccak-f
     */
    public static void simpleSqueeze()
    {
	simpleSqueeze(1);
    }
    
    
    /**
     * Force some rounds of Keccak-f
     * 
     * @param  times  The number of rounds
     */
    public static native void simpleSqueeze(int times);
    
    
    /**
     * Squeeze as much as is needed to get a digest
     */
    public static void fastSqueeze()
    {
	fastSqueeze(1);
    }
    
    
    /**
     * Squeeze as much as is needed to get a digest a number of times
     * 
     * @param  times  The number of digests
     */
    public static native void fastSqueeze(int times);
    
    
    /**
     * Squeeze out another digest
     * 
     * @return  The hash sum
     */
    public static native byte[] squeeze();
    
}


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

import java.io.*;
import java.util.*;


/**
 * SHA-3/Keccak checksum calculator
 * 
 * @author  Mattias Andrée  <a href="mailto:maandree@member.fsf.org">maandree@member.fsf.org</a>
 */
public class sha3sum
{
    /**
     * This is the main entry point of the program
     * 
     * @param   args         Command line arguments
     * @throws  IOException  On I/O error (such as broken pipes)
     */
    public static void main(String[] args) throws IOException
    {
	run("sha3sum", args);
    }
    
    
    /**
     * Run the program
     * 
     * @param   cmd          The command
     * @param   argv         Command line arguments
     * @throws  IOException  On I/O error (such as broken pipes)
     */
    public static void run(String cmd, String[] argv) throws IOException
    {
	if (cmd.indexOf('/') >= 0)
	    cmd = cmd.substring(cmd.lastIndexOf('/') + 1);
	if (cmd.endsWith(".jar"))
	    cmd = cmd.substring(0, cmd.length() - 4);
	cmd = cmd.intern();
	
	Integer O = null; int _o = 512;             /* --outputsize */
	Integer S = null; int _s = 1600;            /* --statesize  */
	Integer R = null; int _r = _s - (_o << 1);  /* --bitrate    */
	Integer C = null; int _c = _s - _r;         /* --capacity   */
	Integer W = null; int _w = _s / 25;         /* --wordsize   */
	Integer I = null; int _i = 1;               /* --iterations */
	int o = 0, s = 0, r = 0, c = 0, w = 0, i = 0;
	
	if      (cmd == "sha3-224sum")  o = _o = 224;
	else if (cmd == "sha3-256sum")  o = _o = 256;
	else if (cmd == "sha3-384sum")  o = _o = 384;
	else if (cmd == "sha3-512sum")  o = _o = 512;
	boolean binary = false, hex = false;
	int multi = 0;
	
	String[] files = new String[argv.length + 1];
	int fptr = 0;
	boolean dashed = false;
	String[] linger = null;
	
	String[] args = new String[argv.length + 1];
	System.arraycopy(argv, 0, args, 0, argv.length);
	for (int a = 0, an = args.length; a < an; a++)
	{   String arg = args[a];
	    arg = arg == null ? null : arg.intern();
	    if (linger != null)
	    {
		linger[0] = linger[0].intern();
		if ((linger[0] == "-h") || (linger[0] == "--help"))
		{
		    System.out.println("");
		    System.out.println("SHA-3/Keccak checksum calculator");
		    System.out.println("");
		    System.out.println("USAGE:	sha3sum [option...] < file");
		    System.out.println("	sha3sum [option...] file...");
		    System.out.println("");
		    System.out.println("");
		    System.out.println("OPTIONS:");
		    System.out.println("        -r BITRATE");
		    System.out.println("        --bitrate       The bitrate to use for SHA-3.           (default: " + _r + ")");
		    System.out.println("        ");
		    System.out.println("        -c CAPACITY");
		    System.out.println("        --capacity      The capacity to use for SHA-3.          (default: " + _c + ")");
		    System.out.println("        ");
		    System.out.println("        -w WORDSIZE");
		    System.out.println("        --wordsize      The word size to use for SHA-3.         (default: " + _w + ")");
		    System.out.println("        ");
		    System.out.println("        -o OUTPUTSIZE");
		    System.out.println("        --outputsize    The output size to use for SHA-3.       (default: " + _o + ")");
		    System.out.println("        ");
		    System.out.println("        -s STATESIZE");
		    System.out.println("        --statesize     The state size to use for SHA-3.        (default: " + _s + ")");
		    System.out.println("        ");
		    System.out.println("        -i ITERATIONS");
		    System.out.println("        --iterations    The number of hash iterations to run.   (default: " + _i + ")");
		    System.out.println("        ");
		    System.out.println("        -h");
		    System.out.println("        --hex           Read the input in hexadecimal, rather than binary.");
		    System.out.println("        ");
		    System.out.println("        -b");
		    System.out.println("        --binary        Print the checksum in binary, rather than hexadecimal.");
		    System.out.println("        ");
		    System.out.println("        -m");
		    System.out.println("        --multi         Print the chechsum at all iterations.");
		    System.out.println("");
		    System.out.println("");
		    System.out.println("COPYRIGHT:");
		    System.out.println("");
		    System.out.println("Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)");
		    System.out.println("");
		    System.out.println("This program is free software: you can redistribute it and/or modify");
		    System.out.println("it under the terms of the GNU General Public License as published by");
		    System.out.println("the Free Software Foundation, either version 3 of the License, or");
		    System.out.println("(at your option) any later version.");
		    System.out.println("");
		    System.out.println("This program is distributed in the hope that it will be useful,");
		    System.out.println("but WITHOUT ANY WARRANTY; without even the implied warranty of");
		    System.out.println("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the");
		    System.out.println("GNU General Public License for more details.");
		    System.out.println("");
		    System.out.println("You should have received a copy of the GNU General Public License");
		    System.out.println("along with this program.  If not, see <http://www.gnu.org/licenses/>.");
		    System.out.println("");
		    System.exit(2);
		}
		else
		{
		    if (linger[1] == null)
		    {
			linger[1] = arg;
			arg = null;
		    }
		    if ((linger[0] == "-r") || (linger[0] == "--bitrate"))
			R = Integer.valueOf(linger[1]);
		    else if ((linger[0] == "-c") || (linger[0] == "--capacity"))
			C = Integer.valueOf(linger[1]);
		    else if ((linger[0] == "-w") || (linger[0] == "--wordsize"))
			W = Integer.valueOf(linger[1]);
		    else if ((linger[0] == "-o") || (linger[0] == "--outputsize"))
			O = Integer.valueOf(linger[1]);
		    else if ((linger[0] == "-s") || (linger[0] == "--statesize"))
			S = Integer.valueOf(linger[1]);
		    else if ((linger[0] == "-i") || (linger[0] == "--iterations"))
			I = Integer.valueOf(linger[1]);
		    else
		    {
			System.err.println(cmd + ": unrecognised option: " + linger[0]);
			System.exit(1);
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
	    else if (arg.startsWith("--"))
		if (arg.indexOf('=') >= 0)
	            linger = new String[] { arg.substring(0, arg.indexOf('=')), arg.substring(arg.indexOf('=') + 1) };
		else
		    if (arg == "--binary")
	                binary = true;
		    else if (arg == "--multi")
	                multi++;
		    else if (arg == "--hex")
	                hex = true;
		    else
			linger = new String[] { arg, null };
	    else if (arg.startsWith("-"))
	    {
		arg = arg.substring(1);
                if (arg.charAt(0) == 'b')
		{
                    binary = true;
		    arg = arg.substring(1);
		}
                else if (arg.charAt(0) == 'm')
		{
                    multi++;
		    arg = arg.substring(1);
		}
                else if (arg.charAt(0) == 'h')
		{
                    hex = true;
		    arg = arg.substring(1);
		}
                else if (arg.length() == 1)
		    linger = new String[] { "-" + arg, null };
                else
                    linger = new String[] { "-" + arg.charAt(0), arg.substring(1) };
	    }
            else
                files[fptr++] = arg;
	}
	
	
	i = I == null ? _i : I.intValue();
	
	if (S != null)
	{   s = S.intValue();
	    if ((s <= 0) || (s > 1600) || (s % 25 != 0))
	    {	System.err.println("The state size must be a positive multiple of 25 and is limited to 1600.");
		System.exit(6);
	}   }
	
	if (W != null)
	{   w = W.intValue();
	    if ((w <= 0) || (w > 64))
	    {	System.err.println("The word size must be positive and is limited to 64.");
		System.exit(6);
	    }
	    if ((S != null) && (s != w * 25))
	    {	System.err.println("The state size must be 25 times of the word size.");
		System.exit(6);
	    }
	    else if (S == null)
		s = new Integer(w * 25);
	}
	
	if (C != null)
	{   c = C.intValue();
	    if ((c <= 0) || ((c & 7) != 0))
	    {	System.err.println("The capacity must be a positive multiple of 8.");
		System.exit(6);
	}   }
	
	if (R != null)
	{   r = R.intValue();
	    if ((r <= 0) || ((r & 7) != 0))
	    {	System.err.println("The bitrate must be a positive multiple of 8.");
		System.exit(6);
	}   }
	
	if (O != null)
	{   o = O.intValue();
	    if (o <= 0)
	    {	System.err.println("The output size must be positive.");
		System.exit(6);
	}   }
	
	
	if ((R == null) && (C == null) && (O == null)) // s?
	{   r = -((c = (o = ((((s = S == null ? _s : s) << 5) / 100 + 7) >> 3) << 3) << 1) - s);
	    o = o < 8 ? 8 : o;
	}
	else if ((R == null) && (C == null)) // !o s?
	{   r = _r;
	    c = _c;
	    s = S == null ? (r + c) : s;
	}
	else if (R == null) // !c o? s?
	{   r = (s = S == null ? _s : s) - c;
	    o = O == null ? (c == 8 ? 8 : (c << 1)) : o;
	}
	else if (C == null) // !r o? s?
	{   c = (s = S == null ? _s : s) - r;
	    o = O == null ? (c == 8 ? 8 : (c << 1)) : o;
	}
	else // !r !c o? s?
	{   s = S == null ? (r + c) : s;
	    o = O == null ? (c == 8 ? 8 : (c << 1)) : o;
	}
	
	
	if (r > s)
	{   System.err.println("The bitrate must not be higher than the state size.");
	    System.exit(6);
	}
	if (c > s)
	{   System.err.println("The capacity must not be higher than the state size.");
	    System.exit(6);
	}
	if (r + c != s)
	{   System.err.println("The sum of the bitrate and the capacity must equal the state size.");
	    System.exit(6);
	}
	
	
	System.err.println("Bitrate: " + r);
	System.err.println("Capacity: " + c);
	System.err.println("Word size: " + w);
	System.err.println("State size: " + s);
	System.err.println("Output size: " + o);
	System.err.println("Iterations: " + i);
	
	
	if (fptr == 0)
	    files[fptr++] = null;
	if (i < 1)
	{
	    System.err.println(cmd + ": sorry, I will only do at least one iteration!");
	    System.exit(3);
	}
	
	byte[] stdin = null;
	boolean fail = false;
	String filename;

	for (int f = 0; f < fptr; f++)
	{   if (((filename = files[f]) == null) && (stdin != null))
	    {	System.out.write(stdin);
		continue;
	    }
	    String rc = "";
	    String fn = filename == null ? "/dev/stdin" : filename;
	    InputStream file = null;
	    try
	    {
		file = new FileInputStream(fn);
		SHA3.initialise(r, c, o);
		int blksize = 4096; /** XXX os.stat(os.path.realpath(fn)).st_size; **/
		byte[] chunk = new byte[blksize];
		for (;;)
		{
		    int read = file.read(chunk, 0, blksize);
		    if (read <= 0)
			break;
		    if (hex == false)
			SHA3.update(chunk, read);
		    else
		    {
		        int n = read << 1;
			for (int _ = 0; _ < n; _++)
			{
			    byte a = chunk[_ << 1], b = chunk[(_ << 1) | 1];
			    chunk[_] = (byte)((((a & 15) + (a <= '9' ? 0 : 9)) << 4) | ((b & 15) + (b <= '9' ? 0 : 9)));
			}
			SHA3.update(chunk, n);
		    }
		}
		byte[] bs = SHA3.digest();
		if (multi == 0)
		{
		    for (int _ = 1; _ < i; _++)
		    {
			SHA3.initialise(r, c, o);
			bs = SHA3.digest(bs);
		    }
		    if (binary)
		    {   if (filename == null)
			    stdin = bs;
			System.out.write(bs);
		    }
		    else
		    {   for (int b = 0, bn = bs.length; b < bn; b++)
			{   rc += "0123456789ABCDEF".charAt((bs[b] >> 4) & 15);
			    rc += "0123456789ABCDEF".charAt(bs[b] & 15);
			}
			rc += " " + (filename == null ? "-" : filename) + "\n";
			if (filename == null)
			    stdin = rc.getBytes("UTF-8");
			System.out.print(rc);
		    }
		}
		else if (binary)
		{
		    System.out.write(bs);
		    for (int _ = 1; _ < i; _++)
		    {
			SHA3.initialise(r, c, o);
			System.out.write(bs = SHA3.digest(bs));
		    }
		}
		else if (multi == 1)
		{
		    byte[] out = new byte[(bs.length << 1) + 1];
		    for (int b = 0, bn = bs.length; b < bn; b++)
		    {   out[ b << 1     ] = (byte)("0123456789ABCDEF".charAt((bs[b] >> 4) & 15));
			out[(b << 1) | 1] = (byte)("0123456789ABCDEF".charAt(bs[b] & 15));
		    }
		    out[out.length - 1] = '\n';
		    System.out.write(out);
		    for (int _ = 1; _ < i; _++)
		    {
			SHA3.initialise(r, c, o);
			bs = SHA3.digest(bs);
			for (int b = 0, bn = bs.length; b < bn; b++)
			{   out[ b << 1     ] = (byte)("0123456789ABCDEF".charAt((bs[b] >> 4) & 15));
			    out[(b << 1) | 1] = (byte)("0123456789ABCDEF".charAt(bs[b] & 15));
			}
			System.out.write(out);
		    }
		}
		else
		{
		    HashSet<String> got = new HashSet<String>();
		    String loop = null;
		    byte[] out = new byte[(bs.length << 1)];
		    for (int _ = 0; _ < i; _++)
		    {
			if (_ > 0)
			{   SHA3.initialise(r, c, o);
			    bs = SHA3.digest(bs);
			}
			for (int b = 0, bn = bs.length; b < bn; b++)
			{   out[ b << 1     ] = (byte)("0123456789ABCDEF".charAt((bs[b] >> 4) & 15));
			    out[(b << 1) | 1] = (byte)("0123456789ABCDEF".charAt(bs[b] & 15));
			}
			String now = new String(out, "UTF-8");
			if (loop == null)
			    if (got.contains(now))
				loop = now;
			    else
				got.add(now);
			if ((loop != null) && (loop.equals(now)))
			    now = "\033[31m" + now + "\033[00m";
			System.out.println(now);
		    }
		    if (loop != null)
			System.out.println("\033[01;31mLoop found\033[00m");
		}
		System.out.flush();
	    }
	    catch (final IOException err)
	    {   System.err.println(cmd + ": cannot read file: " + filename + ": " + err);
		fail = true;
	    }
	    finally
	    {   if (file != null)
		    try
		    {	file.close();
		    }
		    catch (final Throwable ignore)
		    {   //ignore
	}   }	    }
	
	System.out.flush();
	if (fail)
	    System.exit(5);
    }
    
}


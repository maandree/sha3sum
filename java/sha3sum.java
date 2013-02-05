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
 * SHA-3/Keccak chechsum calculator
 * 
 * @author  Mattias Andrée  <a href="mailto:maandree@member.fsf.org">maandree@member.fsf.org</a>
 */
public class sha3sum
{
    /**
     * This is the main entry point of the program
     * 
     * @param   argv         Command line arguments
     * @throws  IOException  On I/O error (such as broken pipes)
     */
    public static void main(String[] argv) throws IOException
    {
	String cmd, _cmd = cmd = ""; //FIXME  /proc/self/cmdline split ^@ [0]
	if (cmd.indexOf('/') >= 0)
	    cmd = cmd.substring(cmd.lastIndexOf('/') + 1);
	if (cmd.endsWith(".jar"))
	    cmd = cmd.substring(0, cmd.length() - 3);
	cmd = cmd.intern();
	
	int _o, o = _o = 512;           /* --outputsize */
	if      (cmd == "sha3-224sum")  o = _o = 224;
	else if (cmd == "sha3-256sum")  o = _o = 256;
	else if (cmd == "sha3-384sum")  o = _o = 384;
	else if (cmd == "sha3-512sum")  o = _o = 512;
	int _s, s = _s = 1600;          /* --statesiz e */
	int _r, r = _r = s - (o << 1);  /* --bitrate    */
	int _c, c = _c = s - r;         /* --capacity   */
	int _w, w = _w = s / 25;        /* --wordsize   */
	int _i, i = _i = 1;             /* --iterations */
	boolean binary = false;
	
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
		    System.out.println("        -b");
		    System.out.println("        --binary        Print the checksum in binary, rather than hexadecimal.");
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
			o = (s - (r = Integer.parseInt(linger[1]))) >> 1;
		    else if ((linger[0] == "-c") || (linger[0] == "--capacity"))
			r = s - (c = Integer.parseInt(linger[1]));
		    else if ((linger[0] == "-w") || (linger[0] == "--wordsize"))
			s = (w = Integer.parseInt(linger[1])) * 25;
		    else if ((linger[0] == "-o") || (linger[0] == "--outputsize"))
			r = s - ((o = Integer.parseInt(linger[1])) << 1);
		    else if ((linger[0] == "-s") || (linger[0] == "--statesize"))
			r = (s = Integer.parseInt(linger[1])) - (o << 1);
		    else if ((linger[0] == "-i") || (linger[0] == "--iterations"))
			i = Integer.parseInt(linger[1]);
		    else
		    {
			System.err.println(_cmd + ": unrecognised option: " + linger[0]);
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
                else if (arg.length() == 1)
		    linger = new String[] { "-" + arg, null };
                else
                    linger = new String[] { "-" + arg.charAt(0), arg.substring(1) };
	    }
            else
                files[fptr++] = arg;
	}
	
	if (fptr == 0)
	    files[fptr++] = null;
	if (i < 1)
	{
	    System.err.println(_cmd + ": sorry, I will only do at least one iteration!\n");
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
		    SHA3.update(chunk, read);
		}
		byte[] bs = SHA3.digest();
		for (int _ = 1; _ < i; _++)
		{
		    SHA3.initialise(r, c, o);
		    bs = SHA3.digest(bs);
		}
		if (binary)
		{   if (filename == null)
			stdin = bs;
		    System.out.write(bs);
		    System.out.flush();
		}
		else
		{   for (int b = 0, bn = bs.length; b < bn; b++)
		    {	rc += "0123456789ABCDEF".charAt((bs[b] >> 4) & 15);
			rc += "0123456789ABCDEF".charAt(bs[b] & 15);
		    }
		    rc += " " + (filename == null ? "-" : filename) + "\n";
		    if (filename == null)
			stdin = rc.getBytes("UTF-8");
		    System.out.print(rc);
		    System.out.flush();
		}
	    }
	    catch (final IOException err)
	    {   System.err.println(_cmd + ": Cannot read file: " + filename + ": " + err);
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


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
#include <stdio.h>
#include <alloca.h>
#include <sys/stat.h>

#include "sha3.h"


#define false 0
#define true  1
#define null  0

#define SET void**

#define HEXADECA "0123456789ABCDEF"


/**
 * Prints a number of bytes to stdout
 * 
 * @param  BYTES:char*  The bytes to print
 * @param  N:long       The number of bytes
 */
#define putchars(BYTES, N)  fwrite(BYTES, 1, N, stdout)


/**
 * Creates a new set
 * 
 * @return  The set
 */
SET set_new()
{
  long i;
  void** rc = (void**)malloc(sizeof(void*) << 4);
  for (i = 0; i < 16; i++)
    *(rc + i) = 0;
  return rc;
}


/**
 * Frees a set
 * 
 * @param  set  The set
 */
void set_free(SET restrict_ set)
{
  if (*(set +  0))  set_free((void**)*(set +  0));
  if (*(set +  1))  set_free((void**)*(set +  1));
  if (*(set +  2))  set_free((void**)*(set +  2));
  if (*(set +  3))  set_free((void**)*(set +  3));
  if (*(set +  4))  set_free((void**)*(set +  4));
  if (*(set +  5))  set_free((void**)*(set +  5));
  if (*(set +  6))  set_free((void**)*(set +  6));
  if (*(set +  7))  set_free((void**)*(set +  7));
  if (*(set +  8))  set_free((void**)*(set +  8));
  if (*(set +  9))  set_free((void**)*(set +  9));
  if (*(set + 10))  set_free((void**)*(set + 10));
  if (*(set + 11))  set_free((void**)*(set + 11));
  if (*(set + 12))  set_free((void**)*(set + 12));
  if (*(set + 13))  set_free((void**)*(set + 13));
  if (*(set + 14))  set_free((void**)*(set + 14));
  if (*(set + 15))  set_free((void**)*(set + 15));
  free(set);
}


/**
 * Adds an item to a set
 * 
 * @param  set   The set
 * @param  item  The item
 * @param  n     The length of the item
 */
void set_add(SET restrict_ set, char* restrict_ item, long n)
{
  long i, j;
  void** at = set;
  for (i = 0; i < n; i++)
    {
      long a = (long)((*(item + i)) & 15), b = (long)((*(item + i) >> 4) & 15);
      if (*(at + a))
	at = (void**)*(at + a);
      else
	{
	  at = (void**)(*(at + a) = (void*)malloc(sizeof(void*) << 4));
	  for (j = 0; j < 16; j++)
	    *(at + j) = 0;
	}
      if (*(at + b))
	at = (void**)*(at + b);
      else
	{
	  at = (void**)(*(at + b) = (void*)malloc(sizeof(void*) << 4));
	  for (j = 0; j < 16; j++)
	    *(at + j) = 0;
	}
    }
}


/**
 * Checks if a set contains an item
 * 
 * @param   set   The set
 * @param   item  The item
 * @param   n     The length of the item
 * @return        Whether the set contains the item
 */
long set_contains(SET restrict_ set, byte* restrict_ item, long n)
{
  long i;
  void** at = set;
  for (i = 0; i < n; i++)
    {
      long a = (long)((*(item + i)) & 15), b = (long)((*(item + i) >> 4) & 15);
      if (*(at + a))
	at = (void**)*(at + a);
      else
	return false;
      if (*(at + b))
	at = (void**)*(at + b);
      else
	return false;
    }
  return true;
}


/**
 * String equality comparator
 * 
 * @param   a  First comparand
 * @param   b  Second comparand
 * @return     Whether the comparands are equal
 */
long eq(char* restrict_ a, char* restrict_ b)
{
  while (*a)
    if (*a++ != *b++)
      return false;
  return !*b;
}


/**
 * Convert a string to an integer
 * 
 * @param   str  String representation
 * @return       Native representation
 */
long parseInt(char* restrict_ str)
{
  long rc = 0;
  while (*str)
    rc = rc * 10 - (*str++ & 15);
  return -rc;
}


/**
 * This is the main entry point of the program
 * 
 * @param   argc  Command line argument count
 * @param   argv  Command line arguments
 * @return        Exit value, zero on and only on successful execution
 */
int main(int argc, char** argv)
{
  char* out_alloc;
  byte* stdin_alloc;
  
  long _o, o, _s, s, _r, r, _c, c, _w, w, _i, i, _j, j;
  long _O, O, _S, S, _R, R, _C, C, _W, W, _I, I, _J, J;
  long binary = false, hex = false, dashed = false;
  long multi = 0, fptr = 0, bn;
  
  char** files = (char**)alloca((argc + 2) * sizeof(char*));
  char** linger = files + argc;
  char* linger0 = (char*)alloca(sizeof(char) << 13);
  
  long a = 0, an = argc - 1;
  char** args = argv + 1;
  char* cmd = *argv;
  
  
  _O = _S = _R = _C = _W = _I = _J = false;
  O = S = R = C = W = I = J = 0;
  o = s = r = c = w = i = j = 0;
  
  *linger = 0;
  
  
  s = -1;
  for (i = 0; *(cmd + i); i++)
    if (*(cmd + i) == '/')
      s = i;
  if (s >= 0)
    cmd += s + 1;
  
  _o = 512;           /* --outputsize */
  if ((cmd[0] == 's') && (cmd[1] == 'h') && (cmd[2] == 'a') && (cmd[3] == '3') && (cmd[4] == '-'))
    if ((cmd[5] != 0) && (cmd[6] != 0) && (cmd[7] != 0))
      if ((cmd[8] == 's') && (cmd[9] == 'u') && (cmd[10] == 'm') && (cmd[11] == 0))
	{
	  if ((cmd[5] == '2') && (cmd[6] == '2') && (cmd[7] == '4'))
	    _o = 224;
	  else if ((cmd[5] == '2') && (cmd[6] == '5') && (cmd[7] == '6'))
	    _o = 256;
	  else if ((cmd[5] == '3') && (cmd[6] == '8') && (cmd[7] == '4'))
	    _o = 384;
	  else if ((cmd[5] == '5') && (cmd[6] == '1') && (cmd[7] == '2'))
	    _o = 512;
	}
  _s = 1600;            /* --statesize  */
  _c = _s - (_o << 1);  /* --capacity   */
  _r = _s - _c;         /* --bitrate    */
  _w = _s / 25;         /* --wordsize   */
  _i = 1;               /* --iterations */
  _j = 1;               /* --squeezes   */
  
  
  for (; a <= an; a++)
    {
      char* arg = a == an ? null : *(args + a);
      if (*linger)
	{
	  if (eq(*linger, "-h") || eq(*linger, "--help"))
	    {
	      printf("\n");
	      printf("SHA-3/Keccak checksum calculator\n");
	      printf("\n");
	      printf("USAGE:	sha3sum [option...] < file\n");
	      printf("	sha3sum [option...] file...\n");
	      printf("\n");
	      printf("\n");
	      printf("OPTIONS:\n");
	      printf("        -r BITRATE\n");
	      printf("        --bitrate       The bitrate to use for checksum.        (default: %li)\n", _r);
	      printf("        \n");
	      printf("        -c CAPACITY\n");
	      printf("        --capacity      The capacity to use for checksum.       (default: %li)\n", _c);
	      printf("        \n");
	      printf("        -w WORDSIZE\n");
	      printf("        --wordsize      The word size to use for checksum.      (default: %li)\n", _w);
	      printf("        \n");
	      printf("        -o OUTPUTSIZE\n");
	      printf("        --outputsize    The output size to use for checksum.    (default: %li)\n", _o);
	      printf("        \n");
	      printf("        -s STATESIZE\n");
	      printf("        --statesize     The state size to use for ckecksum.     (default: %li)\n", _s);
	      printf("        \n");
	      printf("        -i ITERATIONS\n");
	      printf("        --iterations    The number of hash iterations to run.   (default: %li)\n", _i);
	      printf("        \n");
	      printf("        -j SQUEEZES\n");
	      printf("        --squeezes      The number of hash squeezes to run.     (default: %li)\n", _j);
	      printf("        \n");
	      printf("        -x\n");
	      printf("        --hex           Read the input in hexadecimal, rather than binary.\n");
	      printf("        \n");
	      printf("        -b\n");
	      printf("        --binary        Print the checksum in binary, rather than hexadecimal.\n");
	      printf("        \n");
	      printf("        -m\n");
	      printf("        --multi         Print the checksum at all iterations.\n");
	      printf("\n");
	      printf("\n");
	      printf("COPYRIGHT:\n");
	      printf("\n");
	      printf("Copyright © 2013, 2014  Mattias Andrée (maandree@member.fsf.org)\n");
	      printf("\n");
	      printf("This program is free software: you can redistribute it and/or modify\n");
	      printf("it under the terms of the GNU Affero General Public License as published by\n");
	      printf("the Free Software Foundation, either version 3 of the License, or\n");
	      printf("(at your option) any later version.\n");
	      printf("\n");
	      printf("This program is distributed in the hope that it will be useful,\n");
	      printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	      printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	      printf("GNU Affero General Public License for more details.\n");
	      printf("\n");
	      printf("You should have received a copy of the GNU Affero General Public License\n");
	      printf("along with this program.  If not, see <http://www.gnu.org/licenses/>.\n");
	      printf("\n");
	      fflush(stdout);
	      fflush(stderr);
	      return 0;
	    }
	  else
	    {
	      if (*(linger + 1) == null)
		{
		  *(linger + 1) = arg;
		  arg = null;
		}
	      if (eq(*linger, "-r") || eq(*linger, "--bitrate"))
		_R = 1 | (R = parseInt(linger[1]));
	      else if (eq(*linger, "-c") || eq(*linger, "--capacity"))
		_C = 1 | (C = parseInt(linger[1]));
	      else if (eq(*linger, "-w") || eq(*linger, "--wordsize"))
		_W = 1 | (W = parseInt(linger[1]));
	      else if (eq(*linger, "-o") || eq(*linger, "--outputsize"))
		_O = 1 | (O = parseInt(linger[1]));
	      else if (eq(*linger, "-s") || eq(*linger, "--statesize"))
		_S = 1 | (S = parseInt(linger[1]));
	      else if (eq(*linger, "-i") || eq(*linger, "--iterations"))
		_I = 1 | (I = parseInt(linger[1]));
	      else if (eq(*linger, "-j") || eq(*linger, "--squeezes"))
		_J = 1 | (J = parseInt(linger[1]));
	      else
		{
		  fprintf(stderr, "%s: unrecognised option: %s\n", cmd, *linger);
		  fflush(stdout);
		  fflush(stderr);
		  return 1;
		}
	    }
	  *linger = null;
	  if (arg == null)
	    continue;
	}
      if (arg == null)
	continue;
      if (dashed)
	files[fptr++] = ((arg[0] == '-') && (arg[1] == 0)) ? null : arg;
      else if ((arg[0] == '-') && (arg[1] == '-') && (arg[2] == 0))
	dashed = true;
      else if ((arg[0] == '-') && (arg[1] == 0))
	files[fptr++] = null;
      else if ((arg[0] == '-') && (arg[1] == '-') && arg[2])
	{
	  long idx = -1, j;
	  for (j = 0; *(arg + j); j++)
	    if (*(arg + j) == '=')
	      {
		idx = j;
		break;
	      }
	  if (idx >= 0)
	    {
	      linger[0] = linger0;
	      linger[1] = arg + idx + 1;
	      for (j = 0; j < idx; j++)
		*(*linger + j) = *(arg + j);
	    }
	  else
	    if (eq(arg, "--binary"))
	      binary = true;
	    else if (eq(arg, "--multi"))
	      multi++;
	    else if (eq(arg, "--hex"))
	      hex = true;
	    else
	      {
		linger[0] = arg;
		linger[1] = null;
	      }
	}
      else if ((arg[0] == '-') && arg[1])
	{
	  arg++;
	  if (*arg == 'b')
	    {
	      binary = true;
	      arg++;
	    }
	  else if (*arg == 'm')
	    {
	      multi++;
	      arg++;
	    }
	  else if (*arg == 'x')
	    {
	      hex = true;
	      arg++;
	    }
	  else
	    {
	      {
		char* _ = linger0;
		*_++ = '-'; *_++ = *arg; *_ = 0;
		linger[0] = _ - 2;
	      }
	      {
		long _ = 0;
		while (*(arg + _))
		  _++;
		linger[1] = _ == 1 ? null : arg + 1;
	      }
	    }
	}
      else
	files[fptr++] = arg;
    }
  
  
  i = _I ? I : _i;
  j = _J ? J : _j;
  
  #define ERR(text)  fprintf(stderr, "%s: " text "\n", cmd);  fflush(stdout);  fflush(stderr)
  
  if (_S)
    {
      s = S;
      if ((s <= 0) || (s > 1600) || (s % 25))
	{
	  ERR("the state size must be a positive multiple of 25 and is limited to 1600.");
	  return 6;
	}
    }
  
  if (_W)
    {
      w = W;
      if ((w <= 0) || (w > 64))
	{
	  ERR("the word size must be positive and is limited to 64.");
	  return 6;
	}
      if (_S && (s != w * 25))
	{
	  ERR("the state size must be 25 times of the word size.");
	  return 6;
	}
      else if (_S == null)
	_S = 1 | (S = w * 25);
    }
  
  if (_C)
    {
      c = C;
      if ((c <= 0) || (c & 7))
	{
	  ERR("the capacity must be a positive multiple of 8.");
	  return 6;
	}
    }
  
  if (_R)
    {
      r = R;
      if ((r <= 0) || (r & 7))
	{
	  ERR("the bitrate must be a positive multiple of 8.");
	  return 6;
	}
    }
  
  if (_O)
    {
      o = O;
      if (o <= 0)
	{
	  ERR("the output size must be positive.");
	  return 6;
	}
    }
  
  if ((_R & _C & _O) == null) /* s? */
    {
      s = _S ? s : _s;
      c = -((r = (o = (((s << 5) / 100 + 7) >> 3) << 3) << 1) - s);
      o = o < 8 ? 8 : o;
    }
  else if ((_R & _C) == null) /* !o s? */
    {
      r = _r;
      c = _c;
      s = _S ? s : (r + c);
    }
  else if (_R == null) /* !c o? s? */
    {
      r = (s = _S ? s : _s) - c;
      o = _O ? o : (c == 8 ? 8 : (c << 1));
    }
  else if (_C == null) /* !r o? s? */
    {
      c = (s = _S ? s : _s) - r;
      o = _O ? o : (c == 8 ? 8 : (c << 1));
    }
  else /* !r !c o? s? */
    {
      s = _S ? s : (r + c);
      o = _O ? o : (c == 8 ? 8 : (c << 1));
    }
  
  
  fprintf(stderr, "Bitrate: %li\n", r);
  fprintf(stderr, "Capacity: %li\n", c);
  fprintf(stderr, "Word size: %li\n", w);
  fprintf(stderr, "State size: %li\n", s);
  fprintf(stderr, "Output Size: %li\n", o);
  fprintf(stderr, "Iterations: %li\n", i);
  fprintf(stderr, "Squeezes: %li\n", j);
  
  
  if (r > s)
    {
      ERR("the bitrate must not be higher than the state size.");
      return 6;
    }
  if (c > s)
    {
      ERR("the capacity must not be higher than the state size.");
      return 6;
    }
  if (r + c != s)
    {
      ERR("the sum of the bitrate and the capacity must equal the state size.");
      return 6;
    }
  
  
  if (fptr == 0)
    files[fptr++] = null;
  if (i < 1)
    {
      ERR("sorry, I will only do at least one hash iteration!");
      return 3;
    }
  if (j < 1)
    {
      ERR("sorry, I will only do at least one squeeze iteration!");
      return 3;
    }
  
  #undef ERR
  
  bn = (o + 7) >> 3;
  out_alloc = (char*)alloca(bn * 2 * sizeof(char) + bn * sizeof(byte));
  stdin_alloc = (byte*)(out_alloc + bn * 2);
  {
    byte* stdin;
    char* filename;
    char* fn;
    long f, fail, _;
    struct stat attr;
    
    char* out = binary ? null : out_alloc;
    
    fail = false;
    stdin = null;
    
    for (f = 0; f < fptr; f++)
      {
	FILE* file;
	long blksize;
	byte* chunk;
	byte* bs;
	
	filename = *(files + f);
	fn = filename ? filename : "/dev/stdin";
	file = fopen(fn, "r");
	if (file == null)
	  {
	    fprintf(stderr, "%s: cannot read file: %s\n", cmd, filename);
	    fail = true;
	    continue;
	  }
	
	if ((filename != null) || (stdin == null))
	  {
	    sha3_initialise(r, c, o);
	    blksize = stat(*(argv + f), &attr) ? 0 : attr.st_blksize;
	    if (blksize <= 0)
	      blksize = 4096;
	    chunk = (byte*)alloca(blksize * sizeof(byte));
	    for (;;)
	      {
		long read = fread(chunk, 1, blksize, file);
		if (read <= 0)
		  break;
		if (hex == false)
		  sha3_update(chunk, read);
		else
		  {
		    int n = read >> 1;
		    for (_ = 0; _ < n; _++)
		      {
			byte a = *(chunk + (_ << 1)), b = *(chunk + ((_ << 1) | 1));
			a = (a & 15) + (a <= '9' ? 0 : 9);
			b = (b & 15) + (b <= '9' ? 0 : 9);
			*(chunk + _) = (a << 4) | b;
		      }
		    sha3_update(chunk, n);
		  }
	      }
	    bs = sha3_digest(null, 0, 0, SHA3_SUFFIX, j == 1);
	    if (j > 2)
	      sha3_fastSqueeze(j - 2);
	    if (j > 1)
	      bs = sha3_squeeze();
	    sha3_dispose();
	    
	    if (filename == null)
	      {
		stdin = stdin_alloc;
		for (_ = 0; _ < bn; _++)
		  *(stdin_alloc + _) = *(bs + _);
	      }
          }
	else
	  bs = stdin;
	
	if (multi == 0)
	  {
	    for (_ = 1; _ < i; _++)
	      {
		byte* _bs = bs;
		sha3_initialise(r, c, o);
		bs = sha3_digest(bs, bn, 0, SHA3_SUFFIX, j == 1);
		if (j > 2)
		  sha3_fastSqueeze(j - 2);
		if (j > 1)
		  bs = sha3_squeeze();
		free(_bs);
		sha3_dispose();
	      }
	    if (binary)
	      putchars((char*)bs, bn);
	    else
	      {
		long b, outptr = 0;
		for (b = 0; b < bn; b++)
		  {
		    byte v = bs[b];
		    *(out + outptr++) = HEXADECA[(v >> 4) & 15];
		    *(out + outptr++) = HEXADECA[v & 15];
		  }
		out[outptr] = '\0';
		printf("%s %s\n", out, filename ? filename : "-");
	      }
	  }
	else if (multi == 1)
	  {
	    long b;
	    if (binary)
	      putchars((char*)bs, bn);
	    else
	      {
		for (b = 0; b < bn; b++)
		  {
		    byte v = bs[b];
		    out[b * 2    ] = HEXADECA[(v >> 4) & 15];
		    out[b * 2 + 1] = HEXADECA[v & 15];
		  }
		out[b*2] = '\0';
		printf("%s %s\n", out, filename ? filename : "-");
	      }
	    for (_ = 1; _ < i; _++)
	      {
		byte* _bs = bs;
		sha3_initialise(r, c, o);
		bs = sha3_digest(bs, bn, 0, SHA3_SUFFIX, j == 1);
		if (j > 2)
		  sha3_fastSqueeze(j - 2);
		if (j > 1)
		  bs = sha3_squeeze();
		free(_bs);
		sha3_dispose();
		if (binary)
		  putchars((char*)bs, bn);
		else
		  {
		    for (b = 0; b < bn; b++)
		      {
			byte v = bs[b];
			out[b * 2    ] = HEXADECA[(v >> 4) & 15];
			out[b * 2 + 1] = HEXADECA[v & 15];
		      }
		    out[b*2] = '\0';
		    printf("%s\n", out);
		  }
	      }
	  }
	else
	  {
	    long b;
	    char loophere;
	    char* loop = null;
	    SET got = set_new();
	    for (_ = 0; _ < i; _++)
	      {
		if (_ > 0)
		  {
		    byte* _bs = bs;
		    sha3_initialise(r, c, o);
		    bs = sha3_digest(bs, bn, 0, SHA3_SUFFIX, j == 1);
		    if (j > 2)
		      sha3_fastSqueeze(j - 2);
		    if (j > 1)
		      bs = sha3_squeeze();
		    free(_bs);
		    sha3_dispose();
		  }
		for (b = 0; b < bn; b++)
		  {
		    byte v = bs[b];
		    out[b * 2    ] = HEXADECA[(v >> 4) & 15];
		    out[b * 2 + 1] = HEXADECA[v & 15];
		  }
		if (loop == null)
		  {
		    if (set_contains(got, bs, bn))
		      {
			loop = (char*)malloc(bn * 2 * sizeof(char));
			for (b = 0; b < bn * 2; b++)
			  *(loop + b) = *(out + b);
		      }
		    else
		      set_add(got, out, bn);
		  }
		loophere = loop && eq(loop, out);
		if (loophere)
		  printf("\033[31m");
		putchars(out, bn * 2);
		if (loophere)
		  printf("\033[00m");
		fflush(stdout);
	      }
	    if (loop)
	      {
		fprintf(stderr, "\033[01;31mLoop found\033[00m\n");
		free(loop);
	      }
	    set_free(got);
	  }
	if (bs != null)
	  free(bs);
	fclose(file);
      }
    
    fflush(stdout);
    fflush(stderr);
    if (fail)
      return 5;
  }
  
  return 0;
}


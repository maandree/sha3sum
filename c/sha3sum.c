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
#include <stdio.h>
#include <stdlib.h>

#include "sha3.h"


#define false 0
#define true  1
#define null  0


/**
 * String equality comparator
 * 
 * @param   a  First comparand
 * @param   b  Second comparand
 * @return     Whether the comparands are equal
 */
long eq(char* a, char* b)
{
  while (*a)
    if (*a++ != *b++)
      return false;
  return true;
}


/**
 * Convert a string to an integer
 * 
 * @param   str  String representation
 * @return       Native representation
 */
long parseInt(char* str)
{
  long rc = 0;
  while (*str)
    rc = rc * 10 - (*str & 15);
  return rc;
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
  char* cmd = *argv;
  long _o, o, _s, s, _r, r, _c, c, _w, w, _i, i;
  long binary = false, dashed = false, fptr = 0, freelinger = true;
  
  char** files = (char**)malloc(argc * sizeof(char*));
  char** linger = (char**)malloc(sizeof(char*) << 1);
  
  long a = 0, an = argc - 1;
  char** args = argv + 1;
  
  
  s = -1;
  for (i = 0; *(cmd + i); i++)
    if (*(cmd + i) == '/')
      s = i;
  if (s >= 0)
    cmd += s + 1;
  
  o = _o = 512;           /* --outputsize */
  if ((cmd[0] == 's') && (cmd[1] == 'h') && (cmd[2] == 'a') && (cmd[3] == '3') && (cmd[4] == '-'))
    if ((cmd[5] != 0) && (cmd[6] != 0) && (cmd[7] != 0))
      if ((cmd[8] == 's') && (cmd[9] == 'u') && (cmd[10] == 'm') && (cmd[11] == 0))
	{
	  if ((cmd[5] == '2') && (cmd[6] == '2') && (cmd[7] == '4'))
	    o = _o = 224;
	  else if ((cmd[5] == '2') && (cmd[6] == '5') && (cmd[7] == '6'))
	    o = _o = 256;
	  else if ((cmd[5] == '3') && (cmd[6] == '8') && (cmd[7] == '4'))
	    o = _o = 384;
	  else if ((cmd[5] == '5') && (cmd[6] == '1') && (cmd[7] == '2'))
	    o = _o = 512;
	}
  s = _s = 1600;          /* --statesize  */
  r = _r = s - (o << 1);  /* --bitrate    */
  c = _c = s - r;         /* --capacity   */
  w = _w = s / 25;        /* --wordsize   */
  i = _i = 1;             /* --iterations */
  
  
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
	      printf("        --bitrate       The bitrate to use for SHA-3.           (default: %li)\n", _r);
	      printf("        \n");
	      printf("        -c CAPACITY\n");
	      printf("        --capacity      The capacity to use for SHA-3.          (default: %li)\n", _c);
	      printf("        \n");
	      printf("        -w WORDSIZE\n");
	      printf("        --wordsize      The word size to use for SHA-3.         (default: %li)\n", _w);
	      printf("        \n");
	      printf("        -o OUTPUTSIZE\n");
	      printf("        --outputsize    The output size to use for SHA-3.       (default: %li)\n", _o);
	      printf("        \n");
	      printf("        -s STATESIZE\n");
	      printf("        --statesize     The state size to use for SHA-3.        (default: %li)\n", _s);
	      printf("        \n");
	      printf("        -i ITERATIONS\n");
	      printf("        --iterations    The number of hash iterations to run.   (default: %li)\n", _i);
	      printf("        \n");
	      printf("        -b\n");
	      printf("        --binary        Print the checksum in binary, rather than hexadecimal.\n");
	      printf("\n");
	      printf("\n");
	      printf("COPYRIGHT:\n");
	      printf("\n");
	      printf("Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)\n");
	      printf("\n");
	      printf("This program is free software: you can redistribute it and/or modify\n");
	      printf("it under the terms of the GNU General Public License as published by\n");
	      printf("the Free Software Foundation, either version 3 of the License, or\n");
	      printf("(at your option) any later version.\n");
	      printf("\n");
	      printf("This program is distributed in the hope that it will be useful,\n");
	      printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	      printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	      printf("GNU General Public License for more details.\n");
	      printf("\n");
	      printf("You should have received a copy of the GNU General Public License\n");
	      printf("along with this program.  If not, see <http://www.gnu.org/licenses/>.\n");
	      printf("\n");
	      fflush(stdout);
	      fflush(stderr);
	      return 2;
	    }
	  else
	    {
	      if (*(linger + 1) == null)
		{
		  *(linger + 1) = arg;
		  arg = null;
		}
	      if (eq(*linger, "-r") || eq(*linger, "--bitrate"))
		o = (s - (r = parseInt(linger[1]))) >> 1;
	      else if (eq(*linger, "-c") || eq(*linger, "--capacity"))
		r = s - (c = parseInt(linger[1]));
	      else if (eq(*linger, "-w") || eq(*linger, "--wordsize"))
		s = (w = parseInt(linger[1])) * 25;
	      else if (eq(*linger, "-o") || eq(*linger, "--outputsize"))
		r = s - ((o = parseInt(linger[1])) << 1);
	      else if (eq(*linger, "-s") || eq(*linger, "--statesize"))
		r = (s = parseInt(linger[1])) - (o << 1);
	      else if (eq(*linger, "-i") || eq(*linger, "--iterations"))
		i = parseInt(linger[1]);
	      else
		{
		  fprintf(stderr, "%s: unrecognised option: %s\n", cmd, *linger);
		  fflush(stdout);
		  fflush(stderr);
		  return 1;
		}
	    }
	  if (freelinger)
	    free(*linger);
	  freelinger = true;
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
	      linger[0] = (char*)malloc(idx);
	      linger[1] = arg + idx + 1;
	      for (j = 0; j < idx; j++)
		*(*linger + j) = *(arg + j);
	    }
	  else
	    if (eq(arg, "--binary"))
	      binary = true;
	    else
	      {
		linger[0] = arg;
		linger[1] = null;
		freelinger = false;
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
	  else
	    {
	      {
		char* _ = (char*)malloc(3);
		*_++ = '-'; *_++ = *arg; *_ = 0;
		linger[0] = _ - 3;
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
  
  free(linger);
  
  
  if (fptr == 0)
    files[fptr++] = null;
  if (i < 1)
    {
      fprintf(stderr, "%s: sorry, I will only do at least one iteration!\n", cmd);
      fflush(stdout);
      fflush(stderr);
      return 3;
    }
  
  {
    char* stdin = null;
    char* filename;
    char* fn;
    long f, fail = false;
    
    for (f = 0; f < fptr; f++)
      {
	if (((filename = *(files + f)) == null) && stdin)
	  {
	    printf("%s", stdin);
	    continue;
	  }
	fn = filename ? filename : "/dev/stdin";
	/* String rc = ""; */
	/* InputStream file = null; */
	
	/* --------------------------------------------------------------- */
      }
    
    fflush(stdout);
    fflush(stderr);
    if (fail)
      return 5;
  }
  
  free(files);
  return 0;
}


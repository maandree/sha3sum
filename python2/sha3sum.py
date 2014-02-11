#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
sha3sum – SHA-3 (Keccak) checksum calculator

Copyright © 2013, 2014  Mattias Andrée (maandree@member.fsf.org)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys
import os

from sha3 import SHA3


stdout = os.fdopen(1, 'w')
stderr = os.fdopen(2, 'w')


def printerr(text, end = '\n'):
    stderr.write(text + end)
    stderr.flush()


def write(data):
    stdout.write(data)


def flush():
    stdout.flush()



if __name__ == '__main__':
    cmd = sys.argv[0]
    args = sys.argv[1:]
    if '/' in cmd:
        cmd = cmd[cmd.rfind('/') + 1:]
    if cmd.endswith('.py'):
        cmd = cmd[:-3]
    
    (O, S, R, C, W, I, J) = (None, None, None, None, None, None, None)
    (o, s, r, c, w, i, j) = (0, 0, 0, 0, 0, 0, 0)
    _o = 512             # --outputsize
    if   cmd == 'sha3-224sum':  _o = 224
    elif cmd == 'sha3-256sum':  _o = 256
    elif cmd == 'sha3-384sum':  _o = 384
    elif cmd == 'sha3-512sum':  _o = 512
    _s = 1600            # --statesize
    _c = _s - (_o << 1)  # --capacity
    _r = _s - _c         # --bitrate
    _w = _s / 25         # --wordsize
    _i = 1               # --iterations
    _j = 1               # --squeezes
    (binary, hex, multi) = (False, False, 0)
    
    files = []
    dashed = False
    linger = None
    
    for arg in args + [None]:
        if linger is not None:
            if linger[0] in ('-h', '--help'):
                sys.stderr.buffer.write(('''
SHA-3/Keccak checksum calculator

USAGE:  sha3sum [option...] < file
        sha3sum [option...] file...


OPTIONS:
        -r BITRATE
        --bitrate       The bitrate to use for SHA-3.           (default: %d)
        
        -c CAPACITY
        --capacity      The capacity to use for SHA-3.          (default: %d)
        
        -w WORDSIZE
        --wordsize      The word size to use for SHA-3.         (default: %d)
        
        -o OUTPUTSIZE
        --outputsize    The output size to use for SHA-3.       (default: %d)
        
        -s STATESIZE
        --statesize     The state size to use for SHA-3.        (default: %d)
        
        -i ITERATIONS
        --iterations    The number of hash iterations to run.   (default: %d)
        
        -j SQUEEZES
        --squeezes      The number of hash squeezes to run.     (default: %d)
        
        -x
        --hex           Read the input in hexadecimal, rather than binary.
        
        -b
        --binary        Print the checksum in binary, rather than hexadecimal.
        
        -m
        --multi         Print the checksum at all iterations.


COPYRIGHT:

Copyright © 2013, 2014  Mattias Andrée (maandree@member.fsf.org)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

''' % (_r, _c, _w, _o, _s, _i, _j)).encode('utf-8'))
                sys.stderr.buffer.flush()
                exit(0)
            else:
                if linger[1] is None:
                    linger[1] = arg
                    arg = None
                if linger[0] in ('-r', '--bitrate'):
                    R = int(linger[1])
                elif linger[0] in ('-c', '--capacity'):
                    C = int(linger[1])
                elif linger[0] in ('-w', '--wordsize'):
                    W = int(linger[1])
                elif linger[0] in ('-o', '--outputsize'):
                    O = int(linger[1])
                elif linger[0] in ('-s', '--statesize'):
                    S = int(linger[1])
                elif linger[0] in ('-i', '--iterations'):
                    I = int(linger[1])
                elif linger[0] in ('-j', '--squeezes'):
                    J = int(linger[1])
                else:
                    printerr(sys.argv[0] + ': unrecognised option: ' + linger[0])
                    sys.exit(1)
            linger = None
            if arg is None:
                continue
        if arg is None:
            continue
        if dashed:
            files.append(None if arg == '-' else arg)
        elif arg == '--':
            dashed = True
        elif arg == '-':
            files.append(None)
        elif arg.startswith('--'):
            if '=' in arg:
                linger = (arg[:arg.find('=')], arg[arg.find('=') + 1:])
            else:
                if arg == '--binary':
                    binary = True
                elif arg == '--multi':
                    multi += 1
                elif arg == '--hex':
                    hex = True
                else:
                    linger = [arg, None]
        elif arg.startswith('-'):
            arg = arg[1:]
            if arg[0] == 'b':
                binary = True
                arg = arg[1:]
            elif arg[0] == 'b':
                multi += 1
                arg = arg[1:]
            elif arg[0] == 'x':
                hex = True
                arg = arg[1:]
            elif len(arg) == 1:
                linger = ['-' + arg, None]
            else:
                linger = ['-' + arg[0], arg[1:]]
        else:
            files.append(arg)
    
    
    i = _i if I is None else I
    j = _j if J is None else J
    
    
    if S is not None:
        s = S
        if ((s <= 0) or (s > 1600) or (s % 25 != 0)):
            printerr(cmd + ': the state size must be a positive multiple of 25 and is limited to 1600.')
            sys.exit(6)
    
    if W is not None:
        w = W
        if (w <= 0) or (w > 64):
            printerr(cmd + ': the word size must be positive and is limited to 64.')
            sys.exit(6)
        if (S is not None) and (s != w * 25):
            printerr(cmd + ': the state size must be 25 times of the word size.')
            sys.exit(6)
        elif S is None:
            S = w * 25
    
    if C is not None:
        c = C
        if (c <= 0) or ((c & 7) != 0):
            printerr(cmd + ': the capacity must be a positive multiple of 8.')
            sys.exit(6)
    
    if R is not None:
        r = R
        if (r <= 0) or ((r & 7) != 0):
            printerr(cmd + ': the bitrate must be a positive multiple of 8.')
            sys.exit(6)
    
    if O is not None:
        o = O
        if o <= 0:
            printerr(cmd + ': the output size must be positive.')
            sys.exit(6)
    
    
    if (R is None) and (C is None) and (O is None): ## s?
        s = _s if S is None else s
        o = (((s << 5) // 100 + 7) >> 3) << 3
        r = o << 1
        c = s - r
        o = 8 if o < 8 else o
    elif (R is None) and (C is None): ## !o s?
        r = _r
        c = _c
        s = (r + c) if S is None else s
    elif R is None: ## !c o? s?
        s = _s if S is None else s
        r = s - c
        o = (8 if c == 8 else (c << 1)) if O is None else o
    elif C is None: ## !r o? s?
        s = _s if S is None else s
        c = s - r
        o = (8 if c == 8 else (c << 1)) if O is None else o
    else: ## !r !c o? s?
        s = (r + c) if S is None else s
        o = (8 if c == 8 else (c << 1)) if O is None else o
    
    
    printerr('Bitrate: %d' % r)
    printerr('Capacity: %d' % c)
    printerr('Word size: %d' % w)
    printerr('State size: %d' % s)
    printerr('Output size: %d' % o)
    printerr('Iterations: %d' % i)
    printerr('Squeezes: %d' % j)
    
    
    if r > s:
        printerr(cmd + ': the bitrate must not be higher than the state size.')
        sys.exit(6)
    if c > s:
        printerr(cmd + ': the capacity must not be higher than the state size.')
        sys.exit(6)
    if r + c != s:
        printerr(cmd + ': the sum of the bitrate and the capacity must equal the state size.')
        sys.exit(6)
    
    
    if len(files) == 0:
        files.append(None)
    if i < 1:
        printerr(cmd + ': sorry, I will only do at least one hash iteration!\n')
        sys.exit(3)
    if j < 1:
        printerr(cmd + ': sorry, I will only do at least one squeeze iteration!\n')
        sys.exit(3)
    stdin = None
    fail = False
    sha = SHA3()
    for filename in files:
        rc = ''
        fn = '/dev/stdin' if filename is None else filename
        with open(fn, 'rb') as file:
            try:
                if (filename is not None) or (stdin is None):
                    sha.initialise(r, c, o)
                    blksize = 4096
                    try:
                        blksize = os.stat(os.path.realpath(fn)).st_blksize
                        if blksize <= 0:
                            blksize = 4096
                    except:
                        pass
                    while True:
                        chunk = [ord(b) for b in file.read(blksize)]
                        if len(chunk) == 0:
                            break
                        if not hex:
                            sha.update(chunk)
                        else:
                            n = len(chunk) >> 1
                            for _ in range(n):
                                (a, b) = (chunk[_ << 1], chunk[(_ << 1 | 1)])
                                a = ((a & 15) + (0 if a <= '9' else 9)) << 4
                                b =  (b & 15) + (0 if b <= '9' else 0)
                                chunk[_] = a | b
                            sha.update(chunk, n)
                    bs = sha.digest(j == 1)
                    if j > 2:
                        sha.fastSqueeze(j - 2)
                    if j > 1:
                        bs = sha.squeeze();
                    if filename is None:
                        stdin = bs
                else:
                    bs = stdin
                if multi == 0:
                    for _ in range(i - 1):
                        sha.initialise(r, c, o)
                        bs = sha.digest(bs, j == 1)
                        if j > 2:
                            sha.fastSqueeze(j - 2)
                        if j > 1:
                            bs = sha.squeeze();
                    if binary:
                        write(bs)
                    else:
                        for b in bs:
                            rc += "0123456789ABCDEF"[b >> 4]
                            rc += "0123456789ABCDEF"[b & 15]
                        rc += ' ' + ('-' if filename is None else filename) + '\n'
                        write(rc.encode('utf-8'))
                elif multi == 1:
                    if binary:
                        write(bs)
                    else:
                        for b in bs:
                            rc += "0123456789ABCDEF"[b >> 4]
                            rc += "0123456789ABCDEF"[b & 15]
                        rc += '\n'
                        write(rc.encode('UTF-8'))
                    for _ in range(i - 1):
                        sha.initialise(r, c, o)
                        bs = sha.digest(bs, j == 1)
                        if j > 2:
                            sha.fastSqueeze(j - 2)
                        if j > 1:
                            bs = sha.squeeze();
                        if binary:
                            write(bs);
                        else:
                            rc = ''
                            for b in bs:
                                rc += "0123456789ABCDEF"[b >> 4]
                                rc += "0123456789ABCDEF"[b & 15]
                            rc += '\n'
                            write(rc.encode('UTF-8'))
                else:
                    got = set()
                    loop = None
                    for _ in range(i):
                        if _ > 0:
                            pass
                        rc = ''
                        for b in bs:
                            rc += "0123456789ABCDEF"[b >> 4]
                            rc += "0123456789ABCDEF"[b & 15]
                        if loop is None:
                            if rc in got:
                                loop = rc
                            else:
                                got.add(rc)
                        if loop == rc:
                            rc = '\033[31m%s\033[00m' % rc;
                        write(rc.encode('utf-8'))
                        flush()
                    if loop is not None:
                        printerr('\033[01;31mLoop found\033[00m')
                flush()
            except Exception as err:
                printerr(cmd + ': connot read file: ' + fn + ': ' + str(err))
                fail = True
        flush()
    if fail:
        sys.exit(5)


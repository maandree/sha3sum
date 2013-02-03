#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
sha3sum – SHA-3 (Keccak) checksum calculator

Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys


class SHA3:
    '''
    @author  Mattias Andrée (maandree@member.fsf.org)
    '''
    
    RC=[0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    '''
    :list<int>  Round contants
    '''
    
    R=[0,  36,  3, 41, 18,
       1,  44, 10, 45,  2,
       62,  6, 43, 15, 61,
       28, 55, 25, 21, 56,
       27, 20, 39,  8, 14]
    '''
    :list<int>  Rotate constants
    '''
    
    
    
    B = [[0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]]
    '''
    :list<list<int>>  Keccak-f round temporary
    '''
    
    C = [0, 0, 0, 0, 0]
    '''
    :list<int>  Keccak-f round temporary
    '''
    
    D = [0, 0, 0, 0, 0]
    '''
    :list<int>  Keccak-f round temporary
    '''
    

    r = 0
    '''
    :int  The bitrate
    '''
    
    c = 0
    '''
    :int  The capacity
    '''
    
    n = 0
    '''
    :int  The output size
    '''
        
    b = 0
    '''
    :int  The state size
    '''
    
    w = 0
    '''
    :int  The word size
    '''
    
    wmod = 0
    '''
    :int  The word mask
    '''
    
    l = 0
    '''
    :int  ℓ, the binary logarithm of the word size
    '''
    
    nr = 0
    '''
    :int  12 + 2ℓ, the number of rounds
    '''
    
    S = None
    '''
    :list<list<int>>  The current state
    '''
    
    M = None
    '''
    :bytes  Left over water to fill the sponge with at next update
    '''
    
    
    
    @staticmethod
    def rotate(x, n):
        '''
        Rotate a word
        
        @param   x:int  The value to rotate
        @param   n:int  Rotation steps
        @return   :int  The value rotated
        '''
        return ((x >> (SHA3.w - (n % SHA3.w))) + (x << (n % SHA3.w))) & SHA3.wmod
    
    
    @staticmethod
    def lb(x):
        '''
        Binary logarithm
        
        @param   x:int  The value of which to calculate the binary logarithm
        @return   :int  The binary logarithm
        '''
        rc_a = 0 if (x & 0xFF00) == 0 else  8
        rc_b = 0 if (x & 0xF0F0) == 0 else  4
        rc_c = 0 if (x & 0xCCCC) == 0 else  2
        rc_d = 0 if (x & 0xAAAA) == 0 else  1
        return rc_a + rc_b + rc_c + rc_d
    
    
    @staticmethod
    def keccakFRound(A, rc):
        '''
        Perform one round of computation
        
        @param   A:list<list<int>>  The current state
        @param  rc:int              Round constant
        '''
        # θ step
        for x in range(5):
            SHA3.C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
        for x in range(5):
            SHA3.D[x] = SHA3.C[(x - 1) % 5] ^ SHA3.rotate(SHA3.C[(x + 1) % 5], 1)
        for x in range(5):
            for y in range(5):
                A[x][y] ^= SHA3.D[x]
        
        # ρ and π steps
        for x in range(5):
            for y in range(5):
                SHA3.B[y][(2 * x + 3 * y) % 5] = SHA3.rotate(A[x][y], SHA3.R[x * 5 + y])
        
        # ξ step
        for x in range(5):
            for y in range(5):
                A[x][y] = SHA3.B[x][y] ^ ((~(SHA3.B[(x + 1) % 5][y])) & SHA3.B[(x + 2) % 5][y])
        
        # ι step
        A[0][0] ^= rc
    
    
    @staticmethod
    def keccakF(A):
        '''
        Perform Keccak-f function
        
        @param  A:list<list<int>>  The current state
        '''
        for i in range(SHA3.nr):
            SHA3.keccakFRound(A, SHA3.RC[i] & SHA3.wmod)
    
    
    @staticmethod
    def toLane(message, rr, ww, off):
        '''
        Convert a chunk of char:s to a word
        
        @param   message:str  The message
        @param        rr:int  Bitrate in bytes
        @param        ww:int  Word size in bytes
        @param       off:int  The offset in the message
        @return         :int  Lane
        '''
        rc = 0
        i = off + ww - 1
        while i >= off:
            rc <<= 8
            rc |= message[i] if (i < rr) else 0
            i -= 1
        return rc
    
    
    @staticmethod
    def pad10star1(msg, r):
        '''
        pad 10*1
        
        @param   msg:bytes  The message to pad
        @param     n:int    The The message to pad
        @param     r:int    The bitrate
        @return     :str    The message padded
        '''
        nnn = len(msg)
        
        nrf = nnn >> 3
        nbrf = nnn & 7
        ll = nnn % r
        
        bbbb = 1 if nbrf == 0 else ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf))
        
        message = None
        if ((r - 8 <= ll) and (ll <= r - 2)):
            nnn = nrf + 1
            message = [bbbb ^ 128]
        else:
            nnn = (nrf + 1) << 3
            nnn = ((nnn - (nnn % r) + (r - 8)) >> 3) + 1
            message = [0] * (nnn - nrf)
            message[0] = bbbb
            i = nrf + 1
            while i < nnn:
                message[i - nrf] = 0
                i += 1
            message[nnn - nrf - 1] = 0x80
        
        return msg[:nrf] + bytes(message)
    
    
    @staticmethod
    def initalise(r, c, n):
        '''
        Initalise Keccak sponge
        
        @param  r:int  The bitrate
        @param  c:int  The capacity
        @param  n:int  The output size
        '''
        SHA3.r = r
        SHA3.c = c
        SHA3.n = n
        SHA3.b = (r + c)
        SHA3.w = SHA3.b // 25
        SHA3.l = SHA3.lb(SHA3.w)
        SHA3.nr = 12 + (SHA3.l << 1)
        SHA3.wmod = (1 << SHA3.w) - 1
        SHA3.S=[[0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0]]
        SHA3.M = bytes([])
    
    
    @staticmethod
    def update(msg):
        '''
        Absorb the more of the message message to the Keccak sponge
        
        @param  msg:bytes  The partial message
        '''
        rr = SHA3.r >> 3
        ww = SHA3.w >> 3
        
        SHA3.M += msg
        nnn = len(SHA3.M)
        nnn -= nnn % rr
        message = SHA3.M[:nnn]
        SHA3.M = SHA3.M[nnn:]
        
        # Absorbing phase
        msg_i =[0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0]
        m = nnn
        for i in range(0, m, rr):
            for j in range(25):
                SHA3.S[j % 5][j // 5] ^= SHA3.toLane(message[i:], rr, ww, j * ww)
            SHA3.keccakF(SHA3.S)
    
    
    @staticmethod
    def digest(msg):
        '''
        Absorb the last part of the message and squeeze the Keccak sponge
        
        @param  msg:bytes  The rest of the message
        '''
        message = SHA3.pad10star1(SHA3.M + msg, SHA3.r)
        nnn = len(message)
        rc = [0] * ((SHA3.n + 7) >> 3)
        ptr = 0
        
        # Absorbing phase
        rr = SHA3.r >> 3
        ww = SHA3.w >> 3
        msg_i =[0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0]
        m = nnn
        for i in range(0, m, rr):
            for j in range(25):
                SHA3.S[j % 5][j // 5] ^= SHA3.toLane(message[i:], rr, ww, j * ww)
            SHA3.keccakF(SHA3.S)
        
        # Squeezing phase
        rr = SHA3.r >> 3
        nn = SHA3.n >> 3
        olen = SHA3.n
        j = 0
        while (olen > 0):
            i = 0
            while (i < 25) and (i < rr) and (j < nn):
                v = SHA3.S[i % 5][i // 5]
                for _ in range(8):
                    if (j < nn):
                        rc[ptr] = v & 255
                        ptr += 1
                    v >>= 8
                    j += 1
                i += 1
            olen -= SHA3.r
            if olen > 0:
                SHA3.keccakF(S)
        
        return rc


output = 512
total = 1600
bitrate = total - output * 2
MESSAGE = 'The quick brown fox jumps over the lazy dog.'.encode('UTF-8')

SHA3.initalise(bitrate, total - bitrate, output)
SHA3.update(MESSAGE[:20])
sys.stdout.buffer.write(bytes(SHA3.digest(MESSAGE[20:])))
sys.stdout.buffer.flush()

# 0e ab 42 de  4c 3c eb 92  35 fc 91 ac  ff e7 46 b2
# 9c 29 a8 c3  66 b7 c6 0e  4e 67 c4 66  f3 6a 43 04
# c0 0f a9 ca  f9 d8 79 76  ba 46 9b cb  e0 67 13 b4
# 35 f0 91 ef  27 69 fb 16  0c da b3 3d  36 70 68 0e

# 87 e3 33 fa 22 26 2a aa 97 c4 4e ca 0a 92 67 3e
# f0 06 1c d7 8b 5e 72 22 ca 51 a9 54 cb a0 4f 0d
# 19 3a 82 2f 11 b8 3f 72 d0 41 7c 42 74 31 78 a9
# c2 b9 e1 27 8e c9 4c b7 5d 50 88 aa b8 d2 60 c9


'''
SHA-3/Keccak checksum calculator

USAGE:	sha3sum [option...] < FILE
	sha3sum [option...] file...

OPTIONS:
	-r BITRATE
	--bitrate	The bitrate to use for SHA-3.		(default: 576)
	
	-c CAPACITY
	--capacity	The capacity to use for SHA-3.		(default: 1024)
	
	-w WORDSIZE
	--wordsize	The word size to use for SHA-3.		(default: 64)
	
	-o OUTPUTSIZE
	--outputsize	The output size to use for SHA-3.	(default: 512)
	
	-s STATESIZE
	--statesize	The state size to use for SHA-3.	(default: 1600)
	
	-i ITERATIONS
	--iterations	The number of hash iterations to run.	(default: 1)

	-b
	--binary	Print the checksum in binary, rather than hexadecimal.

'''


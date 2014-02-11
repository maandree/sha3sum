#!/usr/bin/env python3
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

class SHA3:
    '''
    SHA-3/Keccak hash algorithm implementation
    
    @author  Mattias Andrée  (maandree@member.fsf.org)
    '''
    
    
    def __init__(self):
        '''
        Constructor
        '''
        
        self.RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
                   0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                   0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
                   0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
        '''
        :list<int>  Round contants
        '''
        
        self.B = [0] * 25
        '''
        :list<int>  Keccak-f round temporary
        '''
        
        self.C = [0] * 5
        '''
        :list<int>  Keccak-f round temporary
        '''
        
        
        (self.r, self.c, self.n, self.b, self.w, self.wmod, self.l, self.nr) = (0, 0, 0, 0, 0, 0, 0, 0)
        '''
           r:int  The bitrate
           c:int  The capacity
           n:int  The output size
           b:int  The state size
           w:int  The word size
        wmod:int  The word mask
           l:int  ℓ, the binary logarithm of the word size
          nr:int  12 + 2ℓ, the number of rounds
        '''
        
        self.S = None
        '''
        :list<int>  The current state
        '''
        
        self.M = None
        '''
        :bytes  Left over water to fill the sponge with at next update
        '''
    
    
    
    def rotate(self, x, n):
        '''
        Rotate a word
        
        @param   x:int  The value to rotate
        @param   n:int  Rotation steps
        @return   :int  The value rotated
        '''
        m = n % self.w
        return ((x >> (self.w - m)) + (x << m)) & self.wmod
    
    
    def rotate64(self, x, n):
        '''
        Rotate a 64-bit word
        
        @param   x:int  The value to rotate
        @param   n:int  Rotation steps
        @return   :int  The value rotated
        '''
        return ((x >> (64 - n)) + (x << n)) & 0xFFFFFFFFFFFFFFFF
    
    
    def lb(self, x):
        '''
        Binary logarithm
        
        @param   x:int  The value of which to calculate the binary logarithm
        @return   :int  The binary logarithm
        '''
        rc = 0
        if (x & 0xFF00) != 0:  rc +=  8 ;  x >>=  8
        if (x & 0x00F0) != 0:  rc +=  4 ;  x >>=  4
        if (x & 0x000C) != 0:  rc +=  2 ;  x >>=  2
        if (x & 0x0002) != 0:  rc +=  1
        return rc
    
    
    def keccakFRound(self, A, rc):
        '''
        Perform one round of computation
        
        @param   A:list<int>  The current state
        @param  rc:int        Round constant
        '''
        if self.w == 64:
            # θ step (step 1 and 2 of 3)
            self.C[0] = (A[0]  ^ A[1])  ^ (A[2]  ^ A[3])  ^ A[4]
            self.C[2] = (A[10] ^ A[11]) ^ (A[12] ^ A[13]) ^ A[14]
            db = self.C[0] ^ self.rotate64(self.C[2], 1)
            self.C[4] = (A[20] ^ A[21]) ^ (A[22] ^ A[23]) ^ A[24]
            dd = self.C[2] ^ self.rotate64(self.C[4], 1)
            self.C[1] = (A[5]  ^ A[6])  ^ (A[7]  ^ A[8])  ^ A[9]
            da = self.C[4] ^ self.rotate64(self.C[1], 1)
            self.C[3] = (A[15] ^ A[16]) ^ (A[17] ^ A[18]) ^ A[19]
            dc = self.C[1] ^ self.rotate64(self.C[3], 1)
            de = self.C[3] ^ self.rotate64(self.C[0], 1)
            
            # ρ and π steps, with last part of θ
            self.B[0] = self.rotate64(A[0] ^ da, 0)
            self.B[1] = self.rotate64(A[15] ^ dd, 28)
            self.B[2] = self.rotate64(A[5] ^ db, 1)
            self.B[3] = self.rotate64(A[20] ^ de, 27)
            self.B[4] = self.rotate64(A[10] ^ dc, 62)
            
            self.B[5] = self.rotate64(A[6] ^ db, 44)
            self.B[6] = self.rotate64(A[21] ^ de, 20)
            self.B[7] = self.rotate64(A[11] ^ dc, 6)
            self.B[8] = self.rotate64(A[1] ^ da, 36)
            self.B[9] = self.rotate64(A[16] ^ dd, 55)
            
            self.B[10] = self.rotate64(A[12] ^ dc, 43)
            self.B[11] = self.rotate64(A[2] ^ da, 3)
            self.B[12] = self.rotate64(A[17] ^ dd, 25)
            self.B[13] = self.rotate64(A[7] ^ db, 10)
            self.B[14] = self.rotate64(A[22] ^ de, 39)
            
            self.B[15] = self.rotate64(A[18] ^ dd, 21)
            self.B[16] = self.rotate64(A[8] ^ db, 45)
            self.B[17] = self.rotate64(A[23] ^ de, 8)
            self.B[18] = self.rotate64(A[13] ^ dc, 15)
            self.B[19] = self.rotate64(A[3] ^ da, 41)
            
            self.B[20] = self.rotate64(A[24] ^ de, 14)
            self.B[21] = self.rotate64(A[14] ^ dc, 61)
            self.B[22] = self.rotate64(A[4] ^ da, 18)
            self.B[23] = self.rotate64(A[19] ^ dd, 56)
            self.B[24] = self.rotate64(A[9] ^ db, 2)
        else:
            # θ step (step 1 and 2 of 3)
            self.C[0] = (A[0]  ^ A[1])  ^ (A[2]  ^ A[3])  ^ A[4]
            self.C[2] = (A[10] ^ A[11]) ^ (A[12] ^ A[13]) ^ A[14]
            db = self.C[0] ^ self.rotate(self.C[2], 1)
            self.C[4] = (A[20] ^ A[21]) ^ (A[22] ^ A[23]) ^ A[24]
            dd = self.C[2] ^ self.rotate(self.C[4], 1)
            self.C[1] = (A[5]  ^ A[6])  ^ (A[7]  ^ A[8])  ^ A[9]
            da = self.C[4] ^ self.rotate(self.C[1], 1)
            self.C[3] = (A[15] ^ A[16]) ^ (A[17] ^ A[18]) ^ A[19]
            dc = self.C[1] ^ self.rotate(self.C[3], 1)
            de = self.C[3] ^ self.rotate(self.C[0], 1)
            
            # ρ and π steps, with last part of θ
            self.B[0] = self.rotate(A[0] ^ da, 0)
            self.B[1] = self.rotate(A[15] ^ dd, 28)
            self.B[2] = self.rotate(A[5] ^ db, 1)
            self.B[3] = self.rotate(A[20] ^ de, 27)
            self.B[4] = self.rotate(A[10] ^ dc, 62)
            
            self.B[5] = self.rotate(A[6] ^ db, 44)
            self.B[6] = self.rotate(A[21] ^ de, 20)
            self.B[7] = self.rotate(A[11] ^ dc, 6)
            self.B[8] = self.rotate(A[1] ^ da, 36)
            self.B[9] = self.rotate(A[16] ^ dd, 55)
            
            self.B[10] = self.rotate(A[12] ^ dc, 43)
            self.B[11] = self.rotate(A[2] ^ da, 3)
            self.B[12] = self.rotate(A[17] ^ dd, 25)
            self.B[13] = self.rotate(A[7] ^ db, 10)
            self.B[14] = self.rotate(A[22] ^ de, 39)
            
            self.B[15] = self.rotate(A[18] ^ dd, 21)
            self.B[16] = self.rotate(A[8] ^ db, 45)
            self.B[17] = self.rotate(A[23] ^ de, 8)
            self.B[18] = self.rotate(A[13] ^ dc, 15)
            self.B[19] = self.rotate(A[3] ^ da, 41)
            
            self.B[20] = self.rotate(A[24] ^ de, 14)
            self.B[21] = self.rotate(A[14] ^ dc, 61)
            self.B[22] = self.rotate(A[4] ^ da, 18)
            self.B[23] = self.rotate(A[19] ^ dd, 56)
            self.B[24] = self.rotate(A[9] ^ db, 2)
        
        # ξ step
        A[0] = self.B[0] ^ ((~(self.B[5])) & self.B[10])
        A[1] = self.B[1] ^ ((~(self.B[6])) & self.B[11])
        A[2] = self.B[2] ^ ((~(self.B[7])) & self.B[12])
        A[3] = self.B[3] ^ ((~(self.B[8])) & self.B[13])
        A[4] = self.B[4] ^ ((~(self.B[9])) & self.B[14])
        
        A[5] = self.B[5] ^ ((~(self.B[10])) & self.B[15])
        A[6] = self.B[6] ^ ((~(self.B[11])) & self.B[16])
        A[7] = self.B[7] ^ ((~(self.B[12])) & self.B[17])
        A[8] = self.B[8] ^ ((~(self.B[13])) & self.B[18])
        A[9] = self.B[9] ^ ((~(self.B[14])) & self.B[19])
        
        A[10] = self.B[10] ^ ((~(self.B[15])) & self.B[20])
        A[11] = self.B[11] ^ ((~(self.B[16])) & self.B[21])
        A[12] = self.B[12] ^ ((~(self.B[17])) & self.B[22])
        A[13] = self.B[13] ^ ((~(self.B[18])) & self.B[23])
        A[14] = self.B[14] ^ ((~(self.B[19])) & self.B[24])
        
        A[15] = self.B[15] ^ ((~(self.B[20])) & self.B[0])
        A[16] = self.B[16] ^ ((~(self.B[21])) & self.B[1])
        A[17] = self.B[17] ^ ((~(self.B[22])) & self.B[2])
        A[18] = self.B[18] ^ ((~(self.B[23])) & self.B[3])
        A[19] = self.B[19] ^ ((~(self.B[24])) & self.B[4])
        
        A[20] = self.B[20] ^ ((~(self.B[0])) & self.B[5])
        A[21] = self.B[21] ^ ((~(self.B[1])) & self.B[6])
        A[22] = self.B[22] ^ ((~(self.B[2])) & self.B[7])
        A[23] = self.B[23] ^ ((~(self.B[3])) & self.B[8])
        A[24] = self.B[24] ^ ((~(self.B[4])) & self.B[9])
        
        # ι step
        A[0] ^= rc
    
    
    def keccakF(self, A):
        '''
        Perform Keccak-f function
        
        @param  A:list<int>  The current state
        '''
        if (self.nr == 24):
            self.keccakFRound(A, 0x0000000000000001)
            self.keccakFRound(A, 0x0000000000008082)
            self.keccakFRound(A, 0x800000000000808A)
            self.keccakFRound(A, 0x8000000080008000)
            self.keccakFRound(A, 0x000000000000808B)
            self.keccakFRound(A, 0x0000000080000001)
            self.keccakFRound(A, 0x8000000080008081)
            self.keccakFRound(A, 0x8000000000008009)
            self.keccakFRound(A, 0x000000000000008A)
            self.keccakFRound(A, 0x0000000000000088)
            self.keccakFRound(A, 0x0000000080008009)
            self.keccakFRound(A, 0x000000008000000A)
            self.keccakFRound(A, 0x000000008000808B)
            self.keccakFRound(A, 0x800000000000008B)
            self.keccakFRound(A, 0x8000000000008089)
            self.keccakFRound(A, 0x8000000000008003)
            self.keccakFRound(A, 0x8000000000008002)
            self.keccakFRound(A, 0x8000000000000080)
            self.keccakFRound(A, 0x000000000000800A)
            self.keccakFRound(A, 0x800000008000000A)
            self.keccakFRound(A, 0x8000000080008081)
            self.keccakFRound(A, 0x8000000000008080)
            self.keccakFRound(A, 0x0000000080000001)
            self.keccakFRound(A, 0x8000000080008008)
        else:
            for i in range(self.nr):
                self.keccakFRound(A, self.RC[i] & self.wmod)
    
    
    def toLane(self, message, n, ww, off):
        '''
        Convert a chunk of byte:s to a word
        
        @param   message:bytes  The message
        @param         n:int    `min(len(message), rr)`
                      rr:int    Bitrate in bytes
        @param        ww:int    Word size in bytes
        @param       off:int    The offset in the message
        @return         :int    Lane
        '''
        rc = 0
        i = off + ww - 1
        while i >= off:
            rc = (rc << 8) | (message[i] if (i < n) else 0)
            i -= 1
        return rc
    
    
    def toLane64(self, message, n, off):
        '''
        Convert a chunk of byte:s to a 64-bit word
        
        @param   message:bytes  The message
        @param         n:int    `min(len(message), rr)`
                      rr:int    Bitrate in bytes
        @param       off:int    The offset in the message
        @return         :int    Lane
        '''
        return ((message[off + 7] << 56) if (off + 7 < n) else 0) | ((message[off + 6] << 48) if (off + 6 < n) else 0) | ((message[off + 5] << 40) if (off + 5 < n) else 0) | ((message[off + 4] << 32) if (off + 4 < n) else 0) | ((message[off + 3] << 24) if (off + 3 < n) else 0) | ((message[off + 2] << 16) if (off + 2 < n) else 0) | ((message[off + 1] <<  8) if (off + 1 < n) else 0) | ((message[off]) if (off < n) else 0)
    
    
    def pad10star1(self, msg, r):
        '''
        pad 10*1
        
        @param   msg:bytes  The message to pad
        @param     r:int    The bitrate
        @return     :bytes  The message padded
        '''
        nnn = len(msg) << 3
        
        nrf = nnn >> 3
        nbrf = nnn & 7
        ll = nnn % r
        
        bbbb = 1 if nbrf == 0 else ((msg[nrf] >> (8 - nbrf)) | (1 << nbrf))
        
        message = None
        if ((r - 8 <= ll) and (ll <= r - 2)):
            message = [bbbb ^ 128]
        else:
            nnn = (nrf + 1) << 3
            nnn = ((nnn - (nnn % r) + (r - 8)) >> 3) + 1
            message = [0] * (nnn - nrf)
            message[0] = bbbb
            nnn -= nrf
            message[nnn - 1] = 0x80
        
        return msg[:nrf] + bytes(message)
    
    
    def initialise(self, r, c, n):
        '''
        Initialise Keccak sponge
        
        @param  r:int  The bitrate
        @param  c:int  The capacity
        @param  n:int  The output size
        '''
        self.r = r
        self.c = c
        self.n = n
        self.b = r + c
        self.w = self.b // 25
        self.l = self.lb(self.w)
        self.nr = 12 + (self.l << 1)
        self.wmod = (1 << self.w) - 1
        self.S = [0] * 25
        self.M = bytes([])
    
    
    def update(self, msg, msglen = None):
        '''
        Absorb the more of the message message to the Keccak sponge
        
        @param  msg:bytes   The partial message
        @param  msglen:int  The length of the partial message
        '''
        if msglen is not None:
            msg = msg[:msglen]
        
        rr = self.r >> 3
        ww = self.w >> 3
        
        self.M += msg
        nnn = len(self.M)
        nnn -= nnn % ((self.r * self.b) >> 3)
        message = self.M[:nnn]
        self.M = self.M[nnn:]
        
        # Absorbing phase
        if ww == 8:
            for i in range(0, nnn, rr):
                n = min(len(message), rr)
                self.S[ 0] ^= self.toLane64(message, n, 0)
                self.S[ 5] ^= self.toLane64(message, n, 8)
                self.S[10] ^= self.toLane64(message, n, 16)
                self.S[15] ^= self.toLane64(message, n, 24)
                self.S[20] ^= self.toLane64(message, n, 32)
                self.S[ 1] ^= self.toLane64(message, n, 40)
                self.S[ 6] ^= self.toLane64(message, n, 48)
                self.S[11] ^= self.toLane64(message, n, 56)
                self.S[16] ^= self.toLane64(message, n, 64)
                self.S[21] ^= self.toLane64(message, n, 72)
                self.S[ 2] ^= self.toLane64(message, n, 80)
                self.S[ 7] ^= self.toLane64(message, n, 88)
                self.S[12] ^= self.toLane64(message, n, 96)
                self.S[17] ^= self.toLane64(message, n, 104)
                self.S[22] ^= self.toLane64(message, n, 112)
                self.S[ 3] ^= self.toLane64(message, n, 120)
                self.S[ 8] ^= self.toLane64(message, n, 128)
                self.S[13] ^= self.toLane64(message, n, 136)
                self.S[18] ^= self.toLane64(message, n, 144)
                self.S[23] ^= self.toLane64(message, n, 152)
                self.S[ 4] ^= self.toLane64(message, n, 160)
                self.S[ 9] ^= self.toLane64(message, n, 168)
                self.S[14] ^= self.toLane64(message, n, 176)
                self.S[19] ^= self.toLane64(message, n, 184)
                self.S[24] ^= self.toLane64(message, n, 192)
                self.keccakF(self.S)
                message = message[rr:]
        else:
            for i in range(0, nnn, rr):
                n = min(len(message), rr)
                self.S[ 0] ^= self.toLane(message, n, ww,  0)
                self.S[ 5] ^= self.toLane(message, n, ww,      ww)
                self.S[10] ^= self.toLane(message, n, ww,  2 * ww)
                self.S[15] ^= self.toLane(message, n, ww,  3 * ww)
                self.S[20] ^= self.toLane(message, n, ww,  4 * ww)
                self.S[ 1] ^= self.toLane(message, n, ww,  5 * ww)
                self.S[ 6] ^= self.toLane(message, n, ww,  6 * ww)
                self.S[11] ^= self.toLane(message, n, ww,  7 * ww)
                self.S[16] ^= self.toLane(message, n, ww,  8 * ww)
                self.S[21] ^= self.toLane(message, n, ww,  9 * ww)
                self.S[ 2] ^= self.toLane(message, n, ww, 10 * ww)
                self.S[ 7] ^= self.toLane(message, n, ww, 11 * ww)
                self.S[12] ^= self.toLane(message, n, ww, 12 * ww)
                self.S[17] ^= self.toLane(message, n, ww, 13 * ww)
                self.S[22] ^= self.toLane(message, n, ww, 14 * ww)
                self.S[ 3] ^= self.toLane(message, n, ww, 15 * ww)
                self.S[ 8] ^= self.toLane(message, n, ww, 16 * ww)
                self.S[13] ^= self.toLane(message, n, ww, 17 * ww)
                self.S[18] ^= self.toLane(message, n, ww, 18 * ww)
                self.S[23] ^= self.toLane(message, n, ww, 19 * ww)
                self.S[ 4] ^= self.toLane(message, n, ww, 20 * ww)
                self.S[ 9] ^= self.toLane(message, n, ww, 21 * ww)
                self.S[14] ^= self.toLane(message, n, ww, 22 * ww)
                self.S[19] ^= self.toLane(message, n, ww, 23 * ww)
                self.S[24] ^= self.toLane(message, n, ww, 24 * ww)
                self.keccakF(self.S)
                message = message[rr:]
    
    
    def digest(self, msg = None, msglen = None, withReturn = None):
        '''
        Absorb the last part of the message and squeeze the Keccak sponge
        
        @param   msg:bytes?       The rest of the message
        @param   msglen:int       The length of the partial message
        @param   withReturn:bool  Whether to return the hash instead of just do a quick squeeze phrase and return `None`
        @return  :bytes?          The hash sum, or `None` if `withReturn` is `False`
        '''
        if (msg is not None) and isinstance(msg, bool):
            (msg, withReturn) = (withReturn, msg)
        elif (msglen is not None) and isinstance(msglen, bool):
            (msglen, withReturn) = (withReturn, msglen)
        if msg is None:
            msg = bytes([])
        elif msglen is not None:
            msg = msg[:msglen]
        message = self.pad10star1(self.M + msg, self.r)
        self.M = None
        nnn = len(message)
        
        rr = self.r >> 3
        nn = (self.n + 7) >> 3
        ww = self.w >> 3
        
        # Absorbing phase
        if ww == 8:
            for i in range(0, nnn, rr):
                n = min(len(message), rr)
                self.S[ 0] ^= self.toLane64(message, n, 0)
                self.S[ 5] ^= self.toLane64(message, n, 8)
                self.S[10] ^= self.toLane64(message, n, 16)
                self.S[15] ^= self.toLane64(message, n, 24)
                self.S[20] ^= self.toLane64(message, n, 32)
                self.S[ 1] ^= self.toLane64(message, n, 40)
                self.S[ 6] ^= self.toLane64(message, n, 48)
                self.S[11] ^= self.toLane64(message, n, 56)
                self.S[16] ^= self.toLane64(message, n, 64)
                self.S[21] ^= self.toLane64(message, n, 72)
                self.S[ 2] ^= self.toLane64(message, n, 80)
                self.S[ 7] ^= self.toLane64(message, n, 88)
                self.S[12] ^= self.toLane64(message, n, 96)
                self.S[17] ^= self.toLane64(message, n, 104)
                self.S[22] ^= self.toLane64(message, n, 112)
                self.S[ 3] ^= self.toLane64(message, n, 120)
                self.S[ 8] ^= self.toLane64(message, n, 128)
                self.S[13] ^= self.toLane64(message, n, 136)
                self.S[18] ^= self.toLane64(message, n, 144)
                self.S[23] ^= self.toLane64(message, n, 152)
                self.S[ 4] ^= self.toLane64(message, n, 160)
                self.S[ 9] ^= self.toLane64(message, n, 168)
                self.S[14] ^= self.toLane64(message, n, 176)
                self.S[19] ^= self.toLane64(message, n, 184)
                self.S[24] ^= self.toLane64(message, n, 192)
                self.keccakF(self.S)
                message = message[rr:]
        else:
            for i in range(0, nnn, rr):
                n = min(len(message), rr)
                self.S[ 0] ^= self.toLane(message, n, ww,  0)
                self.S[ 5] ^= self.toLane(message, n, ww,      ww)
                self.S[10] ^= self.toLane(message, n, ww,  2 * ww)
                self.S[15] ^= self.toLane(message, n, ww,  3 * ww)
                self.S[20] ^= self.toLane(message, n, ww,  4 * ww)
                self.S[ 1] ^= self.toLane(message, n, ww,  5 * ww)
                self.S[ 6] ^= self.toLane(message, n, ww,  6 * ww)
                self.S[11] ^= self.toLane(message, n, ww,  7 * ww)
                self.S[16] ^= self.toLane(message, n, ww,  8 * ww)
                self.S[21] ^= self.toLane(message, n, ww,  9 * ww)
                self.S[ 2] ^= self.toLane(message, n, ww, 10 * ww)
                self.S[ 7] ^= self.toLane(message, n, ww, 11 * ww)
                self.S[12] ^= self.toLane(message, n, ww, 12 * ww)
                self.S[17] ^= self.toLane(message, n, ww, 13 * ww)
                self.S[22] ^= self.toLane(message, n, ww, 14 * ww)
                self.S[ 3] ^= self.toLane(message, n, ww, 15 * ww)
                self.S[ 8] ^= self.toLane(message, n, ww, 16 * ww)
                self.S[13] ^= self.toLane(message, n, ww, 17 * ww)
                self.S[18] ^= self.toLane(message, n, ww, 18 * ww)
                self.S[23] ^= self.toLane(message, n, ww, 19 * ww)
                self.S[ 4] ^= self.toLane(message, n, ww, 20 * ww)
                self.S[ 9] ^= self.toLane(message, n, ww, 21 * ww)
                self.S[14] ^= self.toLane(message, n, ww, 22 * ww)
                self.S[19] ^= self.toLane(message, n, ww, 23 * ww)
                self.S[24] ^= self.toLane(message, n, ww, 24 * ww)
                self.keccakF(self.S)
                message = message[rr:]
        
        # Squeezing phase
        if withReturn:
            rc = [0] * ((self.n + 7) >> 3)
            ptr = 0
            
            olen = self.n
            j = 0
            ni = min(25, rr)
            while olen > 0:
                i = 0
                while (i < ni) and (j < nn):
                    v = self.S[(i % 5) * 5 + i // 5]
                    for _ in range(ww):
                        if j < nn:
                            rc[ptr] = v & 255
                            ptr += 1
                        v >>= 8
                        j += 1
                    i += 1
                olen -= self.r
                if olen > 0:
                    self.keccakF(self.S)
            if (self.n & 7) != 0:
                rc[len(rc) - 1] &= (1 << (self.n & 7)) - 1
            
            return bytes(rc)
        
        olen = self.n
        while olen > self.r:
            olen -= self.r
            self.keccakF(self.S)
        return None
    
    
    def simpleSqueeze(self, times = 1):
        '''
        Force some rounds of Keccak-f
        
        @param  times:int  The number of rounds
        '''
        for i in range(times):
            self.keccakF(self.S)
    
    
    def fastSqueeze(self, times = 1):
        '''
        Squeeze as much as is needed to get a digest a number of times
        
        @param  times:int  The number of digests
        '''
        for i in range(times):
            self.keccakF(self.S) # Last squeeze did not do a ending squeeze
            olen = self.n
            while olen > self.r:
                olen -= self.r
                self.keccakF(self.S)
    
    
    def squeeze(self):
        '''
        Squeeze out another digest
        
        @return  :bytes  The hash sum
        '''
        self.keccakF(self.S) # Last squeeze did not do a ending squeeze
        
        nn = (self.n + 7) >> 3
        ww = self.w >> 3
        rc = [0] * nn
        olen = self.n
        j = 0
        ptr = 0
        ni = min(25, self.r >> 3)
        
        while olen > 0:
            i = 0
            while (i < ni) and (j < nn):
                v = self.S[(i % 5) * 5 + i // 5]
                for _ in range(ww):
                    if j < nn:
                        rc[ptr] = v
                        ptr += 1
                    v >>= 8
                    j += 1
                i += 1
            olen -= self.r
            if olen > 0:
                self.keccakF(self.S)
        
        if (self.n & 7) != 0:
            rc[len(rc) - 1] &= (1 << (self.n & 7)) - 1
        
        return bytes(rc)


import sys


class SHA3:
    
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
    
    
    
    B = [[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0]]
    '''
    :list<list<int>>  Keccak-f round temporary
    '''
    
    C = [0,0,0,0,0]
    '''
    :list<int>  Keccak-f round temporary
    '''
    
    D = [0,0,0,0,0]
    '''
    :list<int>  Keccak-f round temporary
    '''
    
    
    b = 0
    '''
    :int  The bitrate
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
    
    
    
    @staticmethod
    def rotate(x, n):
        '''
        Rotate a word
        
        @param   x:int  The value to rotate
        @param   n:int  Rotation steps
        @return   :int  The value rotated
        '''
        return ((x >> (Keccak.w - (n % Keccak.w))) + (x << (n % Keccak.w))) & Keccak.wmod
    
    
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
            Keccak.C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
        for x in range(5):
            Keccak.D[x] = Keccak.C[(x - 1) % 5] ^ Keccak.rotate(Keccak.C[(x + 1) % 5], 1)
        for x in range(5):
            for y in range(5):
                A[x][y] ^= Keccak.D[x]
        
        # ρ and π steps
        for x in range(5):
            for y in range(5):
                Keccak.B[y][(2 * x + 3 * y) % 5] = Keccak.rotate(A[x][y], Keccak.R[x * 5 + y])
        
        # ξ step
        for x in range(5):
            for y in range(5):
                A[x][y] = Keccak.B[x][y] ^ ((~(Keccak.B[(x + 1) % 5][y])) & Keccak.B[(x + 2) % 5][y])
        
        # ι step
        A[0][0] ^= rc
    
    
    @staticmethod
    def keccakF(A):
        '''
        Perform Keccak-f function
        
        @param  A:list<list<int>>  The current state
        '''
        for i in range(Keccak.nr):
            Keccak.keccakFRound(A, Keccak.RC[i] & Keccak.wmod)
    
    
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
            rc |= ord(message[i]) if (i < rr) else 0
            i -= 1
        return rc
    
    
    @staticmethod
    def pad10star1(M, r):
        '''
        pad 10*1
        
        @param   M:str  The message to pad
        @param   r:int  The bitrate
        @return   :str  The message padded
        '''
        [nnn, msg] = M
        
        nrf = nnn >> 3
        nbrf = nnn & 7
        ll = nnn % r
        
        bbbb = 1 if nbrf == 0 else ((ord(msg[nrf]) >> (8 - nbrf)) | (1 << nbrf))
        
        message = None
        if ((r - 8 <= ll) and (ll <= r - 2)):
            nnn = nrf + 1
            message = [''] * 1
            message[0] = chr(bbbb ^ 128)
        else:
            nnn = (nrf + 1) << 3
            nnn = ((nnn - (nnn % r) + (r - 8)) >> 3) + 1
            message = [''] * (nnn - nrf)
            message[0] = chr(bbbb)
            i = nrf + 1
            while i < nnn:
                message[i - nrf] += '\0'
                i += 1
            message[nnn - nrf - 1] = chr(0x80)
        
        return msg[:nrf] + ''.join(message)
    
    
    @staticmethod
    def keccak(M, r = 1024, c = 576, n = 1024):
        Keccak.b = (r + c)
        Keccak.w = Keccak.b // 25
        Keccak.l = Keccak.lb(Keccak.w)
        Keccak.nr = 12 + (Keccak.l << 1)
        Keccak.wmod = (1 << Keccak.w) - 1
        
        S=[[0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0],
           [0, 0, 0, 0, 0]]
        
        message = Keccak.pad10star1(M, r)
        nnn = len(message)
        
        rr = r >> 3
        cc = c >> 3
        nn = n >> 3
        ww = Keccak.w >> 3
        
        #Absorbing phase
        msg_i =[[0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0]]
        m = nnn
        i = 0
        while i < m:
            for y in range(5):
                for x in range(5):
                    off = (5 * y + x) * ww
                    msg_i[x][y] = Keccak.toLane(message[i:], rr, ww, off)
            for y in range(5):
              for x in range(5):
                  S[x][y] ^= msg_i[x][y]
            Keccak.keccakF(S)
            i += rr
        
        
        #Squeezing phase
        olen = n
        j = 0
        while (olen > 0):
            i = 0
            while (i < 25) and (i < rr) and (j < nn):
                v = S[i % 5][i // 5]
                for _ in range(8):
                    if (j < nn):
                        sys.stdout.buffer.write(bytes([v & 255]))
                    v >>= 8
                    j += 1
                i += 1
            olen -= r
            if olen > 0:
                Keccak.keccakF(S)


output = 512
total = 1600
bitrate = total - output * 2
MESSAGE = "The quick brown fox jumps over the lazy dog."
SHA3.keccak([len(MESSAGE)*0, MESSAGE], bitrate, total - bitrate, output)
sys.stdout.buffer.flush()

# 0e ab 42 de  4c 3c eb 92  35 fc 91 ac  ff e7 46 b2
# 9c 29 a8 c3  66 b7 c6 0e  4e 67 c4 66  f3 6a 43 04
# c0 0f a9 ca  f9 d8 79 76  ba 46 9b cb  e0 67 13 b4
# 35 f0 91 ef  27 69 fb 16  0c da b3 3d  36 70 68 0e


#!/usr/bin/env python3

from fpylll import IntegerMatrix, LLL
from hashlib import sha512
from fastecdsa.curve import P521
from fastecdsa.point import Point
from pwn import *
import sys

lcg_a = 200565257846616591441313188858237974233
lcg_c = 1
n = P521.q # curve prime order

def construct_matrix(m, r, s):
    h = int.from_bytes(sha512(m).digest(), 'little')
    M = IntegerMatrix(10, 10)

    # First column:
    # Signature equation is h + d*r - k*s + L0*n = 0
    M[0, 0] = n
    M[4, 0] = -2**384*s
    M[5, 0] = -2**256*s
    M[6, 0] = -2**128*s
    M[7, 0] = -s
    M[8, 0] = r
    M[9, 0] = h

    # Second column:
    # Equation X1 - a*X0 - c + L1*2^128
    M[1, 1] = 2**128
    M[4, 1] = -lcg_a
    M[5, 1] = 1
    M[9, 1] = -lcg_c
    
    # Third column:
    # Equation X2 - a*X1 - c + L2*2^128
    M[2, 2] = 2**128
    M[5, 2] = -lcg_a
    M[6, 2] = 1
    M[9, 2] = -lcg_c

    # Fourth column:
    # Equation X3 - c1*X0 - c0 + L3*2^128
    M[3, 3] = 2**128
    M[6, 3] = -lcg_a
    M[7, 3] = 1
    M[9, 3] = -lcg_c

    # Multiply by 2**384 to avoid factors in following columns
    for i in range(10):
        for j in range(4):
            M[i, j] *= 2**384

    M[4, 4] = 2**256 # 2^384 * 1/2^128
    M[5, 5] = 2**256 # 2^384 * 1/2^128
    M[6, 6] = 2**256 # 2^384 * 1/2^128
    M[7, 7] = 2**256 # 2^384 * 1/2^128
    M[8, 8] = 1      # 2^384 * 1/2^384
    M[9, 9] = 2**384 # 2^384 * 1
        
    return M

def find_privkey(pubkey, m, r, s):
    M = construct_matrix(m, r, s)
    LLL.reduction(M)
    for i in range(10):
        guess = int(abs(M[i, 8]))
        if guess*P521.G == pubkey:
            return guess
    return None

def ecdsa_sign(privkey, m):
    # k = 1
    h = int.from_bytes(sha512(m).digest(), 'little')
    r = P521.G.x
    s = (h + privkey*r) % n
    return r, s

def solve_challenge():
    ss = remote('challenges.france-cybersecurity-challenge.fr', 2151)

    # Parse public key
    tmp = ss.recvline().decode()[17:-2].split(', ')
    xQ = int(tmp[0])
    yQ = int(tmp[1])
    pubkey = Point(xQ, yQ, curve=P521)

    # Parse message and signatures
    data = ss.recvline() # "Here is a valid signature"
    m = bytes.fromhex(ss.recvline().decode().split(' = ')[1][2:])
    tmp = ss.recvline().decode()[7:-2].split(', ')
    r = int(tmp[0])
    s = int(tmp[1])

    # Use LLL to find the private key
    privkey = find_privkey(pubkey, m, r, s)
    if privkey is None:
        ss.close()
        sys.exit()

    # Forge signature
    forged_sig = ecdsa_sign(privkey, b'All right, everybody be cool, this is a robbery! Give me the flag!')

    # Send forged signature and get the flag
    data = ss.recvline() # "Your turn! Give me another one!"
    data = ss.recv(4)    # "r = "
    ss.send(str(forged_sig[0]).encode() + b'\n')
    data = ss.recv(4)    # "s = "
    ss.send(str(forged_sig[1]).encode() + b'\n')
    data = ss.recvline()
    print(f'Flag: {data.decode()}')

    ss.close()

if __name__ == "__main__":
    solve_challenge()

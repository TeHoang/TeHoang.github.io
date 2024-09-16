---
layout: post
title: m0leCon 2025 Teaser CTF
date: 2024-09-15 17:34 +0700
tags: [ctf, crypto]
categories: [CTF Writeups]
description: Write up for crypto challenges in m0leCon 
img_path: /assets/img/molecon2025
image: banner.png
toc: true 
math: true 
---

I got absolutely carried by my team, this post will cover all of the crypto problems in the CTF.

## Quadratic Leak

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

flag = b'ptm{REDACTED}'
flag = bytes_to_long(flag)

key = RSA.generate(2048)
n = key.n
e = key.e
p, q = key.p, key.q

leak = (p**2 + q**2 - p - q)%key.n

ciph = pow(flag, key.e, key.n)
ciph = long_to_bytes(ciph)

print(f'{n = }')
print(f'{e = }')
print(f'{ciph = }')
print(f'{leak = }')
```

### Overview 

RSA with extra information: 

$$ leak \equiv (p^2 + q^2 - p - q) \pmod {n}$$

### Solution 

We have:

$$

\begin{aligned}

leak &\equiv p^2 + q^2 - p - q + 2pq &\pmod{n} \\
                  &\equiv (p + q)^2 - (p + q) &\pmod{n} \\

\Rightarrow leak &= (p + q)^2 - (p + q) + kn

\end{aligned}
$$

Since $(p + q)^2 - (p + q)$ and $leak$ are almost the same bit length as $n$ $\rightarrow$ $k$ is pretty small and we can bruteforce it.

```python
sage: key = RSA.generate(2048)
sage: n = key.n
sage: p, q = key.p, key.q
sage: x = (p + q)^2 - (p + q)
sage: leak = (p**2 + q**2 - p - q) % n
sage: (x - leak) // n
4
sage: x - leak - 4 * n == 0 # (k = -4)
True
```

After that we can solve for $(p + q)$ over $\mathbb{Z}$

```python
PR.<x> = PolynomialRing(ZZ)

for k in range(-10, 10): 
    f = x^2 - x - leak + k * n 
    r = f.roots()
    if r: 
        phi = n - int(r[0][0]) + 1 
        d = pow(e, -1, phi)
        print(long_to_bytes(pow(ct, d, n)))

# ptm{Nonlinear_Algebra_Preserved_Over_Large_Integers}

```

![alt text](ZYAN.png)

Let him cook!

## ECSign

```python
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Random import random
import hashlib
import json
import os

FLAG = os.environ.get("FLAG", "ptm{test}")

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = EccPoint(Gx, Gy)

N = 32
T = 64
B = 4

bases = [random.randint(1, q-1) for _ in range(N)]

def action(pub, priv):
    res = 1
    for li, ei in zip(bases, priv):
        res = (res * pow(li, ei, q)) % q
    Q = res * pub
    return Q

def keygen():
    sk = [random.randint(-B, B) for _ in range(N)]
    pk = action(G, sk)
    return (sk, pk)

def sub(a, b):
    return [x-y for x,y in zip(a, b)]

def sign(msg, sk):
    fs = []
    Ps = []
    cnt = 0
    while cnt < T:
        f = [random.randint(-(N*T+1)*B, (N*T+1)*B) for _ in range(N)]
        b = sub(f, sk)
        vec = [-N*T*B <= bb <= N*T*B for bb in b]
        if all(vec):
            P = action(G, f) 
            fs.append(f)
            Ps.append((P.x,P.y))
            cnt += 1
    s = ",".join(map(str, Ps)) + "," + msg
    h = int.from_bytes(hashlib.sha256(s.encode()).digest(), "big")
    outs = []
    for i in range(T):
        b = (h>>i) & 1
        if b:
            outs.append((b, sub(fs[i], sk)))
        else:
            outs.append((b, fs[i]))
    return outs

def verify(msg, sigma, pk):
    Ps = []
    for i in range(T):
        if sigma[i][0]:
            start = pk
        else:
            start = G
        end = action(start, sigma[i][1])
        Ps.append((end.x, end.y))
    s = ",".join(map(str, Ps)) + "," + msg
    h = int.from_bytes(hashlib.sha256(s.encode()).digest(), "big")
    for i in range(T):
        b = (h>>i) & 1
        if b != sigma[i][0]:
            return False
    return True


def menu():
    print("Choose an action")
    print("1. Sign a message")
    print("2. Get the flag")
    print("3. Quit")
    return int(input(">"))

def main():
    print("Let's sign some messages!")

    FLAG_MSG = "gimmetheflag"

    sk, pk = keygen()

    print(bases)
    print(pk.x, pk.y)

    while True:
        choice = menu()
        if choice == 1:
            m = input("The message to sign: ")
            if m == FLAG_MSG:
                print("Lol nope")
                exit(0)
            signature = sign(m, sk)
            print(json.dumps(signature))
        elif choice == 2:
            sigma = json.loads(input("Give me a valid signature: "))
            if verify(FLAG_MSG, sigma, pk):
                print(FLAG)
        else:
            break


if __name__ == "__main__":
    main()

```

### Overview 

We can send 2 options to the server: 

1. Obtain a valid signature for message $m$ $(m \neq flag_{msg})$

2. Send a signature $s$ to the server, if $s = sign(flag_{msg}, sk)$ we get flag

### Solution 

In order to forge a valid signature $s$, we will have to get the secret key $sk$. 

So we first examine the signing process: 

```python
def sign(msg, sk):
    fs = []
    Ps = []
    cnt = 0
    while cnt < T:
        f = [random.randint(-(N*T+1)*B, (N*T+1)*B) for _ in range(N)]
        b = sub(f, sk)
        vec = [-N*T*B <= bb <= N*T*B for bb in b]
        if all(vec):
            P = action(G, f) 
            fs.append(f)
            Ps.append((P.x,P.y))
            cnt += 1
    s = ",".join(map(str, Ps)) + "," + msg
    h = int.from_bytes(hashlib.sha256(s.encode()).digest(), "big")
    outs = []
    for i in range(T):
        b = (h>>i) & 1
        if b:
            outs.append((b, sub(fs[i], sk)))
        else:
            outs.append((b, fs[i]))
    return outs
```

Notice the case $b = 0$ in the output, we get $fs[i]$ which is has the following property:

$$ - NTB \leq fs[i] - sk[i] \leq NTB $$

From the `keygen` function we also know that: 

$$ -4 \leq sk[i] \leq 4$$

With these information, we can have a better bound for the secret key: 

$$
\begin{aligned}

sk[i] &\leq min( 4, fs[i] + NTB) \\

sk[i] &\geq max(-4, fs[i] - NTB)

\end{aligned}
$$

So I tried to obtain many signatures and keep improving the bounds until $lb[i] = ub[i]$ which looked a bit like this: 

```python
lb, ub = [-4] * N, [4] * N 

msg = 'mr_zyan_can_cook_my_goat'

while any(u - l != 0 for u, l in zip(ub, lb)): 
    io.sendlineafter('>', '1')
    io.sendlineafter('The message to sign:', msg)
    fs = eval(io.recvline().strip().decode())

    for b, f in fs: 
        if b == 0: 
            for i in range(N): 
                lb[i] = max(lb[i], f[i] - N * T * B)
                ub[i] = min(ub[i], f[i] + N * T * B)
```

Credits to one of my teammate Zayn for finding this solution (as you can see the msg I send to the server, and yes zyan is not a typo of zayn).

Unfortunately (or more like skill issue as I didn't even try to batch request), I got timed out while having recovered ~ 27, 28 values.

![alt text](timeout1.png)

Changing the plan, I decided to bruteforce all the missing values instead. 

```python
import itertools

ranges = [range(lb[i], ub[i] + 1) for i in range(N)]
all_combinations = list(itertools.product(*ranges))

for sk in all_combinations:
    sig = sign('gimmetheflag', sk)
    io.sendlineafter('>', '2')
    io.sendlineafter("Give me a valid signature: ", json.dumps(sig))
    recv = io.recvline()
    if b'ptm' in recv:
        print(recv)
        break 

# ptm{r3j3c710n_54mpl1ng_g0n3_wr0ng}
```

## Yet another OT

```python
import random
from hashlib import sha256
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

random = random.SystemRandom()


def jacobi(a, n):
    if n <= 0:
        raise ValueError("'n' must be a positive integer.")
    if n % 2 == 0:
        raise ValueError("'n' must be odd.")
    a %= n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            n_mod_8 = n % 8
            if n_mod_8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    if n == 1:
        return result
    else:
        return 0


def sample(start, N):
    while jacobi(start, N) != 1:
        start += 1
    return start


class Challenge:
    def __init__(self, N):
        assert N > 2**1024
        assert N % 2 != 0
        self.N = N
        self.x = sample(int.from_bytes(sha256(("x"+str(N)).encode()).digest(), "big"), N)
        ts = []
        tts = []
        for _ in range(128):
            t = random.randint(1, self.N)
            ts.append(t)
            tts.append(pow(t, N, N))
        print(json.dumps({"vals": tts}))
        self.key = sha256((",".join(map(str, ts))).encode()).digest()

    def one_round(self):
        z = sample(random.randint(1, self.N), self.N)
        r0 = random.randint(1, self.N)
        r1 = random.randint(1, self.N)

        m0, m1 = random.getrandbits(1), random.getrandbits(1)

        c0 = (r0**2 * (z)**m0) % self.N
        c1 = (r1**2 * (z*self.x)**m1) % self.N

        print(json.dumps({"c0": c0, "c1": c1}))
        data = json.loads(input())
        v0, v1 = data["m0"], data["m1"]
        return v0 == m0 and v1 == m1
    
    def send_flag(self, flag):
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(flag.encode(), 16))
        print(ct.hex())


FLAG = os.environ.get("FLAG", "ptm{test}")

def main():
    print("Welcome to my guessing game!")
    N = int(input("Send me a number: "))
    chall = Challenge(N)
    for _ in range(128):
        if not chall.one_round():
            exit(1)
    chall.send_flag(FLAG)


if __name__ == "__main__":
    main()
```

### Overview

As the name suggests, we have yet another oblivious transter protocol. We can send the server $N$, guessing correctly $m_0, m_1$ from $c_0, c_1$ 128 rounds to get the encrypted flag. Where:

$$

\begin{aligned}

c_0 &\equiv r_0^2 * z^{m_0} &\pmod{N} \\

c_1 &\equiv r_1^2 * (z * x)^{m_1} &\pmod{N}

\end{aligned}

$$

Notice that $z$ is unknown and is a quadratic residue mod $N$

### Solution

First notice that since we have the ability to control $N$, we can calculate $ts \equiv (ts^N)^d \pmod {N}$ where $d * N \equiv 1 \pmod{\phi(N)}$ and therefore recover the encryption key. Now the remaining task is to retrieve the encrypted flag.  

Let's denote $(\dfrac{a}{n})$ to be the Jacobi symbol, if we have $n = p_1^{k_1} * p_2^{k_2} \dots p_m^{k_m}$ then by definition, we have: 

$$ 

\left(\dfrac{a}{n}\right) = \left(\dfrac{a}{p_1}\right)^{k_1} * \left(\dfrac{a}{p_2}\right)^{k_2} \dots \left(\dfrac{a}{p_m}\right)^{k_m}

$$

Where $\left(\dfrac{a}{p_i}\right)$ is the Legendre symbols corresponding to $p_i$

Let's assume $N = p$ where $p$ is a prime $\geq 2^{1024}$

Now we have: 

$$
\begin{aligned}
\left(\dfrac{c_0}{N}\right) &= \left(\dfrac{r_0^2 * z^{m_0}}{p}\right) \\
        \\

                            &= \left(\dfrac{r_0}{p}\right)^2 * \left(\dfrac{z}{p}\right)^{m_0} \\
        \\

                            &= \left(\dfrac{z}{p}\right)^{m_0}

\end{aligned}
$$

Since $z$ was sampled to be a quadratic residue mod $N$ and $N = p$, $z$ will be a quadratic residue mod $p$. Therefore $\left(\dfrac{z}{p}\right)$ will always be $1$, providing us no information to differentiate the case $m_0 = 0$ and $m_0 = 1$. 

So the idea of using a prime $N$ is out of the window, let's consider the case where $N$ is a product of 2 distinct primes $p_1, p_2$  

With the same calculation as above, we have:

$$
\begin{aligned}
\left(\dfrac{c_0}{N}\right) &= \left(\dfrac{z}{p_1}\right)^{m_0} * \left(\dfrac{z}{p_2}\right)^{m_0}

\end{aligned}
$$

Now if $m_0 = 0$ 

$$

\begin{aligned}
\left(\dfrac{c_0}{N}\right) &= \left(\dfrac{z}{p_1}\right)^{0} * \left(\dfrac{z}{p_2}\right)^{0} \\
    \\
                            &= 1 * 1
\end{aligned}

$$

So $\left(\dfrac{c_0}{p_i}\right)$ will always be $1$

Otherwise
$$
\begin{aligned}
\left(\dfrac{c_0}{N}\right) &= \left(\dfrac{z}{p_1}\right) * \left(\dfrac{z}{p_2}\right) \\
\end{aligned}
$$

We know that $z$ guaranteed to be a quadratic residue modulo $N$ but this does not necessarily imply that $z$ is a quadratic residue modulo $p_i$. It is possible for both $\left(\dfrac{z}{p_1}\right)= \left(\dfrac{z}{p_2}\right) = -1$, in which case $z$ remains a quadratic residue mod $N$ since $-1 * -1 = 1$. This occurs 50% of the time, as there are only two possibilities $\{(1, 1), (-1, -1)\}$

So $\left(\dfrac{c_0}{p_i}\right)$ can be $-1$ with the probality $1 - 2^{-m}$

From here we can distinguish $m_0$, do the same for $m_1$ and retrieve the encrypted flag. 

```python
from Crypto.Util.number import * 
from pwn import * 
import json 
from hashlib import sha256 
from math import prod 
from sage.all import legendre_symbol 

ps = [getPrime(25) for _ in range(50)] 

n = prod(ps)

phi = prod([x - 1 for x in ps])

d = pow(n, -1, phi)

# io = process(["python3", "chall.py"])
io = remote('yaot.challs.m0lecon.it', 2844)

io.sendlineafter('Send me a number: ', str(n))

tts = json.loads(io.recvline())['vals']

ts = [pow(x, d, n) for x in tts]

key = sha256((",".join(map(str, ts))).encode()).digest()

def check(x): 
    for p in ps: 
        if pow(x, (p - 1) // 2, p) == p-1: 
            return 1 
    return 0 

import time 

for _ in range(128): 
    # print(io.recvline())
    timer = time.time()
    data = json.loads(io.recvline())
    c0, c1 = data['c0'], data['c1']
    m0, m1 = check(c0), check(c1)
    elapsed_time = time.time() - timer
    print(f"Time taken to find answer: {elapsed_time:.4f} seconds")
    print(_, m0, m1)
    to_send = {"m0": m0, "m1": m1}
    io.sendline(json.dumps(to_send))

print(key)

# ptm{t0_b3_0r_n07_t0_b3_4_qu4dr471c_r351du3?}

io.interactive()
```

## Talor 

```python
#!/usr/bin/env python3

from random import SystemRandom
import os

random = SystemRandom()

p = 241
SB = [31, 32, 57, 9, 31, 144, 126, 114, 1, 38, 231, 220, 122, 169, 105, 29, 33, 81, 129, 4, 6, 64, 97, 134, 193, 160, 150, 145, 114, 133, 23, 193, 73, 162, 220, 111, 164, 88, 56, 102, 0, 107, 37, 227, 129, 17, 143, 134, 76, 152, 39, 233, 0, 147, 9, 220, 182, 113, 203, 11, 31, 125, 125, 194, 223, 192, 49, 71, 20, 227, 25, 38, 132, 17, 90, 109, 36, 157, 238, 127, 115, 92, 149, 216, 182, 15, 123, 28, 173, 114, 86, 159, 117, 60, 42, 191, 106, 182, 43, 108, 24, 232, 159, 25, 240, 78, 207, 158, 132, 156, 203, 71, 226, 235, 91, 92, 238, 110, 195, 78, 8, 54, 225, 108, 193, 65, 211, 212, 68, 77, 232, 100, 147, 171, 145, 96, 225, 63, 37, 144, 71, 38, 195, 19, 121, 197, 112, 20, 2, 186, 144, 217, 189, 130, 34, 180, 47, 121, 87, 154, 211, 188, 176, 65, 146, 26, 194, 213, 45, 171, 24, 37, 76, 42, 232, 13, 111, 80, 109, 178, 178, 31, 51, 100, 190, 121, 83, 53, 156, 62, 70, 23, 151, 227, 169, 160, 45, 174, 76, 25, 196, 62, 201, 6, 215, 139, 192, 83, 141, 230, 110, 39, 170, 189, 158, 153, 143, 110, 169, 206, 239, 56, 58, 174, 222, 29, 33, 198, 134, 181, 83, 72, 24, 61, 189, 177, 159, 31, 53, 5, 30]
state_size = 32
r = 16
c = state_size - r
ROUNDS = 140
rc = [0 for i in range(ROUNDS)]
start_state = [0]*state_size

flag = os.environ.get("FLAG", "ptm{REDACTED}")

def absorb(state):
    state = state[:]
    for i in range(ROUNDS):
        tmp = SB[(state[0] + rc[i]) % p]
        for j in range(1, len(state)):
            state[j] += tmp
            state[j] %= p
        state = state[1:] + state[:1]
    return state

def sponge(payload):
    assert len(payload) % r == 0
    state = start_state[:]
    for i in range(0, len(payload), r):
        state = [(state[j] + payload[i+j]) % p for j in range(r)] + state[r:]
        state = absorb(state)
    return state[:r-4]

def h(msg):
    m = msg[:]
    m.append(len(m))
    if len(m) % r != 0:
        m += [0] * (r - (len(m) % r))
    return sponge(m) 

for i in range(10):
    rc = [random.randint(1,p-1) for i in range(ROUNDS)]

    print(f"Iteration {i+1}")
    print(f"{rc = }")
    m1 = list(bytes.fromhex(input("M1: ")))
    m2 = list(bytes.fromhex(input("M2: ")))

    if m1 == m2 or h(m1) != h(m2) or any([x>=p for x in m1]) or any([x>=p for x in m2]) or len(m1)>=p or len(m2)>=p:
        print("Nope!", m1, m2, h(m1), h(m2))
        exit()

print(flag)
```

### Overview 

A hash collision type challenge, we have to give the server distinct $m_1, m_2$ $10$ times such that $h(m_1) = h(m_2)$ where $h$ is the custom hash function. 

### Solution

I wasn't able to solve this problem during the CTF, but I found it interesting, so I decided to write more about it.

Anyways, let's take a look at what `h` is actually doing 

```python
def h(msg):
    m = msg[:]
    m.append(len(m))
    if len(m) % r != 0:
        m += [0] * (r - (len(m) % r))
    return sponge(m) 
```

The function will first append `len(msg)` to the `msg` and pad it with `0` until its length is divisible by `r` which is $16$.  

Simple enough, how about `sponge(m)` ?

```python
def sponge(payload):
    assert len(payload) % r == 0
    state = start_state[:]
    for i in range(0, len(payload), r):
        state = [(state[j] + payload[i+j]) % p for j in range(r)] + state[r:]
        state = absorb(state)
    return state[:r-4]
```

We have the assertion `len(payload) % r == 0` which is always true because the payload has been paded. It follows by initializing the `state` with `start_state` which is just $32$ zeros.

For each block of size `r` in the payload:
Adds the payload block to the first `r` elements of the state $\rightarrow$ applies the absorb function.

The first 12 values in `state` will be the hash output. 

```python
def absorb(state):
    state = state[:]
    for i in range(ROUNDS):
        tmp = SB[(state[0] + rc[i]) % p]
        for j in range(1, len(state)):
            state[j] += tmp
            state[j] %= p
        state = state[1:] + state[:1]
    return state
```

The `absorb` function will iterates $140$ rounds, in each round: 

1. Computes an index using the first element of the state and a round constant $rc[i]$, then retrieves a value from the substitution box $SB$.

2. Updates each element of the state (except the first) by adding the substituted value and mod $p$. 

3. Rotate the state 

Notice that $SB$ is not bijective $(SB[40] = SB[52] = 0, SB[20] = SB[203] = 6, \dots)$ so maybe we can play with some values $m_1$ and $m_2$?

For simplicity, I set $rc$ to be all zeros and scaled down to 32 rounds (a full rotation of `state`) instead of 140 rounds.

```python
m1 = [40] * 16
m2 = [40] * 15 + [52]

print(f"{sponge(m1) = }")
print(f"{sponge(m2) = }")
```

I chose 40, 52 because $SB[40] = SB[52] = 0$


```
start_state: [40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

Round: 1
state: [40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40]
Round: 2
state: [40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 40]

...

Round: 15
state: [40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40]
Round: 16
state: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40]

...

Round: 31
state: [31, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 0, 79, 50, 133, 6, 204, 227, 0, 79, 50, 133, 6, 204, 227, 0]
Round: 32
state: [23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 193, 31, 2, 85, 199, 156, 179, 193, 31, 2, 85, 199, 156, 179, 193, 31]

sponge(m1) = [23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23]

---------------------------------------------------------------------

start_state: [40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

Round: 1
state: [40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40]
Round: 2
state: [40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 40]

...

Round: 15
state: [52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40]
Round: 16
state: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 52]

...

Round: 31
state: [31, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 71, 83, 0, 79, 50, 133, 6, 204, 227, 0, 79, 50, 133, 6, 204, 227, 0]
Round: 32
state: [23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 35, 193, 31, 2, 85, 199, 156, 179, 193, 31, 2, 85, 199, 156, 179, 193, 31]

sponge(m2) = [23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23]
```

The final states of $m_1$ and $m_2$ differ by only a single value, which makes sense since $m_1$ and $m_2$ originally differed by just one value.

However, this pattern doesn’t persist for long. 

```
Round: 47
state: [125, 54, 133, 104, 187, 60, 17, 40, 54, 133, 104, 187, 60, 17, 40, 54, 133, 232, 4, 37, 60, 55, 121, 232, 4, 37, 60, 55, 121, 232, 4, 37]
Round: 48
state: [119, 198, 169, 11, 125, 82, 105, 119, 198, 169, 11, 125, 82, 105, 119, 198, 56, 69, 102, 125, 120, 186, 56, 69, 102, 125, 120, 186, 56, 69, 102, 125]
---------------------------------------------------------------------

Round: 47
state: [137, 54, 133, 104, 187, 60, 17, 40, 54, 133, 104, 187, 60, 17, 40, 54, 133, 232, 4, 37, 60, 55, 121, 232, 4, 37, 60, 55, 121, 232, 4, 37]
Round: 48
state: [117, 196, 167, 9, 123, 80, 103, 117, 196, 167, 9, 123, 80, 103, 117, 196, 54, 67, 100, 123, 118, 184, 54, 67, 100, 123, 118, 184, 54, 67, 100, 137]
```

Since $SB[125] \neq SB[137]$, the pattern breaks.

Because $m_1$ differs from $m_2$ only at position 15, for the pattern to continue, I need to ensure that:

```
After round 15  (15 + 0 * 32): SB[state_m1[0]] = SB[state_m2[0]]
After round 47  (15 + 1 * 32): SB[state_m1[0]] = SB[state_m2[0]]
After round 79  (15 + 2 * 32): SB[state_m1[0]] = SB[state_m2[0]]
After round 111 (15 + 3 * 32): SB[state_m1[0]] = SB[state_m2[0]]
```

We can do this with a bit of bruteforcing

```python
def absorb(state):
    state = state[:]
    need = [15, 47, 79, 111]
    ans = []
    for i in range(ROUNDS):
        tmp = SB[(state[0] + rc[i]) % p]
        for j in range(1, len(state)):
            state[j] += tmp
            state[j] %= p
        state = state[1:] + state[:1]
        if i in need:
            ans.append(tmp) 
    return ans, state


def brute(): 
    payload = [random.randint(1,p-1) for _ in range(r)]
    table = {}
    for i in range(p): 
        payload[15] = i 
        x, _ = sponge(payload)
        if str(x) in table: 
            print(f"Found {table[str(x)], i}")
            return [payload, table[str(x)], i] 
        table[str(x)] = i 
    return None 

ans = brute()

while not ans: 
    ans = brute()

print(ans)
```

With a bit of luck: 

```
Found (153, 166)
[[205, 100, 141, 218, 217, 177, 53, 156, 191, 122, 208, 211, 160, 50, 52, 166], 153, 166]
```

Now we can try again: 

```python
m1 = [205, 100, 141, 218, 217, 177, 53, 156, 191, 122, 208, 211, 160, 50, 52, 153]
m2 = [205, 100, 141, 218, 217, 177, 53, 156, 191, 122, 208, 211, 160, 50, 52, 166]

print(f"{sponge(m1) = }")
print(f"{sponge(m2) = }")
```

```
Round: 140
state: [175, 154, 200, 117, 100, 225, 191, 29, 176, 42, 87, 109, 211, 202, 169, 92, 60, 211, 25, 142, 231, 185, 237, 164, 93, 19, 157, 62, 93, 90, 156, 178]

sponge(m1) = [175, 154, 200, 117, 100, 225, 191, 29, 176, 42, 87, 109]

---------------------------------------------------------------------

Round: 140
state: [175, 154, 200, 130, 100, 225, 191, 29, 176, 42, 87, 109, 211, 202, 169, 92, 60, 211, 25, 142, 231, 185, 237, 164, 93, 19, 157, 62, 93, 90, 156, 178]

sponge(m2) = [175, 154, 200, 130, 100, 225, 191, 29, 176, 42, 87, 109]
```

Niceeee, the problem is not over yet tho, we want $h(m_1) = h(m_2)$ (remember h appends the length of m and some 0 padding to our msg)

```python
    for i in range(0, len(payload), r):
        state = [(state[j] + payload[i+j]) % p for j in range(r)] + state[r:]
        state = absorb(state)
```

The first 16 values of the state will be incremented by the second block of our payload, while the last 16 values will remain unchanged.

This is excellent! Since the last 16 values of the state are identical for both $m_1$ and $m_2$ after the first 140 rounds, we can modify only the second block of the payloads, ensuring that the two states become identical.

```python
m1 = [205, 100, 141, 218, 217, 177, 53, 156, 191, 122, 208, 211, 160, 50, 52, 153]
m2 = [205, 100, 141, 218, 217, 177, 53, 156, 191, 122, 208, 211, 160, 50, 52, 166]

s1 = sponge(m1)
s2 = sponge(m2)

m1.extend([0 for _ in range(3)])
m2.extend([0 for _ in range(3)])

m1.append(0 if s1[3] >= s2[3] else s2[3] - s1[3])
m2.append(0 if s2[3] >= s1[3] else s1[3] - s2[3])

print(f"{h(m1) = }")
print(f"{h(m2) = }")
```

```
state after the 1 block: [175, 154, 200, 117, 100, 225, 191, 29, 176, 42, 87, 109, 211, 202, 169, 92, 60, 211, 25, 142, 231, 185, 237, 164, 93, 19, 157, 62, 93, 90, 156, 178]
state after the 2 block: [235, 82, 44, 212, 77, 176, 81, 64, 22, 75, 183, 67, 41, 213, 124, 165, 107, 35, 101, 30, 180, 34, 88, 161, 132, 204, 4, 21, 90, 55, 184, 144]
h(m1) = [235, 82, 44, 212, 77, 176, 81, 64, 22, 75, 183, 67]

--------------------------------------------------

state after the 1 block: [175, 154, 200, 130, 100, 225, 191, 29, 176, 42, 87, 109, 211, 202, 169, 92, 60, 211, 25, 142, 231, 185, 237, 164, 93, 19, 157, 62, 93, 90, 156, 178]
state after the 2 block: [235, 82, 44, 212, 77, 176, 81, 64, 22, 75, 183, 67, 41, 213, 124, 165, 107, 35, 101, 30, 180, 34, 88, 161, 132, 204, 4, 21, 90, 55, 184, 144]
h(m2) = [235, 82, 44, 212, 77, 176, 81, 64, 22, 75, 183, 67]
```

Now we just need to repeat this process for 10 rounds and hope for the best (painnnnn~~). We can also optimize the brute-force process using parallel computing.


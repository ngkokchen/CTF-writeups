# [Everything is Big]
**Category:** Crypto 
**Keywords:** #RSA #CryptoHack


This challenge involves the following code and output:

``` text
N = 0xb8af3d3afb893a602de4afe2a29d7615075d1e570f8bad8ebbe9b5b9076594cf06b6e7b30905b6420e950043380ea746f0a14dae34469aa723e946e484a58bcd92d1039105871ffd63ffe64534b7d7f8d84b4a569723f7a833e6daf5e182d658655f739a4e37bd9f4a44aff6ca0255cda5313c3048f56eed5b21dc8d88bf5a8f8379eac83d8523e484fa6ae8dbcb239e65d3777829a6903d779cd2498b255fcf275e5f49471f35992435ee7cade98c8e82a8beb5ce1749349caa16759afc4e799edb12d299374d748a9e3c82e1cc983cdf9daec0a2739dadcc0982c1e7e492139cbff18c5d44529407edfd8e75743d2f51ce2b58573fea6fbd4fe25154b9964d
e = 0x9ab58dbc8049b574c361573955f08ea69f97ecf37400f9626d8f5ac55ca087165ce5e1f459ef6fa5f158cc8e75cb400a7473e89dd38922ead221b33bc33d6d716fb0e4e127b0fc18a197daf856a7062b49fba7a86e3a138956af04f481b7a7d481994aeebc2672e500f3f6d8c581268c2cfad4845158f79c2ef28f242f4fa8f6e573b8723a752d96169c9d885ada59cdeb6dbe932de86a019a7e8fc8aeb07748cfb272bd36d94fe83351252187c2e0bc58bb7a0a0af154b63397e6c68af4314601e29b07caed301b6831cf34caa579eb42a8c8bf69898d04b495174b5d7de0f20cf2b8fc55ed35c6ad157d3e7009f16d6b61786ee40583850e67af13e9d25be3
c = 0x3f984ff5244f1836ed69361f29905ca1ae6b3dcf249133c398d7762f5e277919174694293989144c9d25e940d2f66058b2289c75d1b8d0729f9a7c4564404a5fd4313675f85f31b47156068878e236c5635156b0fa21e24346c2041ae42423078577a1413f41375a4d49296ab17910ae214b45155c4570f95ca874ccae9fa80433a1ab453cbb28d780c2f1f4dc7071c93aff3924d76c5b4068a0371dff82531313f281a8acadaa2bd5078d3ddcefcb981f37ff9b8b14c7d9bf1accffe7857160982a2c7d9ee01d3e82265eec9c7401ecc7f02581fd0d912684f42d1b71df87a1ca51515aab4e58fab4da96e154ea6cdfb573a71d81b2ea4a080a1066e1bc3474
```

```
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = b"crypto{?????????????????????????}"

m = bytes_to_long(FLAG)

def get_huge_RSA():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p*q
    phi = (p-1)*(q-1)
    while True:
        d = getPrime(256)
        e = pow(d,-1,phi)
        if e.bit_length() == N.bit_length():
            break
    return N,e


N, e = get_huge_RSA()
c = pow(m, e, N)

print(f'N = {hex(N)}')
print(f'e = {hex(e)}')
print(f'c = {hex(c)}')
```

So based on the code given, we can identify that the unique thing here is that d is a random small prime (only 256 bits), while e is the inverse of d. 

Googling around, this is known as a weakness, because if d is small, there is a known attack called Wiener attack, where it is used for when the condition $$d < \frac{1}{3} n^{1/4}$$ is fulfilled.

The theory for this attack is as follows: 
We can rewrite the formula to this
$$ed - k \cdot \phi(n) = 1$$

and if we divide by $d \cdot \phi(n)$, we get this:

$$\frac{e}{\phi(n)} - \frac{k}{d} = \frac{1}{d \cdot \phi(n)}$$

Since $d\phi(n)$ is a very large number, the difference is tiny.

And since $\phi(n)$ is very close to $n$, the fraction $\frac{e}{n}$ is an extremely good approximation of $\frac{k}{d}$. More specifically, it fulfills the Legendre's Theorem, where
$$\left| \frac{e}{n} - \frac{k}{d} \right| < \frac{1}{2d^2}$$

We can then guarantee $\frac{k}{d}$ as one of the convergents of the continued fraction expansion of $\frac{e}{n}$.

Here's the structure of a continued fraction:

$$\frac{e}{n} = a_0 + \frac{1}{a_1 + \frac{1}{a_2 + \frac{1}{a_3 + \dots}}}$$

First convergent: $a_0$
Second convergent: $a_0 + \frac{1}{a_1}$
Third convergent: $a_0 + \frac{1}{a_1 + \frac{1}{a_2}}$

Since N is 2048 bits (p*q), 1/4N is 512 bits, and so d is significantly smaller, we will use this attack. 
```
def get_continued_fraction(e, n):
    """Generates the continued fraction expansion coefficients [a0, a1, ...]."""
    cf = []
    while n:
        a = e // n
        cf.append(a)
        e, n = n, e % n
    return cf

def get_convergents(cf):
    """Yields each convergent (k, d) from the continued fraction coefficients."""
    n0, d0 = 0, 1
    n1, d1 = 1, 0
    for a in cf:
        n2, d2 = a * n1 + n0, a * d1 + d0
        yield n2, d2
        n0, d0, n1, d1 = n1, d1, n2, d2

def wiener_attack(e, n):
    """The main attack loop."""
    cf = get_continued_fraction(e, n)
    for k, d in get_convergents(cf):
        if k == 0: continue
        
        # We use a small number like 42 to verify the key
        msg = 42
        c = pow(msg, e, n)
        if pow(c, d, n) == msg:
            return d
            
    return None
```

Then once we find d, we can decrypt the script.

```
d = wiener_attack(e, n)

if d:
    print(f"[+] Found Private Key d: {d}")
    m = pow(c, d, n)
    
    # 5. CONVERT TO BYTES
    flag = long_to_bytes(m)
    print(f"[!] Flag: {flag.decode()}")
else:
    print("[-] Wiener's Attack failed (d might not be small enough).")
```


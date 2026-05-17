# Kraken AES

## Category

Cryptography / Side-channel Attacks

## Challenge Files

The useful challenge artifacts were:

- `plaintexts.npy`
- `traces.npy`

Locally, I solved it from `E:\School\CTF\cddc\crypto`.

The dataset contained 7,500 known plaintext inputs and 7,500 corresponding power traces:

```text
plaintexts shape: (7500, 4)
traces shape: (7500, 1000)
```

The first plaintext sample was:

```text
[102 179  92  14]
```

As bytes, that is:

```text
66 b3 5c 0e
```

## Summary

This was an AES side-channel challenge. Instead of attacking AES mathematically, the goal was to recover the secret key by correlating known plaintext bytes with measured leakage traces.

The leakage matched the AES first-round S-box model:

```text
HW(SBOX[plaintext_byte ^ key_guess])
```

For each key byte, I tried all 256 possible byte values and measured which guess had the highest correlation with the trace data.

## Approach

First, I inspected the NumPy arrays to understand the data format. `plaintexts.npy` held 4-byte plaintext inputs, and `traces.npy` held 1,000 sample points per trace.

Then I performed Correlation Power Analysis (CPA):

1. For each plaintext byte position, choose a key-byte guess from `0x00` to `0xff`.
2. Compute the AES intermediate value `SBOX[plaintext ^ key_guess]`.
3. Convert the intermediate value to a Hamming weight leakage model.
4. Correlate the model against every point in the measured traces.
5. Pick the key guess with the strongest absolute correlation.

The recovered bytes were:

```text
Byte 0: 0xA1
Byte 1: 0x59
Byte 2: 0x1D
Byte 3: 0xA8
```

So the recovered 4-byte key was:

```text
0xA1591DA8
```

## Solver Output

```text
Byte 0: key=0xA1 corr=0.0541
Byte 1: key=0x59 corr=0.0600
Byte 2: key=0x1D corr=0.0544
Byte 3: key=0xA8 corr=0.0592

Recovered key (4 bytes): 0xA1591DA8
Flag: CDDC2026{0xA1591DA8}
```

## Flag

```text
CDDC2026{0xA1591DA8}
```

## Lessons Learned

- Known plaintext plus trace leakage is enough to recover AES key bytes when the implementation leaks S-box intermediates.
- The correct leakage model matters. Here, `HW(SBOX[P ^ K])` produced the clearest key-byte candidates.
- Even relatively small correlations can be meaningful when they consistently rank the right byte above other guesses.

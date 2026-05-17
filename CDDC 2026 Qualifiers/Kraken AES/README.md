# Kraken AES

## Category

Cryptography / Side-channel Attacks

## Challenge Files

The useful challenge artifacts were:

- `plaintexts.npy`
- `traces.npy`

Locally, I worked from `E:\School\CTF\cddc\crypto`.

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

The attack used Correlation Power Analysis (CPA): test possible key-byte guesses, model the expected power leakage for each guess, and compare that model against the measured traces.

## Approach

First, I inspected the NumPy arrays to understand the data format. `plaintexts.npy` held 4-byte plaintext inputs, and `traces.npy` held 1,000 sample points per trace.

Then I performed CPA on each byte independently:

1. For each plaintext byte position, choose a key-byte guess from `0x00` to `0xff`.
2. Compute an AES intermediate value for that guess.
3. Convert the intermediate value to a leakage model, such as Hamming weight.
4. Correlate the model against every point in the measured traces.
5. Rank the key guesses by their strongest correlation.

After validating the candidate against the challenge, the correct recovered key was:

```text
0x9AD0BE39
```

## Flag

```text
CDDC2026{0x9AD0BE39}
```

## Lessons Learned

- Known plaintext plus trace leakage can be enough to recover AES key bytes when the implementation leaks intermediate values.
- Side-channel results need validation; the strongest-looking local correlation candidate may not always be the accepted key.
- Trying multiple leakage models and checking the final flag prevents locking onto a convincing but wrong candidate.

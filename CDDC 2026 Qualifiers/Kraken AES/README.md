# Kraken AES

## Category

Cryptography / Side-channel Attacks

## Challenge Files

The challenge provided two NumPy files:

- `plaintexts.npy`
- `traces.npy`

The data shape was:

```text
plaintexts shape: (7500, 4)
traces shape: (7500, 1000)
```

Each row in `plaintexts.npy` contained a 4-byte plaintext input. Each matching row in `traces.npy` contained a power trace with 1000 sample points.

The first plaintext sample was:

```text
[102 179  92  14]
```

As bytes:

```text
66 b3 5c 0e
```

## Summary

This was an AES side-channel challenge. The goal was to recover a 4-byte key from known plaintexts and power traces.

The important part was choosing the correct leakage model. A basic Hamming weight model such as:

```text
HW(SBOX[P ^ K])
```

produced convincing but wrong candidates.

The correct model was Hamming distance between the plaintext byte and the AES S-box output:

```text
HD(P, SBOX[P ^ K])
```

which can be computed as:

```text
HW(P ^ SBOX[P ^ K])
```

After aligning the traces and applying CPA with this Hamming distance model, the recovered key was:

```text
0x9AD0BE39
```

## Trace Alignment

The traces were desynchronised, meaning the same operation did not occur at exactly the same sample index in every trace.

If the traces are not aligned, the leakage signal gets blurred. This makes the correct key look weak or hidden by noise.

To fix this, I aligned the traces using a strong early bump in the power trace. This bump was not the secret-dependent leakage itself. It was just a stable timing landmark that appeared in every trace.

The alignment process was:

1. Look only at the early part of each trace.
2. Pick one reference trace.
3. Find the highest-energy short segment in that reference trace.
4. Use that segment as a template.
5. Slide the template across every trace and find where it matches best.
6. Shift each trace so that the matching segments line up.
7. Average the aligned segments into a cleaner template and repeat.

After alignment, the byte leakages were clearly located at these sample positions:

```text
101, 151, 201, 251
```

## Attack

For each byte position, I tested every possible key byte from `0x00` to `0xff`.

For a plaintext byte `P` and key guess `K`, I computed:

```text
SBOX[P ^ K]
```

Then I modeled the leakage as:

```text
HD(P, SBOX[P ^ K]) = HW(P ^ SBOX[P ^ K])
```

Finally, I correlated this predicted leakage against the aligned trace sample for that byte.

The strongest correlations were:

```text
byte 0: 9A, corr=+0.3228, pos=101
byte 1: D0, corr=+0.3079, pos=151
byte 2: BE, corr=+0.3045, pos=201
byte 3: 39, corr=+0.2936, pos=251
```

This gave the key:

```text
9AD0BE39
```

## Solver

```python
import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

PLAINTEXTS = "plaintexts.npy"
TRACES = "traces.npy"

SBOX = np.array([
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
], dtype=np.uint8)

HW = np.array([bin(i).count("1") for i in range(256)], dtype=float)

def shift_traces(traces, shifts):
    out = np.zeros_like(traces)
    for i, s in enumerate(shifts):
        if s > 0:
            out[i, :-s] = traces[i, s:]
        elif s < 0:
            out[i, -s:] = traces[i, :s]
        else:
            out[i] = traces[i]
    return out

def align_traces(traces, win=140, seg_len=35, ref_idx=3, iterations=3):
    early = traces[:, :win]
    ref = early[ref_idx]

    energy = np.cumsum(np.pad(ref * ref, (1, 0)))
    base = int(np.argmax(energy[seg_len:] - energy[:-seg_len]))
    template = ref[base:base + seg_len]

    for _ in range(iterations):
        t = template - template.mean()
        t /= np.sqrt(np.sum(t * t)) + 1e-12

        windows = sliding_window_view(early, seg_len, axis=1)
        centered = windows - windows.mean(axis=2, keepdims=True)

        denom = np.sqrt(np.sum(centered * centered, axis=2))
        denom[denom == 0] = 1

        corr = (centered @ t) / denom
        starts = np.argmax(corr, axis=1)

        aligned = shift_traces(traces, starts - base)
        template = aligned[:, base:base + seg_len].mean(axis=0)

    return aligned

def cpa_at_position(pt_byte, samples, pos):
    keys = np.arange(256, dtype=np.uint8)
    vals = np.arange(256, dtype=np.uint8)

    p = vals[None, :]
    k = keys[:, None]

    hyp = HW[np.bitwise_xor(p, SBOX[np.bitwise_xor(p, k)])]

    y = samples[:, pos].astype(float)
    y -= y.mean()
    yn = np.sqrt(np.sum(y * y))

    counts = np.bincount(pt_byte, minlength=256).astype(float)
    sums = np.bincount(pt_byte, weights=y, minlength=256).astype(float)

    n = len(pt_byte)
    mean_h = (hyp @ counts) / n
    h2 = (hyp * hyp) @ counts
    hnorm = np.sqrt(np.maximum(h2 - n * mean_h * mean_h, 1e-12))

    corr = (hyp @ sums) / (hnorm * yn)
    key = int(np.argmax(np.abs(corr)))

    return key, float(corr[key])

def main():
    plaintexts = np.load(PLAINTEXTS).astype(np.uint8)
    traces = np.load(TRACES).astype(float)

    aligned = align_traces(traces)
    positions = [101, 151, 201, 251]

    key = []
    for b, pos in enumerate(positions):
        kb, corr = cpa_at_position(plaintexts[:, b], aligned, pos)
        key.append(kb)
        print(f"byte {b}: {kb:02X}, corr={corr:+.4f}, pos={pos}")

    key_hex = "".join(f"{b:02X}" for b in key)
    print("Recovered 32-bit key:", key_hex)
    print("Flag:", f"CDDC2026{{0x{key_hex}}}")

if __name__ == "__main__":
    main()
```

## Output

```text
byte 0: 9A, corr=+0.3228, pos=101
byte 1: D0, corr=+0.3079, pos=151
byte 2: BE, corr=+0.3045, pos=201
byte 3: 39, corr=+0.2936, pos=251
Recovered 32-bit key: 9AD0BE39
Flag: CDDC2026{0x9AD0BE39}
```

## Flag

```text
CDDC2026{0x9AD0BE39}
```

## Lessons Learned

- Choosing the correct leakage model is critical. Hamming weight looked plausible, but Hamming distance was the correct model here.
- Trace alignment can make or break a side-channel attack. Without alignment, the leakage was spread out and correlations were weak.
- A stable non-secret-dependent feature, such as a large early power bump, can be used as a timing landmark.
- After alignment, the correct key bytes had much stronger correlations, making the solution clear.

# value_splitter.py

OSED prep script focused on **fast splitting of a 32-bit value into 2, 3 or 4 parts without badchars**, for use with **ADD** and (optionally) **SUB** gadgets in ROP chains.

You give it:

- a target value (e.g. `0x210`);
- a set of badchars (e.g. `\x00\x09\x0a\x0b\x0c\x0d\x20`);

and it tries to find:

- additive forms: `V0 + V1 (+ V2 + V3) = target (mod 2^32)`;
- optional subtractive form: `A - B = target (mod 2^32)`;

where each value is badchar-free in **little-endian**.

---

## Usage example

  $ python3 value_splitter.py -b "\x00\x09\x0A\x0B\x0C\x0D\x20" 0x210
    [+] Target: 0x00000210
    [+] Bad chars: 00 09 0a 0b 0c 0d 20

    [*] Direct value contains badchars in little-endian, trying decompositions...

    [*] Trying additive decompositions (V0 + V1 + ... = target mod 2^32)...
        [-] Trying with 2 term(s)...
    [+] Found additive decomposition with 2 term(s):
        V0 = 0x3de52f77  ->  77 2f e5 3d
        V1 = 0xc21ad299  ->  99 d2 1a c2

        Sum(Vi) mod 2^32 = 0x00000210
        Target           = 0x00000210

    [+] Example ROP-style usage (pseudo):
        # reg += V0; reg += V1; ...
        reg += 0x3de52f77  # 77 2f e5 3d
        reg += 0xc21ad299  # 99 d2 1a c2

---

## Arguments

### Positional

- `target`  
  32-bit value to decompose. Examples:
  - `0x210`
  - `528`
  - `0xdeadbeef`

### Options

- `-b`, `--bad`  
  Badchars, can be specified multiple times. Examples:
  - `-b "\x00\x0a\x0d\x20"`
  - `-b "\x00\x09" -b "\x0a\x0b"`

- `--max-terms`  
  Maximum number of additive terms to try (default: `4`, allowed values: `2`, `3`, `4`).

- `--max-tries`  
  Maximum random attempts per decomposition (default: `1000000`).

- `--allow-sub`  
  Also try to find a decomposition of the form  
  `A - B = target (mod 2^32)`  
  with both `A` and `B` free of badchars in little-endian.

- `--seed`  
  Optional RNG seed for reproducible results.

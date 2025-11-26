# value_splitter.py

OSED prep script focused on **fast splitting of a 32-bit value into 1, 2, 3 or 4 parts without badchars**, for use with **ADD** and **SUB** gadgets in ROP chains.

You give it:

- a target **delta** value (for example `0x210`);
- a set of badchars (for example `\x00\x09\x0a\x0b\x0c\x0d\x20`);

and it tries to find values that are badchar-free in **little-endian** such that:

- for **`+delta` (increase reg)**:  
  `V0 + V1 (+ V2 + V3) = +delta (mod 2^32)`
- for **`-delta` (decrease reg)**:  
  `W0 + W1 (+ W2 + W3) = -delta (mod 2^32)`

Then it prints ready-to-use ROP snippets for:

- increasing / decreasing a register with **ADD** gadgets;
- increasing / decreasing a register with **SUB** gadgets.

---

## Usage example

    $ python3 value_splitter.py -b "\x00\x09\x0A\x0B\x0C\x0D\x20" 0x210 --seed 1
    [+] Delta:  0x00000210
    [+] Bad chars: 00 09 0a 0b 0c 0d 20

    [*] Decomposition for +delta (increase reg with ADD)...
    [+] Values for +delta (increase reg)
        V0 = 0x254816ca  ->  ca 16 48 25
        V1 = 0xdab7eb46  ->  46 eb b7 da

        Sum(Vi) mod 2^32 = 0x00000210
        Target           = 0x00000210

    [+] Use with ADD gadget to INCREASE reg by +delta:
        # reg starts with some base address/value
        reg += 0x254816ca  # ca 16 48 25
        reg += 0xdab7eb46  # 46 eb b7 da

    [+] Use with SUB gadget to DECREASE reg by +delta:
        # reg starts with some base address/value
        reg -= 0x254816ca  # ca 16 48 25
        reg -= 0xdab7eb46  # 46 eb b7 da

    [*] Decomposition for -delta (decrease reg with ADD)...
    [+] Values summing to -delta (decrease reg)
        V0 = 0xfffffdf0  ->  f0 fd ff ff

        Sum(Vi) mod 2^32 = 0xfffffdf0
        Target           = 0xfffffdf0

    [+] Use with ADD gadget to DECREASE reg by +delta:
        # reg starts with some base address/value
        reg += 0xfffffdf0  # f0 fd ff ff
        # Overall effect: reg = reg - delta (mod 2^32)

    [+] Use with SUB gadget to INCREASE reg by +delta (two minus = plus):
        # reg starts with some base address/value
        reg -= 0xfffffdf0  # f0 fd ff ff
        # Overall effect: reg = reg + delta (mod 2^32)

    [*] Done.

Summary of how to read this:

- **Increase reg by `delta`:**
  - use `Values for +delta` with **ADD**, or
  - use `Values summing to -delta` with **SUB** (double minus is a plus).
- **Decrease reg by `delta`:**
  - use `Values for +delta` with **SUB**, or
  - use `Values summing to -delta` with **ADD`.

---

## Arguments

### Positional

- `target`  
  32-bit delta to decompose. Examples:
  - `0x210`
  - `528`
  - `0xdeadbeef`

### Options

- `-b`, `--bad`  
  Badchars, can be specified multiple times. Supported formats:

  - Escaped bytes:

        -b "\x00\x0a\x0d\x20"

  - Comma- or space-separated hex:

        -b "0x00, 0x09, 0x0A, 0x20"
        -b "0x00 0x09 0x0A 0x20"

  - You can mix several:

        -b "\x00\x0a" -b "0x09 0x0B 0x0C 0x0D 0x20"

- `--max-terms`  
  Maximum number of terms to try (default: `4`, allowed values: `1`, `2`, `3`, `4`).

- `--max-tries`  
  Maximum random attempts per multi-term decomposition (default: `1000000`).

- `--seed`  
  Optional RNG seed for reproducible results.  
  Same arguments + same `--seed` ⇒ script will show the same value of `V0`, `V1` every run.

---

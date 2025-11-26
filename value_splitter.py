#!/usr/bin/env python3
import argparse
import codecs
import random
import re
import sys
from typing import List, Set, Optional


# ANSI colors (disabled if not a TTY)
if sys.stdout.isatty():
    COLOR_GREEN = "\033[92m"
    COLOR_RED = "\033[91m"
    COLOR_RESET = "\033[0m"
else:
    COLOR_GREEN = COLOR_RED = COLOR_RESET = ""


def parse_badchars(bad_list: List[str]) -> Set[int]:
    """
    Parse badchar specification(s) into a set of bytes (0–255).

    Supports:
      - "\\x00\\x09\\x0a" (escaped bytes)
      - "0x00, 0x09, 0x0A, 0x0B" (comma/space separated)
      - "0x00 0x09 0x0a" (space separated)
    """
    bad: Set[int] = set()

    for spec in bad_list:
        if not spec:
            continue

        # 1) Try to parse 0xNN style tokens: "0x00, 0x09 0x0A"
        hex_matches = re.findall(r'0x([0-9a-fA-F]{2})', spec)
        if hex_matches:
            for h in hex_matches:
                bad.add(int(h, 16))
            continue

        # 2) Otherwise treat as "\x00\x09\x0a" / raw escaped bytes
        decoded = codecs.decode(spec, "unicode_escape")
        bad_bytes = decoded.encode("latin-1", errors="ignore")
        bad.update(bad_bytes)

    return bad


def has_bad_bytes(value: int, bad: Set[int]) -> bool:
    """Check if a 32-bit value has any bad bytes in its little-endian representation."""
    b = value.to_bytes(4, "little", signed=False)
    return any(byte in bad for byte in b)


def format_bytes_le(value: int) -> str:
    """Format 32-bit value as LE bytes: 'aa bb cc dd'."""
    b = value.to_bytes(4, "little", signed=False)
    return " ".join(f"{x:02x}" for x in b)


def random_good_value(allowed: List[int]) -> int:
    """
    Generate a random 32-bit value whose 4 bytes (little-endian)
    are all in the 'allowed' list.
    """
    v = 0
    for i in range(4):
        v |= random.choice(allowed) << (8 * i)
    return v & 0xFFFFFFFF


def decompose_add_fixed_terms(
    target: int,
    bad: Set[int],
    terms: int,
    max_tries: int = 1000000,
) -> Optional[List[int]]:
    """
    Try to find an additive decomposition with a fixed number of terms:

        V0 + V1 + ... + V(terms-1) ≡ target (mod 2^32),

    where each Vi has no bad bytes in its little-endian representation.

    Randomized search:
      - for 2 terms: pick random A, compute B = target - A
      - for 3 terms: pick random A, B, compute C = target - A - B
      - for 4 terms: pick random A, B, C, compute D = target - A - B - C
    """
    if terms < 2 or terms > 4:
        raise ValueError("This function supports 2, 3, or 4 terms only.")

    allowed = [b for b in range(256) if b not in bad]
    if not allowed:
        return None

    target &= 0xFFFFFFFF

    for _ in range(max_tries):
        if terms == 2:
            a = random_good_value(allowed)
            b = (target - a) & 0xFFFFFFFF
            if not has_bad_bytes(a, bad) and not has_bad_bytes(b, bad):
                return [a, b]

        elif terms == 3:
            a = random_good_value(allowed)
            b = random_good_value(allowed)
            c = (target - a - b) & 0xFFFFFFFF
            if (not has_bad_bytes(a, bad) and
                not has_bad_bytes(b, bad) and
                not has_bad_bytes(c, bad)):
                return [a, b, c]

        elif terms == 4:
            a = random_good_value(allowed)
            b = random_good_value(allowed)
            c = random_good_value(allowed)
            d = (target - a - b - c) & 0xFFFFFFFF
            if all(not has_bad_bytes(v, bad) for v in (a, b, c, d)):
                return [a, b, c, d]

    return None


def find_decomposition(
    target: int,
    bad: Set[int],
    max_terms: int,
    max_tries: int,
) -> Optional[List[int]]:
    """
    Find a decomposition of target as sum of 1..max_terms terms without badchars.

    - If target itself has no badchars (in LE), returns [target].
    - Otherwise tries 2, 3, ..., max_terms using randomized search.
    """
    target &= 0xFFFFFFFF

    # 1-term case
    if not has_bad_bytes(target, bad):
        return [target]

    # 2..max_terms
    for terms in range(2, max_terms + 1):
        res = decompose_add_fixed_terms(target, bad, terms, max_tries=max_tries)
        if res is not None:
            return res

    return None


def verify_decomposition(target: int, values: List[int], bad: Set[int]) -> None:
    """
    Verify that:
      - all values are badchar-free in LE
      - sum(values) mod 2^32 == target
    Raises AssertionError on failure.
    """
    total = 0
    for v in values:
        assert not has_bad_bytes(v, bad), f"value {v:#x} contains bad bytes"
        total = (total + v) & 0xFFFFFFFF
    assert total == (target & 0xFFFFFFFF), "sum(values) does not match target"


def print_decomposition(label: str, target: int, values: List[int]) -> None:
    """Pretty-print a decomposition block."""
    print(f"[+] {label}")
    total = 0
    for i, v in enumerate(values):
        total = (total + v) & 0xFFFFFFFF
        print(f"    V{i} = 0x{v:08x}  ->  {format_bytes_le(v)}")
    print()
    print(f"    Sum(Vi) mod 2^32 = 0x{total:08x}")
    print(f"    Target           = 0x{target:08x}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "OSED prep tool: fast split of a 32-bit value into 1/2/3/4 parts "
            "without badchars, for use with ADD and SUB gadgets."
        )
    )
    parser.add_argument(
        "target",
        help='Target delta, e.g. "0x210" or "528". Interpreted as unsigned 32-bit.',
    )
    parser.add_argument(
        "-b",
        "--bad",
        action="append",
        default=[],
        help=(
            r'Badchars. Supports formats like "\x00\x0a", '
            r'"0x00, 0x0A, 0x20", or "0x00 0x0a 0x20". '
            r'Can be specified multiple times.'
        ),
    )
    parser.add_argument(
        "--max-terms",
        type=int,
        default=4,
        choices=[1, 2, 3, 4],
        help="Maximum number of terms to try (default: 4).",
    )
    parser.add_argument(
        "--max-tries",
        type=int,
        default=1000000,
        help="Maximum random attempts per multi-term decomposition (default: 1000000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional RNG seed for reproducible results.",
    )

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    delta = int(args.target, 0) & 0xFFFFFFFF  # logical +delta
    bad = parse_badchars(args.bad)

    print(f"[+] Delta:  0x{delta:08x}")
    if bad:
        print("[+] Bad chars:", " ".join(f"{b:02x}" for b in sorted(bad)))
    else:
        print("[+] Bad chars: <none>")

    # ---------- ADD / SUB(-delta) decomposition (sum == +delta) ----------
    print(
        f"\n{COLOR_GREEN}[*] Decomposition for +delta (increase reg with ADD)...{COLOR_RESET}"
    )
    add_dec = find_decomposition(delta, bad, args.max_terms, args.max_tries)

    if add_dec is None:
        print("[-] No decomposition for +delta found "
              f"up to {args.max_terms} term(s) with {args.max_tries} tries.")
    else:
        verify_decomposition(delta, add_dec, bad)
        print_decomposition("Values for +delta (increase reg)", delta, add_dec)

        print("[+] Use with ADD gadget to INCREASE reg by +delta:")
        print("    # reg starts with some base address/value")
        for i, v in enumerate(add_dec):
            print(f"    reg += 0x{v:08x}  # {format_bytes_le(v)}")
        print()

        print("[+] Use with SUB gadget to DECREASE reg by +delta:")
        print("    # reg starts with some base address/value")
        for i, v in enumerate(add_dec):
            print(f"    reg -= 0x{v:08x}  # {format_bytes_le(v)}")
        print()

    # ---------- SUB/ADD decomposition for -delta (sum == -delta mod 2^32) ----------
    neg_delta = (-delta) & 0xFFFFFFFF
    print(
        f"{COLOR_RED}[*] Decomposition for -delta (decrease reg with ADD)...{COLOR_RESET}"
    )
    neg_dec = find_decomposition(neg_delta, bad, args.max_terms, args.max_tries)

    if neg_dec is None:
        print("[-] No decomposition for -delta found "
              f"up to {args.max_terms} term(s) with {args.max_tries} tries.")
    else:
        verify_decomposition(neg_delta, neg_dec, bad)
        print_decomposition("Values summing to -delta (decrease reg)", neg_delta, neg_dec)

        print("[+] Use with ADD gadget to DECREASE reg by +delta:")
        print("    # reg starts with some base address/value")
        for i, v in enumerate(neg_dec):
            print(f"    reg += 0x{v:08x}  # {format_bytes_le(v)}")
        print("    # Overall effect: reg = reg - delta (mod 2^32)")
        print()

        print("[+] Use with SUB gadget to INCREASE reg by +delta (two minus = plus):")
        print("    # reg starts with some base address/value")
        for i, v in enumerate(neg_dec):
            print(f"    reg -= 0x{v:08x}  # {format_bytes_le(v)}")
        print("    # Overall effect: reg = reg + delta (mod 2^32)")
        print()

    print("[*] Done.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import codecs
import random
from typing import List, Set, Optional, Tuple


def parse_badchars(bad_list: List[str]) -> Set[int]:
    """
    Parse badchar specification(s) into a set of bytes (0–255).

    Accepts things like:
      - "\\x00\\x0a"
      - "\\x00"
      - raw bytes if shell passes them through.
    """
    bad = set()
    for spec in bad_list:
        # Interpret escape sequences: \xNN, \n, etc.
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


def decompose_add(
    target: int,
    bad: Set[int],
    terms: int,
    max_tries: int = 1000000,
) -> Optional[List[int]]:
    """
    Try to find an additive decomposition:

        V0 + V1 + ... + V(terms-1) ≡ target (mod 2^32),

    where each Vi has no bad bytes in its little-endian representation.

    The algorithm is randomized:
      - for 2 terms: pick random A, compute B = target - A
      - for 3 terms: pick random A, B; compute C = target - A - B
      - for 4 terms: pick random A, B, C; compute D = target - A - B - C
    """
    if terms < 2 or terms > 4:
        raise ValueError("This function supports 2, 3, or 4 terms only.")

    allowed = [b for b in range(256) if b not in bad]
    if not allowed:
        return None

    target &= 0xFFFFFFFF

    for _ in range(max_tries):
        if terms == 2:
            A = random_good_value(allowed)
            B = (target - A) & 0xFFFFFFFF
            if not has_bad_bytes(A, bad) and not has_bad_bytes(B, bad):
                return [A, B]

        elif terms == 3:
            A = random_good_value(allowed)
            B = random_good_value(allowed)
            C = (target - A - B) & 0xFFFFFFFF
            if (not has_bad_bytes(A, bad) and
                not has_bad_bytes(B, bad) and
                not has_bad_bytes(C, bad)):
                return [A, B, C]

        elif terms == 4:
            A = random_good_value(allowed)
            B = random_good_value(allowed)
            C = random_good_value(allowed)
            D = (target - A - B - C) & 0xFFFFFFFF
            if all(not has_bad_bytes(v, bad) for v in (A, B, C, D)):
                return [A, B, C, D]

    return None


def decompose_sub(
    target: int,
    bad: Set[int],
    max_tries: int = 1000000,
) -> Optional[Tuple[int, int]]:
    """
    Try to find a subtraction decomposition:

        A - B ≡ target (mod 2^32),

    where both A and B have no bad bytes in their little-endian representation.

    Algorithm (randomized):
      - pick random A
      - compute B = A - target (mod 2^32)
      - check both A and B for bad bytes
    """
    allowed = [b for b in range(256) if b not in bad]
    if not allowed:
        return None

    target &= 0xFFFFFFFF

    for _ in range(max_tries):
        A = random_good_value(allowed)
        B = (A - target) & 0xFFFFFFFF
        if not has_bad_bytes(A, bad) and not has_bad_bytes(B, bad):
            return A, B

    return None


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Split a 32-bit integer into 2–4 terms without badchars "
            "(little-endian). Supports additive and optional A - B form. "
            "Uses a fast randomized search instead of heavy DFS."
        )
    )
    parser.add_argument(
        "target",
        help='Target value, e.g. "0x210" or "528". Interpreted as unsigned 32-bit.',
    )
    parser.add_argument(
        "-b",
        "--bad",
        action="append",
        default=[],
        help=r'Badchars, e.g. -b "\x00\x0a\x0d". You can specify -b multiple times.',
    )
    parser.add_argument(
        "--max-terms",
        type=int,
        default=4,
        choices=[2, 3, 4],
        help="Maximum number of additive terms to try (default: 4).",
    )
    parser.add_argument(
        "--max-tries",
        type=int,
        default=1000000,
        help="Maximum number of random attempts per decomposition (default: 1000000).",
    )
    parser.add_argument(
        "--allow-sub",
        action="store_true",
        help="Also try to find a representation A - B = target (mod 2^32).",
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

    target = int(args.target, 0) & 0xFFFFFFFF
    bad = parse_badchars(args.bad)

    print(f"[+] Target: 0x{target:08x}")
    if bad:
        print("[+] Bad chars:", " ".join(f"{b:02x}" for b in sorted(bad)))
    else:
        print("[+] Bad chars: <none>")

    # 1-term case (direct value)
    if not has_bad_bytes(target, bad):
        print("\n[+] Direct value has no badchars in little-endian:")
        print(f"    V0 = 0x{target:08x}  ->  {format_bytes_le(target)}")
    else:
        print("\n[*] Direct value contains badchars in little-endian, "
              "trying decompositions...")

    # Additive decompositions: 2..max_terms
    print("\n[*] Trying additive decompositions (V0 + V1 + ... = target mod 2^32)...")

    add_result: Optional[List[int]] = None
    for terms in range(2, args.max_terms + 1):
        print(f"    [-] Trying with {terms} term(s)...")
        res = decompose_add(target, bad, terms, max_tries=args.max_tries)
        if res is not None:
            add_result = res
            print(f"[+] Found additive decomposition with {terms} term(s):")
            total = 0
            for i, v in enumerate(res):
                total = (total + v) & 0xFFFFFFFF
                print(f"    V{i} = 0x{v:08x}  ->  {format_bytes_le(v)}")
            print()
            print(f"    Sum(Vi) mod 2^32 = 0x{total:08x}")
            print(f"    Target           = 0x{target:08x}")

            print("\n[+] Example ROP-style usage (pseudo):")
            print("    # reg += V0; reg += V1; ...")
            for i, v in enumerate(res):
                print(f"    reg += 0x{v:08x}  # {format_bytes_le(v)}")
            break

    if add_result is None:
        print("[-] No additive decomposition found up to "
              f"{args.max_terms} term(s) with {args.max_tries} tries each.")

    # Subtraction form: A - B = target
    if args.allow_sub:
        print("\n[*] Trying subtraction form: A - B = target (mod 2^32)...")
        sub_res = decompose_sub(target, bad, max_tries=args.max_tries)
        if sub_res is None:
            print("[-] No A - B decomposition found without badchars.")
        else:
            A, B = sub_res
            check = (A - B) & 0xFFFFFFFF
            print("[+] Found A - B decomposition:")
            print(f"    A = 0x{A:08x}  ->  {format_bytes_le(A)}")
            print(f"    B = 0x{B:08x}  ->  {format_bytes_le(B)}")
            print()
            print(f"    (A - B) mod 2^32 = 0x{check:08x}")
            print(f"    Target           = 0x{target:08x}")

            print("\n[+] Example ROP-style usage (pseudo):")
            print("    reg = 0x{0:08x}  # {1}".format(A, format_bytes_le(A)))
            print("    reg -= 0x{0:08x} # {1}".format(B, format_bytes_le(B)))

    print("\n[*] Done.")


if __name__ == "__main__":
    main()


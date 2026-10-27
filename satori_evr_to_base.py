#!/usr/bin/env python3
"""
SATORI - Evrmore (EVR) WIF private key -> MetaMask / Base (EVM) converter

* Works on Windows, macOS and Linux with plain Python 3.8+.
* ZERO third-party dependencies. Keccak-256 and secp256k1 are implemented
  below in pure Python, so there is nothing to download or install.
* 100% OFFLINE. The script never opens a network connection and never
  writes anything to disk. You can run it with Wi-Fi / Ethernet disabled.

RUN:
    Windows:      python satori_evr_to_base.py
    macOS/Linux:  python3 satori_evr_to_base.py
    Self-test:    python satori_evr_to_base.py --test
"""

import getpass
import hashlib
import platform
import sys

MIN_PYTHON = (3, 8)

LOGO = r"""
   _____      _______ ____  _____  _____
  / ____|  /\|__   __/ __ \|  __ \|_   _|
 | (___   /  \  | | | |  | | |__) | | |
  \___ \ / /\ \ | | | |  | |  _  /  | |
  ____) / ____ \| | | |__| | | \ \ _| |_
 |_____/_/    \_\_|  \____/|_|  \_\_____|

   Evrmore (EVR) -> Base / MetaMask key converter
"""

# =============================================================================
# Environment check (replaces "pip install": there is nothing to install)
# =============================================================================
def check_environment() -> None:
    if sys.version_info < MIN_PYTHON:
        sys.exit(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required, "
            f"you have {platform.python_version()}. "
            "Download it from https://www.python.org/downloads/"
        )
    print(f"System:        {platform.system()} {platform.release()} "
          f"({platform.machine()})")
    print(f"Python:        {platform.python_version()}")
    print("Dependencies:  none required (pure Python)  [OK]")


# =============================================================================
# Keccak-256 (original Keccak padding 0x01, as used by Ethereum).
# NOTE: this is NOT hashlib.sha3_256 (which uses 0x06 padding).
# =============================================================================
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a):
    for rc in _RC:
        # theta
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        # chi
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
              for y in range(5)] for x in range(5)]
        # iota
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136  # (1600 - 2*256) / 8
    # pad10*1 with Keccak domain byte 0x01
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * ((rate - len(padded) % rate) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            state[i % 5][i // 5] ^= lane
        state = _keccak_f(state)
    out = b""
    for i in range(4):  # 4 lanes * 8 bytes = 32 bytes
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return out


# =============================================================================
# secp256k1 (pure Python; fine for a one-off local conversion)
# =============================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _scalar_mult(k: int, point):
    result, addend = None, point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def eth_address(priv: bytes) -> str:
    x, y = _scalar_mult(int.from_bytes(priv, "big"), G)
    addr = keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex()
    h = keccak256(addr.encode()).hex()  # EIP-55 checksum casing
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c
                          for i, c in enumerate(addr))


# =============================================================================
# WIF (Base58Check) decoding for Evrmore
# =============================================================================
WIF_VERSIONS = {0x80: "Evrmore mainnet", 0xEF: "Evrmore testnet"}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in B58:
            raise ValueError(f"Invalid Base58 character: {ch!r}")
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def decode_wif(wif: str):
    """Return (32-byte private key, compressed flag, network name)."""
    wif = wif.strip()
    if not wif:
        raise ValueError("Empty input.")
    raw = base58_decode(wif)
    if len(raw) < 5:
        raise ValueError("Input is too short to be a WIF key.")
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("Base58Check checksum mismatch (typo or corrupted key).")
    version = payload[0]
    if version not in WIF_VERSIONS:
        raise ValueError(f"WIF version byte 0x{version:02X} is not Evrmore "
                         "(expected 0x80 mainnet or 0xEF testnet).")
    if len(payload) == 33:
        compressed = False
    elif len(payload) == 34 and payload[33] == 0x01:
        compressed = True
    else:
        raise ValueError("Invalid WIF payload length / compression flag.")
    priv = payload[1:33]
    if not 1 <= int.from_bytes(priv, "big") < N:
        raise ValueError("Private key is outside the valid secp256k1 range.")
    return priv, compressed, WIF_VERSIONS[version]


# =============================================================================
# Self-test with publicly known vectors
# =============================================================================
def self_test() -> int:
    fails = 0

    def check(name, ok):
        nonlocal fails
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
        fails += not ok

    # Keccak-256 known answers (must differ from SHA3-256).
    check("Keccak-256(empty) = c5d24601...",
          keccak256(b"").hex() ==
          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    check("Keccak-256('abc') = 4e03657a...",
          keccak256(b"abc").hex() ==
          "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    check("Keccak-256 differs from hashlib.sha3_256",
          keccak256(b"") != hashlib.sha3_256(b"").digest())

    # Private key = 1 -> famous Ethereum address. Evrmore shares the 0x80 WIF
    # prefix with Bitcoin, so these are valid EVR mainnet WIF keys.
    exp_hex = "0x" + "00" * 31 + "01"
    exp_addr = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    for wif, comp in [
        ("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", True),
        ("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", False),
    ]:
        priv, c, _ = decode_wif(wif)
        check(f"WIF ({'compressed' if comp else 'uncompressed'}) -> hex & address",
              "0x" + priv.hex() == exp_hex and c == comp
              and eth_address(priv) == exp_addr)

    # secp256k1 scalar multiplication vs. Bitcoin-wiki published key pair.
    k = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    check("secp256k1 pubkey matches Bitcoin-wiki vector",
          _scalar_mult(k, G) == (
              0x50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352,
              0x2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6))
    check("secp256k1 2*G and 3*G vectors",
          _scalar_mult(2, G)[0] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
          and _scalar_mult(3, G)[0] == 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9)

    # Bitcoin-wiki example key, hex value is public.
    priv, _, _ = decode_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    check("Bitcoin-wiki WIF -> known hex",
          priv.hex() == "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")

    # Negative tests.
    for name, bad in [
        ("corrupted checksum rejected",
         "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm"),
        ("invalid character rejected", "0OIl"),
        ("empty input rejected", "   "),
    ]:
        try:
            decode_wif(bad)
            check(name, False)
        except ValueError:
            check(name, True)

    print("\nAll tests passed." if not fails else f"\n{fails} test(s) FAILED.")
    return 1 if fails else 0


# =============================================================================
# Main
# =============================================================================
def main() -> int:
    print(LOGO)
    check_environment()
    print()
    print("  This tool runs 100% OFFLINE.")
    print("  It does NOT connect to the internet and does NOT send anything to any server.")
    print("  It does NOT save your keys to disk. Everything stays in this window.")
    print("  Tip: you can disconnect from the network before entering your key.")
    print()

    if "--test" in sys.argv:
        print("Running self-test...\n")
        return self_test()

    print("WARNING: anyone who has the private key controls the funds. Never share it.")
    try:
        if sys.stdin.isatty():
            # Real terminal: hide the key while typing/pasting.
            wif = getpass.getpass("Enter Evrmore private key (WIF) [input is hidden]: ")
        else:
            # Piped / non-console input (e.g. Git Bash mintty): plain read.
            wif = input("Enter Evrmore private key (WIF): ")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return 1
    try:
        priv, compressed, network = decode_wif(wif)
    except ValueError as e:
        print(f"\nError: {e}")
        return 1

    print()
    print(f"  Network:                {network}")
    print(f"  WIF type:               {'compressed' if compressed else 'uncompressed'}")
    print(f"  Private Key (MetaMask): 0x{priv.hex()}")
    print(f"  Base Wallet Address:    {eth_address(priv)}")
    print()
    print("  MetaMask: Account menu -> Import account -> Private Key -> paste the key.")
    print("  The address shown in MetaMask must match the Base Wallet Address above.")
    print("  Close this window when you are done so the key is not left on screen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

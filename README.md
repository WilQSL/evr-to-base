# Satori EVR → Base key converter

Convert an **Evrmore (EVR)** wallet private key from WIF format to the
64-character HEX private key used by **MetaMask** and the **Base** network
(or any other EVM chain), and show the matching `0x...` address.

```
   _____      _______ ____  _____  _____
  / ____|  /\|__   __/ __ \|  __ \|_   _|
 | (___   /  \  | | | |  | | |__) | | |
  \___ \ / /\ \ | | | |  | |  _  /  | |
  ____) / ____ \| | | |__| | | \ \ _| |_
 |_____/_/    \_\_|  \____/|_|  \_\_____|
```

## Security model

- **100% offline.** The script never opens a network connection and never
  sends anything anywhere. You can run it with Wi-Fi / Ethernet disabled.
- **Nothing is written to disk.** Keys exist only in memory and on your screen.
- **Zero third-party dependencies.** Keccak-256 and secp256k1 are implemented
  in the script itself, so there is nothing to `pip install` and no external
  code to trust. The only imports are Python standard library modules
  (`getpass`, `hashlib`, `platform`, `sys`).
- **Single file.** Everything is in `satori_evr_to_base.py`, about 300 lines.
  Read it before you run it.

## Requirements

Python 3.8 or newer. Works on Windows, macOS and Linux.

Check your version:

```
python --version
```

If you do not have Python, download it from https://www.python.org/downloads/

## Usage

1. Download `satori_evr_to_base.py`.
2. Open a terminal in the folder where you saved it.
3. Run the built-in self-test first:

   ```
   python satori_evr_to_base.py --test
   ```

   (on macOS / Linux use `python3` instead of `python`)

   Every line should show `[OK]` and the output should end with
   `All tests passed.`

4. Run the converter:

   ```
   python satori_evr_to_base.py
   ```

5. Paste your Evrmore WIF private key and press Enter. The input is hidden
   while you type or paste it.

6. You will see:

   ```
   Network:                Evrmore mainnet
   WIF type:               compressed
   Private Key (MetaMask): 0x...
   Base Wallet Address:    0x...
   ```

7. In MetaMask: **Account menu → Import account → Private Key** and paste the
   value from the `Private Key (MetaMask)` line. The address MetaMask shows
   must match `Base Wallet Address`.

8. Close the terminal window when you are done so the key is not left on
   screen.

## What the script checks

- Base58Check checksum (catches typos and corrupted keys)
- Evrmore WIF version byte (`0x80` mainnet, `0xEF` testnet)
- Compressed and uncompressed WIF keys (both give the same 32-byte key)
- Private key is within the valid secp256k1 range
- Address is computed with Ethereum **Keccak-256** (not SHA3-256) and shown
  with EIP-55 checksum casing, exactly as MetaMask displays it

## Self-test vectors

`--test` verifies the implementation against publicly known values:

- Keccak-256 of an empty string and of `"abc"`
- Private key `1` → address `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`
- Bitcoin-wiki example key pair (secp256k1 scalar multiplication)
- Corrupted checksum, invalid characters and empty input are rejected

## Warning

Anyone who has the private key controls the funds. Never share it, never
paste it into a website, and never run this tool on a computer you do not
trust.

## License

MIT, see [LICENSE](LICENSE).

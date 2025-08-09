# Hash-Cracker

HashCracker is a versatile Python tool designed to crack various hash algorithms using either a wordlist or brute-force generation of possible passwords.

## Features

- Supports multiple hashing algorithms:
  - MD5
  - SHA1
  - SHA256
  - SHA512
  - SHA256 (Base64 encoded from raw hash bytes)
  - Auto-detection for common hash lengths
- Crack single hashes or entire files containing hashes
- Replace cracked hashes directly in files
- Stupid mode for brute-forcing passwords of a given length and character set

## Installation

Clone this repository and install any required dependencies:

```bash
git clone https://github.com/yourusername/HashCracker.git
cd HashCracker
```

This script requires Python 3.x.

## Usage

### Modes

- **hash** – Crack a single hash
- **file** – Crack hashes from a file
- **stupid-mode** – Brute-force attack with customizable length range

### Examples

#### Crack a single SHA256 hash with a wordlist:
```bash
python main.py -m hash -t sha256 -hs <hash_value> -w wordlist.txt
```

#### Crack hashes from a file and replace them in place:
```bash
python main.py -m file -t sha1 -f hashes.txt -w wordlist.txt -fm replace
```

#### Use stupid mode to brute-force:
```bash
python main.py -m stupid-mode -t sha256 -f hashes.txt -smm 4 -smx 6 -fm replace
```

## Arguments

| Argument                  | Description |
|---------------------------|-------------|
| `--mode`, `-m`            | Mode of operation: `hash`, `file`, `stupid-mode` |
| `--type`, `-t`            | Hash type: `md5`, `sha1`, `sha256`, `sha512`, `auto`, `sha256-b64-unhex` |
| `--save`, `-s`            | Save results to file (default: results.txt) |
| `--file`, `-f`            | Path to file containing hashes (required in `file` and `stupid-mode`) |
| `--wordlist`, `-w`        | Path to wordlist file (required unless using `stupid-mode`) |
| `--file-mode`, `-fm`      | For `file` mode: `replace` or `show` |
| `--hash`, `-hs`           | Single hash to crack (required in `hash` mode) |
| `--stupid-mode-min`, `-smm` | Minimum password length in `stupid-mode` |
| `--stupid-mode-max`, `-smx` | Maximum password length in `stupid-mode` |

## License

This project is released under the MIT License.

## Donation
- **LTC**: ```ltc1qcylc450gq9nr2gspn3x905kvj6jesmnm0fj8p6```
- **BTC**: ```bc1qp52tyf9hykehc4mjexj5ep36asjr0qskywzxtj```
- **ETH**: ```0x73100e9DcA1C591d07AaDE2B61F30c00Dd6da379```

Thank you for using Hash-Cracker! 🔐

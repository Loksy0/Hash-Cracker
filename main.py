import os
import shutil
import base64
import hashlib
import argparse
import itertools

def String_to_hash(string, type):
    if type == 'md5':
        return hashlib.md5(string.encode()).hexdigest()
    elif type == 'sha1':
        return hashlib.sha1(string.encode()).hexdigest()
    elif type == 'sha256':
        return hashlib.sha256(string.encode()).hexdigest()
    elif type == 'sha512':
        return hashlib.sha512(string.encode()).hexdigest()
    else:
        raise ValueError("Unknown hash type")

def load_wordlist(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Wordlist file not found: {file_path}")
    with open(file_path, 'r') as f:
        return f.read().splitlines()
    
def check_hash_type(hash_str):
    if not isinstance(hash_str, (str, bytes)):
        return None
    if isinstance(hash_str, bytes):
        hash_str = hash_str.decode()
    hash_str = hash_str.strip().lower()
    if len(hash_str) == 32 and all(c in '0123456789abcdef' for c in hash_str):
        return 'md5'
    elif len(hash_str) == 40 and all(c in '0123456789abcdef' for c in hash_str):
        return 'sha1'
    elif len(hash_str) == 64 and all(c in '0123456789abcdef' for c in hash_str):
        return 'sha256'
    elif len(hash_str) == 128 and all(c in '0123456789abcdef' for c in hash_str):
        return 'sha512'
    else:
        return None

def solve_hash(hash_to_crack, wordlist_path, hash_type):
    wordlist = load_wordlist(wordlist_path)
    print(f"[+] Cracking hash: {hash_to_crack}")

    if hash_type == 'auto':
        detected_type = check_hash_type(hash_to_crack)
        if not detected_type:
            print("[-] Could not detect hash type.")
            return None
        print(f"[+] Detected hash type: {detected_type}")
        hash_type = detected_type

    for word in wordlist:
        try:
            word_hash = String_to_hash(word, hash_type)
        except ValueError:
            print(f"[-] Unknown hash type: {hash_type}")
            return None
        if word_hash == hash_to_crack:
            print(f"[+] Found: {hash_to_crack} -> {word}")
            return word
        else:
            print(f"[-] Wrong word: {word}")
    print("[-] No match found.")
    return None

def file_solve_hash(file_path, wordlist_path, hash_type, tm):
    if not os.path.exists(file_path):
        print(f"[-] Hash file not found: {file_path}")
        return

    with open(file_path, 'r') as f:
        file_lines = f.read().splitlines()

    wordlist = load_wordlist(wordlist_path)

    hash_types = ['md5', 'sha1', 'sha256', 'sha512'] if hash_type == 'auto' else [hash_type]

    hash_map = {}
    for word in wordlist:
        found = False
        for htype in hash_types:
            try:
                h = String_to_hash(word, htype)
                hash_map[h] = (word, htype)
            except Exception:
                continue
        present = any(h in line for h in hash_map if hash_map[h][0] == word for line in file_lines)
        if present:
            for h in hash_map:
                if hash_map[h][0] == word:
                    print(f"[+] Found in file: {word} -> {h}")
        else:
            print(f"[-] Wrong word: {word}")

    if tm == 'replace':
        copy_path = f"{os.path.splitext(file_path)[0]}-copy.txt"
        shutil.copyfile(file_path, copy_path)
        new_lines = []
        for line in file_lines:
            new_line = line
            for h, (word, htype) in hash_map.items():
                idx = new_line.find(h)
                while idx != -1:
                    before = new_line[idx-1] if idx > 0 else ' '
                    if before != ' ':
                        new_line = new_line[:idx] + ' ' + new_line[idx:]
                        idx += 1  
                    new_line = new_line[:idx] + f"{h} -> {word}" + new_line[idx+len(h):]
                    idx = new_line.find(h, idx + len(f"{h} -> {word}"))
            new_lines.append(new_line)
        with open(copy_path, 'w') as f:
            f.write('\n'.join(new_lines))
        print(f"[+] File with replaced hashes saved as: {copy_path}")


def stupid_mode(min_length, max_length, file_path, hash_type, tm):
    abc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#?$%"
    if not os.path.exists(file_path):
        print(f"[-] Hash file not found: {file_path}")
        return

    copy_path = f"{os.path.splitext(file_path)[0]}-copy.txt"
    shutil.copyfile(file_path, copy_path)

    with open(copy_path, 'r') as f:
        file_lines = f.read().splitlines()

    hash_types = ['md5', 'sha1', 'sha256', 'sha512'] if hash_type == 'auto' else [hash_type]
    found_hashes = {}

    for length in range(min_length, max_length + 1):
        for candidate_tuple in itertools.product(abc, repeat=length):
            candidate = ''.join(candidate_tuple)
            for htype in hash_types:
                try:
                    h = String_to_hash(candidate, htype)
                except Exception:
                    continue
                found = False
                for idx, line in enumerate(file_lines):
                    if h in line:
                        print(f"[+] Found in file: {candidate} ({htype}) -> {h}")
                        found_hashes[h] = candidate
                        found = True
                        if tm == 'replace':
                            file_lines[idx] = line.replace(h, f"{h} -> {candidate}")
                            with open(copy_path, 'w') as f:
                                f.write('\n'.join(file_lines))
                        break
                if not found:
                    # print(f"[-] Wrong word: {candidate} ({htype})")
                    pass

    if tm == 'replace':
        print(f"[+] File with replaced hashes saved as: {copy_path}")

def sha256_base64_unhex(plaintext: str) -> str:
    sha256_bytes = hashlib.sha256(plaintext.encode()).digest()
    return base64.b64encode(sha256_bytes).decode()

def stupid_mode_sha256_base64(min_length, max_length, file_path, hash_type, tm):
    abc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#?$%"
    if not os.path.exists(file_path):
        print(f"[-] Hash file not found: {file_path}")
        return

    copy_path = f"{os.path.splitext(file_path)[0]}-copy.txt"
    shutil.copyfile(file_path, copy_path)

    with open(copy_path, 'r') as f:
        file_lines = f.read().splitlines()

    """
    def filt(date):
        return 'password' in date

    filtered_lines = [line for line in file_lines if filt(line)]
    """

    if hash_type == 'auto':
        hash_types = ['md5', 'sha1', 'sha256', 'sha512', 'sha256-b64-unhex']
    else:
        hash_types = [hash_type]

    found_hashes = {}

    for length in range(min_length, max_length + 1):
        for candidate_tuple in itertools.product(abc, repeat=length):
            candidate = ''.join(candidate_tuple)
            for htype in hash_types:
                try:
                    if htype == 'sha256-b64-unhex':
                        h = sha256_base64_unhex(candidate)
                    else:
                        h = String_to_hash(candidate, htype)
                except Exception:
                    continue

                found = False
                for idx, line in enumerate(file_lines):
                    if h in line:
                        print(f"[+] Found in file: {candidate} ({htype}) -> {h}")
                        found_hashes[h] = candidate
                        found = True
                        if tm == 'replace':
                            file_lines[idx] = line.replace(h, f"{h} -> {candidate}")
                            with open(copy_path, 'w') as f:
                                f.write('\n'.join(file_lines))
                        break
                if found:
                    break

    if tm == 'replace':
        print(f"[+] File with replaced hashes saved as: {copy_path}")


def main():
    parser = argparse.ArgumentParser(description="HashCracker - a tool for cracking hashes (md5, sha1, sha256, sha512) using a wordlist.")
    parser.add_argument('--mode', '-m', required=True, choices=['hash', 'file', 'stupid-mode'], help="Select mode: 'hash' for a single hash or 'file' for a file with hashes.")
    parser.add_argument('--type', '-t', required=True, choices=['md5', 'sha1', 'sha256', 'sha512', 'auto', 'sha256-b64-unhex'], help="Hash type to crack: md5, sha1, sha256, sha512, or auto (automatic detection).")
    parser.add_argument('--save', '-s', nargs='?', const='results.txt', help="Save result to file (default: results.txt).")
    parser.add_argument('--file', '-f', help="Path to file with hashes (required if mode is 'file').")
    parser.add_argument('--wordlist', '-w', help="Path to wordlist file. (required except for stupid-mode)")
    parser.add_argument('--file-mode', '-fm', choices=['replace', 'show'], help="For file mode: 'replace' - replace found hashes, 'show' - display found hashes in console.")
    parser.add_argument('--hash', '-hs', help="Single hash to crack (required if mode is 'hash').")

    parser.add_argument('--stupid-mode-min', '-smm', type=int, default=1, help="Minimum length of words to consider in stupid mode. (required for stupid mode)")
    parser.add_argument('--stupid-mode-max', '-smx', type=int, default=6, help="Maximum length of words to consider in stupid mode. (required for stupid mode)")
    args = parser.parse_args()

    if args.mode == 'file' and not args.file:
        parser.error("When --mode file is selected, --file/-f must be provided.")

    if args.mode != 'stupid-mode':
        wordlist_path = args.wordlist
        if not wordlist_path:
            parser.error("Wordlist file must be provided with --wordlist/-w unless using stupid-mode.")
        if not os.path.exists(wordlist_path):
            parser.error(f"Wordlist file not found: {wordlist_path}")

    if args.mode == 'hash':
        hash_value = args.hash
        if not hash_value:
            parser.error("When --mode hash is selected, --hash must be provided.")
        solve_hash(hash_value, wordlist_path, args.type)

    elif args.mode == 'file':
        file_solve_hash(args.file, wordlist_path, args.type, args.file_mode)

    elif args.mode == 'stupid-mode':
        if not args.file:
            parser.error("When using stupid-mode, you must provide --file/-f with hashes to crack.")
        if args.type == 'sha256-b64-unhex':
            stupid_mode_sha256_base64(args.stupid_mode_min, args.stupid_mode_max, args.file, args.type, args.file_mode)
        else:
            stupid_mode(args.stupid_mode_min, args.stupid_mode_max, args.file, args.type, args.file_mode)


if __name__ == "__main__":
    main()

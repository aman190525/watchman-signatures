#!/usr/bin/env python3
"""
secret_scanner.py

Scans a directory for secrets using YAML signatures and exports results to CSV.
Outputs raw matched values with:
    <file_path>:<line_number> [<signature_id>] <matched_text>
"""

import argparse
import os
import re
import sys
import yaml
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_signatures(sig_dir):
    signatures = []
    for root, _, files in os.walk(sig_dir):
        for fname in files:
            if not fname.endswith('.yml') and not fname.endswith('.yaml'):
                continue
            path = os.path.join(root, fname)
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                for sig in data.get('signatures', []):
                    patterns = []
                    if 'pattern' in sig:
                        patterns.append(sig['pattern'])
                    elif 'patterns' in sig:
                        patterns.extend(sig['patterns'])
                    for raw_pattern in patterns:
                        if not raw_pattern.strip():
                            continue
                        try:
                            compiled = re.compile(raw_pattern)
                            signatures.append({
                                'id': sig.get('id', fname),
                                'pattern': compiled,
                                'description': sig.get('description', ''),
                                'category': sig.get('category', 'secret') # default to 'secret'
                            })
                        except re.error as e:
                            print(f" Invalid regex in {fname}: {e}", file=sys.stderr)
    return signatures

def scan_file(path, signatures):
    hits = []
    if not os.path.isfile(path):
        return hits
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                for sig in signatures:

                    sensitive_keywords = ['key', 'password', 'pass', 'username', 'token', 'secret', 'auth', 'apikey', 'access', 'credential']

                    for m in sig['pattern'].finditer(line):
                        raw_val = m.group(0).strip()
                        if not raw_val:
                            continue

                        
                        if sig.get('category', 'secret') == 'filetype':
                            matched_keyword = "filetype"

                        else:

                        
                        
                            prefix = line[:m.start()].lower()
                            matched_keyword = next((kw for kw in sensitive_keywords if kw in prefix), None)

                        # Look for the last word before the match
                        #words = re.findall(r'\b\w+\b', prefix)
                        #matched_keyword = words[-1] if words and words[-1] in sensitive_keywords else None




                       
                            if not any(keyword in prefix for keyword in sensitive_keywords):
                                continue

                        #ends here
                        hits.append((i, sig['id'], raw_val, matched_keyword))


    except (UnicodeDecodeError, PermissionError, FileNotFoundError):
        pass
    return hits

def scan_directory(root_dir, signatures, output_csv='scan_results.csv', max_workers=8):
    results = []
    total = 0
    file_paths = []

    for root, _, files in os.walk(root_dir):
        for fn in files:
            fpath = os.path.join(root, fn)
            file_paths.append(fpath)

    print(f" Scanning {len(file_paths)} files with {max_workers} threads...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(scan_file, path, signatures): path for path in file_paths}
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            try:
                hits = future.result()
                for hit in hits:
                    line_no, sid, val, matched_keyword = hit
                    total += 1
                    print(f"{path}:{line_no}   [{sid}]   {val} (keyword: {matched_keyword})")
                    results.append({
                        'File Path': path,
                        'Line Number': line_no,
                        'Signature ID': sid,
                        'Matched Text': val,
                        'Matched Keyword' : matched_keyword
                    })
            except Exception as e:
                print(f"⚠️ Error scanning {path}: {e}", file=sys.stderr)

    if total == 0:
        print(f"No secrets found in {root_dir!r}.")
    else:
        print(f"✅ Found {total} raw secrets.")

    print(f" Writing results to {output_csv} ...")
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'File Path', 'Line Number', 'Signature ID', 'Matched Text', 'Matched Keyword'
        ])
        writer.writeheader()
        writer.writerows(results)

    print("🏁 All done.")

def main():
    parser = argparse.ArgumentParser(description="Scan with Watchman YAML signatures.")
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Folder to scan (recursive)"
    )
    parser.add_argument(
        "--sigs",
        default="./signatures",
        help="Path to cloned watchman-signatures/signatures folder"
    )
    parser.add_argument(
        "--out",
        default="scan_results.csv",
        help="CSV output file name"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=8,
        help="Number of threads to use for scanning"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"✖ \"{args.directory}\" is not a directory.", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(args.sigs):
        print(f"✖ \"{args.sigs}\" is not a valid signature directory.", file=sys.stderr)
        sys.exit(1)

    sigs = load_signatures(args.sigs)
    print(f"🔍 Loaded {len(sigs)} signatures.")
    scan_directory(args.directory, sigs, args.out, args.threads)

if __name__ == "__main__":
    main()

   
# disabled ->  archive_files.yaml, word_file.yaml, budget_files.yaml, tokens_1password_data_files.yaml, ruby.yaml  , cusip_numbers.yaml


# path, what is the raw value matching , and the path

'''
command to run:

# File path to run the scipt.py will differ and so will the output, so pls change below as per own directory

/Users/amadesai/Documents/watchman-signatures/signatures/script.py \
    /Users/amadesai/Desktop/test \                                   
    --sigs /Users/amadesai/Documents/watchman-signatures/signatures \
    --out /Users/amadesai/Documents/watchman-signatures/secrets.csv
    '''
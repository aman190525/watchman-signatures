#!/usr/bin/env python3
'''
command to run:

# File path to run the scipt.py will differ and so will the output, so pls change below as per own directory/file path


/Users/amadesai/Documents/watchman-signatures/signatures/script.py \
    /Users/amadesai/Desktop/test \                                   
    --sigs /Users/amadesai/Documents/watchman-signatures/signatures \
    --out /Users/amadesai/Documents/watchman-signatures/secrets.csv


    The secrets.csv will be created and saved in the same folder


    # Please also remember to delete the docker images after running scripts 1,2 else all the matches will be duplicated
    '''

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

                    compiled_patterns = []
                    for raw_pattern in patterns:
                        if not raw_pattern.strip():
                            continue
                        try:
                            compiled_patterns.append(re.compile(raw_pattern))
                        except re.error as e:
                            print(f" Invalid regex in {fname}: {e}", file=sys.stderr)

                    # Merge search_strings and file_types from watchman_apps
                    search_strings = set(sig.get('search_strings', []))
                    file_types = set(sig.get('file_types', []))
                    watchman_apps = sig.get('watchman_apps', {})
                    for app in watchman_apps.values():
                        search_strings.update(app.get('search_strings', []) or [])
                        fts = app.get('file_types')
                        if fts:
                            file_types.update(fts)


                    signatures.append({
                        'id': sig.get('id', fname),
                        'patterns': compiled_patterns,
                        'description': sig.get('description', ''),
                        'category': sig.get('category', 'secret'),
                        'search_strings': list(search_strings),
                        'file_types': list(file_types),
                        'watchman_apps': watchman_apps
                    })
    return signatures

def scan_file(path, signatures):
    hits = []
    if not os.path.isfile(path):
        return hits

    sensitive_keywords = ['key', 'password', 'pass', 'username', 'token', 'secret', 'auth', 'apikey', 'access', 'credential']
    filename = os.path.basename(path).lower()

    # Check file type match once per file
    for sig in signatures:
        for ftype in sig.get('file_types', []):
            if filename.endswith(ftype.lower()):
                hits.append((0, sig['id'], ftype, 'filetype'))

    try:
        with open(path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                for sig in signatures:
                    # Match regex patterns
                    for pattern in sig.get('patterns', []):
                        for m in pattern.finditer(line):
                            raw_val = m.group(0).strip()
                            if not raw_val:
                                continue

                            if sig.get('category', 'secret') == 'filetype':
                                matched_keyword = "filetype"
                            else:
                                prefix = line[:m.start()].lower()
                                matched_keyword = next((kw for kw in sensitive_keywords if kw in prefix), None)
                                if not any(keyword in prefix for keyword in sensitive_keywords):
                                    continue

                            hits.append((i, sig['id'], raw_val, matched_keyword))

                    # Match search_strings
                    for sstr in sig.get('search_strings', []):
                        if sstr.lower() in line.lower():
                            hits.append((i, sig['id'], sstr, 'search_string'))

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
                        'Matched Keyword': matched_keyword
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

   



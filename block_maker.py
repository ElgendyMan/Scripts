#!/usr/bin/env python3
"""
extract_lines.py

Usage:
    py extract_lines.py input.txt output.txt START_LINE END_LINE

Example:
    py extract_lines.py words.txt block_7m_8m.txt 7000000 8000000

Notes:
- START_LINE and END_LINE are 1-indexed and inclusive.
- The script is memory-efficient (streams the file).
- It prints progress every 100k written lines.
"""
import argparse
import itertools
import time
import os
import sys

def extract_block(input_path, output_path, start_line, end_line, progress_every=100_000, encoding='utf-8'):
    if start_line < 1 or end_line < start_line:
        raise ValueError("Invalid line range: start_line must be >=1 and end_line >= start_line")

    start_index = start_line - 1          # zero-based index to start reading
    stop_index = end_line                 # islice stop is exclusive; use end_line because end_line-1 is last index

    # Make sure input file exists
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    written = 0
    t0 = time.time()
    with open(input_path, 'r', encoding=encoding, errors='replace') as fin:
        # islice(fin, start_index, stop_index) will begin reading from start_index (0-based)
        lines_iter = itertools.islice(fin, start_index, stop_index)
        # Open output and write streamed lines
        with open(output_path, 'w', encoding=encoding, errors='replace') as fout:
            for line in lines_iter:
                fout.write(line)
                written += 1
                if written % progress_every == 0:
                    elapsed = time.time() - t0
                    print(f"WROTE {written} lines... elapsed {elapsed:.1f}s", flush=True)

    elapsed_total = time.time() - t0
    print(f"Done. Wrote {written} lines to {output_path} in {elapsed_total:.1f}s")

def parse_args():
    p = argparse.ArgumentParser(description="Extract a block of lines from a large text file (1-indexed, inclusive).")
    p.add_argument('input', help="Path to input text file")
    p.add_argument('output', help="Path to output text file (will be overwritten)")
    p.add_argument('start', type=int, help="Start line number (1-indexed, inclusive)")
    p.add_argument('end', type=int, help="End line number (1-indexed, inclusive)")
    p.add_argument('--encoding', default='utf-8', help="File encoding (default: utf-8); use 'latin-1' if needed")
    p.add_argument('--progress', type=int, default=100_000, help="Print progress every N lines written (default 100000)")
    return p.parse_args()

if __name__ == '__main__':
    args = parse_args()
    try:
        extract_block(args.input, args.output, args.start, args.end, progress_every=args.progress, encoding=args.encoding)
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        sys.exit(1)

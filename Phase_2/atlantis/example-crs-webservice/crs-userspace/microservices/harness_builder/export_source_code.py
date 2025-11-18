#!/usr/bin/env python3

import subprocess
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source_code_paths', type=str, required=True)
    args = parser.parse_args()

    subprocess.run(['git', 'clone', args.source_code_path, args.output_path])

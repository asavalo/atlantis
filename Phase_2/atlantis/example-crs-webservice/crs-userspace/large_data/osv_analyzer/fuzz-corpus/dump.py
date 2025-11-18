#!/usr/bin/env python3
"""
Script to dump test cases from bugs.json file based on database type.

Usage:
    python dump.py --type=<dbms_type> --output_dir=<output_directory>
    
Example:
    python dump.py --type=sqlite --output_dir=./sqlite_testcases
    python dump.py --type=sqlite --output_dir=./sqlite_testcases --include-comments
"""

import argparse
import json
import os
import sys
from pathlib import Path


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Dump test cases from bugs.json file based on database type.'
    )
    parser.add_argument(
        '--type',
        type=str,
        required=True,
        help='Database type to filter (e.g., sqlite, mysql, postgresql, mariadb, cockroachdb)',
        choices=['sqlite', 'mysql', 'postgresql', 'mariadb', 'cockroachdb']
    )
    parser.add_argument(
        '--output_dir',
        type=str,
        required=True,
        help='Output directory to store test cases'
    )
    parser.add_argument(
        '--bugs_file',
        type=str,
        default='collections/sqlancer/bugs.json',
        help='Path to bugs.json file (default: collections/sqlancer/bugs.json)'
    )
    parser.add_argument(
        '--include-comments',
        action='store_true',
        help='Include metadata as SQL comments in the output files (default: False)'
    )
    
    return parser.parse_args()


def load_bugs_data(bugs_file_path):
    """Load and parse the bugs.json file."""
    try:
        with open(bugs_file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{bugs_file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON file: {e}")
        sys.exit(1)


def normalize_dbms_type(dbms_type):
    """Normalize DBMS type to lowercase for comparison."""
    return dbms_type.lower()


def filter_bugs_by_type(bugs_data, dbms_type):
    """Filter bugs by database type."""
    normalized_type = normalize_dbms_type(dbms_type)
    filtered_bugs = []
    
    for bug in bugs_data:
        if 'dbms' in bug and normalize_dbms_type(bug['dbms']) == normalized_type:
            filtered_bugs.append(bug)
    
    return filtered_bugs


def create_output_directory(output_dir):
    """Create output directory if it doesn't exist."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)


def write_test_case(output_dir, index, bug_data, include_comments=False):
    """Write a single test case to a file."""
    # Create filename based on index and title (if available)
    title = bug_data.get('title', 'untitled').replace('/', '_').replace(' ', '_')
    title = ''.join(c for c in title if c.isalnum() or c in ['_', '-'])[:100]  # Limit length
    filename = f"test_{index:04d}_{title}.sql"
    
    filepath = os.path.join(output_dir, filename)
    
    # Extract test statements
    test_statements = bug_data.get('test', [])
    
    # Write test case to file
    with open(filepath, 'w', encoding='utf-8') as f:
        if include_comments:
            # Write metadata as SQL comments
            f.write(f"-- Title: {bug_data.get('title', 'N/A')}\n")
            f.write(f"-- Date: {bug_data.get('date', 'N/A')}\n")
            f.write(f"-- DBMS: {bug_data.get('dbms', 'N/A')}\n")
            f.write(f"-- Reporter: {bug_data.get('reporter', 'N/A')}\n")
            f.write(f"-- Status: {bug_data.get('status', 'N/A')}\n")
            
            if 'oracle' in bug_data:
                f.write(f"-- Oracle: {bug_data['oracle']}\n")
            
            if 'severity' in bug_data:
                f.write(f"-- Severity: {bug_data['severity']}\n")
                
            if 'comment' in bug_data:
                f.write(f"-- Comment: {bug_data['comment']}\n")
            
            # Write links if available
            if 'links' in bug_data:
                f.write("-- Links:\n")
                for link_type, link_url in bug_data['links'].items():
                    f.write(f"--   {link_type}: {link_url}\n")
            
            f.write("\n")
        
        # Write the actual test statements
        for statement in test_statements:
            f.write(statement)
            if not statement.rstrip().endswith(';'):
                f.write(';')
            f.write('\n')
    
    return filepath


def main():
    """Main function."""
    args = parse_arguments()
    
    # Load bugs data
    print(f"Loading bugs data from '{args.bugs_file}'...")
    bugs_data = load_bugs_data(args.bugs_file)
    print(f"Total bugs loaded: {len(bugs_data)}")
    
    # Filter bugs by type
    filtered_bugs = filter_bugs_by_type(bugs_data, args.type)
    print(f"Bugs found for '{args.type}': {len(filtered_bugs)}")
    
    if not filtered_bugs:
        print(f"No bugs found for database type '{args.type}'")
        return
    
    # Create output directory
    create_output_directory(args.output_dir)
    
    # Write test cases
    print(f"Writing test cases to '{args.output_dir}'...")
    for index, bug in enumerate(filtered_bugs, 1):
        filepath = write_test_case(args.output_dir, index, bug, args.include_comments)
        print(f"  [{index}/{len(filtered_bugs)}] Written: {os.path.basename(filepath)}")
    
    print(f"\nSuccessfully dumped {len(filtered_bugs)} test cases to '{args.output_dir}'")
    
    # Print summary statistics
    print("\nSummary:")
    print(f"  Total test cases: {len(filtered_bugs)}")
    
    # Count by status
    status_counts = {}
    for bug in filtered_bugs:
        status = bug.get('status', 'unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
    
    print("  By status:")
    for status, count in sorted(status_counts.items()):
        print(f"    {status}: {count}")
    
    # Count by oracle type
    oracle_counts = {}
    for bug in filtered_bugs:
        oracle = bug.get('oracle', 'unknown')
        oracle_counts[oracle] = oracle_counts.get(oracle, 0) + 1
    
    print("  By oracle type:")
    for oracle, count in sorted(oracle_counts.items()):
        print(f"    {oracle}: {count}")


if __name__ == '__main__':
    main() 
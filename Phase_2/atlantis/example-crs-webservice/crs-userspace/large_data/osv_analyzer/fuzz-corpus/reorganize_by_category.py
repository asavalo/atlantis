#!/usr/bin/env python3
"""
Script to reorganize OSS-Fuzz corpus and dictionaries by category.

This script takes a category name and a list of projects, then:
1. Creates a category directory structure in the output directory
2. Copies project dictionaries to the category's dictionary subdirectory (flattened)
3. Extracts all project tarballs to a temporary directory
4. Recompresses the combined corpus into a single category tarball

Usage:
    python reorganize_by_category.py <category> <output_dir> <corpus_dir> <dict_dir> <project1> <project2> ...
"""

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List
import hashlib
import sys
import toml


def extract_tar_zst(tarball_path: Path, extract_dir: Path) -> bool:
    """
    Extract a .tar.zst file to the specified directory.
    
    Args:
        tarball_path: Path to the .tar.zst file
        extract_dir: Directory to extract to
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create extract directory if it doesn't exist
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        # Use zstd to decompress and tar to extract
        cmd = ["zstd", "-d", "-c", str(tarball_path), "|", "tar", "-xf", "-", "-C", str(extract_dir)]
        result = subprocess.run(" ".join(cmd), shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error extracting {tarball_path}: {result.stderr}")
            return False
            
        return True
    except Exception as e:
        print(f"Exception extracting {tarball_path}: {e}")
        return False


def create_tar_zst(source_dir: Path, output_path: Path) -> bool:
    """
    Create a .tar.zst file from a directory.
    
    Args:
        source_dir: Directory to compress
        output_path: Path for the output .tar.zst file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create parent directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use tar to create archive and pipe to zstd for compression
        cmd = ["tar", "-cf", "-", "-C", str(source_dir), ".", "|", "zstd", "-o", str(output_path)]
        result = subprocess.run(" ".join(cmd), shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error creating {output_path}: {result.stderr}")
            return False
            
        return True
    except Exception as e:
        print(f"Exception creating {output_path}: {e}")
        return False


def copy_project_dicts(project_names: List[str], dict_dir: Path, category_dict_dir: Path) -> None:
    """
    Copy project dictionaries to the category dictionary directory (flattened structure).
    
    Args:
        project_names: List of project names
        dict_dir: Source dictionary directory
        category_dict_dir: Destination category dictionary directory
    """
    category_dict_dir.mkdir(parents=True, exist_ok=True)
    
    for project in project_names:
        project_dict_dir = dict_dir / project
        if project_dict_dir.exists() and project_dict_dir.is_dir():
            # Copy all dictionary files from the project directory directly to category_dict_dir
            for dict_file in project_dict_dir.rglob("*.dict"):
                # Create a unique name to avoid conflicts
                # Use project name as prefix if there are multiple dict files
                if len(list(project_dict_dir.rglob("*.dict"))) > 1:
                    # Multiple dict files, prefix with project name
                    dest_name = f"{project}_{dict_file.name}"
                else:
                    # Single dict file, use project name as filename
                    dest_name = f"{project}.dict"
                
                dest_path = category_dict_dir / dest_name
                shutil.copy2(dict_file, dest_path)
                print(f"Copied dictionary: {dict_file.name} -> {dest_name}")
        else:
            print(f"Warning: Dictionary directory not found for {project}")


def file_sha256(path: Path) -> str:
    """
    Compute SHA256 checksum of a file.
    Args:
        path: Path to the file
    Returns:
        Hex digest string
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def process_corpus_tarballs(project_names: List[str], corpus_dir: Path, category_corpus_path: Path) -> None:
    """
    Extract all project tarballs and recompress into a single category tarball, deduplicating files by checksum.
    Args:
        project_names: List of project names
        corpus_dir: Source corpus directory
        category_corpus_path: Path for the output category corpus tarball
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        print(f"Using temporary directory: {temp_path}")

        # Directory to collect deduplicated files
        dedup_dir = temp_path / "deduped"
        dedup_dir.mkdir(parents=True, exist_ok=True)

        # Extract all project tarballs
        extracted_count = 0
        for project in project_names:
            tarball_path = corpus_dir / f"{project}.tar.zst"
            if tarball_path.exists():
                project_extract_dir = temp_path / project
                if extract_tar_zst(tarball_path, project_extract_dir):
                    print(f"Extracted corpus for {project}")
                    extracted_count += 1
                else:
                    print(f"Failed to extract corpus for {project}")
            else:
                print(f"Warning: Corpus tarball not found for {project}")

        if extracted_count == 0:
            print("No corpus tarballs were successfully extracted")
            return

        # Deduplicate files by checksum
        print(f"Deduplicating files by SHA256 checksum...")
        seen_hashes = set()
        deduped_count = 0
        for project in project_names:
            project_extract_dir = temp_path / project
            if not project_extract_dir.exists():
                continue
            for file in project_extract_dir.rglob("*"):
                if file.is_file():
                    checksum = file_sha256(file)
                    if checksum not in seen_hashes:
                        seen_hashes.add(checksum)
                        # Use a unique name: keep original name, but if collision, add hash prefix
                        dest_name = file.name
                        dest_path = dedup_dir / dest_name
                        if dest_path.exists():
                            dest_name = f"{checksum[:8]}_{file.name}"
                            dest_path = dedup_dir / dest_name
                        shutil.copy2(file, dest_path)
                        deduped_count += 1
        print(f"Deduplicated corpus files: {deduped_count}")

        # Create the combined category tarball from dedup_dir
        print(f"Creating combined corpus tarball: {category_corpus_path}")
        if create_tar_zst(dedup_dir, category_corpus_path):
            print(f"Successfully created category corpus: {category_corpus_path}")
        else:
            print(f"Failed to create category corpus: {category_corpus_path}")


def process_category(category, projects, output_dir, corpus_dir, dict_dir):
    output_dir = Path(output_dir)
    corpus_dir = Path(corpus_dir)
    dict_dir = Path(dict_dir)
    category_dir = output_dir / category
    category_dict_dir = category_dir / "dictionaries"
    category_corpus_dir = category_dir / "corpus"
    category_corpus_path = category_corpus_dir / f"{category.lower()}.tar.zst"
    print(f"Creating category directory structure: {category_dir}")
    category_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nProcessing dictionaries for {len(projects)} projects...")
    copy_project_dicts(projects, dict_dir, category_dict_dir)
    print(f"\nProcessing corpus tarballs for {len(projects)} projects...")
    process_corpus_tarballs(projects, corpus_dir, category_corpus_path)
    print(f"\nReorganization complete!")
    print(f"Category directory: {category_dir}")
    print(f"Dictionaries: {category_dict_dir}")
    print(f"Corpus: {category_corpus_path}")


def verify_toml_vs_dirs(toml_file: Path, corpus_dir: Path, dict_dir: Path) -> int:
    """
    Verify that all projects in the TOML file exist in the corpus and dict dirs, and vice versa.
    Args:
        toml_file: Path to TOML file
        corpus_dir: Path to corpus directory
        dict_dir: Path to dict directory
    Returns:
        0 if all is well, 1 if any missing/extra projects found
    """
    data = toml.load(toml_file)
    # Flatten all project names from all categories
    toml_projects = set()
    for projects in data.values():
        if projects:
            toml_projects.update(projects)
    # Projects in corpus dir (by .tar.zst files)
    corpus_projects = set()
    for f in corpus_dir.glob("*.tar.zst"):
        # Remove .tar.zst suffix to get project name
        name = f.name
        if name.endswith(".tar.zst"):
            name = name[:-8]
        corpus_projects.add(name)
    # Projects in dict dir (by subdirectory names)
    dict_projects = set()
    for d in dict_dir.iterdir():
        if d.is_dir():
            dict_projects.add(d.name)
    # Check for missing/extra
    missing_in_corpus = toml_projects - corpus_projects
    missing_in_dict = toml_projects - dict_projects
    extra_in_corpus = corpus_projects - toml_projects
    extra_in_dict = dict_projects - toml_projects
    # Combine extras
    extra_in_dirs = extra_in_corpus | extra_in_dict
    ok = True
    print("\n--- TOML/Corpus/Dict Consistency Check ---")
    if missing_in_corpus:
        print(f"Projects in TOML but missing in corpus dir: {sorted(missing_in_corpus)}")
        ok = False
    else:
        print("All TOML projects found in corpus dir.")
    if missing_in_dict:
        print(f"Projects in TOML but missing in dict dir: {sorted(missing_in_dict)}")
        ok = False
    if extra_in_dirs:
        print(f"Projects in corpus or dict dir but not in TOML: {sorted(extra_in_dirs)}")
        ok = False
    if ok:
        print("\nVerification PASSED: All projects match between TOML, corpus, and dict dirs.")
        return 0
    else:
        print("\nVerification FAILED: See above for missing/extra projects.")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Reorganize OSS-Fuzz corpus and dictionaries by category",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reorganize_by_category.py "JSON" output_dir corpus_dir dict_dir jq json json-c yajl-ruby
  python reorganize_by_category.py "SQL" output_dir corpus_dir dict_dir sqlite3 mysql-server postgresql
  python reorganize_by_category.py "Image" output_dir corpus_dir dict_dir libpng libtiff libheif skia
  python reorganize_by_category.py --from-toml categories_projects.toml output_dir corpus_dir dict_dir
  python reorganize_by_category.py --verify categories_projects.toml corpus_dir dict_dir
        """
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--from-toml', action='store_true', help='Process all categories from a TOML file (category = [...] style)')
    group.add_argument('--verify', action='store_true', help='Verify TOML/corpus/dict consistency and print missing/extra projects')
    parser.add_argument('category_or_toml', nargs='?', help='Category name or TOML file (if --from-toml or --verify)')
    parser.add_argument('output_dir', nargs='?', help='Output directory for reorganized data')
    parser.add_argument('corpus_dir', nargs='?', help='Directory containing .tar.zst corpus files')
    parser.add_argument('dict_dir', nargs='?', help='Directory containing project dictionary directories')
    parser.add_argument('projects', nargs='*', help='List of project names to include in this category (ignored if --from-toml or --verify)')
    args = parser.parse_args()

    if args.verify:
        if not (args.category_or_toml and args.corpus_dir and args.dict_dir):
            parser.error('With --verify, you must specify: toml_file corpus_dir dict_dir')
        toml_file = Path(args.category_or_toml)
        corpus_dir = Path(args.corpus_dir)
        dict_dir = Path(args.dict_dir)
        return verify_toml_vs_dirs(toml_file, corpus_dir, dict_dir)

    if args.from_toml:
        if not (args.category_or_toml and args.output_dir and args.corpus_dir and args.dict_dir):
            parser.error('With --from-toml, you must specify: toml_file output_dir corpus_dir dict_dir')
        toml_file = args.category_or_toml
        data = toml.load(toml_file)
        for category, projects in data.items():
            if not projects:  # skip empty lists
                continue
            print(f"\n=== Processing category: {category} ===")
            process_category(category, projects, args.output_dir, args.corpus_dir, args.dict_dir)
        return 0

    # Single-category mode (original)
    if not (args.category_or_toml and args.output_dir and args.corpus_dir and args.dict_dir and args.projects):
        parser.error('You must specify: category output_dir corpus_dir dict_dir project1 [project2 ...]')
    category = args.category_or_toml
    process_category(category, args.projects, args.output_dir, args.corpus_dir, args.dict_dir)
    return 0


if __name__ == "__main__":
    exit(main()) 
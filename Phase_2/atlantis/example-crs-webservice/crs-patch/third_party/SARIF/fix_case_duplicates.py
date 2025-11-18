#!/usr/bin/env python3
import os
import shutil
import sys
import filecmp
from pathlib import Path
import hashlib


def get_file_hash(filepath):
    """Get MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def find_case_duplicates(base_dir):
    """Find directories that differ only in case and merge them properly."""

    # Walk through language directories
    for lang_dir in os.listdir(base_dir):
        lang_path = os.path.join(base_dir, lang_dir)
        if not os.path.isdir(lang_path):
            continue

        # Walk through project directories
        for project_dir in os.listdir(lang_path):
            project_path = os.path.join(lang_path, project_dir)
            if not os.path.isdir(project_path):
                continue

            # Find case-sensitive duplicates among harness directories
            harness_dirs = os.listdir(project_path)
            lowercase_map = {}

            for harness in harness_dirs:
                harness_path = os.path.join(project_path, harness)
                if not os.path.isdir(harness_path):
                    continue

                harness_lower = harness.lower()
                if harness_lower in lowercase_map:
                    lowercase_map[harness_lower].append(harness)
                else:
                    lowercase_map[harness_lower] = [harness]

            # Process duplicates
            for harness_lower, variants in lowercase_map.items():
                if len(variants) > 1:
                    # Sort to ensure lowercase comes first if it exists
                    variants.sort(key=lambda x: (x != x.lower(), x))

                    lowercase_dir = variants[0]
                    uppercase_dirs = variants[1:]

                    print(f"Found case duplicates in {project_path}:")
                    print(f"  Keeping: {lowercase_dir}")
                    print(f"  Merging from: {', '.join(uppercase_dirs)}")

                    # Merge by pov_id directories
                    for uppercase_dir in uppercase_dirs:
                        uppercase_path = os.path.join(project_path, uppercase_dir)
                        lowercase_path = os.path.join(project_path, lowercase_dir)

                        # Ensure lowercase directory exists
                        os.makedirs(lowercase_path, exist_ok=True)

                        # Get all pov_id directories
                        uppercase_pov_dirs = {}
                        for item in os.listdir(uppercase_path):
                            item_path = os.path.join(uppercase_path, item)
                            if os.path.isdir(item_path):
                                uppercase_pov_dirs[item] = item_path

                        # Process each pov_id directory
                        for pov_id, upper_pov_path in uppercase_pov_dirs.items():
                            lower_pov_path = os.path.join(lowercase_path, pov_id)

                            # If target pov directory already exists
                            if os.path.exists(lower_pov_path):
                                # Compare and merge the files
                                for file_name in os.listdir(upper_pov_path):
                                    upper_file_path = os.path.join(
                                        upper_pov_path, file_name
                                    )
                                    lower_file_path = os.path.join(
                                        lower_pov_path, file_name
                                    )

                                    # If file already exists in lowercase dir
                                    if os.path.exists(lower_file_path):
                                        # If files are identical, skip
                                        if os.path.isfile(
                                            upper_file_path
                                        ) and os.path.isfile(lower_file_path):
                                            try:
                                                if get_file_hash(
                                                    upper_file_path
                                                ) == get_file_hash(lower_file_path):
                                                    print(
                                                        f"  File {pov_id}/{file_name} already exists and is identical, skipping"
                                                    )
                                                    # Remove the source file since it's identical
                                                    os.remove(upper_file_path)
                                                    continue
                                                else:
                                                    # Files differ - prefer lowercase version
                                                    print(
                                                        f"  WARNING: {pov_id}/{file_name} exists in both dirs but differs, keeping lowercase version"
                                                    )
                                                    # Remove the source file
                                                    os.remove(upper_file_path)
                                            except Exception as e:
                                                print(f"  Error comparing files: {e}")
                                        else:
                                            print(
                                                f"  WARNING: {pov_id}/{file_name} exists in both dirs but one is file and one is dir, keeping lowercase version"
                                            )
                                            # Remove the source file/dir
                                            if os.path.isfile(upper_file_path):
                                                os.remove(upper_file_path)
                                            else:
                                                shutil.rmtree(upper_file_path)
                                    else:
                                        # File doesn't exist in lowercase - copy it
                                        try:
                                            if os.path.isfile(upper_file_path):
                                                shutil.copy2(
                                                    upper_file_path, lower_file_path
                                                )
                                                print(
                                                    f"  Copied {pov_id}/{file_name} from {uppercase_dir}"
                                                )
                                                # Remove the source file
                                                os.remove(upper_file_path)
                                            else:
                                                shutil.copytree(
                                                    upper_file_path, lower_file_path
                                                )
                                                print(
                                                    f"  Copied {pov_id}/{file_name} from {uppercase_dir}"
                                                )
                                                # Remove the source directory
                                                shutil.rmtree(upper_file_path)
                                        except Exception as e:
                                            print(
                                                f"  Error copying {pov_id}/{file_name}: {e}"
                                            )
                            else:
                                # If pov dir doesn't exist in lowercase, move the entire directory
                                try:
                                    shutil.move(upper_pov_path, lower_pov_path)
                                    print(
                                        f"  Moved entire directory {pov_id} from {uppercase_dir}"
                                    )
                                except Exception as e:
                                    print(f"  Error moving directory {pov_id}: {e}")

                        # Process any remaining files at the root level of the uppercase directory
                        for item in os.listdir(uppercase_path):
                            src = os.path.join(uppercase_path, item)
                            dst = os.path.join(lowercase_path, item)

                            if os.path.exists(dst):
                                if os.path.isfile(src) and os.path.isfile(dst):
                                    try:
                                        if get_file_hash(src) == get_file_hash(dst):
                                            print(
                                                f"  Root file {item} already exists and is identical, skipping"
                                            )
                                            os.remove(src)
                                        else:
                                            print(
                                                f"  WARNING: Root file {item} exists but differs, keeping lowercase version"
                                            )
                                            os.remove(src)
                                    except Exception as e:
                                        print(f"  Error comparing root files: {e}")
                                else:
                                    print(
                                        f"  WARNING: Root item {item} exists but one is file and one is dir, keeping lowercase version"
                                    )
                                    if os.path.isfile(src):
                                        os.remove(src)
                                    else:
                                        shutil.rmtree(src)
                            else:
                                try:
                                    if os.path.isfile(src):
                                        shutil.copy2(src, dst)
                                        print(
                                            f"  Copied root file {item} from {uppercase_dir}"
                                        )
                                        os.remove(src)
                                    else:
                                        shutil.copytree(src, dst)
                                        print(
                                            f"  Copied root directory {item} from {uppercase_dir}"
                                        )
                                        shutil.rmtree(src)
                                except Exception as e:
                                    print(f"  Error copying root item {item}: {e}")

                        # Force remove the uppercase directory
                        try:
                            # Check if directory is now empty
                            remaining_files = [
                                f
                                for f in os.listdir(uppercase_path)
                                if not f.startswith(".")
                            ]
                            if not remaining_files:
                                shutil.rmtree(uppercase_path)
                                print(f"  Removed empty directory {uppercase_dir}")
                            else:
                                print(
                                    f"  WARNING: {uppercase_dir} still contains {len(remaining_files)} files, forcing removal"
                                )
                                # Force remove the directory even if it's not empty
                                shutil.rmtree(uppercase_path)
                                print(f"  Forcibly removed directory {uppercase_dir}")
                        except Exception as e:
                            print(f"  Error removing directory {uppercase_dir}: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    else:
        base_dir = "benchmarks/matching"

    print(f"Scanning for case-sensitive duplicate directories in {base_dir}...")
    find_case_duplicates(base_dir)
    print("Done.")

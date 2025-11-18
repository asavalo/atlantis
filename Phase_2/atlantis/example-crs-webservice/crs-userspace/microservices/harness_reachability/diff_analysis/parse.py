import re
import random
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def parse_diff(diff_text):
    file_pattern = r'^(---|\+\+\+) (.*)$'
    hunk_pattern = r'^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@'

    hunks = []
    current_file = None
    current_hunk = None

    for line in diff_text.splitlines(keepends=False):
        # 1) File header
        m = re.match(file_pattern, line)
        if m:
            _, path = m.groups()
            current_file = path[2:]    # strip leading "a/" or "b/"
            current_hunk = None
            continue

        # 2) Hunk header
        m = re.match(hunk_pattern, line)
        if m:
            old_start = int(m.group(1))
            old_len   = int(m.group(2)) if m.group(2) else 1
            new_start = int(m.group(3))
            new_len   = int(m.group(4)) if m.group(4) else 1

            current_hunk = {
                'file':      Path(current_file).name,
                'old_start': old_start,
                'new_start': new_start,
                'body':      []
            }
            hunks.append(current_hunk)
            continue

        # 3) Inside a hunk, collect every line (including context)
        if current_hunk:
            current_hunk['body'].append(line)

    # Post-process each hunk to extract changes with line numbers
    for h in hunks:
        old_line = h['old_start']
        new_line = h['new_start']
        changes = []

        for ln in h['body']:
            if ln.startswith(' '):
                old_line += 1
                new_line += 1
            elif ln.startswith('-'):
                changes.append({
                    'type':    '-',
                    'line':    old_line,
                    'content': ln[1:]
                })
                old_line += 1
            elif ln.startswith('+'):
                changes.append({
                    'type':    '+',
                    'line':    new_line,
                    'content': ln[1:]
                })
                new_line += 1
            else:
                # unexpected, but skip
                pass

        h['changes'] = changes
        # no longer need raw body
        del h['body']

    return hunks

def format_hunk(hunk):
    lines = []
    for c in hunk['changes']:
        sign = c['type']
        lines.append(f"line {c['line']} {sign} {c['content']}")
    return '\n'.join(lines)

def format_hunks_with_line_numbers(hunks):
    hunk_strings = []
    for i, h in enumerate(hunks):
        string_builder = []
        if '.c' not in h['file']:
            continue
        string_builder.append(f"Hunk index: {i}")
        string_builder.append(f"File: {h['file']}")
        string_builder.append(f"  Hunk starts @ old {h['old_start']}, new {h['new_start']}")
        if not h['changes']:
            string_builder.append("    (no additions or deletions)")
        else:
            string_builder.append(format_hunk(h))

        hunk_strings.append('\n'.join(string_builder))
    return hunk_strings

def get_delta_locations(diff_path: Path) -> list[str]:
    diff_text = diff_path.read_text()
    hunks = parse_diff(diff_text)
    # print_hunks_with_line_numbers(hunks)
    # exit()
    locations = []
    for hunk in hunks:
        filename = hunk['file']
        if '.c' not in filename:
            continue
        hunk_fmt = format_hunk(hunk)
        # print(hunk_fmt)
        # print(hunk["file"])

        linums = []
        try:
            for _ in range(2):
                from .agent import choose_location_in_hunk
                response = choose_location_in_hunk(hunk_fmt)
                linums = response.splitlines()
                linums = [linum for linum in linums if f"line {linum} +" in hunk_fmt]
                if linums:
                    break
        except:
            pass
        if not linums:
            added = [c['line'] for c in hunk['changes'] if c['type'] == '+']
            if added:
                logger.info("No line numbers selected for the hunk, choosing random added line")
                linums = [random.choice(added)]
            else:
                logger.info("Still no line numbers selected for the hunk, choosing start + 3")
                linums = [hunk['new_start'] + 3]
        for linum in linums:
            locations.append(f'{filename}:{linum}')
    return locations
            

def get_prioritized_delta_locations(diff_path: Path) -> list[str]:
    diff_text = diff_path.read_text()
    hunks = parse_diff(diff_text)
    formatted_hunks = format_hunks_with_line_numbers(hunks)
    
    # Join all hunks with a separator
    all_hunks_text = "\n===============\n".join(formatted_hunks)
    
    locations = []
    for _ in range(2):
        try:
            # Get prioritized locations from LLM
            from .agent import choose_prioritized_locations
            response = choose_prioritized_locations(all_hunks_text)
            
            # Parse the response which should be in filename:linenum format
            for line in response.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                # Validate the format and content
                if ':' not in line:
                    continue
                    
                filename, linenum = line.split(':', 1)
                try:
                    linenum = int(linenum)
                except ValueError:
                    continue
                    
                # Verify this is a valid location in our hunks
                for hunk in hunks:
                    if hunk['file'] == filename and '.c' in filename:
                        added_lines = [c['line'] for c in hunk['changes'] if c['type'] == '+']
                        if linenum in added_lines:
                            locations.append(line)
                            break
            if locations:
                return locations
                    
        except Exception as e:
            logger.error(f"Error getting prioritized locations: {e}")
            continue

    if not locations:
        for hunk in hunks:
            if '.c' not in hunk['file']:
                continue
            added = [c['line'] for c in hunk['changes'] if c['type'] == '+']
            if added:
                logger.info("No line numbers selected for the hunk, choosing random added line")
                linum = random.choice(added)
            else:
                logger.info("Still no line numbers selected for the hunk, choosing start + 3")
                linum = hunk['new_start'] + 3
            filename = hunk['file']
            locations.append(f'{filename}:{linum}')

    return locations

if __name__ == '__main__':
    # diff_path = Path.home() / "oss-fuzz/projects/aixcc/c/r2-libxml2-diff-2/.aixcc/ref.diff"
    # diff_path = Path.home() / "oss-fuzz/projects/aixcc/c/r3-sqlite3-delta-03/.aixcc/ref.diff"
    # diff_path = Path.home() / "oss-fuzz/projects/aixcc/c/r3-sqlite3-delta-01/.aixcc/ref.diff"
    diff_path = Path.home() / "oss-fuzz/projects/aixcc/c/r3-curl-delta-01/.aixcc/ref.diff"
    # diff_path = Path.home() / "oss-fuzz/projects/aixcc/c/r3-sqlite3-delta-02/.aixcc/ref.diff"
    
    # print("Original delta locations:")
    # locations = get_delta_locations(diff_path)
    # for loc in locations:
    #     print(f"  {loc}")
    
    print("\nPrioritized delta locations:")
    prioritized_locations = get_prioritized_delta_locations(diff_path)
    for loc in prioritized_locations:
        print(f"  {loc}")
    
    print("\nFormatted hunks for reference:")
    hunks = parse_diff(diff_path.read_text())
    hunks_formatted = format_hunks_with_line_numbers(hunks)
    for hunk in hunks_formatted:
        print(hunk)
        print('=========')

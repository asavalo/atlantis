from crete.framework.agent.services.vincent.nodes.analyzers.root_cause_analyzer import (
    # PropertyAnalyzer,
    _extract_rca_report,  # pyright: ignore[reportPrivateUsage]
)

valid_rca_report = """[RCA]
The bug is a heap-use-after-free vulnerability in the babynote program's note viewing functionality. The root cause stems from improper handling of freed notes in the `note_list` array.

Detailed Analysis:

1. Bug Location:
- The use-after-free occurs in `view_note()` function at line 117 when accessing `ptr->len`
- The freed memory was originally allocated in `create_note()` at line 80
- The memory was freed in `drop_note()` at lines 150-151

2. Vulnerable Flow:
- A note is created and stored in `note_list[idx]`
- The note is then freed using `drop_note()`
- However, `drop_note()` only frees the memory but doesn't remove the pointer from `note_list`
- When `view_note()` is called, it can still access the freed note through `note_list[note_idx]`

3. Root Cause:
The fundamental issue is that `drop_note()` fails to properly nullify the entry in `note_list`. While it does:
```c
free(ptr->page);
free(ptr);
ptr = 0;  // Line 152
```
The `ptr = 0` operation only modifies the local variable `ptr`, not the actual entry in `note_list`. The pointer in `note_list[note_idx]` remains unchanged and still points to the freed memory.

4. Proof of Bug:
The sanitizer output confirms this analysis showing:
- Memory was allocated in `create_note()`
- Memory was freed in `drop_note()`
- The freed memory was then accessed in `view_note()` at line 117

5. Impact:
This vulnerability allows:
- Reading of freed memory through `view_note()`
- Potential information leaks if the freed memory is reused
- Possible program crashes due to accessing invalid memory
- Potential arbitrary code execution if an attacker can control the reallocation of the freed memory

6. Contributing Factors:
- Lack of proper pointer management in the note tracking system
- Missing validation to check if a note has been freed before accessing it
- Improper cleanup of data structures after freeing resources

The bug can be triggered by:
1. Creating multiple notes
2. Dropping a note using `drop_note()`
3. Attempting to view the dropped note using `view_note()`

This sequence allows accessing freed memory because the program maintains a dangling pointer in the `note_list` array.
[/RCA]"""


def test_extract_rca_report():
    expected = """The bug is a heap-use-after-free vulnerability in the babynote program's note viewing functionality. The root cause stems from improper handling of freed notes in the `note_list` array.

Detailed Analysis:

1. Bug Location:
- The use-after-free occurs in `view_note()` function at line 117 when accessing `ptr->len`
- The freed memory was originally allocated in `create_note()` at line 80
- The memory was freed in `drop_note()` at lines 150-151

2. Vulnerable Flow:
- A note is created and stored in `note_list[idx]`
- The note is then freed using `drop_note()`
- However, `drop_note()` only frees the memory but doesn't remove the pointer from `note_list`
- When `view_note()` is called, it can still access the freed note through `note_list[note_idx]`

3. Root Cause:
The fundamental issue is that `drop_note()` fails to properly nullify the entry in `note_list`. While it does:
```c
free(ptr->page);
free(ptr);
ptr = 0;  // Line 152
```
The `ptr = 0` operation only modifies the local variable `ptr`, not the actual entry in `note_list`. The pointer in `note_list[note_idx]` remains unchanged and still points to the freed memory.

4. Proof of Bug:
The sanitizer output confirms this analysis showing:
- Memory was allocated in `create_note()`
- Memory was freed in `drop_note()`
- The freed memory was then accessed in `view_note()` at line 117

5. Impact:
This vulnerability allows:
- Reading of freed memory through `view_note()`
- Potential information leaks if the freed memory is reused
- Possible program crashes due to accessing invalid memory
- Potential arbitrary code execution if an attacker can control the reallocation of the freed memory

6. Contributing Factors:
- Lack of proper pointer management in the note tracking system
- Missing validation to check if a note has been freed before accessing it
- Improper cleanup of data structures after freeing resources

The bug can be triggered by:
1. Creating multiple notes
2. Dropping a note using `drop_note()`
3. Attempting to view the dropped note using `view_note()`

This sequence allows accessing freed memory because the program maintains a dangling pointer in the `note_list` array.
"""

    extracted_report = _extract_rca_report(valid_rca_report)

    assert extracted_report == expected

from crete.framework.agent.services.vincent.nodes.analyzers.property_analyzer import (
    # RootCauseAnalyzer,
    _extract_properties,  # pyright: ignore[reportPrivateUsage]
)

valid_property_report = """Based on the analysis of the babynote program, here are the essential properties that should hold throughout program execution:

[PROP]
Property #1: Note Count Boundary
The number of notes (tracked by idx) must never exceed 20 (0x14).
Reason: This is a fundamental capacity limit enforced to prevent array overflow of note_list[0x14]. This property is critical for memory safety.
[/PROP]

[PROP]
Property #2: Note Size Limit
Each note's size must be less than or equal to 0x500 bytes.
Reason: This property ensures that individual notes don't consume excessive memory and prevents potential resource exhaustion attacks.
[/PROP]

[PROP]
Property #3: Valid Index Access
Any access to note_list[i] must satisfy: 0 ≤ i < idx AND i < 20.
Reason: This property ensures that only valid indices within both the current note count (idx) and array bounds (20) are accessed, preventing out-of-bounds access.
[/PROP]

[PROP]
Property #4: Valid Offset and Length
For any note access, offset + length must be less than or equal to the note's total length.
Reason: This property ensures that note content access stays within the allocated buffer boundaries, preventing buffer overflows.
[/PROP]

[PROP]
Property #5: Printable Content
All viewable note content must contain only printable characters.
Reason: This security property prevents potential injection attacks or control character abuse through the secure_print function.
[/PROP]

[PROP]
Property #6: Memory Consistency
Any note pointer in note_list that is accessed must point to a valid, allocated memory region.
Reason: This property ensures memory safety by preventing use of freed or unallocated memory regions.
[/PROP]

[PROP]
Property #7: Input Termination
All note content must be properly null-terminated.
Reason: This property ensures string operations on note content are safe and prevents buffer over-reads during printing.
[/PROP]

[PROP]
Property #8: Resource Cleanup
When a note is dropped, both its content (page) and structure memory must be freed.
Reason: This property prevents memory leaks by ensuring proper cleanup of all allocated resources.
[/PROP]

These properties together define the safety, security, and functional correctness requirements of the babynote program. The current vulnerability we found earlier actually violates Property #6, as the program continues to access freed memory through stale pointers in note_list.
"""


def test_extract_properties():
    extracted_properties = _extract_properties(valid_property_report)

    expected = [
        "Property #1: Note Count Boundary\nThe number of notes (tracked by idx) must never exceed 20 (0x14).\nReason: This is a fundamental capacity limit enforced to prevent array overflow of note_list[0x14]. This property is critical for memory safety.",
        "Property #2: Note Size Limit\nEach note's size must be less than or equal to 0x500 bytes.\nReason: This property ensures that individual notes don't consume excessive memory and prevents potential resource exhaustion attacks.",
        "Property #3: Valid Index Access\nAny access to note_list[i] must satisfy: 0 ≤ i < idx AND i < 20.\nReason: This property ensures that only valid indices within both the current note count (idx) and array bounds (20) are accessed, preventing out-of-bounds access.",
        "Property #4: Valid Offset and Length\nFor any note access, offset + length must be less than or equal to the note's total length.\nReason: This property ensures that note content access stays within the allocated buffer boundaries, preventing buffer overflows.",
        "Property #5: Printable Content\nAll viewable note content must contain only printable characters.\nReason: This security property prevents potential injection attacks or control character abuse through the secure_print function.",
        "Property #6: Memory Consistency\nAny note pointer in note_list that is accessed must point to a valid, allocated memory region.\nReason: This property ensures memory safety by preventing use of freed or unallocated memory regions.",
        "Property #7: Input Termination\nAll note content must be properly null-terminated.\nReason: This property ensures string operations on note content are safe and prevents buffer over-reads during printing.",
        "Property #8: Resource Cleanup\nWhen a note is dropped, both its content (page) and structure memory must be freed.\nReason: This property prevents memory leaks by ensuring proper cleanup of all allocated resources.",
    ]

    assert extracted_properties == expected

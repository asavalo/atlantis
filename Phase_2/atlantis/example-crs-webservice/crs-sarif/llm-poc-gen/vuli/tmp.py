from collections import Counter
import random

def pick_most_frequent_lines(lines: list[int], k: int = 2) -> set[int]:
    counter = Counter(lines)
    sorted_lines = sorted(counter.items(), key=lambda x: (-x[1], random.random()))
    top_k = [line for line, _ in sorted_lines[:k]]
    return set(top_k)

print(pick_most_frequent_lines([760, 143, 251, 143, 251, 760]))
print(pick_most_frequent_lines([760, 143, 251, 1, 2, 3]))
print(pick_most_frequent_lines([760, 143, 251, 251, 251, 760]))
print(pick_most_frequent_lines([1, 1, 1]))
print(pick_most_frequent_lines([1, 2, 3]))
print(pick_most_frequent_lines([1, 2, 2]))
print(pick_most_frequent_lines([1, 1]))
print(pick_most_frequent_lines([1, 2]))
print(pick_most_frequent_lines([1]))
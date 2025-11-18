# Seed Ensembler

This application collects seeds generated from various sources, tests them, and -- depending on the results --
- discards them,
- sends them to fuzzers to improve coverage, or
- (optionally) submits them as crashes to VAPI.

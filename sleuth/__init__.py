"""Sleuth — static binary inspector: the security guard, not the laboratory.

Sleuth NEVER executes the target file. Every analysis is read-only and static:
it reads bytes from disk, parses headers, extracts strings, and matches
patterns. Nothing is run, nothing is loaded into memory as code.
"""

__version__ = "0.4.2"

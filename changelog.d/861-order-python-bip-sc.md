---
section: Fixed
---
- Python B/IP, SC and MS/TP endpoint startup and close go through one owner,
  so close joins startup and a second start can't open a second transport
  (#861).

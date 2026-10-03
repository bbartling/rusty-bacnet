---
section: Fixed
commit: 52bfdeb3b6a76c2b953ff8bbfe7a7155ceb76dad
---
- The Python B/IP endpoint tests bind port 0 and read the bound port back
  instead of probing for a free one (#993).

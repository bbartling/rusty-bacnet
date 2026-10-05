---
section: Changed
commit: dfc317a071f8abfa8a0182874cc65fd830a8e211
---
- Releases are built on GitHub's runners, each wheel and CLI binary natively
  on its own platform (Linux x86_64 and arm64, macOS Apple Silicon and Intel,
  Windows), and run there before anything is published (#943, #944, #1472).

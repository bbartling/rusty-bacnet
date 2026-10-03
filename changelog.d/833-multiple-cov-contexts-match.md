---
section: Fixed
---
- **Breaking (Rust API):** COV-multiple contexts match the original client
  whichever router it came through, and `MultipleContextKey` holds a
  `recipient: CovRecipient` (#833).

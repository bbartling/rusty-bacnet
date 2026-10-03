---
section: Fixed
---
- **Wire and Rust API:** SubscribeCOV request encoding returns `Result` and
  refuses a lifetime without a confirmed-notification mode, and the server
  refuses that shape too (#805).

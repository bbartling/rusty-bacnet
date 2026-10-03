---
section: Changed
---
- The conformance ledger check now requires every Markdown `public_claims`
  entry to name a heading (`docs/rust-api.md#heading-slug`), so a renamed or
  removed section is caught. Source files and `CHANGELOG.md` stay bare, since
  they have no stable headings. 82 bare entries now point at specific
  headings, and Recipient_List, Event_Parameters and BACnetTimeStamp framing
  have a short public statement in `docs/rust-api.md` (#1041).

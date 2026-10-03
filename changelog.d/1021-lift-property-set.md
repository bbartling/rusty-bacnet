---
section: Fixed
commit: 8b92c95831394b7d8e19bb683967a724c289875c
---
- **Breaking (wire, Rust API):** the Lift object serves its Table 12-77 rows
  in the table's datatypes, gains the required rows it lacked, and drops
  Tracking_Value and Floor_Number (#1021).

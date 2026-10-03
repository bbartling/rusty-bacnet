---
section: Fixed
---
- **Breaking Rust API:** the client decodes every other structured error body
  of Clause 21 and reports its fields (#1047). A conformant peer's
  CreateObject-Error, SubscribeCOVPropertyMultiple-Error,
  ConfirmedPrivateTransfer-Error or VTClose-Error used to fail APDU decode, so
  the request timed out instead of returning the error. `Error::ChangeList`
  becomes `Error::Structured { class, code, detail: Box<ErrorDetail> }`, one
  variant for every body. `ErrorDetail` has `FirstFailedElementNumber`
  (ChangeList-Error, CreateObject-Error), `FirstFailedWriteAttempt`
  (WritePropertyMultiple-Error, which the client used to reduce to the class
  and code), `FirstFailedSubscription`, `PrivateTransfer { vendor_id,
  service_number, error_parameters }` and `VtSessionIdentifiers`. A body with
  no fields beyond the error (SubscribeCOVPropertyMultiple's general choice,
  VTClose-Error without its list) stays `Error::Protocol`, and
  `Error::protocol(class, code, detail)` builds either. `TsmResponse::Error`
  carries `detail: Option<ErrorDetail>`. `bacnet_services` adds
  `object_mgmt::CreateObjectError`,
  `cov_multiple::SubscribeCOVPropertyMultipleError`,
  `private_transfer::PrivateTransferError`, `virtual_terminal::VTCloseError`
  and `structured_error::detail`, which reads the detail of any Error PDU.

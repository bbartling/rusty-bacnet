---
section: Added
---
- **Schedule reference list through AddListElement and RemoveListElement, and
  references naming this device (wire):** the list services now edit a
  Schedule's List_Of_Object_Property_References, and a member whose Device
  identifier is the server's own Device is accepted (#1121, #1122).
  - Both services edit the stored list and hand the result to the Schedule's
    whole-list write, the one WriteProperty uses, so the pass that follows at
    once sends the current Present_Value to an added target and relinquishes
    the slot the Schedule holds on a removed one. Before, both answered
    WRITE_ACCESS_DENIED.
  - Adding a member the list holds, or the same member twice in one request,
    succeeds and changes nothing. Removing one it doesn't hold is SERVICES /
    LIST_ELEMENT_NOT_FOUND and removes nothing. An element that doesn't
    decode as a reference is INVALID_DATA_TYPE, a member past the 1,024 cap
    RESOURCES / NO_SPACE_TO_ADD_LIST_ELEMENT, and a member in another device
    PROPERTY / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED. Each ChangeList-Error
    names the request element at fault, counted from 1.
  - Clause 12.24.10 lets a Schedule refuse only references outside its own
    device. A member naming the Device the server answers for is now taken as
    the local reference it stands for, through WriteProperty,
    WritePropertyMultiple, `write_local` and both list services. It reads
    back without the Device member, and the list services match it to the
    member stored that way. A member naming any other device is still
    OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED. Before, any member with a Device
    identifier was refused. The server does the rewrite: a
    `ScheduleObject` written directly still refuses every Device member.
  - The Schedule's whole-list write names the member it refuses, as
    `Error::Structured` with `ErrorDetail::FirstFailedElementNumber`;
    WriteProperty and WritePropertyMultiple keep the plain class and code on
    the wire. New: `bacnet_encoding::constructed::encode_device_object_property_reference`,
    the counterpart of the existing decoder.

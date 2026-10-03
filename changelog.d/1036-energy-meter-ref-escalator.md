---
section: Added
---
- **Energy_Meter_Ref on the Escalator and Lift (API and wire):** the
  application can now set the Energy_Meter_Ref of an Escalator, and of a Lift,
  which gains the optional property after Energy_Meter in its Property_List,
  property metadata, RPM ALL and OPTIONAL, and PICS rows (#1036). The new
  `EscalatorObject::set_energy_meter_ref` and `LiftObject::set_energy_meter_ref`
  take a BACnetDeviceObjectReference naming the meter object that totals the
  lift's or escalator's energy use, local or in another device: an Accumulator,
  Pulse Converter, Analog Input, Analog Value, Large Analog Value, Integer
  Value, Positive Integer Value or proprietary object type (128 to 1023, for
  vendor meters). Any other object type, or a device that
  isn't a Device object, is refused with VALUE_OUT_OF_RANGE. A reference to
  instance 4194303 clears it, and `energy_meter_ref()` reads it back. While a
  reference is set, Energy_Meter reads 0.0, as the Lift and Escalator
  descriptions require: setting one zeroes the reading, and a write of any
  value but 0.0 fails with VALUE_OUT_OF_RANGE. Energy_Meter_Ref stays
  read-only over the network, since neither table gives it a write
  requirement, so a WriteProperty fails with WRITE_ACCESS_DENIED.

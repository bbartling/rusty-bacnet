//! Registration of the access-control objects whose arrays the application
//! configures: Access Door Door_Members, Access Point Access_Doors and
//! Credential Data Input Supported_Formats with Supported_Format_Classes
//! (#1249). Each array is read-only over the network, so these keyword
//! arguments are the Python route to it.
use super::super::*;
use bacnet_types::constructed::BACnetAuthenticationFactorFormat;
use bacnet_types::enums::{AuthenticationFactorType, ErrorClass, ErrorCode};
use bacnet_types::error::Error;

/// One element of Door_Members or Access_Doors as Python gives it: an object
/// in this device, or a `(device, object)` pair naming an object in another
/// device.
#[derive(FromPyObject)]
enum PyDeviceObjectReference {
    Local(PyObjectIdentifier),
    Remote(PyObjectIdentifier, PyObjectIdentifier),
}

impl From<PyDeviceObjectReference> for BACnetDeviceObjectReference {
    fn from(reference: PyDeviceObjectReference) -> Self {
        match reference {
            PyDeviceObjectReference::Local(object) => object.to_rust().into(),
            PyDeviceObjectReference::Remote(device, object) => Self {
                device_identifier: Some(device.to_rust()),
                object_identifier: object.to_rust(),
            },
        }
    }
}

/// One Supported_Formats element as Python gives it: a format type number,
/// or a `(format_type, vendor_id, vendor_format)` triple for a format that
/// names its vendor members (a CUSTOM format must).
#[derive(FromPyObject)]
enum PyFactorFormat {
    Standard(u32),
    Vendor(u32, u32, u32),
}

impl TryFrom<PyFactorFormat> for BACnetAuthenticationFactorFormat {
    type Error = Error;

    /// A vendor member too wide for its Unsigned16 is VALUE_OUT_OF_RANGE, as
    /// the object's own checks answer any other ill-formed format.
    fn try_from(format: PyFactorFormat) -> Result<Self, Error> {
        Ok(match format {
            PyFactorFormat::Standard(format_type) => {
                Self::standard(AuthenticationFactorType::from_raw(format_type))
            }
            PyFactorFormat::Vendor(format_type, vendor_id, vendor_format) => Self {
                format_type: AuthenticationFactorType::from_raw(format_type),
                vendor_id: Some(unsigned16(vendor_id)?),
                vendor_format: Some(unsigned16(vendor_format)?),
            },
        })
    }
}

fn unsigned16(value: u32) -> Result<u16, Error> {
    u16::try_from(value).map_err(|_| Error::Protocol {
        class: ErrorClass::PROPERTY.to_raw() as u32,
        code: ErrorCode::VALUE_OUT_OF_RANGE.to_raw() as u32,
    })
}

#[pymethods]
impl BACnetServer {
    /// Add an Access Door object to the server (before starting).
    ///
    /// `door_members` sets Door_Members, the objects that make up the door.
    /// Each element is an `ObjectIdentifier` in this device or a
    /// `(device, object)` pair of identifiers for one in another device.
    #[pyo3(signature = (instance, name, *, door_members=None))]
    fn add_access_door(
        &self,
        instance: u32,
        name: &str,
        door_members: Option<Vec<PyDeviceObjectReference>>,
    ) -> PyResult<()> {
        let obj = access_door(instance, name, door_members).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Access Point object to the server (before starting).
    ///
    /// `access_doors` sets Access_Doors, in the same element forms as an
    /// Access Door's `door_members`; a reference to anything but an Access
    /// Door raises VALUE_OUT_OF_RANGE.
    #[pyo3(signature = (instance, name, *, access_doors=None))]
    fn add_access_point(
        &self,
        instance: u32,
        name: &str,
        access_doors: Option<Vec<PyDeviceObjectReference>>,
    ) -> PyResult<()> {
        let obj = access_point(instance, name, access_doors).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Credential Data Input object to the server (before starting).
    ///
    /// `supported_formats` sets Supported_Formats and Supported_Format_Classes
    /// as `(format, format_class)` pairs. A format is a format type number,
    /// or a `(format_type, vendor_id, vendor_format)` triple. A format outside
    /// the closed production, a CUSTOM format without its vendor members, a
    /// nonzero vendor member on another format or one above 65535 raises
    /// VALUE_OUT_OF_RANGE.
    #[pyo3(signature = (instance, name, *, supported_formats=None))]
    fn add_credential_data_input(
        &self,
        instance: u32,
        name: &str,
        supported_formats: Option<Vec<(PyFactorFormat, u32)>>,
    ) -> PyResult<()> {
        let obj = credential_data_input(instance, name, supported_formats).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }
}

/// Build an Access Door, applying Door_Members through its own setter.
fn access_door(
    instance: u32,
    name: &str,
    members: Option<Vec<PyDeviceObjectReference>>,
) -> Result<AccessDoorObject, Error> {
    let mut obj = AccessDoorObject::new(instance, name)?;
    if let Some(members) = members {
        obj.set_door_members(members.into_iter().map(BACnetDeviceObjectReference::from));
    }
    Ok(obj)
}

/// Build an Access Point, applying Access_Doors through its validating
/// setter.
fn access_point(
    instance: u32,
    name: &str,
    doors: Option<Vec<PyDeviceObjectReference>>,
) -> Result<AccessPointObject, Error> {
    let mut obj = AccessPointObject::new(instance, name)?;
    if let Some(doors) = doors {
        obj.set_access_doors(doors.into_iter().map(BACnetDeviceObjectReference::from))?;
    }
    Ok(obj)
}

/// Build a Credential Data Input, applying the formats through its validating
/// setter.
fn credential_data_input(
    instance: u32,
    name: &str,
    formats: Option<Vec<(PyFactorFormat, u32)>>,
) -> Result<CredentialDataInputObject, Error> {
    let mut obj = CredentialDataInputObject::new(instance, name)?;
    if let Some(formats) = formats {
        let formats = formats
            .into_iter()
            .map(|(format, class)| Ok((format.try_into()?, class)))
            .collect::<Result<Vec<_>, Error>>()?;
        obj.set_supported_formats(formats)?;
    }
    Ok(obj)
}

#[cfg(test)]
#[path = "access_control_methods_tests.rs"]
mod tests;

//! Registration of the access-control objects whose arrays and lists the
//! application configures: Access Door Door_Members, Access Point
//! Access_Doors and Credential Data Input Supported_Formats with
//! Supported_Format_Classes (#1249), and Access Zone Entry_Points and
//! Exit_Points (#1306). Each is read-only over the network, so these keyword
//! arguments are the Python route to it. The Access Point's policy count,
//! supported authorization modes and Priority_For_Writing are read-only
//! too, and take keyword arguments the same way (#1307).
use super::super::*;
use bacnet_types::constructed::BACnetAuthenticationFactorFormat;
use bacnet_types::enums::{AuthenticationFactorType, AuthorizationMode, ErrorClass, ErrorCode};
use bacnet_types::error::Error;

/// One element of Door_Members, Access_Doors, Entry_Points or Exit_Points as
/// Python gives it: an object in this device, or a `(device, object)` pair
/// naming an object in another device.
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

/// The references Python gave for the keyword argument `name`, each checked
/// as it converts: a pair whose device isn't a Device object identifier is
/// no reference (#1285), so the shared `check_device` raises ValueError,
/// naming the element, before any setter sees it.
fn device_references(
    references: Option<Vec<PyDeviceObjectReference>>,
    name: &str,
) -> PyResult<Option<Vec<BACnetDeviceObjectReference>>> {
    references
        .map(|references| {
            references
                .into_iter()
                .enumerate()
                .map(|(index, reference)| {
                    let reference = BACnetDeviceObjectReference::from(reference);
                    crate::types::check_device(
                        reference.device_identifier,
                        &format!("{name}[{index}]"),
                    )?;
                    Ok(reference)
                })
                .collect()
        })
        .transpose()
}

/// One Supported_Formats element as Python gives it: a format type number,
/// or a `(format_type, vendor_id, vendor_format)` triple for a format that
/// names its vendor members (a CUSTOM format must name both). Each vendor
/// member is optional in the datatype, so either may be `None`, the form a
/// read gives a format that carries only one of them.
#[derive(FromPyObject)]
enum PyFactorFormat {
    Standard(u32),
    Vendor(u32, Option<u32>, Option<u32>),
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
                vendor_id: vendor_id.map(unsigned16).transpose()?,
                vendor_format: vendor_format.map(unsigned16).transpose()?,
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
    /// `(device, object)` pair of identifiers for one in another device; a
    /// pair whose device isn't a Device raises ValueError.
    #[pyo3(signature = (instance, name, *, door_members=None))]
    fn add_access_door(
        &self,
        instance: u32,
        name: &str,
        door_members: Option<Vec<PyDeviceObjectReference>>,
    ) -> PyResult<()> {
        let members = device_references(door_members, "door_members")?;
        let obj = access_door(instance, name, members).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Access Point object to the server (before starting).
    ///
    /// `access_doors` sets Access_Doors, in the same element forms as an
    /// Access Door's `door_members`; a pair whose device isn't a Device
    /// raises ValueError, and a reference to anything but an Access Door
    /// raises VALUE_OUT_OF_RANGE.
    ///
    /// `number_of_authentication_policies` sets the policy count (1 when
    /// omitted, never 0), `supported_authorization_modes` the
    /// BACnetAuthorizationMode numbers the application carries out, which a
    /// write of Authorization_Mode can take (AUTHORIZE alone when omitted;
    /// AUTHORIZE must be among them, and a proprietary mode runs from 64 to
    /// 65535), and `priority_for_writing` the door command priority (16 when
    /// omitted, else 1 to 16). A value outside those raises
    /// VALUE_OUT_OF_RANGE.
    #[pyo3(signature = (
        instance,
        name,
        *,
        access_doors=None,
        number_of_authentication_policies=None,
        supported_authorization_modes=None,
        priority_for_writing=None
    ))]
    fn add_access_point(
        &self,
        instance: u32,
        name: &str,
        access_doors: Option<Vec<PyDeviceObjectReference>>,
        number_of_authentication_policies: Option<u32>,
        supported_authorization_modes: Option<Vec<u32>>,
        priority_for_writing: Option<u32>,
    ) -> PyResult<()> {
        let settings = PointSettings {
            access_doors: device_references(access_doors, "access_doors")?,
            number_of_authentication_policies,
            supported_authorization_modes,
            priority_for_writing,
        };
        let obj = access_point(instance, name, settings).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Access Zone object to the server (before starting).
    ///
    /// `entry_points` and `exit_points` set Entry_Points and Exit_Points, the
    /// Access Points leading into and out of the zone, in the element forms
    /// an Access Door's `door_members` takes; a pair whose device isn't a
    /// Device raises ValueError, and a reference to anything but an Access
    /// Point raises VALUE_OUT_OF_RANGE.
    #[pyo3(signature = (instance, name, *, entry_points=None, exit_points=None))]
    fn add_access_zone(
        &self,
        instance: u32,
        name: &str,
        entry_points: Option<Vec<PyDeviceObjectReference>>,
        exit_points: Option<Vec<PyDeviceObjectReference>>,
    ) -> PyResult<()> {
        let entry = device_references(entry_points, "entry_points")?;
        let exit = device_references(exit_points, "exit_points")?;
        let obj = access_zone(instance, name, entry, exit).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Credential Data Input object to the server (before starting).
    ///
    /// `supported_formats` sets Supported_Formats and Supported_Format_Classes
    /// as `(format, format_class)` pairs. A format is a format type number,
    /// or a `(format_type, vendor_id, vendor_format)` triple whose vendor
    /// members may each be `None`, as a read gives them. A format outside
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

/// Build an Access Door, applying Door_Members through its validating
/// setter.
fn access_door(
    instance: u32,
    name: &str,
    members: Option<Vec<BACnetDeviceObjectReference>>,
) -> Result<AccessDoorObject, Error> {
    let mut obj = AccessDoorObject::new(instance, name)?;
    if let Some(members) = members {
        obj.set_door_members(members)?;
    }
    Ok(obj)
}

/// The optional `add_access_point` keyword arguments; `None` keeps the
/// point's default.
#[derive(Default)]
struct PointSettings {
    access_doors: Option<Vec<BACnetDeviceObjectReference>>,
    number_of_authentication_policies: Option<u32>,
    supported_authorization_modes: Option<Vec<u32>>,
    priority_for_writing: Option<u32>,
}

/// Build an Access Point through its validating setters.
fn access_point(
    instance: u32,
    name: &str,
    settings: PointSettings,
) -> Result<AccessPointObject, Error> {
    let mut obj = AccessPointObject::new(instance, name)?;
    if let Some(doors) = settings.access_doors {
        obj.set_access_doors(doors)?;
    }
    if let Some(count) = settings.number_of_authentication_policies {
        obj.set_number_of_authentication_policies(count)?;
    }
    if let Some(modes) = settings.supported_authorization_modes {
        obj.set_supported_authorization_modes(modes.into_iter().map(AuthorizationMode::from_raw))?;
    }
    if let Some(priority) = settings.priority_for_writing {
        // A value too wide for u8 is out of 1..=16 too.
        obj.set_priority_for_writing(u8::try_from(priority).unwrap_or(0))?;
    }
    Ok(obj)
}

/// Build an Access Zone, applying Entry_Points and Exit_Points through its
/// validating setters.
fn access_zone(
    instance: u32,
    name: &str,
    entry: Option<Vec<BACnetDeviceObjectReference>>,
    exit: Option<Vec<BACnetDeviceObjectReference>>,
) -> Result<AccessZoneObject, Error> {
    let mut obj = AccessZoneObject::new(instance, name)?;
    if let Some(entry) = entry {
        obj.set_entry_points(entry)?;
    }
    if let Some(exit) = exit {
        obj.set_exit_points(exit)?;
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

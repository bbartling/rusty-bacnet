//! Registration of the Channel object with its members, their execution
//! delays, its control groups and Allow_Group_Delay_Inhibit (#1262). Peers
//! can write all of these too; the keyword arguments set them before the
//! server starts.
use super::super::*;
use bacnet_objects::channel::ChannelObject;
use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;

#[pymethods]
impl BACnetServer {
    /// Add a Channel object to the server (before starting).
    ///
    /// `channel_number` is the number a WriteGroup names (0 to 65535; above
    /// that raises VALUE_OUT_OF_RANGE). `members` sets
    /// List_Of_Object_Property_References: each element is an
    /// `(object, property)` or `(object, property, array_index)` tuple for a
    /// property in this device, or a mapping of `object_identifier`,
    /// `property_identifier` and the optional `property_array_index` and
    /// `device_identifier`. A member naming this server's Device is kept as
    /// the local reference it stands for, as a network write of the list
    /// keeps it; one naming another Device is written there through the
    /// server's device bindings.
    /// `execution_delay` gives one delay in milliseconds per member (zeros
    /// when omitted), `control_groups` the groups the Channel answers a
    /// WriteGroup for (`[0]`, no group, when omitted), and
    /// `allow_group_delay_inhibit` whether a WriteGroup asking for no delays
    /// skips them.
    ///
    /// A wrong shape or type raises TypeError, an unknown or missing mapping
    /// key or a device that isn't a Device raises ValueError, and an integer
    /// outside unsigned32 raises OverflowError (ValueError for a mapping's
    /// index). The Channel's setters refuse the rest as a protocol error: a
    /// delay count that differs from the member count or an empty group list
    /// (VALUE_OUT_OF_RANGE), and more than 1024 members or 64 groups
    /// (NO_SPACE_TO_WRITE_PROPERTY). Nothing is registered after any of them.
    #[pyo3(signature = (
        instance,
        name,
        channel_number,
        members=None,
        execution_delay=None,
        control_groups=None,
        *,
        allow_group_delay_inhibit=false
    ))]
    fn add_channel(
        &self,
        instance: u32,
        name: &str,
        channel_number: u32,
        members: Option<Bound<'_, PyAny>>,
        execution_delay: Option<Vec<u32>>,
        control_groups: Option<Vec<u32>>,
        allow_group_delay_inhibit: bool,
    ) -> PyResult<()> {
        let members = members
            .map(|members| self.members_from_py(&members, "members"))
            .transpose()?;
        let settings = ChannelSettings {
            members,
            execution_delay,
            control_groups,
            allow_group_delay_inhibit,
        };
        let obj = channel(instance, name, channel_number, settings).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }
}

/// The optional `add_channel` arguments; `None` keeps the Channel's default.
#[derive(Default)]
struct ChannelSettings {
    members: Option<Vec<BACnetDeviceObjectPropertyReference>>,
    execution_delay: Option<Vec<u32>>,
    control_groups: Option<Vec<u32>>,
    allow_group_delay_inhibit: bool,
}

/// Build a Channel through its validating setters, members before their
/// delays.
fn channel(
    instance: u32,
    name: &str,
    channel_number: u32,
    settings: ChannelSettings,
) -> Result<ChannelObject, Error> {
    let channel_number = u16::try_from(channel_number).map_err(|_| Error::Protocol {
        class: ErrorClass::PROPERTY.to_raw() as u32,
        code: ErrorCode::VALUE_OUT_OF_RANGE.to_raw() as u32,
    })?;
    let mut obj = ChannelObject::new(instance, name, channel_number)?;
    if let Some(members) = settings.members {
        obj.set_members(members)?;
    }
    if let Some(delays) = settings.execution_delay {
        obj.set_execution_delay(delays)?;
    }
    if let Some(groups) = settings.control_groups {
        obj.set_control_groups(groups)?;
    }
    obj.set_allow_group_delay_inhibit(settings.allow_group_delay_inhibit);
    Ok(obj)
}

#[cfg(test)]
#[path = "channel_methods_tests.rs"]
mod tests;

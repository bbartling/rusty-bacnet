//! Write commands: WriteProperty (WP) and WritePropertyMultiple (WPM).

use bacnet_client::client::BACnetClient;
use bacnet_encoding::primitives::encode_property_value;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::WriteAccessSpecification;
use bacnet_transport::port::TransportPort;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::BytesMut;

use crate::output::{self, OutputFormat};

/// Encode a `PropertyValue` into raw application-tagged bytes.
fn encode_value(value: &PropertyValue) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = BytesMut::new();
    encode_property_value(&mut buf, value)?;
    Ok(buf.to_vec())
}

/// The target and value of a single-property write.
pub struct WritePropertyArgs {
    /// Type of the object to write.
    pub object_type: ObjectType,
    /// Instance number of the object to write.
    pub instance: u32,
    /// Property to write.
    pub property: PropertyIdentifier,
    /// Array index within the property, if any.
    pub index: Option<u32>,
    /// Value to write.
    pub value: PropertyValue,
    /// Write priority (1-16), if any.
    pub priority: Option<u8>,
}

/// One property write inside a WritePropertyMultiple object entry:
/// property, array index, value and priority.
pub type PropertyWrite = (PropertyIdentifier, Option<u32>, PropertyValue, Option<u8>);

/// All property writes for one object: object type, instance and its property writes.
pub type ObjectWrites = (ObjectType, u32, Vec<PropertyWrite>);

/// Write a single property value.
pub async fn write_property_cmd<T: TransportPort + 'static>(
    client: &BACnetClient<T>,
    mac: &[u8],
    args: WritePropertyArgs,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let WritePropertyArgs {
        object_type,
        instance,
        property,
        index,
        value,
        priority,
    } = args;
    let oid = ObjectIdentifier::new(object_type, instance)?;
    let encoded = encode_value(&value)?;

    client
        .write_property(mac, oid, property, index, encoded, priority)
        .await?;

    output::print_success("OK", format);
    Ok(())
}

/// Write multiple properties to one or more objects.
pub async fn write_property_multiple_cmd<T: TransportPort + 'static>(
    client: &BACnetClient<T>,
    mac: &[u8],
    specs: Vec<ObjectWrites>,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let access_specs: Vec<WriteAccessSpecification> = specs
        .into_iter()
        .map(|(obj_type, instance, props)| {
            let oid = ObjectIdentifier::new(obj_type, instance)?;
            let prop_values = props
                .into_iter()
                .map(|(prop, idx, pv, priority)| {
                    let encoded = encode_value(&pv)
                        .map_err(|e| bacnet_types::error::Error::Encoding(e.to_string()))?;
                    Ok(BACnetPropertyValue {
                        property_identifier: prop,
                        property_array_index: idx,
                        value: encoded,
                        priority,
                    })
                })
                .collect::<Result<Vec<_>, bacnet_types::error::Error>>()?;
            Ok(WriteAccessSpecification {
                object_identifier: oid,
                list_of_properties: prop_values,
            })
        })
        .collect::<Result<Vec<_>, bacnet_types::error::Error>>()?;

    client.write_property_multiple(mac, access_specs).await?;

    output::print_success("OK", format);
    Ok(())
}

//! Passing a Channel object's Present_Value on to its members (Clause 12.53,
//! #1151, #1264).
//!
//! Each member's Execution_Delay is measured from the moment the
//! distribution starts, so the delays overlap rather than add up
//! (Clause 12.53.12): the members go in order of delay, list order among
//! equal delays, each as soon as its time is reached. They go one at a time,
//! so a member whose time comes while a write in another device waits for its
//! answer is written once that write ends: its delay is the least it waits
//! (#1343).
//!
//! A device that answers none of a write's attempts, or none of the Who-Is
//! sent to find it when it had no binding (#1322), is taken to be offline
//! for the rest of the distribution: its later members fail at once as
//! communication failures, with nothing sent, so a distribution waits out at
//! most one Who-Is and one write's retries per silent device rather than per
//! member. Members in other devices, and local ones, are still written.
//!
//! For a member in this device the runner looks up the datatype of the
//! property's current value, coerces the channel value to it (Table 12-63)
//! and writes the result through the host's local write path at the priority
//! the Present_Value write carried, or none if it carried none. A member
//! naming another Device goes out as a confirmed WriteProperty through
//! [`RunHost::write_remote`] (Clause 12.53.11 leaves the method open). Its
//! datatype is unknown here, so the value goes as written, except that a
//! lighting command still goes only to Lighting_Command; the device itself
//! refuses a datatype its property doesn't take.
//!
//! A coercion failure means that member isn't written, and counts as a
//! configuration failure: the member's datatype doesn't fit the value. A
//! refused or unanswered write counts as a failure too (sorted in `target`),
//! with one exception: a NULL refused as an invalid datatype, by an Error or
//! a Reject, so one channel can relinquish its commandable members while its
//! other members ignore the NULL (Clause 12.53.7). One failure doesn't stop
//! the rest (Clause 12.53.5.8); once every member has been tried, the
//! Channel's Write_Status becomes SUCCESSFUL or FAILED and its Reliability
//! takes the first failure's kind (Clause 12.53.9).

use bacnet_objects::channel::{
    coerce_channel_value, ChannelDistribution, ChannelMember, MemberDatatype,
};
use bacnet_objects::command::{CommandRun, WriteFailure};
use bacnet_types::constructed::BACnetActionCommand;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use tracing::debug;

use super::target::{self, Failed};
use super::{Owner, RunHost};

/// Write each member once its delay is up: `Ok` if all succeeded, otherwise
/// the first failure, or `None` once the run is stale.
pub(super) async fn distribute<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    owner: &mut Owner<'_, H>,
) -> Option<Result<(), WriteFailure>> {
    let start = tokio::time::Instant::now();
    let mut members: Vec<&ChannelMember> = distribution.members.iter().collect();
    members.sort_by_key(|member| member.delay_ms);
    let mut outcome = Ok(());
    // Devices that answered none of a write's attempts, or its Who-Is, in
    // this distribution.
    let mut silent = Vec::new();
    for (written, member) in members.into_iter().enumerate() {
        if member.delay_ms > 0 {
            let due = start + std::time::Duration::from_millis(member.delay_ms.into());
            tokio::time::sleep_until(due).await;
        }
        // The first failure in write order stands.
        let made = write_member(host, run, distribution, member, &mut silent).await?;
        outcome = outcome.and(made);
        owner.progress(written + 1, outcome);
    }
    Some(outcome)
}

/// Write one member: `Ok` if that counts as a success, otherwise how it
/// failed. `None` once the run is stale.
async fn write_member<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    member: &ChannelMember,
    silent: &mut Vec<ObjectIdentifier>,
) -> Option<Result<(), WriteFailure>> {
    let reference = &member.reference;
    let property = PropertyIdentifier::from_raw(reference.property_identifier);
    let (device, datatype) = {
        let db = host.database().read().await;
        if db
            .get(&run.source)
            .and_then(|object| object.command_generation_internal())
            != Some(run.generation)
        {
            return None;
        }
        // A member naming this Device is local, as one naming none is.
        if db.local_device().is_local(reference.device_identifier) {
            let current = db.get(&reference.object_identifier).and_then(|object| {
                object
                    .read_property(property, reference.property_array_index)
                    .ok()
            });
            (None, MemberDatatype::of(property, current.as_ref()))
        } else {
            (
                reference.device_identifier,
                MemberDatatype::of(property, None),
            )
        }
    };
    if let Some(device) = device.filter(|device| silent.contains(device)) {
        debug!(
            channel = %run.source,
            %device,
            target = %reference.object_identifier,
            ?property,
            "Channel member not sent: its device answered nothing earlier in this distribution"
        );
        return Some(Err(WriteFailure::Communication));
    }
    let Ok(value) = coerce_channel_value(&distribution.value, datatype) else {
        debug!(
            channel = %run.source,
            device = ?device,
            target = %reference.object_identifier,
            ?property,
            ?datatype,
            "Channel value can't be coerced to the member's datatype"
        );
        return Some(Err(WriteFailure::Configuration));
    };
    let command = BACnetActionCommand {
        device_identifier: device,
        object_identifier: reference.object_identifier,
        property_identifier: property,
        property_array_index: reference.property_array_index,
        property_value: value,
        priority: distribution.priority,
        post_delay: None,
        quit_on_failure: false,
        write_successful: false,
    };
    Some(match target::write(host, run, device, &command).await {
        Ok(()) => Ok(()),
        Err(Failed {
            answer: Some(answer),
            ..
        }) if command.property_value == PropertyValue::Null
            && target::refuses_datatype(&answer) =>
        {
            Ok(())
        }
        Err(failed) => {
            if let Some(device) = device.filter(|_| failed.unanswered) {
                silent.push(device);
            }
            Err(failed.failure)
        }
    })
}

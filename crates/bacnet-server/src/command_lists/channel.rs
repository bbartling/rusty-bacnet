//! Passing a Channel object's Present_Value on to its members (Clause 12.53,
//! #1151, #1264).
//!
//! Each member's Execution_Delay is measured from the moment the
//! distribution starts, so the delays overlap rather than add up
//! (Clause 12.53.12), and each member is written as soon as its own time is
//! reached, whatever the members before it are doing (#1343). Members in this
//! device are written by the distribution itself, in order of delay and list
//! order among equal delays, so their writes keep that order. A member in
//! another device is its own future, so a write there that waits for its
//! answer holds back no other member; at most [`REMOTE_IN_FLIGHT`] requests
//! to other devices are outstanding at once in one distribution, and a member
//! whose time comes while all of them are taken waits for one to end.
//!
//! A device that answers none of a write's attempts, or none of the Who-Is
//! sent to find it when it had no binding (#1322), is taken to be offline for
//! the rest of the distribution: its members whose writes start after that
//! fail at once as communication failures, with nothing sent. Members already
//! outstanding there wait out their own retries, side by side.
//!
//! For a member in this device the runner looks up the datatype of the
//! property's current value, coerces the channel value to it (Table 12-63)
//! and writes the result through the host's local write path at the priority
//! the Present_Value write carried, or none if it carried none. A member
//! naming another Device goes out as a confirmed WriteProperty through
//! [`RunHost::write_remote`] (Clause 12.53.11 leaves the method open). Its
//! datatype is learned first (#1342): a ReadProperty of the member's property
//! in that device, sent when the distribution starts so it overlaps the
//! member's delay, and the value is coerced to the datatype of what it
//! returns, as for a member here. A primitive datatype learned is kept on the
//! Channel for later distributions until the member is replaced. No read is
//! sent when the coercion can't depend on the answer: for a NULL, a lighting
//! command, or a member that is a Lighting_Command. A read that is refused,
//! gets no answer, or returns NULL or a constructed value leaves the value
//! as written, and the device itself refuses a datatype its property doesn't
//! take; nothing is kept, so the next distribution reads again.
//!
//! A coercion failure means that member isn't written, and counts as a
//! configuration failure: the member's datatype doesn't fit the value. A
//! refused or unanswered write counts as a failure too (sorted in `target`),
//! with one exception: a NULL refused as an invalid datatype, by an Error or
//! a Reject, so one channel can relinquish its commandable members while its
//! other members ignore the NULL (Clause 12.53.7). One failure doesn't stop
//! the rest (Clause 12.53.5.8); once every member has been tried, the
//! Channel's Write_Status becomes SUCCESSFUL or FAILED and its Reliability
//! takes the kind of the first failure to finish (Clause 12.53.9).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use bacnet_objects::channel::{
    coerce_channel_value, ChannelDistribution, ChannelMember, MemberDatatype,
};
use bacnet_objects::command::{CommandRun, WriteFailure};
use bacnet_types::constructed::BACnetActionCommand;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tracing::debug;

use super::target::{self, Failed};
use super::{Owner, RunHost};

/// The most requests to other devices, reads and writes together, one
/// distribution keeps outstanding at once: a sixteenth of the device's 256
/// invoke IDs, which its notifications and other runs share.
pub(super) const REMOTE_IN_FLIGHT: usize = 16;

/// What a distribution's members share while they are written.
struct Shared {
    start: Instant,
    /// Devices that answered none of a write's attempts, or its Who-Is, in
    /// this distribution. Never held across an await.
    silent: Mutex<Vec<ObjectIdentifier>>,
    /// One permit per outstanding request to another device.
    remote: Semaphore,
}

impl Shared {
    fn is_silent(&self, device: ObjectIdentifier) -> bool {
        self.silent
            .lock()
            .is_ok_and(|silent| silent.contains(&device))
    }

    fn found_silent(&self, device: ObjectIdentifier) {
        if let Ok(mut silent) = self.silent.lock() {
            silent.push(device);
        }
    }

    fn due(&self, member: &ChannelMember) -> Instant {
        self.start + Duration::from_millis(member.delay_ms.into())
    }
}

/// Write each member once its delay is up: `Ok` if all succeeded, otherwise
/// the first failure to finish, or `None` once the run is stale.
pub(super) async fn distribute<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    owner: &mut Owner<'_, H>,
) -> Option<Result<(), WriteFailure>> {
    let shared = Shared {
        start: Instant::now(),
        silent: Mutex::new(Vec::new()),
        remote: Semaphore::new(REMOTE_IN_FLIGHT),
    };
    let (mut local, remote): (Vec<&ChannelMember>, Vec<(&ChannelMember, ObjectIdentifier)>) = {
        let db = host.database().read().await;
        if !current(&db, run) {
            return None;
        }
        let mut local = Vec::new();
        let mut remote = Vec::new();
        for member in &distribution.members {
            // A member naming this Device is local, as one naming none is.
            match member.reference.device_identifier {
                Some(device) if !db.local_device().is_local(Some(device)) => {
                    remote.push((member, device));
                }
                _ => local.push(member),
            }
        }
        (local, remote)
    };
    local.sort_by_key(|member| member.delay_ms);
    let mut local = VecDeque::from(local);
    let mut remote: FuturesUnordered<_> = remote
        .into_iter()
        .map(|(member, device)| write_remote(host, run, distribution, member, device, &shared))
        .collect();
    let mut outcome = Ok(());
    let mut made = 0;
    loop {
        let due = local.front().map(|member| shared.due(member));
        let finished = tokio::select! {
            biased;
            Some(finished) = remote.next() => finished,
            () = tokio::time::sleep_until(due.unwrap_or(shared.start)), if due.is_some() => {
                let Some(member) = local.pop_front() else {
                    continue;
                };
                write_member(host, run, distribution, member, None, &shared).await
            }
            else => break,
        };
        // The first failure to finish stands.
        outcome = outcome.and(finished?);
        made += 1;
        owner.progress(made, outcome);
    }
    Some(outcome)
}

/// Whether `run` is still its object's current run.
fn current(db: &bacnet_objects::database::ObjectDatabase, run: &CommandRun) -> bool {
    db.get(&run.source)
        .and_then(|object| object.command_generation_internal())
        == Some(run.generation)
}

/// Learn the datatype of `member`, in `device`, then write it once its delay
/// is up.
async fn write_remote<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    member: &ChannelMember,
    device: ObjectIdentifier,
    shared: &Shared,
) -> Option<Result<(), WriteFailure>> {
    let datatype = match member.learned {
        Some(learned) => learned,
        None => learn(host, run, distribution, member, device, shared).await,
    };
    tokio::time::sleep_until(shared.due(member)).await;
    write_member(
        host,
        run,
        distribution,
        member,
        Some((device, datatype)),
        shared,
    )
    .await
}

/// The datatype `member`'s property in `device` holds, read there when the
/// coercion depends on it and kept on the Channel when it's a primitive one.
/// Anything short of that is [`MemberDatatype::Unknown`], or Lighting_Command
/// for that property, and the value goes as written.
async fn learn<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    member: &ChannelMember,
    device: ObjectIdentifier,
    shared: &Shared,
) -> MemberDatatype {
    let reference = &member.reference;
    let property = PropertyIdentifier::from_raw(reference.property_identifier);
    let unread = MemberDatatype::of(property, None);
    // NULL passes to every datatype, a lighting command goes only to a
    // Lighting_Command, and a Lighting_Command takes nothing else.
    let decides = !matches!(
        distribution.value,
        PropertyValue::Null | PropertyValue::ApplicationData(_)
    ) && unread == MemberDatatype::Unknown;
    if !decides || shared.is_silent(device) {
        return unread;
    }
    let read = {
        let Ok(_permit) = shared.remote.acquire().await else {
            return unread;
        };
        host.read_remote(device, reference).await
    };
    let datatype = match read {
        Ok(value) => MemberDatatype::of(property, Some(&value)),
        Err(error) => {
            debug!(
                channel = %run.source,
                %device,
                target = %reference.object_identifier,
                ?property,
                %error,
                "Channel member's datatype not learned; its value goes as written"
            );
            return unread;
        }
    };
    if datatype != MemberDatatype::Unknown {
        let mut db = host.database().write().await;
        if let Some(channel) = db.get_mut(&run.source) {
            channel.learn_member_datatype_internal(member.slot, reference, datatype);
        }
    }
    datatype
}

/// Write one member: `Ok` if that counts as a success, otherwise how it
/// failed. `None` once the run is stale. `remote` names the member's device
/// and datatype when it is in another device; a member here takes the
/// datatype of the value its property holds now.
async fn write_member<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    member: &ChannelMember,
    remote: Option<(ObjectIdentifier, MemberDatatype)>,
    shared: &Shared,
) -> Option<Result<(), WriteFailure>> {
    let reference = &member.reference;
    let property = PropertyIdentifier::from_raw(reference.property_identifier);
    let (device, datatype) = {
        let db = host.database().read().await;
        if !current(&db, run) {
            return None;
        }
        match remote {
            Some((device, datatype)) => (Some(device), datatype),
            None => {
                let value = db.get(&reference.object_identifier).and_then(|object| {
                    object
                        .read_property(property, reference.property_array_index)
                        .ok()
                });
                (None, MemberDatatype::of(property, value.as_ref()))
            }
        }
    };
    if let Some(device) = device.filter(|device| shared.is_silent(*device)) {
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
    let written = match device {
        None => target::write(host, run, None, &command).await,
        Some(_) => {
            let Ok(_permit) = shared.remote.acquire().await else {
                return Some(Err(WriteFailure::Process));
            };
            target::write(host, run, device, &command).await
        }
    };
    Some(match written {
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
                shared.found_silent(device);
            }
            Err(failed.failure)
        }
    })
}

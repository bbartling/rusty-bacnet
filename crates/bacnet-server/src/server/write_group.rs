//! Executing an inbound WriteGroup request (Clause 15.11, #1151).
//!
//! A WriteGroup names a control group, a write priority and a change list of
//! channel numbers, each with a BACnetChannelValue and maybe a priority of its
//! own. The server writes each value to the Present_Value of every local
//! Channel whose Channel_Number is that channel and whose Control_Groups holds
//! the group, at the entry's priority when it has one and at the request's
//! otherwise. Membership is read Channel by Channel: Clause 12.53.15 makes a
//! Channel, not its device, the member of a group, so a Channel outside the
//! group is left alone even when another Channel here is in it. Group 0 means
//! no assignment and never reaches here: the codec refuses it.
//!
//! Each value goes through the same [`LocalWriter`] path as `write_local` and
//! a Command's writes, so the Channel's own checks hold (BUSY while it
//! distributes, the value and priority checks, Out_Of_Service), and the
//! distribution the write queues starts through the server's
//! [`CommandRunner`]: coercion, Write_Status, the run chain, delays
//! and COV all behave as for a WriteProperty. One refused write is logged at
//! debug and the rest still go (Clause 15.11.2). The service is unconfirmed:
//! nothing goes back, and a request the codec refuses is dropped.
//!
//! The Inhibit Delay flag zeroes the delays of a Channel's distribution only
//! when that Channel's Allow_Group_Delay_Inhibit is TRUE (Clause 12.53.13);
//! otherwise each member waits its Execution_Delay as usual.
//!
//! WriteGroup carries no invoke ID and isn't one of the confirmed services
//! the mutation authorizer decides, so a server that restricts network
//! writes, with [`MutationPolicy::DenyAll`] or an installed authorizer, drops
//! every WriteGroup rather than let one past its policy. The writes make no
//! Audit records, and DCC's DISABLE drops the request before it gets here.

use super::command_runs::CommandRunner;
use super::local_writes::{LocalWrite, LocalWriter};
use super::request_services::UnconfirmedServices;
use super::*;
use crate::mutation::MutationPolicy;
use bacnet_objects::command::{CommandRun, RunPlan};
use bacnet_objects::traits::BACnetObject;
use bacnet_services::write_group::WriteGroupRequest;

/// One Channel Present_Value write a WriteGroup asks for.
#[derive(Debug, Clone, PartialEq)]
struct GroupWrite<'r> {
    channel: ObjectIdentifier,
    /// The entry's BACnetChannelValue, as the codec checked it.
    value: &'r [u8],
    priority: u8,
    /// The request asked for no delays and this Channel allows that.
    skip_delays: bool,
}

/// Whether local policy lets an inbound WriteGroup change anything.
fn admitted(config: &ServerConfig) -> bool {
    config.mutation_policy == MutationPolicy::Permissive && config.mutation_authorizer.is_none()
}

/// The Channel_Number `object` serves, if it serves one that fits.
fn channel_number(object: &dyn BACnetObject) -> Option<u16> {
    match object.read_property(PropertyIdentifier::CHANNEL_NUMBER, None) {
        Ok(PropertyValue::Unsigned(number)) => u16::try_from(number).ok(),
        _ => None,
    }
}

/// Whether `object`'s Control_Groups holds `group`.
fn in_group(object: &dyn BACnetObject, group: u32) -> bool {
    let wanted = PropertyValue::Unsigned(group.into());
    match object.read_property(PropertyIdentifier::CONTROL_GROUPS, None) {
        Ok(PropertyValue::List(groups)) => groups.contains(&wanted),
        Ok(single) => single == wanted,
        Err(_) => false,
    }
}

/// Whether `object`'s Allow_Group_Delay_Inhibit is present and TRUE.
fn allows_delay_inhibit(object: &dyn BACnetObject) -> bool {
    matches!(
        object.read_property(PropertyIdentifier::ALLOW_GROUP_DELAY_INHIBIT, None),
        Ok(PropertyValue::Boolean(true))
    )
}

/// The writes `request` asks of `db`'s Channels: change-list order, and
/// Channels by instance within one entry.
fn plan<'r>(db: &ObjectDatabase, request: &'r WriteGroupRequest) -> Vec<GroupWrite<'r>> {
    let group = request.group_number.get();
    let inhibit = request.inhibit_delay == Some(true);
    let mut members: Vec<(ObjectIdentifier, u16, bool)> = db
        .find_by_type(ObjectType::CHANNEL)
        .into_iter()
        .filter_map(|oid| {
            let object = db.get(&oid)?;
            if !in_group(object, group) {
                return None;
            }
            let skip_delays = inhibit && allows_delay_inhibit(object);
            Some((oid, channel_number(object)?, skip_delays))
        })
        .collect();
    members.sort_by_key(|(oid, ..)| oid.instance_number());
    request
        .change_list
        .iter()
        .flat_map(|entry| {
            let priority = entry.override_priority.unwrap_or(request.write_priority);
            members
                .iter()
                .filter(move |(_, number, _)| *number == entry.channel)
                .map(move |&(channel, _, skip_delays)| GroupWrite {
                    channel,
                    value: &entry.value,
                    priority,
                    skip_delays,
                })
        })
        .collect()
}

/// Write one value to its Channel; the runs that queued, delays zeroed where
/// the inhibit applies.
async fn write_channel<T: TransportPort + 'static>(
    writer: &LocalWriter<'_, T>,
    write: &GroupWrite<'_>,
) -> Result<Vec<CommandRun>, Error> {
    let value = handlers::decode_write_property_value(
        PropertyIdentifier::PRESENT_VALUE,
        None,
        write.value,
    )?;
    let mut runs = writer
        .write(
            &write.channel,
            LocalWrite::WriteGroup {
                priority: write.priority,
            },
            value,
            None,
        )
        .await?;
    if write.skip_delays {
        for run in runs.iter_mut().filter(|run| run.source == write.channel) {
            if let RunPlan::Channel(distribution) = &mut run.plan {
                for member in &mut distribution.members {
                    member.delay_ms = 0;
                }
            }
        }
    }
    Ok(runs)
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Execute an inbound WriteGroup's change list on the local Channels.
    pub(super) async fn execute_write_group(
        services: &UnconfirmedServices<T>,
        service_request: &[u8],
    ) {
        let request = match WriteGroupRequest::decode(service_request) {
            Ok(request) => request,
            Err(error) => {
                debug!(%error, "Ignoring malformed WriteGroup");
                return;
            }
        };
        if !admitted(&services.config) {
            debug!(
                group = request.group_number.get(),
                "Ignoring WriteGroup: local mutation policy restricts network writes"
            );
            return;
        }
        let writes = plan(&*services.db.read().await, &request);
        if writes.is_empty() {
            return;
        }
        let runner = CommandRunner::for_unconfirmed(services);
        let writer = runner.writer();
        for write in &writes {
            match write_channel(&writer, write).await {
                Ok(runs) => runner.start(runs),
                Err(error) => debug!(
                    channel = %write.channel,
                    priority = write.priority,
                    %error,
                    "WriteGroup value refused by its Channel"
                ),
            }
        }
    }
}

#[cfg(test)]
#[path = "write_group_tests.rs"]
mod tests;

//! Passing a Channel object's Present_Value on to its members (Clause 12.53,
//! #1151).
//!
//! A Channel's write queues a [`CommandRun`] whose plan is a
//! [`ChannelDistribution`], and the server runs it the way it runs a
//! Command's list (`command_runs`): as its own request task, each member
//! written through [`CommandRunner::write_value`] with the Channel as the
//! initiating object, and every step guarded by the Channel's generation.
//!
//! Each member's Execution_Delay is measured from the moment the
//! distribution starts, so the delays overlap rather than add up
//! (Clause 12.53.12): the members go in order of delay, list order among
//! equal delays, each as soon as its time is reached.
//!
//! For each member the server looks up the datatype of the property's current
//! value, coerces the channel value to it (Table 12-63) and writes the result
//! at the priority the Present_Value write carried, or none if it carried
//! none. A coercion failure means that member isn't written. A refused write
//! counts as a failure too, with one exception: a NULL refused as an invalid
//! datatype, so one channel can relinquish its commandable members while its
//! other members ignore the NULL (Clause 12.53.7). One failure doesn't stop
//! the rest (Clause 12.53.5.8); once every member has been tried, the
//! Channel's Write_Status becomes SUCCESSFUL or FAILED.

use super::command_runs::{CommandRunner, RunTarget};
use super::*;
use bacnet_objects::channel::{
    coerce_channel_value, ChannelDistribution, ChannelMember, MemberDatatype,
};
use bacnet_objects::command::CommandRun;

impl<T: TransportPort + 'static> CommandRunner<T> {
    /// Write each member of a Channel's distribution once its delay is up,
    /// then end the run.
    pub(super) async fn distribute(&self, run: &CommandRun, distribution: &ChannelDistribution) {
        let start = tokio::time::Instant::now();
        let mut members: Vec<&ChannelMember> = distribution.members.iter().collect();
        members.sort_by_key(|member| member.delay_ms);
        let mut all_succeeded = true;
        for member in members {
            if member.delay_ms > 0 {
                let due = start + Duration::from_millis(member.delay_ms.into());
                tokio::time::sleep_until(due).await;
            }
            let Some(success) = self.write_member(run, distribution, member).await else {
                // The Channel changed under the run; whatever replaced it
                // owns Write_Status now.
                return;
            };
            all_succeeded &= success;
        }
        self.complete(run.source, run.generation, all_succeeded)
            .await;
    }

    /// Write one member; whether that counts as a success. `None` once the
    /// run is stale.
    async fn write_member(
        &self,
        run: &CommandRun,
        distribution: &ChannelDistribution,
        member: &ChannelMember,
    ) -> Option<bool> {
        let reference = &member.reference;
        let property = PropertyIdentifier::from_raw(reference.property_identifier);
        let datatype = {
            let db = self.db.read().await;
            if db
                .get(&run.source)
                .and_then(|object| object.command_generation_internal())
                != Some(run.generation)
            {
                return None;
            }
            let current = db.get(&reference.object_identifier).and_then(|object| {
                object
                    .read_property(property, reference.property_array_index)
                    .ok()
            });
            MemberDatatype::of(property, current.as_ref())
        };
        let Ok(value) = coerce_channel_value(&distribution.value, datatype) else {
            debug!(
                channel = %run.source,
                target = %reference.object_identifier,
                ?property,
                ?datatype,
                "Channel value can't be coerced to the member's datatype"
            );
            return Some(false);
        };
        let target = RunTarget {
            object: reference.object_identifier,
            property,
            array_index: reference.property_array_index,
            priority: distribution.priority,
        };
        match self.write_value(run, target, &value).await {
            Ok(()) => Some(true),
            Err(error) if value == PropertyValue::Null && is_invalid_datatype(&error) => Some(true),
            Err(error) => {
                debug!(
                    channel = %run.source,
                    target = %reference.object_identifier,
                    ?property,
                    %error,
                    "Channel member write failed"
                );
                Some(false)
            }
        }
    }
}

/// Whether a refused write named the value's datatype as the reason.
fn is_invalid_datatype(error: &Error) -> bool {
    let invalid = ErrorCode::INVALID_DATA_TYPE.to_raw() as u32;
    matches!(
        error,
        Error::Protocol { code, .. } | Error::Structured { code, .. } if *code == invalid
    )
}

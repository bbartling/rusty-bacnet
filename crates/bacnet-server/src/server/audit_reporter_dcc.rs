//! DeviceCommunicationControl Audit records (Clause 19.6, Table 19-5, #1387).
use super::*;

impl<T: TransportPort + 'static> WriteAudit<'_, T> {
    /// Report a DeviceCommunicationControl change that has taken effect:
    /// DEVICE_DISABLE_COMM or DEVICE_ENABLE_COMM, named by `operation`.
    ///
    /// The change is to the device as a whole, so the record goes through
    /// the Reporter that monitors the local Device object, filtered by that
    /// Device's audit policy, with its Maximum_Send_Delay, and its resource
    /// losses summarized as AUDITING_FAILURE, as a CREATE is. Table 19-5
    /// gives these operations no target object, property or value, so the
    /// record names only this Device as its target. Its source and invoke ID
    /// are the requester's, or this device's own with no invoke ID for a
    /// disable that runs out ([`WriteAudit::local`]). Only a change carried
    /// out is reported, so the record has no Result.
    ///
    /// Called under the database guard, after the change commits.
    pub(in crate::server) fn device_communication(
        &mut self,
        db: &mut ObjectDatabase,
        operation: AuditOperation,
    ) {
        let Some(device) = db.local_device().identifier() else {
            return;
        };
        self.before_lifecycle(db, operation, Some(device), ObjectType::DEVICE, true);
        if let Some(pending) = &mut self.pending {
            pending.notification.target_object = None;
        }
        self.lifecycle_completed(db, &Ok(()));
    }
}

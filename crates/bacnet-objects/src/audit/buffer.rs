//! Resizing and purging an Audit Log (#1238).
//!
//! Buffer_Size is writable, but only while Log_Enable is FALSE (Clause
//! 12.64.9). The clause leaves the records already held to the
//! implementation. This log keeps the newest of them, as many as the new
//! size holds: the records its ring would hold had it been that size all
//! along. Growing the buffer therefore loses nothing, and shrinking it drops
//! the oldest records without a status record, as an overflowing ring does;
//! their sequence numbers stay unused.
//!
//! No peer can empty an Audit Log. Its Record_Count is read-only, unlike the
//! other logs' (Clause 12.64.11), and Clause 12.64.10 gives no other way to
//! reset one. The application purges it instead, through
//! [`AuditLogObject::purge`] or the bundled server's `purge_audit_log`. The
//! purge leaves one BUFFER_PURGED status record, which also carries
//! LOG_DISABLED while logging is off; it is written either way, since a
//! log-status record ignores Log_Enable (Clause 12.64.10). Total_Record_Count
//! and the completed-receipt ledger survive the purge, so sequence numbers
//! keep counting and a confirmed notification sent again after it is still
//! recognized as a duplicate.
//!
//! Both changes reach storage before the log serves them, through the same
//! writer as every other commit ([`super::staging`]). A commit that fails
//! refuses the change with DEVICE / OPERATIONAL_PROBLEM and leaves the log as
//! it was.

use super::*;

impl AuditLogObject {
    /// Clear the records and append a BUFFER_PURGED status record. Returns
    /// that record's sequence number.
    ///
    /// This is the application's purge: peers cannot purge an Audit Log,
    /// whose Record_Count is read-only (Clause 12.64.11). The record is
    /// appended whether or not logging is enabled, flagged LOG_DISABLED too
    /// while it is not, and Total_Record_Count keeps counting. Without a valid clock, or when the
    /// commit fails, the purge fails with DEVICE / OPERATIONAL_PROBLEM and
    /// the log is left as it was.
    ///
    /// Called directly, the purge commits in place and waits for the commit
    /// there. The bundled server's `purge_audit_log` stages it instead, so
    /// the commit runs with the object database guard dropped.
    pub fn purge(&mut self) -> Result<u64, Error> {
        self.commit_change(staging::StagedChange::Purge, Self::purged_snapshot)?;
        Ok(self.total_record_count)
    }

    /// A Buffer_Size write. Writing the size the log already has changes
    /// nothing.
    pub(super) fn write_buffer_size(&mut self, value: &PropertyValue) -> Result<(), Error> {
        let size = self.written_buffer_size(value)?;
        if size == self.buffer_size {
            return Ok(());
        }
        self.commit_change(staging::StagedChange::BufferSize(size), |log| {
            log.resized_snapshot(size)
        })
    }

    /// The size a Buffer_Size write asks for, or the reason it is refused:
    /// PROPERTY / WRITE_ACCESS_DENIED while Log_Enable is TRUE,
    /// INVALID_DATA_TYPE for a value that is not Unsigned, and
    /// VALUE_OUT_OF_RANGE above [`MAX_AUDIT_RECORDS`]. That includes
    /// 2^32-1, which Clause 12.64.9 sets aside for a log whose size is
    /// unknown.
    pub(super) fn written_buffer_size(&self, value: &PropertyValue) -> Result<u32, Error> {
        if self.log_enable {
            return Err(property_error(ErrorCode::WRITE_ACCESS_DENIED));
        }
        let PropertyValue::Unsigned(size) = value else {
            return Err(property_error(ErrorCode::INVALID_DATA_TYPE));
        };
        u32::try_from(*size)
            .ok()
            .filter(|size| *size <= MAX_AUDIT_RECORDS)
            .ok_or_else(|| property_error(ErrorCode::VALUE_OUT_OF_RANGE))
    }

    /// The next snapshot with room for `size` records: the newest that fit
    /// are kept.
    pub(super) fn resized_snapshot(&mut self, size: u32) -> Result<AuditLogSnapshot, Error> {
        let mut prospective = self.snapshot_for_next_generation()?;
        let dropped = prospective.records.len().saturating_sub(size as usize);
        prospective.records.drain(..dropped);
        prospective.capacity = size;
        Ok(prospective)
    }

    /// The next snapshot with every record gone but the purge's own.
    pub(super) fn purged_snapshot(&mut self) -> Result<AuditLogSnapshot, Error> {
        let timestamp = self.valid_timestamp()?;
        let mut prospective = self.snapshot_for_next_generation()?;
        prospective.records.clear();
        let mut status = LogStatus::BUFFER_PURGED;
        status.set(LogStatus::LOG_DISABLED, !prospective.log_enable);
        append_record(
            &mut prospective,
            BACnetAuditLogRecord {
                timestamp,
                datum: BACnetAuditLogDatum::LogStatus(status),
            },
        );
        Ok(prospective)
    }

    /// The next snapshot after a Log_Enable change to `log_enable`, with the
    /// status record the change appends.
    pub(super) fn log_enable_snapshot(
        &mut self,
        log_enable: bool,
    ) -> Result<AuditLogSnapshot, Error> {
        let timestamp = self.valid_timestamp()?;
        let mut prospective = self.snapshot_for_next_generation()?;
        prospective.log_enable = log_enable;
        append_record(&mut prospective, log_enable_record(timestamp, log_enable));
        Ok(prospective)
    }
}

fn property_error(code: ErrorCode) -> Error {
    Error::Protocol {
        class: ErrorClass::PROPERTY.to_raw() as u32,
        code: code.to_raw() as u32,
    }
}

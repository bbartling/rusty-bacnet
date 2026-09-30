//! COV fanout owed by a background commit (#889).
//!
//! Background tasks (periodic intrinsic reporting, fault detection, schedule
//! writes) mutate objects under the database guard and fan COV out after
//! dropping it, as a network write does. Ordinary objects are re-evaluated as a
//! whole; Life Safety objects report exactly the properties the pass changed.

use crate::cov::CovSubscriptionTable;
use crate::life_safety_cov::{is_life_safety_object, LifeSafetyCovChange, LifeSafetyCovSnapshots};
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::ObjectIdentifier;
use tokio::sync::RwLock;

/// Objects one background pass changed, collected under its database guard.
pub(crate) struct BackgroundCommit {
    life_safety: LifeSafetyCovSnapshots,
    changed: Vec<ObjectIdentifier>,
}

impl BackgroundCommit {
    /// Snapshot Life Safety state before the pass mutates anything.
    pub(crate) fn begin(db: &ObjectDatabase) -> Self {
        let life_safety = db
            .find_by_type(ObjectType::LIFE_SAFETY_POINT)
            .into_iter()
            .chain(db.find_by_type(ObjectType::LIFE_SAFETY_ZONE));
        Self {
            life_safety: LifeSafetyCovSnapshots::capture_oids(db, life_safety),
            changed: Vec::new(),
        }
    }

    pub(crate) fn changed(&mut self, oid: ObjectIdentifier) {
        if !self.changed.contains(&oid) {
            self.changed.push(oid);
        }
    }

    /// Finish under the same guard: record timestamped COV-multiple history at
    /// commit time, then split the fanout owed once the guard is dropped.
    pub(crate) async fn finish(
        self,
        db: &ObjectDatabase,
        cov_table: &RwLock<CovSubscriptionTable>,
    ) -> CommittedCov {
        if self.changed.is_empty() {
            return CommittedCov::default();
        }
        let captures: Vec<_> = {
            let table = cov_table.read().await;
            self.changed
                .iter()
                .map(|oid| table.timed_capture(*oid))
                .collect()
        };
        for capture in captures {
            capture.run(db);
        }
        let (life_safety, coarse): (Vec<_>, Vec<_>) = self
            .changed
            .into_iter()
            .partition(|oid| is_life_safety_object(*oid));
        CommittedCov {
            life_safety: self.life_safety.changes(db, &life_safety),
            coarse,
        }
    }
}

/// COV fanout owed after a background commit.
#[derive(Debug, Default)]
pub(crate) struct CommittedCov {
    pub(crate) coarse: Vec<ObjectIdentifier>,
    pub(crate) life_safety: Vec<LifeSafetyCovChange>,
}

impl CommittedCov {
    pub(crate) fn is_empty(&self) -> bool {
        self.coarse.is_empty() && self.life_safety.is_empty()
    }
}

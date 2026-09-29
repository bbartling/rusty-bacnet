//! Item assembly for one COV-multiple notification: queued timestamped history
//! followed by one current value per coordinate.
use std::collections::HashSet;

use bacnet_services::cov_multiple::{COVNotificationItem, COVNotificationValue};
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::ObjectIdentifier;

use crate::cov::multiple_reads::MultipleReads;
use crate::cov::timed::TimedClaim;
use crate::cov::CovSubscriptionSnapshot;

/// Object, property and index of a subscribed coordinate.
pub(super) type Coordinate = (ObjectIdentifier, Option<PropertyIdentifier>, Option<u32>);

/// Build the items conveyed for `retained` references. Untimestamped
/// references supply their prepared current values; timestamped references
/// supply their claimed changes. `untimed` holds coordinates the context
/// explicitly subscribes without timestamps.
pub(super) fn build_items(
    claim: &TimedClaim,
    retained: &[(&CovSubscriptionSnapshot, &[COVNotificationValue])],
    reads: &MultipleReads,
    untimed: &HashSet<Coordinate>,
) -> Vec<COVNotificationItem> {
    let mut items: Vec<COVNotificationItem> = Vec::new();
    let item_for = |items: &mut Vec<COVNotificationItem>, oid: ObjectIdentifier| {
        items
            .iter()
            .position(|item| item.monitored_object_identifier == oid)
            .unwrap_or_else(|| {
                items.push(COVNotificationItem {
                    monitored_object_identifier: oid,
                    list_of_values: Vec::new(),
                });
                items.len() - 1
            })
    };
    // Queued history first: every earlier timestamped change as distinct
    // values with its own time (repeated coordinates are permitted). A
    // coordinate explicitly subscribed without timestamps is never repeated
    // or timestamped (§13.17.3.1.2.4).
    for (key, change) in claim.earlier() {
        let index = item_for(&mut items, key.object());
        let list = &mut items[index].list_of_values;
        for value in change.values() {
            let coordinate = (
                key.object(),
                Some(value.property_identifier),
                value.property_array_index,
            );
            if !untimed.contains(&coordinate) && !list.contains(value) {
                list.push(value.clone());
            }
        }
    }
    let history: Vec<usize> = items.iter().map(|item| item.list_of_values.len()).collect();
    let start = |index: usize| history.get(index).copied().unwrap_or(0);
    // Current state: one value per coordinate. A timestamped reference
    // contributes its latest change stamped with that change's own time.
    for (sub, values) in retained {
        let values = if sub.timestamped {
            claim
                .latest(sub.key())
                .map(|change| change.values().to_vec())
                .unwrap_or_default()
        } else {
            values.to_vec()
        };
        let index = item_for(&mut items, sub.monitored_object_identifier);
        let from = start(index);
        for value in values {
            let current = &mut items[index].list_of_values[from..];
            if let Some(existing) = current.iter_mut().find(|v| {
                v.property_identifier == value.property_identifier
                    && v.property_array_index == value.property_array_index
            }) {
                existing.time_of_change = existing.time_of_change.or(value.time_of_change);
            } else {
                items[index].list_of_values.push(value);
            }
        }
    }
    for (index, item) in items.iter_mut().enumerate() {
        if item.list_of_values[start(index)..]
            .iter()
            .any(|v| v.property_identifier == PropertyIdentifier::STATUS_FLAGS)
        {
            continue;
        }
        if let Some(encoded) = reads.encoded_flags(&item.monitored_object_identifier) {
            item.list_of_values.push(COVNotificationValue {
                property_identifier: PropertyIdentifier::STATUS_FLAGS,
                property_array_index: None,
                value: encoded.to_vec(),
                time_of_change: None,
            });
        }
    }
    // Qualified explicit selectors control their own current coordinate. OR
    // above combines only implicit companion intent; an explicit false remains
    // false. Unqualified references have no entry in this list.
    for (sub, _) in retained {
        let Some(index) = items
            .iter()
            .position(|item| item.monitored_object_identifier == sub.monitored_object_identifier)
        else {
            continue;
        };
        let from = start(index);
        if let Some(value) = items[index].list_of_values[from..]
            .iter_mut()
            .find(|value| {
                Some(value.property_identifier) == sub.monitored_property
                    && value.property_array_index == sub.monitored_property_array_index
            })
        {
            value.time_of_change = sub
                .timestamped
                .then(|| claim.latest(sub.key()).map(|c| c.frame().local_time))
                .flatten();
        }
    }
    // A history row identical to a current row adds nothing.
    for (index, item) in items.iter_mut().enumerate() {
        let (earlier, current) = item.list_of_values.split_at(start(index));
        let mut values: Vec<_> = earlier
            .iter()
            .filter(|value| !current.contains(value))
            .cloned()
            .collect();
        values.extend_from_slice(current);
        item.list_of_values = values;
    }
    items
}

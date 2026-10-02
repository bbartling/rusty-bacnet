//! Item assembly for one COV-multiple notification: queued timestamped history
//! followed by one current value per coordinate.
use std::collections::HashSet;

use bacnet_services::cov_multiple::{COVNotificationItem, COVNotificationValue};
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::ObjectIdentifier;

use crate::cov::multiple_reads::MultipleReads;
use crate::cov::timed::{TimedChange, TimedClaim};
use crate::cov::{CovSubscriptionKey, CovSubscriptionSnapshot};

/// Object, property and index of a subscribed coordinate.
pub(super) type Coordinate = (ObjectIdentifier, Option<PropertyIdentifier>, Option<u32>);

/// Each retained reference with its prepared current values (empty for a
/// timestamped reference, whose claimed latest change supplies them).
pub(super) type Retained<'a> = [(&'a CovSubscriptionSnapshot, &'a [COVNotificationValue])];

/// Queued history conveyed as distinct timestamped values, in capture order.
pub(super) type History<'a> = [(&'a CovSubscriptionKey, &'a TimedChange)];

/// Build the items of one notification: `history`, then, unless `retained` is
/// `None` (a notification carrying history only), the current state of the
/// `retained` references. Untimestamped references supply their prepared
/// current values; timestamped references their latest change in `claim`.
/// `untimed` holds coordinates the context explicitly subscribes without
/// timestamps.
pub(super) fn build_items(
    claim: &TimedClaim,
    history: &History<'_>,
    retained: Option<&Retained<'_>>,
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
    for &(key, change) in history {
        let index = item_for(&mut items, key.object());
        let list = &mut items[index].list_of_values;
        for value in change.values() {
            let coordinate = (
                key.object(),
                Some(value.property_identifier),
                value.property_array_index,
            );
            if !untimed.contains(&coordinate) {
                list.push(value.clone());
            }
        }
    }
    let Some(retained) = retained else {
        // Each history value keeps its own time; no current state follows.
        items.retain(|item| !item.list_of_values.is_empty());
        for item in &mut items {
            let values = std::mem::take(&mut item.list_of_values);
            let rows = values.len();
            item.list_of_values = collapse_repeats(values, rows);
        }
        return items;
    };
    let history_rows: Vec<usize> = items.iter().map(|item| item.list_of_values.len()).collect();
    let start = |index: usize| history_rows.get(index).copied().unwrap_or(0);
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
    // An explicit untimestamped selector governs its coordinate whether or not
    // it qualified this round, over any timestamped companion (§13.17.3.1.2.4).
    for (index, item) in items.iter_mut().enumerate() {
        let oid = item.monitored_object_identifier;
        for value in &mut item.list_of_values[start(index)..] {
            if untimed.contains(&(
                oid,
                Some(value.property_identifier),
                value.property_array_index,
            )) {
                value.time_of_change = None;
            }
        }
    }
    for (index, item) in items.iter_mut().enumerate() {
        item.list_of_values =
            collapse_repeats(std::mem::take(&mut item.list_of_values), start(index));
    }
    // An object whose history rows were all explicitly untimestamped.
    items.retain(|item| !item.list_of_values.is_empty());
    items
}

/// Drop each history row (the first `history` values) whose next row for the
/// same coordinate repeats it exactly, value and time: overlapping selectors
/// of one change, or a companion that did not change. A value that returns
/// after a different one is a distinct change and stays (A-B-A).
fn collapse_repeats(
    values: Vec<COVNotificationValue>,
    history: usize,
) -> Vec<COVNotificationValue> {
    let repeated: Vec<bool> = (0..values.len())
        .map(|at| {
            at < history
                && values[at + 1..]
                    .iter()
                    .find(|later| {
                        later.property_identifier == values[at].property_identifier
                            && later.property_array_index == values[at].property_array_index
                    })
                    .is_some_and(|next| *next == values[at])
        })
        .collect();
    values
        .into_iter()
        .zip(repeated)
        .filter_map(|(value, repeated)| (!repeated).then_some(value))
        .collect()
}

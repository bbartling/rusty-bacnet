//! The device table: rows from I-Am, sorting, filtering, selection and the
//! duplicate-instance record.
//!
//! Sorting and filtering live in the model. [`DeviceTable::settle`] rebuilds
//! the visible order only when something changed, and the view renders only
//! the rows that fit on screen.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

use bacnet_types::enums::Segmentation;

use crate::tui::message::DeviceRow;

/// Columns the table can sort by, in the order `s` cycles through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SortKey {
    /// Device instance.
    Instance,
    /// Address text.
    Address,
    /// Remote network (local devices first).
    Network,
    /// Vendor identifier.
    Vendor,
    /// Most recently seen first.
    LastSeen,
}

impl SortKey {
    fn next(self) -> Self {
        match self {
            Self::Instance => Self::Address,
            Self::Address => Self::Network,
            Self::Network => Self::Vendor,
            Self::Vendor => Self::LastSeen,
            Self::LastSeen => Self::Instance,
        }
    }

    /// Column name for the title line.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Address => "address",
            Self::Network => "network",
            Self::Vendor => "vendor",
            Self::LastSeen => "last seen",
        }
    }
}

/// Cursor movement in a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Movement {
    /// One row up.
    Up,
    /// One row down.
    Down,
    /// One page up.
    PageUp,
    /// One page down.
    PageDown,
    /// First row.
    Home,
    /// Last row.
    End,
}

/// The live device table.
pub(crate) struct DeviceTable {
    rows: HashMap<u32, DeviceRow>,
    sort: SortKey,
    descending: bool,
    filter: String,
    visible: Vec<u32>,
    selected: Option<u32>,
    selected_index: Option<usize>,
    stale: bool,
    /// First visible row, kept by the view between frames.
    pub(crate) offset: Cell<usize>,
    /// Rows that fit on screen in the last frame; PgUp and PgDn move this far.
    pub(crate) page: Cell<usize>,
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self {
            rows: HashMap::new(),
            sort: SortKey::Instance,
            descending: false,
            filter: String::new(),
            visible: Vec::new(),
            selected: None,
            selected_index: None,
            stale: false,
            offset: Cell::new(0),
            page: Cell::new(10),
        }
    }
}

impl DeviceTable {
    /// Insert or replace a row.
    pub(crate) fn upsert(&mut self, row: DeviceRow) {
        let reorders = match self.rows.get(&row.instance) {
            // A refresh changes only `last_seen` unless the device moved.
            Some(old) => {
                self.sort == SortKey::LastSeen
                    || old.address != row.address
                    || old.network != row.network
                    || old.vendor_id != row.vendor_id
            }
            None => true,
        };
        self.rows.insert(row.instance, row);
        self.stale |= reorders;
    }

    /// Remove a row.
    pub(crate) fn remove(&mut self, instance: u32) {
        if self.rows.remove(&instance).is_some() {
            self.stale = true;
        }
    }

    /// Replace every row (a resync after dropped events).
    pub(crate) fn replace_all(&mut self, rows: Vec<DeviceRow>) {
        self.rows = rows.into_iter().map(|r| (r.instance, r)).collect();
        self.stale = true;
    }

    /// Rows held, filtered or not.
    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when no device has answered.
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Row for an instance.
    #[cfg(test)]
    pub(crate) fn get(&self, instance: u32) -> Option<&DeviceRow> {
        self.rows.get(&instance)
    }

    /// Current sort column and direction.
    pub(crate) fn sort(&self) -> (SortKey, bool) {
        (self.sort, self.descending)
    }

    /// Move to the next sort column, ascending.
    pub(crate) fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
        self.descending = false;
        self.stale = true;
    }

    /// Flip the sort direction.
    pub(crate) fn reverse(&mut self) {
        self.descending = !self.descending;
        self.stale = true;
    }

    /// The filter text.
    pub(crate) fn filter(&self) -> &str {
        &self.filter
    }

    /// Append to the filter.
    pub(crate) fn push_filter(&mut self, ch: char) {
        self.filter.push(ch);
        self.stale = true;
    }

    /// Remove the filter's last character.
    pub(crate) fn pop_filter(&mut self) {
        self.filter.pop();
        self.stale = true;
    }

    /// Clear the filter.
    pub(crate) fn clear_filter(&mut self) {
        if !self.filter.is_empty() {
            self.filter.clear();
            self.stale = true;
        }
    }

    /// Rebuild the visible order if rows, sort or filter changed.
    pub(crate) fn settle(&mut self) {
        if !self.stale {
            return;
        }
        self.stale = false;
        let needle = self.filter.to_lowercase();
        let mut visible: Vec<&DeviceRow> = self
            .rows
            .values()
            .filter(|row| needle.is_empty() || matches(row, &needle))
            .collect();
        let key = self.sort;
        visible.sort_by(|a, b| {
            let order = match key {
                SortKey::Instance => a.instance.cmp(&b.instance),
                SortKey::Address => a.address.cmp(&b.address),
                SortKey::Network => a.network.cmp(&b.network),
                SortKey::Vendor => a.vendor_id.cmp(&b.vendor_id),
                SortKey::LastSeen => b.last_seen.cmp(&a.last_seen),
            };
            order.then(a.instance.cmp(&b.instance))
        });
        if self.descending {
            visible.reverse();
        }
        self.visible = visible.into_iter().map(|r| r.instance).collect();
        self.fix_selection();
    }

    fn fix_selection(&mut self) {
        self.selected_index = self
            .selected
            .and_then(|sel| self.visible.iter().position(|&i| i == sel));
        if self.selected_index.is_none() {
            self.selected_index = (!self.visible.is_empty()).then_some(0);
        }
        self.selected = self.selected_index.map(|i| self.visible[i]);
    }

    /// Visible rows in display order. Call [`settle`](Self::settle) first.
    #[cfg(test)]
    pub(crate) fn visible(&self) -> impl Iterator<Item = &DeviceRow> + '_ {
        self.visible.iter().filter_map(|i| self.rows.get(i))
    }

    /// Number of visible rows.
    pub(crate) fn visible_len(&self) -> usize {
        self.visible.len()
    }

    /// Visible rows `start..start + len`.
    pub(crate) fn visible_window(
        &self,
        start: usize,
        len: usize,
    ) -> impl Iterator<Item = &DeviceRow> + '_ {
        self.visible
            .iter()
            .skip(start)
            .take(len)
            .filter_map(|i| self.rows.get(i))
    }

    /// Index of the selected row among the visible rows.
    pub(crate) fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    /// Move the selection.
    pub(crate) fn move_selection(&mut self, movement: Movement) {
        self.settle();
        let Some(last) = self.visible.len().checked_sub(1) else {
            return;
        };
        let current = self.selected_index.unwrap_or(0);
        let page = self.page.get().max(1);
        let next = match movement {
            Movement::Up => current.saturating_sub(1),
            Movement::Down => (current + 1).min(last),
            Movement::PageUp => current.saturating_sub(page),
            Movement::PageDown => (current + page).min(last),
            Movement::Home => 0,
            Movement::End => last,
        };
        self.selected_index = Some(next);
        self.selected = Some(self.visible[next]);
    }
}

/// Case-insensitive substring match on the text columns. `needle` is lowercase.
fn matches(row: &DeviceRow, needle: &str) -> bool {
    row.instance.to_string().contains(needle)
        || row.address.to_lowercase().contains(needle)
        || row.network.is_some_and(|n| n.to_string().contains(needle))
        || row.vendor_id.to_string().contains(needle)
}

/// Short segmentation label.
pub(crate) fn segmentation_label(segmentation: Segmentation) -> String {
    match segmentation {
        Segmentation::BOTH => "both".into(),
        Segmentation::TRANSMIT => "transmit".into(),
        Segmentation::RECEIVE => "receive".into(),
        Segmentation::NONE => "none".into(),
        other => other.to_raw().to_string(),
    }
}

/// Age as `12s`, `4m` or `3h`.
pub(crate) fn age_label(now: Instant, then: Instant) -> String {
    let secs = now.saturating_duration_since(then).as_secs();
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3_599 => format!("{}m", secs / 60),
        _ => format!("{}h", secs / 3_600),
    }
}

/// Instances that more than one address claims, from the client's collision
/// notices.
#[derive(Default)]
pub(crate) struct Duplicates {
    by_instance: BTreeMap<u32, BTreeSet<String>>,
}

impl Duplicates {
    /// Record that `retained` and `incoming` claim the same instance.
    /// Returns true if this added an address.
    pub(crate) fn record(&mut self, retained: &DeviceRow, incoming: &DeviceRow) -> bool {
        let entry = self.by_instance.entry(retained.instance).or_default();
        let before = entry.len();
        entry.insert(retained.address.clone());
        entry.insert(incoming.address.clone());
        entry.len() != before
    }

    /// True when no duplicate has been seen.
    pub(crate) fn is_empty(&self) -> bool {
        self.by_instance.is_empty()
    }

    /// One line per duplicated instance, such as
    /// `instance 200 claimed by 10.0.0.1:47808 and 10.0.0.2:47808`.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.by_instance
            .iter()
            .map(|(instance, addresses)| {
                let list: Vec<&str> = addresses.iter().map(String::as_str).collect();
                let joined = match list.as_slice() {
                    [one] => (*one).to_string(),
                    [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
                    [] => String::new(),
                };
                format!("instance {instance} claimed by {joined}")
            })
            .collect()
    }
}

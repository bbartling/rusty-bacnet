//! The Devices screen: the duplicate-instance banner and the live table.

use ratatui::layout::{Alignment, Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use super::{Theme, FULL_WIDTH};
use crate::tui::app::devices::{age_label, segmentation_label, SortKey};
use crate::tui::app::{App, Link, OpState};
use crate::tui::message::DeviceRow;

/// The duplicate-instance banner; the model keeps its text up to date.
pub(super) fn banner(frame: &mut Frame, area: Rect, lines: &[String], theme: &Theme) {
    if lines.is_empty() {
        return;
    }
    let text: Vec<Line> = lines
        .iter()
        .map(|l| Line::styled(l.as_str(), theme.danger()))
        .collect();
    frame.render_widget(
        Paragraph::new(text)
            .style(theme.danger())
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Text for the running or last Who-Is, for the table's bottom border.
fn op_status(app: &App) -> Option<String> {
    let op = app.op.as_ref()?;
    let what = format!("Who-Is {}", op.spec.describe());
    let replies = match op.replies {
        1 => "1 reply".to_string(),
        n => format!("{n} replies"),
    };
    Some(match &op.state {
        OpState::Sending => format!("{what}: sending"),
        OpState::Listening { until } => {
            let left = until.saturating_duration_since(app.now);
            let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
            format!("{what}: listening {secs}s, {replies}")
        }
        OpState::Done => format!("{what}: done, {replies}"),
        OpState::Cancelled => format!("{what}: cancelled, {replies}"),
        OpState::Failed(error) => format!("{what} failed: {error}"),
    })
}

fn title(app: &App) -> String {
    let (key, descending) = app.devices.sort();
    let arrow = if descending { "↓" } else { "↑" };
    let shown = app.devices.visible_len();
    let total = app.devices.len();
    let count = if shown == total {
        total.to_string()
    } else {
        format!("{shown} of {total}")
    };
    format!(" Devices ({count}) | sort: {} {arrow} ", key.label())
}

struct Columns {
    headers: [&'static str; 8],
    widths: [Constraint; 8],
}

fn columns(width: u16) -> Columns {
    if width >= FULL_WIDTH {
        Columns {
            headers: [
                "",
                "Instance",
                "Address",
                "Network",
                "Vendor",
                "Max APDU",
                "Segmentation",
                "Last seen",
            ],
            widths: [
                Constraint::Length(1),
                Constraint::Length(9),
                Constraint::Min(24),
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Length(13),
                Constraint::Length(10),
            ],
        }
    } else {
        Columns {
            headers: [
                "", "Instance", "Address", "Net", "Vendor", "APDU", "Seg", "Seen",
            ],
            widths: [
                Constraint::Length(1),
                Constraint::Length(9),
                Constraint::Min(20),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Length(8),
                Constraint::Length(5),
            ],
        }
    }
}

fn cells(row: &DeviceRow, app: &App, selected: bool) -> [String; 8] {
    [
        if selected { ">" } else { " " }.to_string(),
        row.instance.to_string(),
        row.address.clone(),
        row.network
            .map_or_else(|| "local".to_string(), |n| n.to_string()),
        row.vendor_id.to_string(),
        row.max_apdu.to_string(),
        segmentation_label(row.segmentation),
        age_label(app.now, row.last_seen),
    ]
}

pub(super) fn table(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let mut block = Block::bordered()
        .title(Line::styled(title(app), theme.accent()))
        .border_style(theme.dim());
    if !app.devices.filter().is_empty() {
        let filter = format!(" filter: \"{}\" ", app.devices.filter());
        block = block.title(Line::styled(filter, theme.warn()).alignment(Alignment::Right));
    }
    if let Some(status) = op_status(app) {
        block = block.title_bottom(Line::from(format!(" {status} ")));
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if app.devices.visible_len() == 0 {
        empty(frame, inner, app, theme);
        return;
    }
    let columns = columns(area.width);
    // One line for the header row.
    let height = usize::from(inner.height.saturating_sub(1)).max(1);
    let offset = scroll(app, height);
    let selected = app.devices.selected_index();
    let rows: Vec<Row> = app
        .devices
        .visible_window(offset, height)
        .enumerate()
        .map(|(i, row)| {
            let is_selected = selected == Some(offset + i);
            let line = Row::new(cells(row, app, is_selected));
            if is_selected {
                line.style(theme.selected())
            } else {
                line
            }
        })
        .collect();
    let mut header = columns.headers;
    let sorted = sorted_column(app.devices.sort().0);
    header[sorted] = header_with_marker(header[sorted]);
    let table = Table::new(rows, columns.widths)
        .header(Row::new(header).style(theme.accent()))
        .column_spacing(1);
    frame.render_widget(table, inner);
}

/// Index of the sorted column in [`Columns::headers`].
fn sorted_column(key: SortKey) -> usize {
    match key {
        SortKey::Instance => 1,
        SortKey::Address => 2,
        SortKey::Network => 3,
        SortKey::Vendor => 4,
        SortKey::LastSeen => 7,
    }
}

/// Mark the sorted column's header; the strings are static so pick from a
/// fixed set.
fn header_with_marker(header: &'static str) -> &'static str {
    match header {
        "Instance" => "Instance*",
        "Address" => "Address*",
        "Network" => "Network*",
        "Net" => "Net*",
        "Vendor" => "Vendor*",
        "Last seen" => "Last seen*",
        "Seen" => "Seen*",
        other => other,
    }
}

/// First visible row, keeping the selection on screen. The table remembers
/// it between frames so the view only scrolls when the selection leaves it.
fn scroll(app: &App, height: usize) -> usize {
    let table = &app.devices;
    table.page.set(height);
    let mut offset = table.offset.get();
    if let Some(selected) = table.selected_index() {
        if selected < offset {
            offset = selected;
        } else if selected >= offset + height {
            offset = selected + 1 - height;
        }
    }
    offset = offset.min(table.visible_len().saturating_sub(height));
    table.offset.set(offset);
    offset
}

fn empty(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let text = match (&app.link, app.devices.len()) {
        (Link::Picking, _) => String::new(),
        (Link::Connecting, _) => "Connecting...".to_string(),
        (Link::Failed(error), _) => format!("Connection failed: {error}"),
        (Link::Up { .. }, 0) => "No devices yet. Press d to send a Who-Is.".to_string(),
        (Link::Up { .. }, _) => format!(
            "No device matches \"{}\". Esc clears the filter.",
            app.devices.filter()
        ),
    };
    let lines = vec![Line::raw(""), Line::from(Span::styled(text, theme.dim()))];
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}

//! Rendering: pure functions of `&App` (apart from the table's scroll
//! position, which the table keeps in a `Cell` between frames).
//!
//! 80x24 is the smallest supported terminal and 120x40 the full layout.
//! Below the minimum only a notice is drawn.

mod chrome;
mod devices;
mod dialogs;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Overlay};

/// Smallest usable width.
pub(crate) const MIN_WIDTH: u16 = 80;
/// Smallest usable height.
pub(crate) const MIN_HEIGHT: u16 = 24;
/// Width from which the wide table columns are used.
pub(crate) const FULL_WIDTH: u16 = 120;
/// Height from which the log pane gets more room.
pub(crate) const FULL_HEIGHT: u16 = 40;

/// Most duplicate-instance lines shown before summarising the rest.
const MAX_BANNER_LINES: usize = 3;

/// Draw one frame.
pub(crate) fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let theme = Theme { color: app.color };
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        too_small(frame, area, &theme);
        return;
    }
    let banner = devices::banner_lines(app);
    // Long addresses wrap rather than vanish off the edge.
    let banner_height: usize = banner
        .iter()
        .map(|line| {
            line.chars()
                .count()
                .div_ceil(usize::from(area.width))
                .max(1)
        })
        .sum();
    let log_height = match (app.show_log, area.height >= FULL_HEIGHT) {
        (false, _) => 0,
        (true, true) => 12,
        (true, false) => 7,
    };
    let [status, banner_area, body, log, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(banner_height as u16),
        Constraint::Min(5),
        Constraint::Length(log_height),
        Constraint::Length(1),
    ])
    .areas(area);
    chrome::status_bar(frame, status, app, &theme);
    devices::banner(frame, banner_area, banner, &theme);
    devices::table(frame, body, app, &theme);
    if app.show_log {
        chrome::log_pane(frame, log, app, &theme);
    }
    chrome::footer(frame, footer, app, &theme);
    match &app.overlay {
        Overlay::None => {}
        Overlay::Help => chrome::help(frame, area, &theme),
        Overlay::WhoIs(form) => dialogs::who_is(frame, area, app, form, &theme),
        Overlay::Picker(picker) => dialogs::picker(frame, area, picker, &theme),
    }
}

fn too_small(frame: &mut Frame, area: Rect, theme: &Theme) {
    let text = vec![
        Line::styled(
            format!("Terminal too small: {}x{}.", area.width, area.height),
            theme.warn(),
        ),
        Line::raw(format!(
            "bacnet tui needs at least {MIN_WIDTH}x{MIN_HEIGHT} \
             ({FULL_WIDTH}x{FULL_HEIGHT} for the full layout)."
        )),
        Line::raw("Resize the window, or press q to quit."),
    ];
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), area);
}

/// Styles, with colour only when `NO_COLOR` is unset. Without colour every
/// state is still marked by text or a modifier.
pub(crate) struct Theme {
    color: bool,
}

impl Theme {
    fn pick(&self, colored: Style, plain: Style) -> Style {
        if self.color {
            colored
        } else {
            plain
        }
    }

    /// Status bar.
    fn bar(&self) -> Style {
        self.pick(
            Style::new().fg(Color::Black).bg(Color::Cyan),
            Style::new().add_modifier(Modifier::REVERSED),
        )
    }

    /// The READ-ONLY badge.
    fn safe(&self) -> Style {
        self.pick(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
            Style::new().add_modifier(Modifier::BOLD),
        )
    }

    /// Headings and focused labels.
    fn accent(&self) -> Style {
        self.pick(
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            Style::new().add_modifier(Modifier::BOLD),
        )
    }

    /// Warnings.
    fn warn(&self) -> Style {
        self.pick(
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            Style::new().add_modifier(Modifier::BOLD),
        )
    }

    /// Errors and the duplicate banner.
    fn danger(&self) -> Style {
        self.pick(
            Style::new()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
            Style::new().add_modifier(Modifier::BOLD | Modifier::REVERSED),
        )
    }

    /// Secondary text.
    fn dim(&self) -> Style {
        self.pick(
            Style::new().fg(Color::DarkGray),
            Style::new().add_modifier(Modifier::DIM),
        )
    }

    /// Selected row or focused value.
    fn selected(&self) -> Style {
        Style::new().add_modifier(Modifier::REVERSED)
    }
}

/// A `width` x `height` rectangle centred in `area`, clipped to it.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    area.centered(
        Constraint::Length(width.min(area.width)),
        Constraint::Length(height.min(area.height)),
    )
}

//! Keys to [`Action`]s, per context.
//!
//! Text fields take printable characters, so `q` types a `q` in the filter or
//! the Who-Is form; Ctrl-C works everywhere.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::devices::Movement;
use super::app::picker::PickerKey;
use super::app::whois::FormKey;
use super::app::{Action, App, FilterKey, Overlay};

/// Map a key press to an action, or `None` to ignore it.
pub(crate) fn map_key(app: &App, key: KeyEvent) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return Some(Action::CtrlC);
    }
    match &app.overlay {
        Overlay::Picker(_) => picker(key),
        Overlay::WhoIs(_) => form(key),
        Overlay::Help => match key.code {
            KeyCode::Esc | KeyCode::Char('?') => Some(Action::ToggleHelp),
            KeyCode::Char('q') => Some(Action::Quit),
            _ => None,
        },
        Overlay::None if app.filter_editing => filter(key),
        Overlay::None => main(key),
    }
}

/// A printable character typed without Ctrl or Alt.
fn typed(key: KeyEvent) -> Option<char> {
    match key.code {
        KeyCode::Char(ch)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            Some(ch)
        }
        _ => None,
    }
}

fn movement(code: KeyCode) -> Option<Movement> {
    Some(match code {
        KeyCode::Up | KeyCode::Char('k') => Movement::Up,
        KeyCode::Down | KeyCode::Char('j') => Movement::Down,
        KeyCode::PageUp => Movement::PageUp,
        KeyCode::PageDown => Movement::PageDown,
        KeyCode::Home | KeyCode::Char('g') => Movement::Home,
        KeyCode::End | KeyCode::Char('G') => Movement::End,
        _ => return None,
    })
}

fn main(key: KeyEvent) -> Option<Action> {
    if matches!(key.code, KeyCode::Char(_)) && typed(key).is_none() {
        return None;
    }
    if let Some(m) = movement(key.code) {
        return Some(Action::Move(m));
    }
    Some(match key.code {
        KeyCode::Esc => Action::Escape,
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('?') => Action::ToggleHelp,
        KeyCode::Char('L') => Action::ToggleLog,
        KeyCode::Char('d') => Action::OpenWhoIs,
        KeyCode::Char('/') => Action::StartFilter,
        KeyCode::Char('s') => Action::CycleSort,
        KeyCode::Char('S') => Action::ReverseSort,
        _ => return None,
    })
}

fn filter(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc => Action::Filter(FilterKey::Clear),
        KeyCode::Enter => Action::Filter(FilterKey::Commit),
        KeyCode::Backspace => Action::Filter(FilterKey::Backspace),
        KeyCode::Up => Action::Move(Movement::Up),
        KeyCode::Down => Action::Move(Movement::Down),
        _ => Action::Filter(FilterKey::Char(typed(key)?)),
    })
}

fn form(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc => Action::Escape,
        KeyCode::Enter => Action::Form(FormKey::Submit),
        KeyCode::Tab | KeyCode::Down => Action::Form(FormKey::Next),
        KeyCode::BackTab | KeyCode::Up => Action::Form(FormKey::Prev),
        KeyCode::Left => Action::Form(FormKey::Left),
        KeyCode::Right => Action::Form(FormKey::Right),
        KeyCode::Backspace => Action::Form(FormKey::Backspace),
        _ => Action::Form(FormKey::Char(typed(key)?)),
    })
}

fn picker(key: KeyEvent) -> Option<Action> {
    Some(match key.code {
        KeyCode::Esc | KeyCode::Char('q') => Action::Quit,
        KeyCode::Up | KeyCode::Char('k') => Action::Picker(PickerKey::Up),
        KeyCode::Down | KeyCode::Char('j') => Action::Picker(PickerKey::Down),
        KeyCode::Enter => Action::Picker(PickerKey::Choose),
        KeyCode::Char(ch @ '1'..='9') => {
            Action::Picker(PickerKey::Number(ch as usize - '0' as usize))
        }
        _ => return None,
    })
}

//! W3C `KeyboardEvent.key` / `.code` to X11 keysym mapping.

/// Keysym for a Unicode character.
pub(crate) fn char_keysym(c: char) -> Option<u32> {
    let cp = c as u32;
    match cp {
        0x08 => Some(0xff08),        // BackSpace
        0x09 => Some(0xff09),        // Tab
        0x0a | 0x0d => Some(0xff0d), // Return
        0x1b => Some(0xff1b),        // Escape
        0x7f => Some(0xffff),        // Delete
        0x20..=0x7e | 0xa0..=0xff => Some(cp), // Latin-1 maps directly
        0x00..=0x1f | 0x80..=0x9f => None,
        _ => Some(0x0100_0000 + cp), // Unicode keysym
    }
}

fn is_right(code: &str) -> bool {
    code.ends_with("Right")
}

/// Keysym for a named `key` value ("Enter", "Shift"...). `code` picks left/right variants.
fn named_keysym(key: &str, code: &str) -> Option<u32> {
    let lr = |left: u32, right: u32| if is_right(code) { right } else { left };
    Some(match key {
        "Enter" => 0xff0d,
        "Backspace" => 0xff08,
        "Tab" => 0xff09,
        "Escape" | "Esc" => 0xff1b,
        "Delete" | "Del" => 0xffff,
        "Insert" => 0xff63,
        "Home" => 0xff50,
        "End" => 0xff57,
        "PageUp" => 0xff55,
        "PageDown" => 0xff56,
        "ArrowLeft" | "Left" => 0xff51,
        "ArrowUp" | "Up" => 0xff52,
        "ArrowRight" | "Right" => 0xff53,
        "ArrowDown" | "Down" => 0xff54,
        "Shift" => lr(0xffe1, 0xffe2),
        "Control" => lr(0xffe3, 0xffe4),
        // Alt = Option on a Mac.
        "Alt" => lr(0xffe9, 0xffea),
        // Cmd / Windows key: Super, which macOS Screen Sharing treats as Command.
        "Meta" | "OS" | "Super" | "Hyper" | "Win" => lr(0xffeb, 0xffec),
        "AltGraph" => 0xfe03, // ISO_Level3_Shift
        "CapsLock" => 0xffe5,
        "NumLock" => 0xff7f,
        "ScrollLock" | "Scroll" => 0xff14,
        "Pause" => 0xff13,
        "PrintScreen" => 0xff61,
        "ContextMenu" | "Apps" => 0xff67,
        "Help" => 0xff6a,
        "Clear" => 0xff0b,
        "Spacebar" | "Space" => 0x20,
        _ => {
            // F1..F24 => 0xffbe..
            let n: u32 = key.strip_prefix('F')?.parse().ok()?;
            if (1..=24).contains(&n) && !key[1..].starts_with('0') {
                0xffbe + n - 1
            } else {
                return None;
            }
        }
    })
}

/// Keysym from the physical key alone (US layout), used when `key` is not usable.
fn code_keysym(code: &str) -> Option<u32> {
    if let Some(letter) = code.strip_prefix("Key") {
        let mut it = letter.chars();
        if let (Some(c), None) = (it.next(), it.next()) {
            if c.is_ascii_uppercase() {
                return Some(c.to_ascii_lowercase() as u32);
            }
        }
        return None;
    }
    if let Some(d) = code.strip_prefix("Digit").or_else(|| code.strip_prefix("Numpad")) {
        let mut it = d.chars();
        if let (Some(c), None) = (it.next(), it.next()) {
            if c.is_ascii_digit() {
                return Some(c as u32);
            }
        }
    }
    let c = match code {
        "Space" => ' ',
        "Minus" | "NumpadSubtract" => '-',
        "Equal" | "NumpadEqual" => '=',
        "BracketLeft" => '[',
        "BracketRight" => ']',
        "Backslash" | "IntlBackslash" => '\\',
        "Semicolon" => ';',
        "Quote" => '\'',
        "Backquote" => '`',
        "Comma" | "NumpadComma" => ',',
        "Period" | "NumpadDecimal" => '.',
        "Slash" | "NumpadDivide" => '/',
        "NumpadAdd" => '+',
        "NumpadMultiply" => '*',
        _ => {
            let name = match code {
                "NumpadEnter" => "Enter",
                "ShiftLeft" | "ShiftRight" => "Shift",
                "ControlLeft" | "ControlRight" => "Control",
                "AltLeft" | "AltRight" => "Alt",
                "MetaLeft" | "MetaRight" | "OSLeft" | "OSRight" => "Meta",
                other => other,
            };
            return named_keysym(name, code);
        }
    };
    Some(c as u32)
}

/// Map a key event to the keysym to send, or `None` if the key has no sensible mapping.
pub(crate) fn keysym(code: &str, key: &str) -> Option<u32> {
    if let Some(sym) = named_keysym(key, code) {
        return Some(sym);
    }
    let mut chars = key.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        if let Some(sym) = char_keysym(c) {
            return Some(sym);
        }
    }
    // "Unidentified", "Dead", "Process", empty, or a named key we do not know.
    code_keysym(code)
}

#[cfg(test)]
mod tests {
    use super::keysym;

    #[test]
    fn characters() {
        assert_eq!(keysym("KeyA", "a"), Some(0x61));
        assert_eq!(keysym("KeyA", "A"), Some(0x41));
        assert_eq!(keysym("Digit2", "@"), Some(0x40));
        assert_eq!(keysym("Space", " "), Some(0x20));
        assert_eq!(keysym("KeyE", "é"), Some(0xe9));
        assert_eq!(keysym("KeyE", "€"), Some(0x0100_20ac));
        assert_eq!(keysym("KeyA", "я"), Some(0x0100_044f));
        assert_eq!(keysym("", "😀"), Some(0x0101_f600));
        assert_eq!(keysym("Digit1", "1"), Some(0x31));
        assert_eq!(keysym("KeyF", "F"), Some(0x46)); // not mistaken for a function key
    }

    #[test]
    fn named_keys() {
        assert_eq!(keysym("Enter", "Enter"), Some(0xff0d));
        assert_eq!(keysym("NumpadEnter", "Enter"), Some(0xff0d));
        assert_eq!(keysym("Backspace", "Backspace"), Some(0xff08));
        assert_eq!(keysym("Tab", "Tab"), Some(0xff09));
        assert_eq!(keysym("Escape", "Escape"), Some(0xff1b));
        assert_eq!(keysym("ArrowLeft", "ArrowLeft"), Some(0xff51));
        assert_eq!(keysym("ArrowUp", "ArrowUp"), Some(0xff52));
        assert_eq!(keysym("ArrowRight", "ArrowRight"), Some(0xff53));
        assert_eq!(keysym("ArrowDown", "ArrowDown"), Some(0xff54));
        assert_eq!(keysym("Home", "Home"), Some(0xff50));
        assert_eq!(keysym("End", "End"), Some(0xff57));
        assert_eq!(keysym("PageUp", "PageUp"), Some(0xff55));
        assert_eq!(keysym("PageDown", "PageDown"), Some(0xff56));
        assert_eq!(keysym("Insert", "Insert"), Some(0xff63));
        assert_eq!(keysym("Delete", "Delete"), Some(0xffff));
        assert_eq!(keysym("F1", "F1"), Some(0xffbe));
        assert_eq!(keysym("F12", "F12"), Some(0xffc9));
        assert_eq!(keysym("F13", "F13"), Some(0xffca));
        assert_eq!(keysym("F24", "F24"), Some(0xffd5));
        assert_eq!(keysym("", "F25"), None);
        assert_eq!(keysym("CapsLock", "CapsLock"), Some(0xffe5));
    }

    #[test]
    fn modifiers_left_right() {
        assert_eq!(keysym("ShiftLeft", "Shift"), Some(0xffe1));
        assert_eq!(keysym("ShiftRight", "Shift"), Some(0xffe2));
        assert_eq!(keysym("ControlLeft", "Control"), Some(0xffe3));
        assert_eq!(keysym("ControlRight", "Control"), Some(0xffe4));
        assert_eq!(keysym("AltLeft", "Alt"), Some(0xffe9));
        assert_eq!(keysym("AltRight", "Alt"), Some(0xffea));
        // Cmd / Windows key => Super (Command on macOS)
        assert_eq!(keysym("MetaLeft", "Meta"), Some(0xffeb));
        assert_eq!(keysym("MetaRight", "Meta"), Some(0xffec));
        assert_eq!(keysym("OSLeft", "OS"), Some(0xffeb));
        assert_eq!(keysym("", "Shift"), Some(0xffe1));
    }

    #[test]
    fn falls_back_to_code() {
        assert_eq!(keysym("KeyQ", "Unidentified"), Some(0x71));
        assert_eq!(keysym("Digit7", "Dead"), Some(0x37));
        assert_eq!(keysym("Backquote", "Dead"), Some(0x60));
        assert_eq!(keysym("Quote", "Dead"), Some(0x27));
        assert_eq!(keysym("ShiftRight", "Unidentified"), Some(0xffe2));
        assert_eq!(keysym("MetaRight", "Unidentified"), Some(0xffec));
        assert_eq!(keysym("ArrowDown", ""), Some(0xff54));
        assert_eq!(keysym("NumpadEnter", "Unidentified"), Some(0xff0d));
        assert_eq!(keysym("Numpad5", "Unidentified"), Some(0x35));
        assert_eq!(keysym("F5", "Unidentified"), Some(0xffc2));
        assert_eq!(keysym("Whatever", "Unidentified"), None);
        assert_eq!(keysym("", ""), None);
    }
}

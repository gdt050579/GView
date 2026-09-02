//! INI metadata emission (spec `03_DUAL_PLUGIN` §2.1, §6.2; C++
//! `GViewApp.cpp` `ResetConfiguration` + each plugin's
//! `UpdateSettings(IniSection)`, serialised by `AppCUI`
//! `IniObject::ToString`).
//!
//! At configuration regeneration the C++ host calls every plugin's
//! `UpdateSettings` on an `IniSection` named `Type.<Name>` /
//! `Generic.<Name>` and writes the INI. Native plugins expose the same
//! data as [`PluginMetadata`] / [`GenericPluginMetadata`]; this module
//! renders it in the `AppCUI` text format so the file stays readable by
//! the C++ parser (`Plugin::Init`, spec §2.2):
//!
//! ```ini
//! [Type.PE]
//! Pattern = "magic:4D 5A"
//! Priority = 1
//! Description = "Portable executable format for Windows OS binaries"
//! OpCodes.Mask = 4294967295
//! Command.DigitalSignature = Alt+F8
//! Command.AreaHighlighter = Alt+F9
//! ```
//!
//! Formatting rules are those of `AddValueToString` /
//! `AddSectionValueToString` (`IniObject.cpp:237-345`): `Key = value`,
//! arrays as `[a , b]`, an empty string as `""`, values containing a
//! space / tab / `#` / `;` wrapped in `"…"`, single quotes forcing
//! `"…"`, double quotes forcing `'…'`, both (or a newline) forcing
//! `"""…"""`; sections start with a blank line. Keys are written in
//! the order the plugin sets them (`Pattern`, `Priority`,
//! `Description`, `Extension`, `OpCodes.Mask`, `Command.*`), i.e. the
//! unsorted `ToString(false)` layout; [`EmitOptions::sorted`] gives
//! the `ToString(true)` case-insensitive key order. Keys render through
//! AppCUI-rs [`Key`]'s `Display` (`Alt+F8`), which matches the C++
//! `KeyUtils::ToString` names except for the C++ `"Righ"` typo for the
//! Right arrow — not reproduced, since the Rust parser expects
//! `Right` and no plugin binds that key.

use appcui::input::Key;

use crate::generic_plugin::GenericPluginMetadata;
use crate::type_plugin::{CommandDef, Pattern, PluginMetadata};

/// Section prefix for type plugins (`GViewApp.cpp:30`).
pub const TYPE_SECTION_PREFIX: &str = "Type.";
/// Section prefix for generic plugins (`GViewApp.cpp:44`).
pub const GENERIC_SECTION_PREFIX: &str = "Generic.";
/// INI key names, as written by the C++ plugins.
pub const KEY_PATTERN: &str = "Pattern";
/// `Priority`.
pub const KEY_PRIORITY: &str = "Priority";
/// `Description`.
pub const KEY_DESCRIPTION: &str = "Description";
/// `Extension`.
pub const KEY_EXTENSION: &str = "Extension";
/// `OpCodes.Mask`.
pub const KEY_OPCODES_MASK: &str = "OpCodes.Mask";
/// `Command.` prefix (`Command.<name>`).
pub const KEY_COMMAND_PREFIX: &str = "Command.";

/// Rendering options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmitOptions {
    /// `IniObject::ToString(sorted = true)`: keys sorted
    /// case-insensitively instead of insertion order.
    pub sorted: bool,
}

/// One `Key = value` entry before rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IniValue {
    /// Scalar string (numbers and keys are rendered to text first).
    Scalar(String),
    /// `[a , b , …]`.
    Array(Vec<String>),
}

/// C++ `AddSectionValueToString`: quoting rules for one value.
#[must_use]
pub fn quote_value(value: &str) -> String {
    if value.is_empty() {
        return String::from("\"\"");
    }
    let mut spaces = 0_u32;
    let mut quotes = 0_u32;
    let mut double_quotes = 0_u32;
    let mut new_lines = 0_u32;
    for ch in value.chars() {
        match ch {
            ' ' | '\t' | '#' | ';' => spaces = spaces.saturating_add(1),
            '"' => double_quotes = double_quotes.saturating_add(1),
            '\'' => quotes = quotes.saturating_add(1),
            '\n' | '\r' => new_lines = new_lines.saturating_add(1),
            _ => {}
        }
    }
    let separator = if new_lines > 0 {
        "\"\"\""
    } else if quotes > 0 && double_quotes == 0 {
        "\""
    } else if quotes == 0 && double_quotes > 0 {
        "'"
    } else if quotes > 0 && double_quotes > 0 {
        "\"\"\""
    } else if spaces > 0 {
        "\""
    } else {
        ""
    };
    format!("{separator}{value}{separator}")
}

/// C++ `AddValueToString`: `Key = value\n` or `Key = [a , b]\n`.
#[must_use]
pub fn render_entry(key: &str, value: &IniValue) -> String {
    let mut out = String::with_capacity(key.len().saturating_add(32));
    out.push_str(key);
    out.push_str(" = ");
    match value {
        IniValue::Scalar(s) => out.push_str(&quote_value(s)),
        IniValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(" , ");
                }
                out.push_str(&quote_value(item));
            }
            out.push(']');
        }
    }
    out.push('\n');
    out
}

/// C++ `AddSectionToString`: a blank line, `[name]`, then the entries
/// (optionally sorted case-insensitively by key).
#[must_use]
pub fn render_section(name: &str, entries: &[(String, IniValue)], options: EmitOptions) -> String {
    let mut out = String::from("\n");
    if !name.is_empty() {
        out.push('[');
        out.push_str(name);
        out.push_str("]\n");
    }
    if options.sorted {
        let mut ordered: Vec<&(String, IniValue)> = entries.iter().collect();
        ordered.sort_by_key(|(key, _)| key.to_ascii_lowercase());
        for (key, value) in ordered {
            out.push_str(&render_entry(key, value));
        }
    } else {
        for (key, value) in entries {
            out.push_str(&render_entry(key, value));
        }
    }
    out
}

/// `Command.<name> = <key>` (C++ `sect["Command.%s"] = command.Key`).
fn command_entry(command: &CommandDef) -> (String, IniValue) {
    (
        format!("{KEY_COMMAND_PREFIX}{}", command.name),
        IniValue::Scalar(key_to_string(command.key)),
    )
}

/// C++ `KeyUtils::ToString`: `<modifiers><key>` (e.g. `Ctrl+Alt+F1`).
#[must_use]
pub fn key_to_string(key: Key) -> String {
    key.to_string()
}

/// The entries a type plugin's `UpdateSettings` writes.
///
/// Order follows the C++ plugins. A single pattern / extension is a
/// scalar (`sect["Pattern"] = "magic:4D 5A"`), several are an array
/// (`sect["Extension"] = { "cpp", "c" }`); absent data writes no key.
#[must_use]
pub fn type_plugin_entries(metadata: &PluginMetadata) -> Vec<(String, IniValue)> {
    let mut entries = Vec::new();
    let patterns: Vec<String> = metadata.pattern.iter().map(Pattern::to_ini_string).collect();
    if let Some(value) = scalar_or_array(patterns) {
        entries.push((String::from(KEY_PATTERN), value));
    }
    entries.push((String::from(KEY_PRIORITY), IniValue::Scalar(metadata.priority.to_string())));
    entries.push((
        String::from(KEY_DESCRIPTION),
        IniValue::Scalar(metadata.description.clone()),
    ));
    if let Some(value) = scalar_or_array(metadata.extensions.clone()) {
        entries.push((String::from(KEY_EXTENSION), value));
    }
    if let Some(mask) = metadata.opcodes_mask {
        entries.push((String::from(KEY_OPCODES_MASK), IniValue::Scalar(mask.to_string())));
    }
    entries.extend(metadata.commands.iter().map(command_entry));
    entries
}

/// The entries a generic plugin's `UpdateSettings` writes.
#[must_use]
pub fn generic_plugin_entries(metadata: &GenericPluginMetadata) -> Vec<(String, IniValue)> {
    let mut entries = Vec::new();
    if !metadata.description.is_empty() {
        entries.push((
            String::from(KEY_DESCRIPTION),
            IniValue::Scalar(metadata.description.clone()),
        ));
    }
    entries.extend(metadata.commands.iter().map(command_entry));
    entries
}

fn scalar_or_array(mut items: Vec<String>) -> Option<IniValue> {
    match items.len() {
        0 => None,
        1 => items.pop().map(IniValue::Scalar),
        _ => Some(IniValue::Array(items)),
    }
}

/// Renders the `[Type.<name>]` section for a type plugin.
#[must_use]
pub fn emit_type_section(name: &str, metadata: &PluginMetadata, options: EmitOptions) -> String {
    render_section(
        &format!("{TYPE_SECTION_PREFIX}{name}"),
        &type_plugin_entries(metadata),
        options,
    )
}

/// Renders the `[Generic.<name>]` section for a generic plugin.
#[must_use]
pub fn emit_generic_section(name: &str, metadata: &GenericPluginMetadata, options: EmitOptions) -> String {
    render_section(
        &format!("{GENERIC_SECTION_PREFIX}{name}"),
        &generic_plugin_entries(metadata),
        options,
    )
}

/// C++ `ResetConfiguration` body: every type plugin section followed
/// by every generic plugin section, in the given order.
#[must_use]
pub fn emit_plugin_sections<'a>(
    types: impl IntoIterator<Item = (&'a str, &'a PluginMetadata)>,
    generics: impl IntoIterator<Item = (&'a str, &'a GenericPluginMetadata)>,
    options: EmitOptions,
) -> String {
    let mut out = String::new();
    for (name, metadata) in types {
        out.push_str(&emit_type_section(name, metadata, options));
    }
    for (name, metadata) in generics {
        out.push_str(&emit_generic_section(name, metadata, options));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_plugin::TypePlugin;
    use appcui::input::{KeyCode, KeyModifier};

    /// The PE plugin's `UpdateSettings` (`Types/PE/src/pe.cpp:334-346`).
    fn pe_metadata() -> PluginMetadata {
        PluginMetadata {
            pattern: vec![Pattern::Magic(vec![0x4D, 0x5A])],
            priority: 1,
            description: String::from("Portable executable format for Windows OS binaries"),
            extensions: Vec::new(),
            commands: vec![
                CommandDef::new(
                    "DigitalSignature",
                    Key::new(KeyCode::F8, KeyModifier::Alt),
                    "Validate digital signature",
                    0,
                ),
                CommandDef::new(
                    "AreaHighlighter",
                    Key::new(KeyCode::F9, KeyModifier::Alt),
                    "Highlight portions of code base on an input file",
                    1,
                ),
            ],
            opcodes_mask: Some(0xFFFF_FFFF),
        }
    }

    #[test]
    fn generated_ini_matches_pe_update_settings() {
        let ini = emit_type_section("PE", &pe_metadata(), EmitOptions::default());
        assert_eq!(
            ini,
            "\n[Type.PE]\n\
             Pattern = \"magic:4D 5A\"\n\
             Priority = 1\n\
             Description = \"Portable executable format for Windows OS binaries\"\n\
             OpCodes.Mask = 4294967295\n\
             Command.DigitalSignature = Alt+F8\n\
             Command.AreaHighlighter = Alt+F9\n"
        );
    }

    #[test]
    fn sorted_output_matches_appcui_case_insensitive_order() {
        let ini = emit_type_section("PE", &pe_metadata(), EmitOptions { sorted: true });
        let keys: Vec<&str> = ini
            .lines()
            .filter(|l| l.contains(" = "))
            .map(|l| l.split(" = ").next().unwrap_or(""))
            .collect();
        assert_eq!(
            keys,
            [
                "Command.AreaHighlighter",
                "Command.DigitalSignature",
                "Description",
                "OpCodes.Mask",
                "Pattern",
                "Priority"
            ]
        );
    }

    #[test]
    fn arrays_and_extensions_render_like_appcui() {
        let metadata = PluginMetadata {
            pattern: vec![
                Pattern::LineStartsWith(String::from("#!")),
                Pattern::StartsWith(b"PK".to_vec()),
            ],
            priority: 0xFFFF,
            description: String::new(),
            extensions: vec![String::from("cpp"), String::from("c"), String::from("h")],
            commands: Vec::new(),
            opcodes_mask: None,
        };
        let ini = emit_type_section("CPP", &metadata, EmitOptions::default());
        assert_eq!(
            ini,
            "\n[Type.CPP]\n\
             Pattern = [\"linestartswith:#!\" , startswith:PK]\n\
             Priority = 65535\n\
             Description = \"\"\n\
             Extension = [cpp , c , h]\n"
        );
        let single = PluginMetadata {
            extensions: vec![String::from("iso")],
            ..PluginMetadata::default()
        };
        let ini = emit_type_section("ISO", &single, EmitOptions::default());
        assert!(ini.contains("\nExtension = iso\n"));
        assert!(!ini.contains("Pattern"));
        assert!(!ini.contains("OpCodes"));
    }

    #[test]
    fn quoting_rules_follow_add_section_value_to_string() {
        assert_eq!(quote_value(""), "\"\"");
        assert_eq!(quote_value("plain"), "plain");
        assert_eq!(quote_value("has space"), "\"has space\"");
        assert_eq!(quote_value("tab\tbed"), "\"tab\tbed\"");
        assert_eq!(quote_value("a#b"), "\"a#b\"");
        assert_eq!(quote_value("a;b"), "\"a;b\"");
        assert_eq!(quote_value("it's"), "\"it's\"");
        assert_eq!(quote_value("say \"hi\""), "'say \"hi\"'");
        assert_eq!(quote_value("it's \"x\""), "\"\"\"it's \"x\"\"\"\"");
        assert_eq!(quote_value("two\nlines"), "\"\"\"two\nlines\"\"\"");
        assert_eq!(render_entry("K", &IniValue::Scalar(String::from("v"))), "K = v\n");
        assert_eq!(
            render_entry("K", &IniValue::Array(vec![String::from("a b"), String::new()])),
            "K = [\"a b\" , \"\"]\n"
        );
    }

    #[test]
    fn keys_render_with_appcui_names() {
        assert_eq!(key_to_string(Key::new(KeyCode::F8, KeyModifier::Alt)), "Alt+F8");
        assert_eq!(
            key_to_string(Key::new(KeyCode::F1, KeyModifier::Ctrl | KeyModifier::Alt)),
            "Ctrl+Alt+F1"
        );
        assert_eq!(
            key_to_string(Key::new(KeyCode::S, KeyModifier::Ctrl | KeyModifier::Shift)),
            "Ctrl+Shift+S"
        );
        assert_eq!(key_to_string(Key::new(KeyCode::Enter, KeyModifier::None)), "Enter");
    }

    #[test]
    fn generic_sections_and_full_regeneration() {
        let hashes = GenericPluginMetadata {
            description: String::from("Compute hashes"),
            commands: vec![CommandDef::new(
                "Hashes",
                Key::new(KeyCode::F5, KeyModifier::Ctrl),
                "Compute hashes",
                0,
            )],
        };
        let entropy = GenericPluginMetadata {
            description: String::new(),
            commands: vec![CommandDef::new(
                "Entropy",
                Key::new(KeyCode::F6, KeyModifier::Ctrl),
                "Entropy",
                0,
            )],
        };
        assert_eq!(
            emit_generic_section("Hashes", &hashes, EmitOptions::default()),
            "\n[Generic.Hashes]\nDescription = \"Compute hashes\"\nCommand.Hashes = Ctrl+F5\n"
        );
        let pe = pe_metadata();
        let ini = emit_plugin_sections(
            [("PE", &pe)],
            [("Hashes", &hashes), ("Entropy", &entropy)],
            EmitOptions::default(),
        );
        assert!(ini.starts_with("\n[Type.PE]\n"));
        assert!(ini.contains("\n[Generic.Hashes]\n"));
        assert!(ini.ends_with("\n[Generic.Entropy]\nCommand.Entropy = Ctrl+F6\n"));
        let pos_type = ini.find("[Type.PE]").expect("type");
        let pos_generic = ini.find("[Generic.Hashes]").expect("generic");
        assert!(pos_type < pos_generic);
    }

    #[test]
    fn metadata_from_a_registered_plugin_type_emits_directly() {
        let ini = emit_type_section(
            "PE",
            &crate::type_plugin::tests::MockPe::metadata(),
            EmitOptions::default(),
        );
        assert!(ini.contains("Extension = [exe , .dll]\n"));
        assert!(ini.contains("Command.DigitalSignature = Alt+F8\n"));
    }
}

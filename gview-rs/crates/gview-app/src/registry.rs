//! Plugin composition root (spec `00_APP §2`).
//!
//! C++ discovers plugins at runtime: `ResetConfiguration` scans
//! `Types/*.tpl` and `GenericPlugins/*.gpl`, `LoadSettings`
//! (`Instance.cpp:88-126`) turns every `[Type.*]` / `[Generic.*]`
//! section into a `Plugin` and sorts the type plugins by priority.
//!
//! The Rust port links its plugins statically (spec `00_APP §0.3 D1`):
//! every plugin crate is an ordinary dependency and [`build`] registers
//! it by name. That keeps `#![forbid(unsafe_code)]` across the whole
//! open path — these parsers are the code that touches hostile input
//! first — and makes the plugin set deterministic instead of dependent
//! on what happens to sit in a directory.
//!
//! Loading legacy `.tpl` / `.gpl` shared objects stays possible behind
//! the `legacy-ffi-plugins` feature (`gview-plugin-ffi`), which is off
//! by default and has no registry adapter yet.
//!
//! Ordering is [`TypePluginRegistry`]'s job and follows
//! `03_DUAL_PLUGIN §7.4`: higher numeric priority first, ties resolved
//! stably in registration order. Every ported plugin currently declares
//! priority 1, so the registration order below *is* the match order.

use gview_generic_entropy::EntropyVisualizerPlugin;
use gview_generic_hashes::HashesPlugin;
use gview_plugin::generic_plugin::GenericPluginRegistry;
use gview_plugin::type_plugin::TypePluginRegistry;
use gview_types_elf::populate::ElfPlugin;
use gview_types_macho::populate::MachoPlugin;
use gview_types_pcap::populate::PcapPlugin;
use gview_types_pe::populate::PePlugin;
use gview_types_zip::container::ZipPlugin;

use crate::error::AppError;

/// Registry name of the Portable Executable plugin.
pub const NAME_PE: &str = "PE";
/// Registry name of the ELF plugin.
pub const NAME_ELF: &str = "ELF";
/// Registry name of the Mach-O plugin (the plugin's own
/// `TypePlugin::name`, hyphen included).
pub const NAME_MACHO: &str = "Mach-O";
/// Registry name of the ZIP plugin.
pub const NAME_ZIP: &str = "ZIP";
/// Registry name of the packet-capture plugin.
pub const NAME_PCAP: &str = "PCAP";
/// Registry name of the hashes tool.
pub const NAME_HASHES: &str = gview_generic_hashes::PLUGIN_NAME;
/// Registry name of the entropy visualiser.
pub const NAME_ENTROPY: &str = gview_generic_entropy::PLUGIN_NAME;

/// Every type-plugin name [`build`] registers, in registration order.
pub const TYPE_PLUGIN_NAMES: [&str; 5] = [NAME_PE, NAME_ELF, NAME_MACHO, NAME_ZIP, NAME_PCAP];

/// Every generic-plugin name [`build`] registers, in registration
/// order.
pub const GENERIC_PLUGIN_NAMES: [&str; 2] = [NAME_HASHES, NAME_ENTROPY];

/// The two plugin tables an [`crate::instance::window_lifecycle::Instance`]
/// needs.
#[derive(Debug)]
pub struct Registries {
    /// Format parsers, ordered by descending priority.
    pub types: TypePluginRegistry,
    /// Object tools reachable from the command bar.
    pub generics: GenericPluginRegistry,
}

impl Registries {
    /// Metadata for every type plugin, for the settings writer.
    #[must_use]
    pub fn type_metadata(&self) -> Vec<(&'static str, gview_plugin::type_plugin::PluginMetadata)> {
        self.types
            .plugins()
            .iter()
            .map(|p| (p.name(), p.metadata().clone()))
            .collect()
    }

    /// Metadata for every generic plugin, for the settings writer.
    #[must_use]
    pub fn generic_metadata(
        &self,
    ) -> Vec<(&'static str, gview_plugin::generic_plugin::GenericPluginMetadata)> {
        self.generics
            .plugins()
            .iter()
            .map(|p| (p.name(), p.metadata().clone()))
            .collect()
    }
}

/// Builds both registries with every statically linked plugin.
///
/// Holds no global state: calling it twice in one process yields two
/// independent, equivalent sets of tables.
///
/// # Errors
///
/// [`AppError::Registry`] if a plugin declares an invalid pattern or
/// two plugins claim the same name — both are programming errors in
/// this crate, surfaced rather than hidden.
pub fn build() -> Result<Registries, AppError> {
    let mut types = TypePluginRegistry::new();
    types.register_type::<PePlugin>(NAME_PE)?;
    types.register_type::<ElfPlugin>(NAME_ELF)?;
    types.register_type::<MachoPlugin>(NAME_MACHO)?;
    types.register_type::<ZipPlugin>(NAME_ZIP)?;
    types.register_type::<PcapPlugin>(NAME_PCAP)?;

    let mut generics = GenericPluginRegistry::new();
    generics.register_type::<HashesPlugin>(NAME_HASHES)?;
    generics.register_type::<EntropyVisualizerPlugin>(NAME_ENTROPY)?;

    Ok(Registries { types, generics })
}

#[cfg(test)]
// Fixture builders index and add on fixed-size buffers, exactly as the
// plugin crates' own `minimal_*` helpers do.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use gview_plugin::generic_plugin::RegisteredGenericPlugin;
    use gview_plugin::matcher::TextParser;
    use gview_plugin::type_plugin::{RegisteredTypePlugin, TypePlugin};

    /// DOS header with `e_lfanew`, then a full `IMAGE_NT_HEADERS32`
    /// (mirrors the PE crate's own `minimal_pe`, which is test-only
    /// and therefore not importable here).
    fn minimal_pe() -> Vec<u8> {
        const E_LFANEW_OFFSET: usize = 60;
        const NT_HEADERS32_SIZE: usize = 4 + 20 + 224;
        let lfanew: u32 = 0x80;
        let mut image = vec![0_u8; lfanew as usize + NT_HEADERS32_SIZE];
        image[0..2].copy_from_slice(b"MZ");
        image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&lfanew.to_le_bytes());
        let nt = lfanew as usize;
        image[nt..nt + 4].copy_from_slice(b"PE\0\0");
        // Optional header magic: PE32.
        let opt = nt + 4 + 20;
        image[opt..opt + 2].copy_from_slice(&0x010B_u16.to_le_bytes());
        image
    }

    fn minimal_elf() -> Vec<u8> {
        let mut buf = vec![0_u8; 64];
        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf
    }

    fn minimal_macho() -> Vec<u8> {
        let mut buf = vec![0_u8; 32];
        buf[0..4].copy_from_slice(&0xFEED_FACF_u32.to_le_bytes());
        buf
    }

    fn minimal_zip() -> Vec<u8> {
        let mut buf = vec![0_u8; 32];
        buf[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        buf
    }

    fn minimal_pcap() -> Vec<u8> {
        let mut buf = vec![0_u8; 32];
        buf[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
        buf
    }

    fn goldens() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            (NAME_PE, minimal_pe()),
            (NAME_ELF, minimal_elf()),
            (NAME_MACHO, minimal_macho()),
            (NAME_ZIP, minimal_zip()),
            (NAME_PCAP, minimal_pcap()),
        ]
    }

    #[test]
    fn build_registers_exactly_the_expected_plugins() {
        let reg = build().expect("build");
        let names: Vec<&str> = reg
            .types
            .plugins()
            .iter()
            .map(RegisteredTypePlugin::name)
            .collect();
        assert_eq!(names, TYPE_PLUGIN_NAMES.to_vec());

        let generics: Vec<&str> = reg
            .generics
            .plugins()
            .iter()
            .map(RegisteredGenericPlugin::name)
            .collect();
        assert_eq!(generics, GENERIC_PLUGIN_NAMES.to_vec());
    }

    #[test]
    fn registry_names_match_the_plugins_own_names() {
        // The registry label and `TypePlugin::name()` must agree, or
        // the window tag and the `[Type.*]` section would disagree.
        assert_eq!(PePlugin::create_instance().name(), NAME_PE);
        assert_eq!(ElfPlugin::create_instance().name(), NAME_ELF);
        assert_eq!(MachoPlugin::create_instance().name(), NAME_MACHO);
        assert_eq!(ZipPlugin::create_instance().name(), NAME_ZIP);
        assert_eq!(PcapPlugin::create_instance().name(), NAME_PCAP);

        let reg = build().expect("build");
        for plugin in reg.types.plugins() {
            assert_eq!(
                plugin.create_instance().name(),
                plugin.name(),
                "registry label and plugin name disagree"
            );
        }
    }

    #[test]
    fn every_plugin_validates_its_own_golden_magic() {
        let reg = build().expect("build");
        for (name, data) in goldens() {
            let plugin = reg
                .types
                .by_name(name)
                .unwrap_or_else(|| panic!("{name} is registered"));
            assert!(
                plugin.is_of_type(&data, ""),
                "{name} must accept its own golden buffer"
            );
        }
    }

    #[test]
    fn a_golden_buffer_matches_only_its_own_plugin() {
        let reg = build().expect("build");
        for (name, data) in goldens() {
            let mut parser = TextParser::new(&[]);
            let matched: Vec<&str> = reg
                .types
                .candidates(&data, &mut parser, "")
                .into_iter()
                .map(RegisteredTypePlugin::name)
                .collect();
            assert_eq!(matched, vec![name], "for the {name} golden buffer");
        }
    }

    #[test]
    fn ordering_follows_priority_then_registration_order() {
        let reg = build().expect("build");
        let priorities: Vec<u32> = reg
            .types
            .plugins()
            .iter()
            .map(|p| p.metadata().priority)
            .collect();
        // Descending: higher priority is tried first (§7.4).
        assert!(
            priorities.windows(2).all(|w| w[0] >= w[1]),
            "not sorted by descending priority: {priorities:?}"
        );
        // All ties today, so registration order is preserved.
        assert!(priorities.iter().all(|p| *p == priorities[0]));
        let names: Vec<&str> = reg
            .types
            .plugins()
            .iter()
            .map(RegisteredTypePlugin::name)
            .collect();
        assert_eq!(names, TYPE_PLUGIN_NAMES.to_vec());
    }

    #[test]
    fn random_bytes_match_no_plugin() {
        let reg = build().expect("build");
        let data: Vec<u8> = (0..512_u32).map(|i| (i.wrapping_mul(37) & 0x7F) as u8).collect();
        let mut parser = TextParser::new(&[]);
        assert!(reg.types.candidates(&data, &mut parser, "").is_empty());
    }

    #[test]
    fn empty_and_tiny_buffers_are_rejected_without_panicking() {
        let reg = build().expect("build");
        for data in [vec![], vec![0x4D], vec![0x4D, 0x5A], vec![0x50, 0x4B, 0x03]] {
            let mut parser = TextParser::new(&[]);
            let _ = reg.types.candidates(&data, &mut parser, "");
            for plugin in reg.types.plugins() {
                let _ = plugin.is_of_type(&data, "exe");
            }
        }
    }

    #[test]
    fn building_twice_in_one_process_succeeds() {
        let first = build().expect("first build");
        let second = build().expect("second build");
        let names = |r: &Registries| -> Vec<&'static str> {
            r.types.plugins().iter().map(RegisteredTypePlugin::name).collect()
        };
        assert_eq!(names(&first), names(&second));
        assert_eq!(first.generics.plugins().len(), second.generics.plugins().len());
    }

    #[test]
    fn metadata_accessors_cover_every_plugin() {
        let reg = build().expect("build");
        let types = reg.type_metadata();
        assert_eq!(types.len(), TYPE_PLUGIN_NAMES.len());
        for (name, meta) in &types {
            assert!(
                !meta.description.is_empty(),
                "{name} needs a description for list-types"
            );
            assert!(!meta.pattern.is_empty(), "{name} needs a magic pattern");
        }
        let generics = reg.generic_metadata();
        assert_eq!(generics.len(), GENERIC_PLUGIN_NAMES.len());
        assert!(generics.iter().all(|(_, m)| !m.commands.is_empty()));
    }

    #[test]
    fn generic_plugins_are_reachable_by_name() {
        let reg = build().expect("build");
        for name in GENERIC_PLUGIN_NAMES {
            assert!(reg.generics.by_name(name).is_some(), "{name} is registered");
        }
    }
}

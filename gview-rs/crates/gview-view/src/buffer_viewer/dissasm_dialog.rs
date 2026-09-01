//! Dissasm overlay dialog (C++ `BufferViewer/DissasmDialog.cpp`;
//! spec `02_VIEWER_BUFFER` §5).
//!
//! Ctrl+D ([`super::input::NavAction::DissasmDialog`]) opens the
//! modal **Dissasm** window (`d:c,w:100%,h:60%`): a `ListView` with
//! the columns *address / Bytes / Instructions / Groups*, three radio
//! groups (architecture, design, endianess) that write straight into
//! the viewer's `SettingsData`, and OK / Cancel buttons.
//!
//! Like the Find dialog, this module is the **UI-free model** of that
//! window — settings normalisation ([`DissasmSettings::normalized`]),
//! radio handling ([`DissasmDialog::on_check`]) and the C++ `Update()`
//! that fills the list ([`DissasmDialog::update`]). The `AppCUI` window
//! wrapping is wired by the shell task.
//!
//! `Update()` flow (`DissasmDialog.cpp:181-256`):
//!
//! 1. clear the list and rename column 0 to
//!    `translationMethods[currentAddressMode].name`;
//! 2. `dissasembler.Init(design, architecture, endianess)`;
//! 3. `address = cursor`, translated through
//!    `offsetTranslateCallback->TranslateFromFileOffset(cursor, mode)`
//!    when a callback is set (the dialog calls it for mode 0 too,
//!    unlike the paint path);
//! 4. read `min(fileSize, 0x2000)` bytes **from the cursor file
//!    offset** with `fail = false` (the read is trimmed at EOF);
//! 5. `DissasembleInstructions` → one row per instruction; rows with
//!    a `Jump` / `Call` / `BranchRelative` group get column 2 painted
//!    pink and carry that group as item data.
//!
//! C++ parity note: `Validate()` only exits with
//! `Dialogs::Result::Ok` (`DissasmDialog.cpp:127-130`); the C++ dialog
//! does not itself open a Dissasm viewer. Spec §5 step 6 describes the
//! intended follow-up, so [`DialogOutcome::Ok`] carries the decoded
//! range ([`DisasmRange`]) for the shell to open in a `DissasmViewer`.

use std::fmt::Write as _;

use gview_core::cache::{CacheError, DataCache};
use gview_disasm::capstone::DissasemblerIntel;
use gview_disasm::{Architecture, Design, DisasmError, Endianess, GroupType, Instruction, BYTES_SIZE};

/// Bytes read from the cursor for the quick disassembly
/// (`DissasmDialog.cpp:206`, spec §5 step 3).
pub const MAX_DISASM_BYTES: u64 = 0x2000;

/// C++ `translationMethods[16]` slot count (spec §2.1).
pub const MAX_TRANSLATION_METHODS: usize = 16;

/// Column-0 name used when no translation list was installed
/// (`Settings::SetOffsetTranslationList`: slot 0 is `"FileOffset"`).
pub const DEFAULT_ADDRESS_COLUMN_NAME: &str = "FileOffset";

/// Separator between group names in the *Groups* column
/// (`tmp4.Add(" | ")`).
pub const GROUP_SEPARATOR: &str = " | ";

/// C++ `OffsetTranslateInterface` (`GView.hpp:1293-1296`).
pub trait OffsetTranslate {
    /// Translates a value expressed in translation method
    /// `from_translation_index` back to a file offset.
    fn translate_to_file_offset(&self, value: u64, from_translation_index: u32) -> u64;
    /// Translates a file offset into translation method
    /// `to_translation_index` (RVA / VA / …).
    fn translate_from_file_offset(&self, value: u64, to_translation_index: u32) -> u64;
}

/// The dissasm triple stored in the viewer's `SettingsData`
/// (spec §2.1 `architecture/design/endianess`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DissasmSettings {
    /// Intel / ARM.
    pub design: Design,
    /// x86 / x64.
    pub architecture: Architecture,
    /// Little / Big.
    pub endianess: Endianess,
}

impl DissasmSettings {
    /// The C++ constructor's `switch` defaults
    /// (`DissasmDialog.cpp:47-89`): every `Invalid` value is replaced
    /// by Intel / x86 / Little and written back to the settings.
    #[must_use]
    pub const fn normalized(self) -> Self {
        Self {
            design: match self.design {
                Design::Invalid => Design::Intel,
                other => other,
            },
            architecture: match self.architecture {
                Architecture::Invalid => Architecture::X86,
                other => other,
            },
            endianess: match self.endianess {
                Endianess::Invalid => Endianess::Little,
                other => other,
            },
        }
    }
}

/// Radio-box control IDs (`DissasmDialog.cpp:8-13`, values preserved).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum RadioId {
    /// `x&86` (group 1).
    ArchitectureX86 = 3,
    /// `x&64` (group 1).
    ArchitectureX64 = 4,
    /// `&Intel` (group 2).
    DesignIntel = 5,
    /// `&ARM` (group 2).
    DesignArm = 6,
    /// `&Little` (group 3).
    EndianessLittle = 7,
    /// `&Big` (group 3).
    EndianessBig = 8,
}

impl RadioId {
    /// C++ `GROUPD_ID_*`: radio group the control belongs to.
    #[must_use]
    pub const fn group(self) -> u32 {
        match self {
            Self::ArchitectureX86 | Self::ArchitectureX64 => 1,
            Self::DesignIntel | Self::DesignArm => 2,
            Self::EndianessLittle | Self::EndianessBig => 3,
        }
    }
}

/// Button control IDs (`BTN_ID_OK` / `BTN_ID_CANCEL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ButtonId {
    /// `&OK`.
    Ok = 1,
    /// `&Cancel`.
    Cancel = 2,
}

/// Events the C++ `OnEvent` handler reacts to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogEvent {
    /// `Event::ButtonClicked` with the button's ID.
    ButtonClicked(ButtonId),
    /// `Event::WindowAccept` (Enter; `WindowFlags::ProcessReturn`).
    WindowAccept,
    /// `Event::WindowClose` (Escape / close button).
    WindowClose,
}

/// Byte range the dialog disassembled: `[start, start + size)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisasmRange {
    /// Cursor file offset the read started at.
    pub start: u64,
    /// Bytes actually decoded into rows (sum of instruction sizes).
    pub size: u64,
}

/// How the dialog was closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogOutcome {
    /// `Dialogs::Result::Ok` (`Validate()`); carries the decoded range
    /// so the shell can open it in a Dissasm viewer (spec §5 step 6).
    Ok(DisasmRange),
    /// `Dialogs::Result::Cancel`.
    Cancel,
}

/// One `ListView` row (`list->AddItem({...})`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DissasmRow {
    /// Column 0: `"0x%llX"` of `address + offset`.
    pub address: String,
    /// Column 1: `"%02X "` per byte, at most [`BYTES_SIZE`] bytes.
    pub bytes: String,
    /// Column 2: `"%s %s"` of mnemonic and operand string.
    pub instruction: String,
    /// Column 3: group names joined by [`GROUP_SEPARATOR`].
    pub groups: String,
    /// `SubItemColored` + pink on column 2: the instruction carries a
    /// `Jump`, `Call` or `BranchRelative` group.
    pub branch_relative: bool,
    /// `item.SetData(...)`: the first `Jump` / `Call` /
    /// `BranchRelative` group, else [`GroupType::Invalid`].
    pub data: GroupType,
}

/// Errors surfaced by `Update()` (each is a C++ `CHECK(..., false)`).
#[derive(Debug)]
pub enum DissasmDialogError {
    /// `dissasembler.Init` or `DissasembleInstructions` failed.
    Disasm(DisasmError),
    /// The cursor read from the object failed.
    Cache(CacheError),
}

impl core::fmt::Display for DissasmDialogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disasm(e) => write!(f, "dissasm dialog: {e}"),
            Self::Cache(e) => write!(f, "dissasm dialog: {e:?}"),
        }
    }
}

impl std::error::Error for DissasmDialogError {}

impl From<DisasmError> for DissasmDialogError {
    fn from(e: DisasmError) -> Self {
        Self::Disasm(e)
    }
}

impl From<CacheError> for DissasmDialogError {
    fn from(e: CacheError) -> Self {
        Self::Cache(e)
    }
}

/// Everything `Update()` pulls from the owning `BufferViewer`
/// instance.
pub struct DialogInput<'a> {
    /// `instance->GetCursorCurrentPosition()`.
    pub cursor_offset: u64,
    /// `instance->GetCurrentAddressMode()`.
    pub address_mode: u32,
    /// `translationMethods[currentAddressMode].name`.
    pub address_column_name: &'a str,
    /// `settings->offsetTranslateCallback` (may be unset).
    pub translator: Option<&'a dyn OffsetTranslate>,
    /// `instance->GetObject()->GetData()`.
    pub cache: &'a mut DataCache,
}

/// The dialog model (C++ `DissasmDialog`).
#[derive(Debug)]
pub struct DissasmDialog {
    settings: DissasmSettings,
    dissasembler: DissasemblerIntel,
    address_column_name: String,
    rows: Vec<DissasmRow>,
    range: DisasmRange,
}

impl DissasmDialog {
    /// C++ constructor: normalises the settings (writing the defaults
    /// back — see [`Self::settings`]), checks the matching radios and
    /// runs `Update()`.
    ///
    /// The dialog is returned even when `Update()` fails
    /// (C++ `CHECKRET(Update(), "")` only logs), so the shell can
    /// still show the window with an empty list; the error is
    /// reported alongside.
    pub fn open(settings: DissasmSettings, input: &mut DialogInput<'_>) -> (Self, Result<(), DissasmDialogError>) {
        let mut dialog = Self {
            settings: settings.normalized(),
            dissasembler: DissasemblerIntel::new(),
            address_column_name: String::from(DEFAULT_ADDRESS_COLUMN_NAME),
            rows: Vec::new(),
            range: DisasmRange::default(),
        };
        let result = dialog.update(input);
        (dialog, result)
    }

    /// Current settings — the C++ dialog mutates the viewer's
    /// `SettingsData` in place; the shell writes this back.
    #[must_use]
    pub const fn settings(&self) -> DissasmSettings {
        self.settings
    }

    /// Whether radio `id` is checked (`SetChecked(true)` state).
    #[must_use]
    pub const fn is_checked(&self, id: RadioId) -> bool {
        match id {
            RadioId::ArchitectureX86 => matches!(self.settings.architecture, Architecture::X86),
            RadioId::ArchitectureX64 => matches!(self.settings.architecture, Architecture::X64),
            RadioId::DesignIntel => matches!(self.settings.design, Design::Intel),
            RadioId::DesignArm => matches!(self.settings.design, Design::Arm),
            RadioId::EndianessLittle => matches!(self.settings.endianess, Endianess::Little),
            RadioId::EndianessBig => matches!(self.settings.endianess, Endianess::Big),
        }
    }

    /// Column-0 header (`list->GetColumn(0).SetText(...)`).
    #[must_use]
    pub fn address_column_name(&self) -> &str {
        &self.address_column_name
    }

    /// The rows produced by the last `Update()`.
    #[must_use]
    pub fn rows(&self) -> &[DissasmRow] {
        &self.rows
    }

    /// Range decoded by the last `Update()`.
    #[must_use]
    pub const fn range(&self) -> DisasmRange {
        self.range
    }

    /// C++ `OnCheck(control, value)`: a checked radio writes its enum
    /// into the settings; every radio event re-runs `Update()`
    /// (even `value == false`, which leaves the settings untouched).
    ///
    /// # Errors
    ///
    /// Propagates the `Update()` failure (e.g. selecting ARM without a
    /// backend yields [`DisasmError::Unsupported`]); the settings keep
    /// the new value and the list is left empty, as in C++.
    pub fn on_check(&mut self, id: RadioId, value: bool, input: &mut DialogInput<'_>) -> Result<(), DissasmDialogError> {
        if value {
            match id {
                RadioId::ArchitectureX86 => self.settings.architecture = Architecture::X86,
                RadioId::ArchitectureX64 => self.settings.architecture = Architecture::X64,
                RadioId::DesignIntel => self.settings.design = Design::Intel,
                RadioId::DesignArm => self.settings.design = Design::Arm,
                RadioId::EndianessLittle => self.settings.endianess = Endianess::Little,
                RadioId::EndianessBig => self.settings.endianess = Endianess::Big,
            }
        }
        self.update(input)
    }

    /// C++ `OnEvent`: OK / Enter validate, Cancel / close cancel.
    /// Returns `None` for events the dialog does not handle.
    #[must_use]
    pub const fn on_event(&self, event: DialogEvent) -> Option<DialogOutcome> {
        match event {
            DialogEvent::ButtonClicked(ButtonId::Ok) | DialogEvent::WindowAccept => Some(self.validate()),
            DialogEvent::ButtonClicked(ButtonId::Cancel) | DialogEvent::WindowClose => Some(DialogOutcome::Cancel),
        }
    }

    /// C++ `Validate()` → `Exit(Dialogs::Result::Ok)`, with the decoded
    /// range attached for the shell (see module docs).
    #[must_use]
    pub const fn validate(&self) -> DialogOutcome {
        DialogOutcome::Ok(self.range)
    }

    /// C++ `Update()` (`DissasmDialog.cpp:181-256`): clears the list,
    /// re-initialises the disassembler from the current settings,
    /// reads up to [`MAX_DISASM_BYTES`] from the cursor and rebuilds
    /// the rows.
    ///
    /// # Errors
    ///
    /// The list is always cleared first; on error it stays empty and
    /// [`Self::range`] reports zero decoded bytes.
    pub fn update(&mut self, input: &mut DialogInput<'_>) -> Result<(), DissasmDialogError> {
        self.rows.clear();
        self.range = DisasmRange {
            start: input.cursor_offset,
            size: 0,
        };
        self.address_column_name.clear();
        self.address_column_name.push_str(input.address_column_name);

        self.dissasembler
            .init(self.settings.design, self.settings.architecture, self.settings.endianess)?;

        let cursor = input.cursor_offset;
        let address = input
            .translator
            .map_or(cursor, |t| t.translate_from_file_offset(cursor, input.address_mode));

        // `std::min<uint64>(GetData().GetSize(), 0x2000)` — the C++
        // caps on the *file* size, not the bytes left after the
        // cursor; the `fail = false` read trims at EOF.
        let size = input.cache.size().min(MAX_DISASM_BYTES) as u32;
        let buffer = input.cache.copy_to_vec(cursor, size, false)?;

        let instructions = self.dissasembler.disassemble_instructions(&buffer, address)?;

        let mut offset = 0_u64;
        self.rows.reserve(instructions.len());
        for instruction in &instructions {
            self.rows.push(build_row(instruction, address.wrapping_add(offset)));
            offset = offset.saturating_add(u64::from(instruction.size));
        }
        self.range.size = offset;
        Ok(())
    }
}

/// `true` for the groups that colour the row pink and become its item
/// data (`GroupType::Jump | Call | BranchRelative`).
const fn is_branch_group(group: GroupType) -> bool {
    matches!(group, GroupType::Jump | GroupType::Call | GroupType::BranchRelative)
}

/// Builds one list row for `instruction` displayed at `address`
/// (`DissasmDialog.cpp:216-252`).
fn build_row(instruction: &Instruction, address: u64) -> DissasmRow {
    let byte_count = usize::from(instruction.size).min(BYTES_SIZE);
    let mut bytes = String::with_capacity(byte_count.saturating_mul(3));
    for byte in instruction.bytes.get(..byte_count).unwrap_or(&[]) {
        // Writing into a `String` cannot fail.
        let _ = write!(bytes, "{byte:02X} ");
    }

    let mut groups = String::new();
    let mut branch_relative = false;
    let mut data = GroupType::Invalid;
    for &group in instruction.groups() {
        if is_branch_group(group) {
            branch_relative = true;
            if data == GroupType::Invalid {
                data = group;
            }
        }
        if !groups.is_empty() {
            groups.push_str(GROUP_SEPARATOR);
        }
        groups.push_str(DissasemblerIntel::instruction_group_name(group as u8));
    }

    DissasmRow {
        address: format!("0x{address:X}"),
        bytes,
        instruction: format!("{} {}", instruction.mnemonic, instruction.op_str),
        groups,
        branch_relative,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_core::source::MemorySource;

    fn cache(data: &[u8]) -> DataCache {
        DataCache::new(Box::new(MemorySource::from_slice(data)), 0)
    }

    fn input(cache: &mut DataCache, cursor: u64) -> DialogInput<'_> {
        DialogInput {
            cursor_offset: cursor,
            address_mode: 0,
            address_column_name: DEFAULT_ADDRESS_COLUMN_NAME,
            translator: None,
            cache,
        }
    }

    struct PlusBase;

    impl OffsetTranslate for PlusBase {
        fn translate_to_file_offset(&self, value: u64, from: u32) -> u64 {
            if from == 0 {
                value
            } else {
                value.saturating_sub(0x40_0000)
            }
        }
        fn translate_from_file_offset(&self, value: u64, to: u32) -> u64 {
            if to == 0 {
                value
            } else {
                value.saturating_add(0x40_0000)
            }
        }
    }

    #[test]
    fn invalid_settings_normalize_to_intel_x86_little() {
        let s = DissasmSettings::default().normalized();
        assert_eq!(s.design, Design::Intel);
        assert_eq!(s.architecture, Architecture::X86);
        assert_eq!(s.endianess, Endianess::Little);

        let keep = DissasmSettings {
            design: Design::Intel,
            architecture: Architecture::X64,
            endianess: Endianess::Big,
        };
        assert_eq!(keep.normalized(), keep);
    }

    #[test]
    fn open_disassembles_from_cursor_and_checks_default_radios() {
        let mut c = cache(&[0x90, 0x90, 0xC3]);
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        res.expect("update");

        assert!(dlg.is_checked(RadioId::DesignIntel));
        assert!(dlg.is_checked(RadioId::ArchitectureX86));
        assert!(dlg.is_checked(RadioId::EndianessLittle));
        assert!(!dlg.is_checked(RadioId::ArchitectureX64));
        assert_eq!(dlg.address_column_name(), "FileOffset");

        let rows = dlg.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].address, "0x0");
        assert_eq!(rows[0].bytes, "90 ");
        assert_eq!(rows[0].instruction, "nop ");
        assert_eq!(rows[0].groups, "");
        assert!(!rows[0].branch_relative);
        assert_eq!(rows[0].data, GroupType::Invalid);

        assert_eq!(rows[2].address, "0x2");
        assert_eq!(rows[2].bytes, "C3 ");
        assert_eq!(rows[2].instruction, "ret ");
        assert_eq!(rows[2].groups, "ret");
        assert!(!rows[2].branch_relative);

        assert_eq!(
            dlg.range(),
            DisasmRange { start: 0, size: 3 }
        );
    }

    #[test]
    fn cursor_offset_is_the_read_start_and_display_address() {
        let mut c = cache(&[0x00, 0x00, 0x90, 0xC3]);
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 2));
        res.expect("update");
        let rows = dlg.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].address, "0x2");
        assert_eq!(rows[0].instruction, "nop ");
        assert_eq!(rows[1].address, "0x3");
        assert_eq!(dlg.range(), DisasmRange { start: 2, size: 2 });
    }

    #[test]
    fn branch_rows_are_flagged_and_carry_the_group_as_data() {
        // call +0 ; jmp +0
        let mut c = cache(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x00]);
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        res.expect("update");
        let rows = dlg.rows();
        assert_eq!(rows.len(), 2);

        assert_eq!(rows[0].bytes, "E8 00 00 00 00 ");
        assert!(rows[0].branch_relative);
        assert_eq!(rows[0].data, GroupType::Call);
        assert!(rows[0].groups.contains("call"));
        assert!(rows[0].groups.contains(GROUP_SEPARATOR));

        assert!(rows[1].branch_relative);
        assert_eq!(rows[1].data, GroupType::Jump);
        assert!(rows[1].groups.contains("jump"));
    }

    #[test]
    fn translator_and_address_mode_shape_the_address_column() {
        let mut c = cache(&[0x90, 0xC3]);
        let translator = PlusBase;
        let mut dialog_input = DialogInput {
            cursor_offset: 1,
            address_mode: 1,
            address_column_name: "VA",
            translator: Some(&translator),
            cache: &mut c,
        };
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut dialog_input);
        res.expect("update");
        assert_eq!(dlg.address_column_name(), "VA");
        assert_eq!(dlg.rows().len(), 1);
        assert_eq!(dlg.rows()[0].address, "0x400001");
        // The range stays in file offsets.
        assert_eq!(dlg.range(), DisasmRange { start: 1, size: 1 });
    }

    #[test]
    fn read_is_capped_at_0x2000_bytes() {
        let data = vec![0x90_u8; 0x3000];
        let mut c = cache(&data);
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        res.expect("update");
        assert_eq!(dlg.rows().len(), MAX_DISASM_BYTES as usize);
        assert_eq!(dlg.range().size, MAX_DISASM_BYTES);
    }

    #[test]
    fn read_near_eof_is_trimmed_not_failed() {
        let data = vec![0x90_u8; 0x3000];
        let mut c = cache(&data);
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0x2FFE));
        res.expect("update");
        assert_eq!(dlg.rows().len(), 2);
        assert_eq!(dlg.range(), DisasmRange { start: 0x2FFE, size: 2 });
    }

    #[test]
    fn on_check_switches_architecture_and_rebuilds() {
        // 48 89 C8 = mov rax, rcx in 64-bit; in 32-bit 48 is dec eax.
        let mut c = cache(&[0x48, 0x89, 0xC8]);
        let (mut dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        res.expect("update");
        assert_eq!(dlg.rows().len(), 2);
        assert!(dlg.rows()[0].instruction.starts_with("dec"));

        dlg.on_check(RadioId::ArchitectureX64, true, &mut input(&mut c, 0))
            .expect("update");
        assert_eq!(dlg.settings().architecture, Architecture::X64);
        assert!(dlg.is_checked(RadioId::ArchitectureX64));
        assert!(!dlg.is_checked(RadioId::ArchitectureX86));
        assert_eq!(dlg.rows().len(), 1);
        assert!(dlg.rows()[0].instruction.starts_with("mov"));
        assert_eq!(dlg.rows()[0].bytes, "48 89 C8 ");
    }

    #[test]
    fn unchecked_radio_event_keeps_settings_but_still_updates() {
        let mut c = cache(&[0x90]);
        let (mut dlg, _) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        dlg.on_check(RadioId::ArchitectureX64, false, &mut input(&mut c, 0))
            .expect("update");
        assert_eq!(dlg.settings().architecture, Architecture::X86);
        assert_eq!(dlg.rows().len(), 1);
    }

    #[test]
    fn arm_without_backend_fails_update_but_keeps_the_setting() {
        let mut c = cache(&[0x90]);
        let (mut dlg, _) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        let err = dlg
            .on_check(RadioId::DesignArm, true, &mut input(&mut c, 0))
            .expect_err("no ARM backend");
        assert!(matches!(
            err,
            DissasmDialogError::Disasm(DisasmError::Unsupported { .. })
        ));
        assert_eq!(dlg.settings().design, Design::Arm);
        assert!(dlg.is_checked(RadioId::DesignArm));
        assert!(dlg.rows().is_empty());
        assert_eq!(dlg.range().size, 0);
    }

    #[test]
    fn big_endian_x86_is_accepted_like_capstone() {
        let mut c = cache(&[0x90]);
        let (mut dlg, _) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        dlg.on_check(RadioId::EndianessBig, true, &mut input(&mut c, 0))
            .expect("update");
        assert!(dlg.is_checked(RadioId::EndianessBig));
        assert_eq!(dlg.rows().len(), 1);
    }

    #[test]
    fn cursor_past_eof_is_a_cache_error_with_an_empty_list() {
        let mut c = cache(&[0x90]);
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 5));
        assert!(matches!(res, Err(DissasmDialogError::Cache(_))));
        assert!(dlg.rows().is_empty());
        assert_eq!(dlg.range(), DisasmRange { start: 5, size: 0 });
    }

    #[test]
    fn empty_object_yields_an_error_and_no_rows() {
        let mut c = cache(&[]);
        let (dlg, res) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        assert!(res.is_err());
        assert!(dlg.rows().is_empty());
    }

    #[test]
    fn events_map_to_ok_and_cancel() {
        let mut c = cache(&[0x90, 0xC3]);
        let (dlg, _) = DissasmDialog::open(DissasmSettings::default(), &mut input(&mut c, 0));
        let ok = DialogOutcome::Ok(DisasmRange { start: 0, size: 2 });
        assert_eq!(dlg.on_event(DialogEvent::ButtonClicked(ButtonId::Ok)), Some(ok));
        assert_eq!(dlg.on_event(DialogEvent::WindowAccept), Some(ok));
        assert_eq!(
            dlg.on_event(DialogEvent::ButtonClicked(ButtonId::Cancel)),
            Some(DialogOutcome::Cancel)
        );
        assert_eq!(dlg.on_event(DialogEvent::WindowClose), Some(DialogOutcome::Cancel));
        assert_eq!(dlg.validate(), ok);
    }

    #[test]
    fn radio_ids_keep_cpp_values_and_groups() {
        assert_eq!(RadioId::ArchitectureX86 as i32, 3);
        assert_eq!(RadioId::EndianessBig as i32, 8);
        assert_eq!(ButtonId::Ok as i32, 1);
        assert_eq!(ButtonId::Cancel as i32, 2);
        assert_eq!(RadioId::ArchitectureX64.group(), 1);
        assert_eq!(RadioId::DesignArm.group(), 2);
        assert_eq!(RadioId::EndianessLittle.group(), 3);
    }

    #[test]
    fn bytes_column_is_capped_at_bytes_size() {
        let insn = Instruction {
            size: 40,
            bytes: [0xAB; BYTES_SIZE],
            mnemonic: String::from("x"),
            ..Default::default()
        };
        let row = build_row(&insn, 0x10);
        assert_eq!(row.bytes.len(), BYTES_SIZE * 3);
        assert_eq!(row.address, "0x10");
        assert_eq!(row.instruction, "x ");
    }
}

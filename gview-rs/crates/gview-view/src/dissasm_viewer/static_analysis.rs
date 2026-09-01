//! `DissasmViewer` static-analysis engine
//! (spec `02_VIEWER_DISSASM` §5.4–§5.9).
//!
//! C++ anchors: `KNOWN_FUNCTIONS` (`Instance.cpp:18-163`), runtime
//! hash index (`Instance.cpp:1433-1441`), digit-count init
//! (`Instance.cpp:1425-1431`), `AnnounceCallInstruction`
//! (`Instance.cpp:1500-1530`), `CheckExtractInsnHexValue`
//! (`DissasmFunctionUtils.cpp:8-123`), `FormatFunctionName`
//! (`DissasmFunctionUtils.cpp:125-132`), `TryExtractPushText`
//! (`DissasmX86.cpp:310-348`), comment column layout
//! (`DissasmX86.cpp:31-42`, `856-868`).
//!
//! Hash note: the C++ index hashes names with
//! `Hashes::CRC32(CRC32Type::JAMCRC)`. That enum value is
//! `0xFFFFFFFF` and `CRC32::Final` XORs it in, so despite the name
//! the digest is the **standard CRC-32** (init `!0`, reflected
//! polynomial `0xEDB88320`, final inversion). [`jamcrc`] reproduces
//! exactly that.

use std::collections::HashMap;

use super::pre_cache::{instruction_flag, DissasmAsmPreCacheData};
use super::zone::DissasmComments;

/// C++ `DISSAM_MAXIMUM_STRING_PREVIEW` (`DissasmViewer.hpp:40`).
pub const DISSAM_MAXIMUM_STRING_PREVIEW: usize = 180;
/// C++ `MAX_LINE_DIFF` (`Instance.cpp:1504`): back-propagation scan
/// window in lines.
pub const MAX_LINE_DIFF: u32 = 10;

/// Column constants (`DissasmX86.cpp:31-42`).
pub mod columns {
    /// `0x{08x}` address field width.
    pub const ADDRESS_TOTAL_LENGTH: u32 = 16;
    /// Opcode byte groups shown.
    pub const OP_CODES_GROUPS_SHOWN: u32 = 8;
    /// `8 * 3 + 1`.
    pub const OP_CODES_TOTAL_LENGTH: u32 = OP_CODES_GROUPS_SHOWN * 3 + 1;
    /// ASCII preview chars.
    pub const TEXT_COLUMN_TEXT_LENGTH: u32 = OP_CODES_GROUPS_SHOWN;
    /// Spaces after the ASCII preview.
    pub const TEXT_COLUMN_SPACES_LENGTH: u32 = 4;
    /// `8 + 4`.
    pub const TEXT_COLUMN_TOTAL_LENGTH: u32 = TEXT_COLUMN_TEXT_LENGTH + TEXT_COLUMN_SPACES_LENGTH;
    /// Jump arrow lanes.
    pub const TEXT_COLUMN_INDICATOR_ARROW_LINES_SPACE: u32 = 3;
    /// `25 + 12`.
    pub const TEXT_AND_OP_CODES_TOTAL_LENGTH: u32 =
        OP_CODES_TOTAL_LENGTH + TEXT_COLUMN_TOTAL_LENGTH;
    /// `16 + 8 + 25 + 12 + 3 = 64`.
    pub const TEXT_TOTAL_COLUMN_LENGTH: u32 = ADDRESS_TOTAL_LENGTH
        + TEXT_COLUMN_TEXT_LENGTH
        + OP_CODES_TOTAL_LENGTH
        + TEXT_COLUMN_TOTAL_LENGTH
        + TEXT_COLUMN_INDICATOR_ARROW_LINES_SPACE;
    /// Minimum gap before `;` on wide instructions.
    pub const COMMENT_PADDING_LENGTH: u32 = 10;
    /// Gap before the mnemonic.
    pub const TEXT_PADDING_LABELS_SPACE: u32 = 3;
}

/// `GView`'s "JAMCRC" digest (`CRC32.cpp:34-79` with
/// `CRC32Type::JAMCRC = 0xFFFFFFFF`) — equal to the standard CRC-32.
#[must_use]
pub fn jamcrc(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// One function parameter (C++ `AsmFunctionDetails::NameType`,
/// `DissasmViewer.hpp:228-231`).
#[derive(Clone, Copy, Debug)]
pub struct AsmParam {
    /// Parameter name (becomes the push comment).
    pub name: &'static str,
    /// Declared C type (informational).
    pub ty: &'static str,
}

/// One known-API entry (C++ `AsmFunctionDetails`,
/// `DissasmViewer.hpp:227-235`); `params` is stored left-to-right in
/// C declaration order.
#[derive(Clone, Copy, Debug)]
pub struct AsmFunctionDetails {
    /// API name (JAMCRC key source).
    pub function_name: &'static str,
    /// Declaration-order parameters.
    pub params: &'static [AsmParam],
}

const fn p(name: &'static str, ty: &'static str) -> AsmParam {
    AsmParam { name, ty }
}

const fn f(function_name: &'static str, params: &'static [AsmParam]) -> AsmFunctionDetails {
    AsmFunctionDetails {
        function_name,
        params,
    }
}

/// The 58-entry static database (`Instance.cpp:18-163`, verbatim).
pub static KNOWN_FUNCTIONS: [AsmFunctionDetails; 58] = [
    f(
        "WriteFile",
        &[
            p("hFile", "HANDLE"),
            p("lpBuffer", "LPCVOID"),
            p("nNumberOfBytesToWrite", "DWORD"),
            p("lpNumberOfBytesWritten", "LPDWORD"),
            p("lpOverlapped", "LPOVERLAPPED"),
        ],
    ),
    f("CloseHandle", &[p("hObject", "HANDLE")]),
    f(
        "CreateFileW",
        &[
            p("lpFileName", "LPCWSTR"),
            p("dwDesiredAccess", "DWORD"),
            p("dwShareMode", "DWORD"),
            p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
            p("dwCreationDisposition", "DWORD"),
            p("dwFlagsAndAttributes", "DWORD"),
            p("hTemplateFile", "HANDLE"),
        ],
    ),
    f(
        "CreateFileA",
        &[
            p("lpFileName", "LPCSTR"),
            p("dwDesiredAccess", "DWORD"),
            p("dwShareMode", "DWORD"),
            p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
            p("dwCreationDisposition", "DWORD"),
            p("dwFlagsAndAttributes", "DWORD"),
            p("hTemplateFile", "HANDLE"),
        ],
    ),
    f(
        "MessageBoxA",
        &[
            p("hWnd", "HWND"),
            p("lpText", "LPCTSTR"),
            p("lpCaption", "LPCTSTR"),
            p("uType", "UINT"),
        ],
    ),
    f(
        "RegOpenKeyExW",
        &[
            p("hKey", "HKEY"),
            p("lpSubKey", "LPCWSTR"),
            p("ulOptions", "DWORD"),
            p("samDesired", "REGSAM"),
            p("phkResult", "PHKEY"),
        ],
    ),
    f(
        "RegOpenKeyExA",
        &[
            p("hKey", "HKEY"),
            p("lpSubKey", "LPCSTR"),
            p("ulOptions", "DWORD"),
            p("samDesired", "REGSAM"),
            p("phkResult", "PHKEY"),
        ],
    ),
    f(
        "RegSetValueExA",
        &[
            p("hKey", "HKEY"),
            p("lpValueName", "LPCSTR"),
            p("Reserved", "DWORD"),
            p("dwType", "DWORD"),
            p("lpData", "const BYTE *"),
            p("cbData", "DWORD"),
        ],
    ),
    f(
        "RegSetValueExW",
        &[
            p("hKey", "HKEY"),
            p("lpValueName", "LPCWSTR"),
            p("lpReserved", "DWORD"),
            p("dwType", "DWORD"),
            p("lpData", "const BYTE*"),
            p("cbData", "DWORD"),
        ],
    ),
    f("RegCloseKey", &[p("hKey", "HKEY")]),
    f("GetKeyboardLayout", &[p("idThread", "DWORD")]),
    f("GetKeyboardState", &[p("lpKeyState", "PBYTE")]),
    f(
        "CreateProcessA",
        &[
            p("lpApplicationName", "LPCSTR"),
            p("lpCommandLine", "LPSTR"),
            p("lpProcessAttributes", "LPSECURITY_ATTRIBUTES"),
            p("lpThreadAttributes", "LPSECURITY_ATTRIBUTES"),
            p("bInheritHandles", "BOOL"),
            p("dwCreationFlags", "DWORD"),
            p("lpEnvironment", "LPVOID"),
            p("lpCurrentDirectory", "LPCSTR"),
            p("lpStartupInfo", "LPSTARTUPINFOA"),
            p("lpProcessInformation", "LPPROCESS_INFORMATION"),
        ],
    ),
    f(
        "WaitForSingleObject",
        &[p("hHandle", "HANDLE"), p("dwMilliseconds", "DWORD")],
    ),
    f("LoadLibraryA", &[p("lpLibFileName", "LPCSTR")]),
    f(
        "GetProcAddress",
        &[p("hModule", "HMODULE"), p("lpProcName", "LPCSTR")],
    ),
    f("FreeLibrary", &[p("hLibModule", "HMODULE")]),
    f(
        "ShellExecuteA",
        &[
            p("hwnd", "HWND"),
            p("lpOperation", "LPCSTR"),
            p("lpFile", "LPCSTR"),
            p("lpParameters", "LPCSTR"),
            p("lpDirectory", "LPCSTR"),
            p("nShowCmd", "int"),
        ],
    ),
    f(
        "EnumWindows",
        &[p("lpEnumFunc", "WNDENUMPROC"), p("lParam", "LPARAM")],
    ),
    f(
        "CallNextHookEx",
        &[
            p("hhk", "HHOOK"),
            p("nCode", "int"),
            p("wParam", "WPARAM"),
            p("lParam", "LPARAM"),
        ],
    ),
    f(
        "SetWindowsHookExA",
        &[
            p("idHook", "int"),
            p("lpfn", "HOOKPROC"),
            p("hmod", "HINSTANCE"),
            p("dwThreadId", "DWORD"),
        ],
    ),
    f(
        "SetWindowsHookExW",
        &[
            p("idHook", "int"),
            p("lpfn", "HOOKPROC"),
            p("hmod", "HINSTANCE"),
            p("dwThreadId", "DWORD"),
        ],
    ),
    f(
        "GetMessageA",
        &[
            p("lpMsg", "LPMSG"),
            p("hWnd", "HWND"),
            p("wMsgFilterMin", "UINT"),
            p("wMsgFilterMax", "UINT"),
        ],
    ),
    f(
        "GetMessageW",
        &[
            p("lpMsg", "LPMSG"),
            p("hWnd", "HWND"),
            p("wMsgFilterMin", "UINT"),
            p("wMsgFilterMax", "UINT"),
        ],
    ),
    f("TranslateMessage", &[p("lpMsg", "const MSG *")]),
    f("DispatchMessageA", &[p("lpMsg", "const MSG *")]),
    f("DispatchMessageW", &[p("lpMsg", "const MSG *")]),
    f("UnhookWindowsHookEx", &[p("hhk", "HHOOK")]),
    f("GetModuleHandleA", &[p("lpModuleName", "LPCSTR")]),
    f("GetModuleHandleW", &[p("lpModuleName", "LPCWSTR")]),
    f(
        "GetComputerNameA",
        &[p("lpBuffer", "LPSTR"), p("nSize", "LPDWORD")],
    ),
    f(
        "GetUserNameA",
        &[p("lpBuffer", "LPSTR"), p("pcbBuffer", "LPDWORD")],
    ),
    f("GetDriveTypeA", &[p("lpRootPathName", "LPCSTR")]),
    f(
        "CopyFileA",
        &[
            p("lpExistingFileName", "LPCSTR"),
            p("lpNewFileName", "LPCSTR"),
            p("bFailIfExists", "BOOL"),
        ],
    ),
    f(
        "URLDownloadToFileA",
        &[
            p("pCaller", "LPUNKNOWN"),
            p("szURL", "LPCSTR"),
            p("szFileName", "LPCSTR"),
            p("dwReserved", "DWORD"),
            p("lpfnCB", "LPBINDSTATUSCALLBACK"),
        ],
    ),
    f("GetDC", &[p("hWnd", "HWND")]),
    f("CreateCompatibleDC", &[p("hDC", "HDC")]),
    f("GetSystemMetrics", &[p("nIndex", "int")]),
    f(
        "CreateCompatibleBitmap",
        &[p("hdc", "HDC"), p("cx", "int"), p("cy", "int")],
    ),
    f(
        "SelectObject",
        &[p("hDC", "HDC"), p("hGdiObj", "HGDIOBJ")],
    ),
    f(
        "BitBlt",
        &[
            p("hdcDest", "HDC"),
            p("xDest", "int"),
            p("yDest", "int"),
            p("cx", "int"),
            p("cy", "int"),
            p("hdcSrc", "HDC"),
            p("xSrc", "int"),
            p("ySrc", "int"),
            p("rop", "DWORD"),
        ],
    ),
    f("DeleteObject", &[p("hObject", "HGDIOBJ")]),
    f("DeleteDC", &[p("hdc", "HDC")]),
    f("ReleaseDC", &[p("hWnd", "HWND"), p("hDC", "HDC")]),
    f(
        "GetKeyboardLayoutList",
        &[p("nBuff", "int"), p("lpList", "HKL *")],
    ),
    f(
        "OpenProcess",
        &[
            p("dwDesiredAccess", "DWORD"),
            p("bInheritHandle", "BOOL"),
            p("dwProcessId", "DWORD"),
        ],
    ),
    f("GetSystemInfo", &[p("lpSystemInfo", "LPSYSTEM_INFO")]),
    f(
        "VirtualQueryEx",
        &[
            p("hProcess", "HANDLE"),
            p("lpAddress", "LPCVOID"),
            p("lpBuffer", "PMEMORY_BASIC_INFORMATION"),
            p("dwLength", "SIZE_T"),
        ],
    ),
    f(
        "ReadProcessMemory",
        &[
            p("hProcess", "HANDLE"),
            p("lpBaseAddress", "LPCVOID"),
            p("lpBuffer", "LPVOID"),
            p("nSize", "SIZE_T"),
            p("lpNumberOfBytesRead", "SIZE_T*"),
        ],
    ),
    f(
        "GetWindowTextA",
        &[
            p("hWnd", "HWND"),
            p("lpString", "LPSTR"),
            p("nMaxCount", "int"),
        ],
    ),
    f(
        "SetWindowsHookEx",
        &[
            p("idHook", "int"),
            p("lpfn", "HOOKPROC"),
            p("hmod", "HINSTANCE"),
            p("dwThreadId", "DWORD"),
        ],
    ),
    f(
        "GetMessage",
        &[
            p("lpMsg", "LPMSG"),
            p("hWnd", "HWND"),
            p("wMsgFilterMin", "UINT"),
            p("wMsgFilterMax", "UINT"),
        ],
    ),
    f("DispatchMessage", &[p("lpMsg", "const MSG*")]),
    f(
        "SetFileAttributesA",
        &[p("lpFileName", "LPCSTR"), p("dwFileAttributes", "DWORD")],
    ),
    f(
        "RegQueryValueExA",
        &[
            p("hKey", "HKEY"),
            p("lpValueName", "LPCSTR"),
            p("lpReserved", "LPDWORD"),
            p("lpType", "LPDWORD"),
            p("lpData", "LPBYTE"),
            p("lpcbData", "LPDWORD"),
        ],
    ),
    f("GetModuleHandle", &[p("lpModuleName", "LPCSTR")]),
    f("DeleteFileA", &[p("lpFileName", "LPCSTR")]),
    f("lstrlenA", &[p("lpString", "LPCSTR")]),
];

/// The runtime hash index (C++ `Instance.cpp:1433-1441`):
/// `jamcrc(functionName) → entry`.
#[must_use]
pub fn build_function_map() -> HashMap<u32, &'static AsmFunctionDetails> {
    KNOWN_FUNCTIONS
        .iter()
        .map(|entry| (jamcrc(entry.function_name.as_bytes()), entry))
        .collect()
}

/// C++ `maxLocationMemoryMappingSize` init
/// (`Instance.cpp:1425-1431`): the numeric setting becomes its digit
/// count.
#[must_use]
pub const fn max_location_digit_count(mut value: u64) -> u64 {
    let mut digits: u64 = 0;
    while value > 0 {
        digits = digits.saturating_add(1);
        value = value.wrapping_div(10);
    }
    digits
}

/// C++ `DissasmAsmPreCacheData::AnnounceCallInstruction`
/// (`Instance.cpp:1500-1530`), spec §5.6.
///
/// Walks the cached lines backwards from the `call` (the last cached
/// line), annotating each `push` with the next declaration-order
/// parameter name — stdcall pushes right-to-left, so the push closest
/// to the call is `params[0]`. The walk stops past
/// [`MAX_LINE_DIFF`] lines or when all parameters are consumed;
/// non-push lines are skipped, **not** terminating. A line whose
/// existing comment already starts with the parameter name is left
/// untouched (counters still advance); any other existing comment is
/// merged as `"param existing"`.
pub fn announce_call_instruction(
    cache: &DissasmAsmPreCacheData,
    function_details: &AsmFunctionDetails,
    comments: &mut DissasmComments,
) {
    let Some(last) = cache.cached_asm_lines.last() else {
        return;
    };
    let starting_line = last.current_line;
    let mut push_index: usize = 0;
    let mut pushes_remaining = function_details.params.len();

    for line in cache.cached_asm_lines.iter().rev() {
        if pushes_remaining == 0 {
            break;
        }
        if starting_line.saturating_sub(line.current_line) > MAX_LINE_DIFF {
            break;
        }
        if line.flags != instruction_flag::PUSH {
            continue;
        }
        let Some(param) = function_details.params.get(push_index) else {
            break;
        };
        let mut comment_result = param.name.to_owned();
        if let Some(found) = comments.get_comment(line.current_line) {
            if found.starts_with(param.name) {
                pushes_remaining = pushes_remaining.saturating_sub(1);
                push_index = push_index.saturating_add(1);
                continue;
            }
            comment_result.push(' ');
            comment_result.push_str(found);
        }
        comments.add_or_update_comment(line.current_line, comment_result);
        pushes_remaining = pushes_remaining.saturating_sub(1);
        push_index = push_index.saturating_add(1);
    }
}

/// The `checkValidSequence` lambda
/// (`DissasmFunctionUtils.cpp:15-32`): skips spaces, one `[` and
/// letters; stops at a digit; any other character invalidates.
fn check_valid_sequence(bytes: &[u8], i: &mut usize, inside_brackets: &mut bool) -> bool {
    while let Some(&b) = bytes.get(*i) {
        if b == b' ' || b == b'[' || b.is_ascii_alphabetic() {
            if b == b'[' {
                if *inside_brackets {
                    return false;
                }
                *inside_brackets = true;
            }
            *i = i.saturating_add(1);
            continue;
        }
        if b.is_ascii_digit() {
            break;
        }
        return false;
    }
    true
}

/// C++ `CheckExtractInsnHexValue` (`DissasmFunctionUtils.cpp:8-123`),
/// spec §5.7.
///
/// Extracts the first numeric immediate from a capstone `op_str`
/// (`0x` hex — lowercase digits only — or decimal), supporting a
/// single bracketed form like `dword ptr [0x401000]`. `max_size` is
/// the digit-count threshold: a number cut short below
/// `max_size - 2` digits is rejected (the C++ subtraction is
/// unsigned, so `max_size < 2` makes that threshold huge — quirk
/// preserved via wrapping), and a longer number keeps only its last
/// `max_size` digits. Returns `None` on any malformed tail.
#[must_use]
pub fn check_extract_insn_hex_value(op_str: &str, max_size: u64) -> Option<u64> {
    let bytes = op_str.as_bytes();
    let mut i: usize = 0;
    let mut inside_brackets = false;

    if !check_valid_sequence(bytes, &mut i, &mut inside_brackets) {
        return None;
    }

    let mut start: Option<usize> = None;
    let mut size: u32 = 0;
    let mut is_hex = false;
    while let Some(&b) = bytes.get(i) {
        if let Some(_started) = start {
            if matches!(b, b'0'..=b'9' | b'a'..=b'f') {
                size = size.saturating_add(1);
            } else {
                if u64::from(size) < max_size.wrapping_sub(2) {
                    return None;
                }
                break;
            }
            i = i.saturating_add(1);
        } else if b == b'0' {
            i = i.saturating_add(1);
            if bytes.get(i) == Some(&b'x') {
                i = i.saturating_add(1);
                start = Some(i);
                is_hex = true;
            } else {
                start = Some(i.saturating_sub(1));
                size = 1;
            }
        } else {
            is_hex = false;
            start = Some(i);
        }
    }

    if inside_brackets {
        if bytes.get(i) != Some(&b']') {
            return None;
        }
        i = i.saturating_add(1);
    }

    let mut start_idx = start?;
    if max_size < u64::from(size) {
        let diff = size.saturating_sub(max_size as u32);
        size = size.saturating_sub(diff);
        start_idx = start_idx.saturating_add(diff as usize);
    }
    if size == 0 {
        return None;
    }
    if size < 2 {
        // Single-digit values: the WHOLE operand string (or the part
        // after "0x") must be hex digits (C++ L102-109).
        let check_from = if is_hex { 2_usize } else { 0 };
        for &b in bytes.get(check_from..)? {
            if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
                return None;
            }
        }
    }
    if !check_valid_sequence(bytes, &mut i, &mut inside_brackets) {
        return None;
    }

    let digits = bytes.get(start_idx..start_idx.saturating_add(size as usize))?;
    let text = std::str::from_utf8(digits).ok()?;
    if is_hex {
        u64::from_str_radix(text, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

/// C++ `FormatFunctionName` (`DissasmFunctionUtils.cpp:125-132`):
/// `prefix` + the lowercase hex address zero-padded to 9 chars, e.g.
/// `sub_0x000000005`.
#[must_use]
pub fn format_function_name(function_address: u64, prefix: &str) -> String {
    format!("{prefix}{:0>9}", format!("{function_address:x}"))
}

/// C++ `TryExtractPushText` (`DissasmX86.cpp:310-348`), spec §5.7:
/// **ASCII-only** string preview over bytes read at the push target.
///
/// Printable chars (`32..=126`) accumulate; a single NUL between
/// printable chars is allowed, a second consecutive NUL (or any other
/// byte) ends the scan. At
/// [`DISSAM_MAXIMUM_STRING_PREVIEW`] chars the text is truncated with
/// `...`. The result mirrors the C++ buffer exactly: opening/closing
/// quotes plus a trailing NUL — the caller stores it only when longer
/// than 3 bytes (empty previews fail that guard). No UTF-16/WCHAR
/// decoding happens regardless of the parameter type.
#[must_use]
pub fn try_extract_push_text(data: &[u8]) -> Vec<u8> {
    let mut text_found = Vec::with_capacity(DISSAM_MAXIMUM_STRING_PREVIEW * 2);
    text_found.push(b'"');
    let mut was_zero = true;
    for &b in data {
        if (32..=126).contains(&b) {
            text_found.push(b);
            was_zero = false;
        } else if b == 0 {
            if was_zero {
                break;
            }
            was_zero = true;
        } else {
            break;
        }
    }
    if text_found.len() >= DISSAM_MAXIMUM_STRING_PREVIEW {
        text_found.truncate(DISSAM_MAXIMUM_STRING_PREVIEW);
        text_found.extend_from_slice(b"...");
    }
    text_found.push(b'"');
    text_found.push(0);
    text_found
}

/// The comment column layout (`DissasmX86.cpp:856-868`, spec §5.9).
///
/// Number of spaces before the `;` for a rendered instruction of
/// `chars_len` cells, aligning to the widest cached line. Wide
/// instructions fall back to the minimum
/// [`columns::COMMENT_PADDING_LENGTH`] gap.
#[must_use]
pub const fn comment_column_padding(
    max_line_size: u32,
    chars_len: u32,
    show_only_dissasm: bool,
) -> u32 {
    let mut diff_line = max_line_size
        .saturating_add(columns::TEXT_TOTAL_COLUMN_LENGTH)
        .saturating_add(columns::COMMENT_PADDING_LENGTH);
    if show_only_dissasm {
        diff_line = diff_line.saturating_sub(columns::TEXT_AND_OP_CODES_TOTAL_LENGTH);
    }
    if chars_len > diff_line {
        columns::COMMENT_PADDING_LENGTH
    } else {
        diff_line.saturating_sub(chars_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissasm_viewer::pre_cache::DissasmAsmPreCacheLine;

    fn cache_line(current_line: u32, flags: u8) -> DissasmAsmPreCacheLine {
        DissasmAsmPreCacheLine {
            current_line,
            flags,
            ..DissasmAsmPreCacheLine::default()
        }
    }

    #[test]
    fn jamcrc_is_standard_crc32() {
        // CRC32Type::JAMCRC == 0xFFFFFFFF, so Final applies the
        // standard inversion: CRC-32/ISO-HDLC check value.
        assert_eq!(jamcrc(b"123456789"), 0xCBF4_3926);
        assert_eq!(jamcrc(b""), 0);
    }

    #[test]
    fn all_58_known_functions_resolve_by_jamcrc() {
        assert_eq!(KNOWN_FUNCTIONS.len(), 58);
        let map = build_function_map();
        // No hash collisions across the table.
        assert_eq!(map.len(), 58);
        for entry in &KNOWN_FUNCTIONS {
            let hash = jamcrc(entry.function_name.as_bytes());
            let found = map.get(&hash).expect("entry indexed");
            assert_eq!(found.function_name, entry.function_name);
            assert_eq!(found.params.len(), entry.params.len());
        }
        // Spot-check parameter schemas.
        let write_file = map[&jamcrc(b"WriteFile")];
        assert_eq!(write_file.params.len(), 5);
        assert_eq!(write_file.params[0].name, "hFile");
        assert_eq!(write_file.params[4].name, "lpOverlapped");
        assert_eq!(map[&jamcrc(b"CloseHandle")].params.len(), 1);
        assert_eq!(map[&jamcrc(b"CreateProcessA")].params.len(), 10);
        assert_eq!(map[&jamcrc(b"BitBlt")].params.len(), 9);
        assert_eq!(map[&jamcrc(b"lstrlenA")].params[0].ty, "LPCSTR");
    }

    #[test]
    fn announce_call_back_propagates_stdcall_params() {
        let map = build_function_map();
        let write_file = map[&jamcrc(b"WriteFile")];
        let mut cache = DissasmAsmPreCacheData::default();
        // push x5, then the call (stdcall right-to-left pushes).
        for line in 10..15 {
            cache.cached_asm_lines.push(cache_line(line, instruction_flag::PUSH));
        }
        cache.cached_asm_lines.push(cache_line(15, instruction_flag::CALL));
        let mut comments = DissasmComments::default();
        announce_call_instruction(&cache, write_file, &mut comments);
        // Closest push (line 14) → params[0] = hFile.
        assert_eq!(comments.get_comment(14), Some("hFile"));
        assert_eq!(comments.get_comment(13), Some("lpBuffer"));
        assert_eq!(comments.get_comment(12), Some("nNumberOfBytesToWrite"));
        assert_eq!(comments.get_comment(11), Some("lpNumberOfBytesWritten"));
        assert_eq!(comments.get_comment(10), Some("lpOverlapped"));
    }

    #[test]
    fn announce_call_respects_max_line_diff_window() {
        let map = build_function_map();
        let close_handle = map[&jamcrc(b"CloseHandle")];
        let mut cache = DissasmAsmPreCacheData::default();
        // The only push sits 11 lines above the call: outside the
        // MAX_LINE_DIFF = 10 window → no annotation.
        cache.cached_asm_lines.push(cache_line(4, instruction_flag::PUSH));
        cache.cached_asm_lines.push(cache_line(15, instruction_flag::CALL));
        let mut comments = DissasmComments::default();
        announce_call_instruction(&cache, close_handle, &mut comments);
        assert!(comments.is_empty());
        // Exactly at the window edge (diff == 10) it still annotates.
        let mut cache = DissasmAsmPreCacheData::default();
        cache.cached_asm_lines.push(cache_line(5, instruction_flag::PUSH));
        cache.cached_asm_lines.push(cache_line(15, instruction_flag::CALL));
        announce_call_instruction(&cache, close_handle, &mut comments);
        assert_eq!(comments.get_comment(5), Some("hObject"));
    }

    #[test]
    fn announce_call_skips_non_push_and_merges_existing() {
        let map = build_function_map();
        let get_proc = map[&jamcrc(b"GetProcAddress")]; // 2 params
        let mut cache = DissasmAsmPreCacheData::default();
        cache.cached_asm_lines.push(cache_line(10, instruction_flag::PUSH));
        cache.cached_asm_lines.push(cache_line(11, instruction_flag::NONE)); // mov: skipped
        cache.cached_asm_lines.push(cache_line(12, instruction_flag::PUSH));
        cache.cached_asm_lines.push(cache_line(13, instruction_flag::CALL));
        let mut comments = DissasmComments::default();
        // String preview already on the closest push: merged.
        comments.add_or_update_comment(12, "\"kernel32\"".to_owned());
        // Already-annotated param on the farther push: untouched.
        comments.add_or_update_comment(10, "lpProcName old".to_owned());
        announce_call_instruction(&cache, get_proc, &mut comments);
        assert_eq!(comments.get_comment(12), Some("hModule \"kernel32\""));
        assert_eq!(comments.get_comment(10), Some("lpProcName old"));
    }

    #[test]
    fn extract_hex_value_vectors() {
        // Plain hex immediate; max_size == digit count → no trim.
        assert_eq!(check_extract_insn_hex_value("0x401000", 6), Some(0x0040_1000));
        // Bracketed immediate (push dword ptr [0x401000]).
        assert_eq!(
            check_extract_insn_hex_value("dword ptr [0x401000]", 6),
            Some(0x0040_1000)
        );
        // Decimal, 7 digits.
        assert_eq!(check_extract_insn_hex_value("4198400", 7), Some(4_198_400));
        // Bare zero (max_size 0 would trim the single digit to
        // nothing and fail, as in C++; digit-count is always >= 1).
        assert_eq!(check_extract_insn_hex_value("0", 1), Some(0));
        assert_eq!(check_extract_insn_hex_value("0", 0), None);
        // Register operand: no digits at all.
        assert_eq!(check_extract_insn_hex_value("eax", 6), None);
        // ',' invalidates the sequence (two-operand strings fail).
        assert_eq!(check_extract_insn_hex_value("eax, 0x5", 6), None);
        // Unclosed bracket.
        assert_eq!(check_extract_insn_hex_value("dword ptr [0x401000", 6), None);
        // max_size < digit count trims from the LEFT (C++ parity):
        // "0x401000" (6 digits) with max_size 5 keeps "01000".
        assert_eq!(check_extract_insn_hex_value("0x401000", 5), Some(0x0000_1000));
        // Oversized number keeps its last max_size digits.
        assert_eq!(check_extract_insn_hex_value("0x1234567", 4), Some(0x4567));
        // Cut short below max_size - 2 digits → rejected.
        assert_eq!(check_extract_insn_hex_value("0x12]", 8), None);
    }

    #[test]
    fn format_function_name_pads_to_nine_hex_chars() {
        assert_eq!(format_function_name(0x5, "sub_0x"), "sub_0x000000005");
        assert_eq!(
            format_function_name(0x0040_1a2b, "offset_0x"),
            "offset_0x000401a2b"
        );
        assert_eq!(
            format_function_name(0x0012_3456_789a, "sub_0x"),
            "sub_0x123456789a" // wider than 9: no truncation
        );
    }

    #[test]
    fn push_text_preview_is_ascii_only() {
        // Double-NUL terminated ASCII (a single NUL would be treated
        // as an inter-string separator and the scan would continue).
        let text = try_extract_push_text(b"filename.txt\0\0rest");
        assert_eq!(&text, b"\"filename.txt\"\0");
        // A single NUL between printable chars is allowed; the second
        // consecutive NUL ends the scan.
        let text = try_extract_push_text(b"ab\0cd\0\0ef");
        assert_eq!(&text, b"\"abcd\"\0");
        // Non-printable byte stops immediately.
        let text = try_extract_push_text(b"ok\x01more");
        assert_eq!(&text, b"\"ok\"\0");
        // Empty data → just quotes + NUL: fails the caller's > 3 guard.
        let text = try_extract_push_text(b"\0\0");
        assert_eq!(text.len(), 3);
    }

    #[test]
    fn push_text_truncates_at_preview_maximum() {
        let data = vec![b'A'; DISSAM_MAXIMUM_STRING_PREVIEW * 2];
        let text = try_extract_push_text(&data);
        // '"' + 179 chars → truncated to 180 total, then "..." + '"' + NUL.
        assert_eq!(text.len(), DISSAM_MAXIMUM_STRING_PREVIEW + 5);
        assert!(text.ends_with(b"...\"\0"));
    }

    #[test]
    fn comment_column_layout_matches_cpp_formula() {
        // diffLine = maxLineSize + 64 + 10 - charsLen.
        assert_eq!(comment_column_padding(20, 30, false), 64);
        // ShowOnlyDissasm subtracts textAndOpCodesTotalLength (37).
        assert_eq!(comment_column_padding(20, 30, true), 27);
        // Wide instruction: fall back to the 10-space minimum gap.
        assert_eq!(comment_column_padding(20, 200, false), 10);
        // Exact fit keeps zero remainder plus the formula result.
        assert_eq!(comment_column_padding(0, 74, false), 0);
    }

    #[test]
    fn digit_count_conversion() {
        assert_eq!(max_location_digit_count(0), 0);
        assert_eq!(max_location_digit_count(9), 1);
        assert_eq!(max_location_digit_count(10_000), 5);
        assert_eq!(max_location_digit_count(123_456_789), 9);
    }
}

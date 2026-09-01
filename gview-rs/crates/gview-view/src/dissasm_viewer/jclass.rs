//! `DissasmViewer` Java bytecode zone path (spec `02_VIEWER_DISSASM`
//! §12A).
//!
//! C++ anchors: `Instance::DrawDissasmJavaByteCodeZone`
//! (`jclass/DissasmJClass.cpp:16-82`), `ClassParser`
//! (`jclass/class_parser.cpp:82-236`), `Demangler` / `AstCreator`
//! (`jclass/class_parser.cpp:238-540`), `BufferReader`
//! (`jclass/buffer_reader.cpp`), `ConstantKindNames`
//! (`jclass/class_parser.hpp:24-44`), opcode table (`jclass/gen.py`,
//! `jclass/raw_opcodes.hpp`), `AdjustZoneExtendedSize`
//! (`Instance.cpp:1255-1278`).
//!
//! A `JavaByteCode` zone is **not** disassembled with capstone: on
//! first draw the whole object is parsed as a `.class` file and the
//! zone's pre-cache is filled with plain text lines (one per constant
//! pool entry, by kind name), which the shared asm paint loop then
//! draws. The C++ line set is exactly:
//!
//! - parse failure (`ClassParser::parse`) → the draw fails, no lines;
//! - AST creation failure (bad descriptors, unknown opcodes, ...) →
//!   one line `Failed to parse class file, ...`;
//! - otherwise `Constant data:` followed by `    <KindName>` for
//!   **every** `constant_data` entry — including the `Nothing` slot 0
//!   the parser seeds and the duplicated slot after a `Double` — or
//!   `No constant data!` when the pool is empty (unreachable with the
//!   seeded slot; preserved).
//!
//! Parity quirks preserved: only the constant tags the C++ switch
//! handles parse (`Long` and `Float` hit `unimplemented` and fail the
//! whole parse); `tableswitch`, `lookupswitch` and `wide` are
//! unimplemented opcodes; method descriptors take at most 16
//! arguments; relative branch operands are folded with 16/32-bit
//! wrapping arithmetic.

use super::pre_cache::{DissasmAsmPreCacheData, DissasmAsmPreCacheLine};
use super::zone::{total_lines, ZoneEntry};

/// C++ zone title (`DissasmJClass.cpp:61`).
pub const JCLASS_ZONE_TITLE: &str = "[JClass] JavaBytecode";
/// C++ header line (`DissasmJClass.cpp:32`).
pub const CONSTANT_DATA_HEADER: &str = "Constant data:";
/// C++ empty-pool line (`DissasmJClass.cpp:34`).
pub const NO_CONSTANT_DATA: &str = "No constant data!";
/// C++ AST failure line (`DissasmJClass.cpp:43`).
pub const PARSE_FAILURE_MESSAGE: &str =
    "Failed to parse class file, there are still some features in progress!";
/// C++ `MAX_NUMBER_OF_ARGS` (`class_parser.cpp:347`).
pub const MAX_NUMBER_OF_ARGS: usize = 16;

/// C++ `ConstantKindNames` (`class_parser.hpp:24-44`), indexed by
/// tag — including the duplicated `"InvalidKind14"` typo at tag 17.
pub const CONSTANT_KIND_NAMES: [&str; 19] = [
    "Nothing",
    "Utf8",
    "InvalidKind2",
    "Integer",
    "Float",
    "Long",
    "Double",
    "Class",
    "String",
    "FieldRef",
    "MethodRef",
    "InterfaceMethodRef",
    "NameAndType",
    "InvalidKind13",
    "InvalidKind14",
    "MethodHandle",
    "MethodType",
    "InvalidKind14",
    "InvokeDynamic",
];

/// C++ `ConstantKind` (`class_parser.hpp:7-22`) — the JVM tag value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ConstantKind {
    /// Seeded slot 0 / long-double second slot.
    Nothing = 0,
    /// `CONSTANT_Utf8`.
    Utf8 = 1,
    /// `CONSTANT_Integer`.
    Integer = 3,
    /// `CONSTANT_Float` (tag accepted, parse **unimplemented**).
    Float = 4,
    /// `CONSTANT_Long` (tag accepted, parse **unimplemented**).
    Long = 5,
    /// `CONSTANT_Double`.
    Double = 6,
    /// `CONSTANT_Class`.
    Class = 7,
    /// `CONSTANT_String`.
    String = 8,
    /// `CONSTANT_Fieldref`.
    FieldRef = 9,
    /// `CONSTANT_Methodref`.
    MethodRef = 10,
    /// `CONSTANT_InterfaceMethodref`.
    InterfaceMethodRef = 11,
    /// `CONSTANT_NameAndType`.
    NameAndType = 12,
    /// `CONSTANT_MethodHandle`.
    MethodHandle = 15,
    /// `CONSTANT_MethodType`.
    MethodType = 16,
    /// `CONSTANT_InvokeDynamic`.
    InvokeDynamic = 18,
}

impl ConstantKind {
    /// C++ `is_valid_constant_pool_tag` + the enum cast: tags
    /// `1..=18` except 2, 13, 14, 17.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Utf8),
            3 => Some(Self::Integer),
            4 => Some(Self::Float),
            5 => Some(Self::Long),
            6 => Some(Self::Double),
            7 => Some(Self::Class),
            8 => Some(Self::String),
            9 => Some(Self::FieldRef),
            10 => Some(Self::MethodRef),
            11 => Some(Self::InterfaceMethodRef),
            12 => Some(Self::NameAndType),
            15 => Some(Self::MethodHandle),
            16 => Some(Self::MethodType),
            18 => Some(Self::InvokeDynamic),
            _ => None,
        }
    }

    /// The display name (`ConstantKindNames[tag]`).
    #[must_use]
    pub fn name(self) -> &'static str {
        CONSTANT_KIND_NAMES
            .get(self as usize)
            .copied()
            .unwrap_or("Nothing")
    }
}

/// Big-endian bounds-checked reader (C++ `BufferReader`,
/// `buffer_reader.cpp`).
#[derive(Clone, Copy, Debug)]
pub struct BufferReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BufferReader<'a> {
    /// Reader over `data` starting at offset 0.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// C++ `available`.
    #[must_use]
    pub const fn available(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// C++ `offset`.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.pos
    }

    /// C++ `has_more`.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.available() > 0
    }

    /// C++ `skip`: `false` when fewer than `size` bytes remain.
    pub const fn skip(&mut self, size: usize) -> bool {
        if size > self.available() {
            return false;
        }
        self.pos = self.pos.saturating_add(size);
        true
    }

    /// C++ `read` — a bounds-checked slice.
    pub fn read_bytes(&mut self, size: usize) -> Option<&'a [u8]> {
        if size > self.available() {
            return None;
        }
        let end = self.pos.checked_add(size)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// C++ `read_big<uint8>`.
    pub fn read_u8(&mut self) -> Option<u8> {
        self.read_bytes(1)?.first().copied()
    }

    /// C++ `read_big<uint16>`.
    pub fn read_u16_be(&mut self) -> Option<u16> {
        let b = self.read_bytes(2)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    /// C++ `read_big<uint32>`.
    pub fn read_u32_be(&mut self) -> Option<u32> {
        let b = self.read_bytes(4)?;
        Some(u32::from_be_bytes([
            *b.first()?,
            *b.get(1)?,
            *b.get(2)?,
            *b.get(3)?,
        ]))
    }

    /// C++ `read_big<uint64>`.
    pub fn read_u64_be(&mut self) -> Option<u64> {
        let hi = self.read_u32_be()?;
        let lo = self.read_u32_be()?;
        Some((u64::from(hi) << 32) | u64::from(lo))
    }
}

/// One constant pool entry (C++ `ConstantData` union collapsed to the
/// fields the viewer reads).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstantPayload {
    /// Seeded / second slot.
    Nothing,
    /// `(length, byte range)` — the text is read back from the class
    /// bytes.
    Utf8 {
        /// Byte offset of the text.
        start: usize,
        /// Text length.
        length: u16,
    },
    /// `CONSTANT_Integer`.
    Integer(u32),
    /// `CONSTANT_Double` raw bits (C++ reinterprets the `u64`).
    Double(u64),
    /// `CONSTANT_Class { name_index }`.
    Class(u16),
    /// `CONSTANT_String { string_index }`.
    String(u16),
    /// Field/Method/InterfaceMethod ref
    /// `{ class_index, name_and_type_index }`.
    MemberRef(u16, u16),
    /// `{ name_index, descriptor_index }`.
    NameAndType(u16, u16),
    /// `{ reference_kind, reference_index }`.
    MethodHandle(u8, u16),
    /// `{ descriptor_index }`.
    MethodType(u16),
    /// `{ bootstrap_method_attr_index, name_and_type_index }`.
    InvokeDynamic(u16, u16),
}

/// C++ `ConstantData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstantData {
    /// Tag.
    pub kind: ConstantKind,
    /// Payload.
    pub payload: ConstantPayload,
}

/// C++ `AttributeInfo`: name index plus the attribute bytes' range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeInfo {
    /// Constant pool index of the attribute name.
    pub attribute_name_index: u16,
    /// Byte offset of the attribute payload.
    pub info_start: usize,
    /// Payload length.
    pub info_length: u32,
}

/// C++ `FieldInfo` / `MethodInfo` (identical layouts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberInfo {
    /// Access flags.
    pub access_flags: u16,
    /// Name constant index.
    pub name_index: u16,
    /// Descriptor constant index.
    pub descriptor_index: u16,
    /// Attributes.
    pub attributes: Vec<AttributeInfo>,
}

/// C++ `ColoredArea` — byte ranges of the class sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColoredArea {
    /// Start offset.
    pub start: u32,
    /// End offset.
    pub end: u32,
    /// Section name.
    pub name: &'static str,
}

/// C++ `ExceptionTable` entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExceptionTable {
    /// Range start.
    pub start_pc: u16,
    /// Range end.
    pub end_pc: u16,
    /// Handler pc.
    pub handler_pc: u16,
    /// Catch type constant.
    pub catch_type: u16,
}

/// C++ `CodeAttribute`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeAttribute {
    /// Max operand stack.
    pub max_stack: u16,
    /// Max locals.
    pub max_locals: u16,
    /// Bytecode range `(start, length)` within the class bytes.
    pub code_start: usize,
    /// Bytecode length.
    pub code_length: u32,
    /// Exception table.
    pub exception_table: Vec<ExceptionTable>,
    /// Nested attributes.
    pub attributes: Vec<AttributeInfo>,
}

/// C++ `ClassParser` (`class_parser.hpp:158-181`).
#[derive(Clone, Debug, Default)]
pub struct ClassParser {
    /// Constant pool with the seeded `Nothing` slot 0.
    pub constant_data: Vec<ConstantData>,
    /// Fields.
    pub fields: Vec<MemberInfo>,
    /// Methods.
    pub methods: Vec<MemberInfo>,
    /// Class attributes (never populated by the C++ `parse`).
    pub attributes: Vec<AttributeInfo>,
}

impl ClassParser {
    /// C++ ctor: seeds constant slot 0 with `Nothing`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            constant_data: vec![ConstantData {
                kind: ConstantKind::Nothing,
                payload: ConstantPayload::Nothing,
            }],
            ..Self::default()
        }
    }

    /// C++ `is_valid_constant_pool_tag`.
    #[must_use]
    pub const fn is_valid_constant_pool_tag(tag: u8) -> bool {
        tag >= 1 && tag <= 18 && tag != 2 && tag != 13 && tag != 14 && tag != 17
    }

    /// C++ `ClassParser::parse` (`class_parser.cpp:88-144`): header,
    /// constant pool (`count - 1` entries, wrapping like the C++
    /// `uint16` loop), access flags, this/super, interfaces, fields,
    /// methods. Class attributes are **not** read (C++ stops after
    /// the methods).
    pub fn parse(&mut self, reader: &mut BufferReader<'_>, areas: &mut Vec<ColoredArea>) -> bool {
        let mut offset = reader.offset();
        if !reader.skip(4) || !reader.skip(2) || !reader.skip(2) {
            return false;
        }
        let Some(constant_pool_count) = reader.read_u16_be() else {
            return false;
        };
        areas.push(ColoredArea {
            start: offset as u32,
            end: reader.offset() as u32,
            name: "header",
        });

        offset = reader.offset();
        let entries = constant_pool_count.wrapping_sub(1);
        for _ in 0..entries {
            if !self.parse_constant_pool(reader) {
                return false;
            }
        }
        areas.push(ColoredArea {
            start: offset as u32,
            end: reader.offset() as u32,
            name: "const",
        });

        // access_flags, this_class, super_class
        if reader.read_u16_be().is_none()
            || reader.read_u16_be().is_none()
            || reader.read_u16_be().is_none()
        {
            return false;
        }

        offset = reader.offset();
        let Some(interfaces_count) = reader.read_u16_be() else {
            return false;
        };
        for _ in 0..interfaces_count {
            if reader.read_u16_be().is_none() {
                return false;
            }
        }
        areas.push(ColoredArea {
            start: offset as u32,
            end: reader.offset() as u32,
            name: "interfaces",
        });

        offset = reader.offset();
        let Some(fields_count) = reader.read_u16_be() else {
            return false;
        };
        for _ in 0..fields_count {
            let Some(field) = Self::parse_member(reader) else {
                return false;
            };
            self.fields.push(field);
        }
        areas.push(ColoredArea {
            start: offset as u32,
            end: reader.offset() as u32,
            name: "fields",
        });

        offset = reader.offset();
        let Some(methods_count) = reader.read_u16_be() else {
            return false;
        };
        for _ in 0..methods_count {
            let Some(method) = Self::parse_member(reader) else {
                return false;
            };
            self.methods.push(method);
        }
        areas.push(ColoredArea {
            start: offset as u32,
            end: reader.offset() as u32,
            name: "methods",
        });
        true
    }

    /// C++ `parse_constant_pool` (`class_parser.cpp:151-203`): the
    /// tag must be valid **and** handled by the switch (`Long` /
    /// `Float` are valid tags but `unimplemented` → fail). A `Double`
    /// pushes its entry twice (the JVM's two-slot rule).
    pub fn parse_constant_pool(&mut self, reader: &mut BufferReader<'_>) -> bool {
        let Some(tag) = reader.read_u8() else {
            return false;
        };
        if !Self::is_valid_constant_pool_tag(tag) {
            return false;
        }
        let Some(kind) = ConstantKind::from_tag(tag) else {
            return false;
        };
        let mut double_entry = false;
        let payload = match kind {
            ConstantKind::Utf8 => {
                let Some(length) = reader.read_u16_be() else {
                    return false;
                };
                let start = reader.offset();
                if !reader.skip(usize::from(length)) {
                    return false;
                }
                ConstantPayload::Utf8 { start, length }
            }
            ConstantKind::Integer => match reader.read_u32_be() {
                Some(v) => ConstantPayload::Integer(v),
                None => return false,
            },
            ConstantKind::Double => match reader.read_u64_be() {
                Some(v) => {
                    double_entry = true;
                    ConstantPayload::Double(v)
                }
                None => return false,
            },
            ConstantKind::Class => match reader.read_u16_be() {
                Some(v) => ConstantPayload::Class(v),
                None => return false,
            },
            ConstantKind::String => match reader.read_u16_be() {
                Some(v) => ConstantPayload::String(v),
                None => return false,
            },
            ConstantKind::FieldRef | ConstantKind::MethodRef | ConstantKind::InterfaceMethodRef => {
                let (Some(a), Some(b)) = (reader.read_u16_be(), reader.read_u16_be()) else {
                    return false;
                };
                ConstantPayload::MemberRef(a, b)
            }
            ConstantKind::NameAndType => {
                let (Some(a), Some(b)) = (reader.read_u16_be(), reader.read_u16_be()) else {
                    return false;
                };
                ConstantPayload::NameAndType(a, b)
            }
            ConstantKind::MethodHandle => {
                let (Some(a), Some(b)) = (reader.read_u8(), reader.read_u16_be()) else {
                    return false;
                };
                ConstantPayload::MethodHandle(a, b)
            }
            ConstantKind::MethodType => match reader.read_u16_be() {
                Some(v) => ConstantPayload::MethodType(v),
                None => return false,
            },
            ConstantKind::InvokeDynamic => {
                let (Some(a), Some(b)) = (reader.read_u16_be(), reader.read_u16_be()) else {
                    return false;
                };
                ConstantPayload::InvokeDynamic(a, b)
            }
            // `unimplemented` in the C++ switch.
            ConstantKind::Nothing | ConstantKind::Float | ConstantKind::Long => return false,
        };
        let data = ConstantData { kind, payload };
        if double_entry {
            self.constant_data.push(data.clone());
        }
        self.constant_data.push(data);
        true
    }

    /// C++ `parse_field` / `parse_method` (identical bodies).
    fn parse_member(reader: &mut BufferReader<'_>) -> Option<MemberInfo> {
        let access_flags = reader.read_u16_be()?;
        let name_index = reader.read_u16_be()?;
        let descriptor_index = reader.read_u16_be()?;
        let attributes = Self::parse_attributes(reader)?;
        Some(MemberInfo {
            access_flags,
            name_index,
            descriptor_index,
            attributes,
        })
    }

    /// C++ `parse_attributes` + `parse_attribute`.
    fn parse_attributes(reader: &mut BufferReader<'_>) -> Option<Vec<AttributeInfo>> {
        let count = reader.read_u16_be()?;
        let mut out = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let attribute_name_index = reader.read_u16_be()?;
            let info_length = reader.read_u32_be()?;
            let info_start = reader.offset();
            if !reader.skip(info_length as usize) {
                return None;
            }
            out.push(AttributeInfo {
                attribute_name_index,
                info_start,
                info_length,
            });
        }
        Some(out)
    }

    /// C++ `parse_attribute_code` (`class_parser.cpp:239-260`).
    #[must_use]
    pub fn parse_attribute_code(data: &[u8], attribute: AttributeInfo) -> Option<CodeAttribute> {
        let end = attribute
            .info_start
            .checked_add(attribute.info_length as usize)?;
        let mut reader = BufferReader::new(data.get(attribute.info_start..end)?);
        let max_stack = reader.read_u16_be()?;
        let max_locals = reader.read_u16_be()?;
        let code_length = reader.read_u32_be()?;
        let code_start = attribute.info_start.checked_add(reader.offset())?;
        if !reader.skip(code_length as usize) {
            return None;
        }
        let exception_table_length = reader.read_u16_be()?;
        let mut exception_table = Vec::with_capacity(usize::from(exception_table_length));
        for _ in 0..exception_table_length {
            exception_table.push(ExceptionTable {
                start_pc: reader.read_u16_be()?,
                end_pc: reader.read_u16_be()?,
                handler_pc: reader.read_u16_be()?,
                catch_type: reader.read_u16_be()?,
            });
        }
        // Nested attribute offsets are relative to the attribute
        // payload; rebase them to the class bytes.
        let nested = Self::parse_attributes(&mut reader)?;
        let attributes = nested
            .into_iter()
            .map(|a| AttributeInfo {
                attribute_name_index: a.attribute_name_index,
                info_start: a.info_start.saturating_add(attribute.info_start),
                info_length: a.info_length,
            })
            .collect();
        Some(CodeAttribute {
            max_stack,
            max_locals,
            code_start,
            code_length,
            exception_table,
            attributes,
        })
    }

    /// C++ `AstCreator::get_constant` + `get_utf8`: the entry at
    /// `index` must exist and be `Utf8`.
    #[must_use]
    pub fn get_utf8<'d>(&self, data: &'d [u8], index: u16) -> Option<&'d [u8]> {
        let entry = self.constant_data.get(usize::from(index))?;
        if entry.kind != ConstantKind::Utf8 {
            return None;
        }
        let ConstantPayload::Utf8 { start, length } = entry.payload else {
            return None;
        };
        data.get(start..start.checked_add(usize::from(length))?)
    }
}

// ------------------------------------------------------------------
// Opcodes (gen.py table)
// ------------------------------------------------------------------

/// C++ `NAMES[256]` (`raw_opcodes.hpp`) — the 202 JVM mnemonics.
pub const OPCODE_NAMES: [&str; 202] = [
    "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4",
    "iconst_5", "lconst_0", "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1",
    "bipush", "sipush", "ldc", "ldc_w", "ldc2_w", "iload", "lload", "fload", "dload", "aload",
    "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1", "lload_2", "lload_3",
    "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1", "dload_2", "dload_3",
    "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload", "faload", "daload", "aaload",
    "baload", "caload", "saload", "istore", "lstore", "fstore", "dstore", "astore", "istore_0",
    "istore_1", "istore_2", "istore_3", "lstore_0", "lstore_1", "lstore_2", "lstore_3", "fstore_0",
    "fstore_1", "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0",
    "astore_1", "astore_2", "astore_3", "iastore", "lastore", "fastore", "dastore", "aastore",
    "bastore", "castore", "sastore", "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1",
    "dup2_x2", "swap", "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul",
    "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg",
    "lneg", "fneg", "dneg", "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land", "ior",
    "lor", "ixor", "lxor", "iinc", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d",
    "d2i", "d2l", "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg", "ifeq",
    "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge",
    "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ret", "tableswitch",
    "lookupswitch", "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return", "getstatic",
    "putstatic", "getfield", "putfield", "invokevirtual", "invokespecial", "invokestatic",
    "invokeinterface", "invokedynamic", "new", "newarray", "anewarray", "arraylength", "athrow",
    "checkcast", "instanceof", "monitorenter", "monitorexit", "wide", "multianewarray", "ifnull",
    "ifnonnull", "goto_w", "jsr_w",
];

/// Operand encoding of one opcode argument (gen.py `Type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgType {
    /// `uint8`.
    U8,
    /// `uint16`.
    U16,
    /// `int8`.
    I8,
    /// `int16`.
    I16,
    /// `int32`.
    I32,
}

/// Operand layout of an opcode: argument types plus the `rel` flag
/// (branch offsets folded with the instruction offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcodeSpec {
    /// Argument encodings (at most 3).
    pub args: &'static [ArgType],
    /// gen.py `.rel()`.
    pub relative: bool,
}

/// The gen.py `OPCODES` table: `None` for `unimplemented` entries
/// (`tableswitch`, `lookupswitch`, `wide`) and unknown opcodes.
#[must_use]
pub const fn opcode_spec(opcode: u8) -> Option<OpcodeSpec> {
    const NONE: &[ArgType] = &[];
    const U8: &[ArgType] = &[ArgType::U8];
    const U16: &[ArgType] = &[ArgType::U16];
    const I8: &[ArgType] = &[ArgType::I8];
    const I16: &[ArgType] = &[ArgType::I16];
    const I32: &[ArgType] = &[ArgType::I32];
    const U8_I8: &[ArgType] = &[ArgType::U8, ArgType::I8];
    const U16_U8_U8: &[ArgType] = &[ArgType::U16, ArgType::U8, ArgType::U8];
    const I16_U8: &[ArgType] = &[ArgType::I16, ArgType::U8];
    const fn plain(args: &'static [ArgType]) -> OpcodeSpec {
        OpcodeSpec {
            args,
            relative: false,
        }
    }
    const fn rel(args: &'static [ArgType]) -> OpcodeSpec {
        OpcodeSpec {
            args,
            relative: true,
        }
    }
    let spec = match opcode {
        0..=15 | 26..=53 | 59..=131 | 133..=152 | 172..=177 | 190 | 191 => plain(NONE),
        16 => plain(I8),
        17 | 168 => plain(I16),
        18 | 21..=25 | 54..=58 | 169 | 188 => plain(U8),
        19 | 20 | 153..=158 | 178..=184 | 187 | 189 | 192..=195 => plain(U16),
        159..=167 | 198 | 199 => rel(I16),
        132 => plain(U8_I8),
        185 | 186 => plain(U16_U8_U8),
        197 => plain(I16_U8),
        200 | 201 => rel(I32),
        _ => return None, // 170, 171, 196 unimplemented; > 201 unknown
    };
    Some(spec)
}

/// C++ `Opcode::Arg`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpcodeArg {
    /// Present.
    pub exists: bool,
    /// Formats with `%llu` (else `%lld`).
    pub is_unsigned: bool,
    /// Value as stored by C++ (`uint32`, signed values wrapped).
    pub value: u32,
}

/// C++ `Opcode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Opcode {
    /// Opcode byte.
    pub opcode: u8,
    /// Up to three operands.
    pub args: [OpcodeArg; 3],
}

impl Opcode {
    /// C++ `get_name`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        OPCODE_NAMES
            .get(usize::from(self.opcode))
            .copied()
            .unwrap_or("")
    }
}

/// C++ `get_opcode` (`raw_opcodes.hpp:49+`): decodes one instruction;
/// relative operands add the instruction offset with the operand's
/// own width (`int16`/`int32` wrapping).
pub fn get_opcode(reader: &mut BufferReader<'_>) -> Option<Opcode> {
    let offset = reader.offset();
    let opcode = reader.read_u8()?;
    let spec = opcode_spec(opcode)?;
    let mut out = Opcode {
        opcode,
        args: [OpcodeArg::default(); 3],
    };
    for (i, arg) in spec.args.iter().enumerate() {
        let (value, is_unsigned) = match arg {
            ArgType::U8 => (u32::from(reader.read_u8()?), true),
            ArgType::U16 => (u32::from(reader.read_u16_be()?), true),
            ArgType::I8 => {
                let v = i32::from(reader.read_u8()?.cast_signed());
                (v.cast_unsigned(), false)
            }
            ArgType::I16 => {
                let mut v = reader.read_u16_be()?.cast_signed();
                if spec.relative {
                    v = v.wrapping_add((offset as u16).cast_signed());
                }
                (i32::from(v).cast_unsigned(), false)
            }
            ArgType::I32 => {
                let mut v = reader.read_u32_be()?.cast_signed();
                if spec.relative {
                    v = v.wrapping_add((offset as u32).cast_signed());
                }
                (v.cast_unsigned(), false)
            }
        };
        if let Some(slot) = out.args.get_mut(i) {
            *slot = OpcodeArg {
                exists: true,
                is_unsigned,
                value,
            };
        }
    }
    Some(out)
}

// ------------------------------------------------------------------
// Demangler + AST creation (only success/failure matters for the
// zone; the type tree is kept for fidelity)
// ------------------------------------------------------------------

/// Demangled JVM type (C++ `Type` hierarchy, `ast.hpp`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JType {
    /// `V`.
    Void,
    /// `B`.
    Byte,
    /// `S`.
    Short,
    /// `I`.
    Int,
    /// `J`.
    Long,
    /// `F`.
    Float,
    /// `D`.
    Double,
    /// `Z`.
    Bool,
    /// `C`.
    Char,
    /// `Lname;` with `/` → `.`.
    ClassRef(String),
    /// `[subtype`.
    Array(Box<Self>),
    /// `(args)ret`.
    Method {
        /// Return type.
        return_type: Box<Self>,
        /// Arguments (max 16).
        args: Vec<Self>,
    },
}

/// C++ `Demangler` (`class_parser.cpp:262-370`).
pub struct Demangler<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Demangler<'a> {
    /// Demangler over a descriptor.
    #[must_use]
    pub const fn new(descriptor: &'a [u8]) -> Self {
        Self {
            bytes: descriptor,
            pos: 0,
        }
    }

    fn demangle_class_ref(&mut self) -> Option<JType> {
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes.get(self.pos) != Some(&b';') {
            self.pos = self.pos.saturating_add(1);
        }
        if self.bytes.get(self.pos) != Some(&b';') {
            return None;
        }
        let name = self.bytes.get(start..self.pos)?;
        self.pos = self.pos.saturating_add(1);
        let dotted: String = name
            .iter()
            .map(|&b| if b == b'/' { '.' } else { char::from(b) })
            .collect();
        Some(JType::ClassRef(dotted))
    }

    /// C++ `demangle` — one type.
    pub fn demangle(&mut self) -> Option<JType> {
        let &ch = self.bytes.get(self.pos)?;
        self.pos = self.pos.saturating_add(1);
        match ch {
            b'B' => Some(JType::Byte),
            b'S' => Some(JType::Short),
            b'I' => Some(JType::Int),
            b'J' => Some(JType::Long),
            b'F' => Some(JType::Float),
            b'D' => Some(JType::Double),
            b'Z' => Some(JType::Bool),
            b'C' => Some(JType::Char),
            b'L' => self.demangle_class_ref(),
            b'[' => Some(JType::Array(Box::new(self.demangle()?))),
            _ => None,
        }
    }

    /// C++ `demangle_field`.
    #[must_use]
    pub fn demangle_field(descriptor: &'a [u8]) -> Option<JType> {
        Self::new(descriptor).demangle()
    }

    /// C++ `demangle_method` (`class_parser.cpp:342-370`): `(` args
    /// `)` return; more than [`MAX_NUMBER_OF_ARGS`] arguments or a
    /// missing return type fails; `V` is void.
    #[must_use]
    pub fn demangle_method(descriptor: &'a [u8]) -> Option<JType> {
        let mut d = Self::new(descriptor);
        if d.bytes.first() != Some(&b'(') {
            return None;
        }
        d.pos = 1;
        let mut args = Vec::new();
        while d.pos < d.bytes.len() && d.bytes.get(d.pos) != Some(&b')') {
            if args.len() == MAX_NUMBER_OF_ARGS {
                return None;
            }
            args.push(d.demangle()?);
        }
        d.pos = d.pos.saturating_add(1);
        if d.pos >= d.bytes.len() {
            return None;
        }
        let return_type = if d.bytes.get(d.pos) == Some(&b'V') {
            JType::Void
        } else {
            d.demangle()?
        };
        Some(JType::Method {
            return_type: Box::new(return_type),
            args,
        })
    }
}

/// C++ `AstCreator::create` (`class_parser.cpp:378-398`) reduced to
/// its validation outcome.
///
/// Every method's name/descriptor must be `Utf8`, descriptors must
/// demangle, every attribute name must be `Utf8`, and each `Code`
/// attribute must parse with every opcode decodable; then the same
/// for fields. `false` mirrors a `nullptr` return.
#[must_use]
pub fn ast_create_succeeds(parser: &ClassParser, data: &[u8]) -> bool {
    for method in &parser.methods {
        if parser.get_utf8(data, method.name_index).is_none() {
            return false;
        }
        let Some(descriptor) = parser.get_utf8(data, method.descriptor_index) else {
            return false;
        };
        if Demangler::demangle_method(descriptor).is_none() {
            return false;
        }
        for attribute in &method.attributes {
            let Some(name) = parser.get_utf8(data, attribute.attribute_name_index) else {
                return false;
            };
            if name == b"Code" && !create_code_succeeds(data, *attribute) {
                return false;
            }
        }
    }
    for field in &parser.fields {
        if parser.get_utf8(data, field.name_index).is_none() {
            return false;
        }
        let Some(descriptor) = parser.get_utf8(data, field.descriptor_index) else {
            return false;
        };
        if Demangler::demangle_field(descriptor).is_none() {
            return false;
        }
        for attribute in &field.attributes {
            if parser.get_utf8(data, attribute.attribute_name_index).is_none() {
                return false;
            }
        }
    }
    true
}

/// C++ `AstCreator::create_code` (`class_parser.cpp:498-519`): the
/// `Code` attribute parses and every opcode decodes.
#[must_use]
pub fn create_code_succeeds(data: &[u8], attribute: AttributeInfo) -> bool {
    let Some(code) = ClassParser::parse_attribute_code(data, attribute) else {
        return false;
    };
    let Some(end) = code.code_start.checked_add(code.code_length as usize) else {
        return false;
    };
    let Some(bytes) = data.get(code.code_start..end) else {
        return false;
    };
    let mut reader = BufferReader::new(bytes);
    while reader.has_more() {
        if get_opcode(&mut reader).is_none() {
            return false;
        }
    }
    true
}

/// The zone's text lines (C++ `DrawDissasmJavaByteCodeZone` init,
/// `DissasmJClass.cpp:16-46`).
///
/// `None` when `ClassParser::parse` fails (the C++ draw returns
/// `false` and adds nothing).
#[must_use]
pub fn build_jclass_zone_lines(data: &[u8]) -> Option<Vec<String>> {
    let mut parser = ClassParser::new();
    let mut areas = Vec::with_capacity(32);
    let mut reader = BufferReader::new(data);
    if !parser.parse(&mut reader, &mut areas) {
        return None;
    }
    let mut lines = Vec::new();
    if ast_create_succeeds(&parser, data) {
        lines.push(CONSTANT_DATA_HEADER.to_owned());
        if parser.constant_data.is_empty() {
            lines.push(NO_CONSTANT_DATA.to_owned());
        }
        for constant in &parser.constant_data {
            lines.push(format!("    {}", constant.kind.name()));
        }
    } else {
        lines.push(PARSE_FAILURE_MESSAGE.to_owned());
    }
    Some(lines)
}

/// C++ `Instance::AdjustZoneExtendedSize` (`Instance.cpp:1255-1278`).
///
/// A collapsed zone just records the new size; an expanded zone
/// grows/shrinks its ending line and shifts every later zone. Returns
/// the new total line count when the layout changed.
pub fn adjust_zone_extended_size(
    zones: &mut [ZoneEntry],
    target_index: usize,
    new_extended_size: u32,
) -> Option<u32> {
    let header = zones.get(target_index)?.header();
    if header.is_collapsed {
        zones.get_mut(target_index)?.header_mut().extended_size = new_extended_size;
        return None;
    }
    if header.extended_size == new_extended_size {
        return None;
    }
    let size_to_adjust = i32::try_from(new_extended_size)
        .unwrap_or(i32::MAX)
        .wrapping_sub(i32::try_from(header.extended_size).unwrap_or(i32::MAX));
    {
        let h = zones.get_mut(target_index)?.header_mut();
        h.ending_line_index = h.ending_line_index.wrapping_add_signed(size_to_adjust);
    }
    for entry in zones.iter_mut().skip(target_index.saturating_add(1)) {
        let h = entry.header_mut();
        h.start_line_index = h.start_line_index.wrapping_add_signed(size_to_adjust);
        h.ending_line_index = h.ending_line_index.wrapping_add_signed(size_to_adjust);
    }
    zones.get_mut(target_index)?.header_mut().extended_size = new_extended_size;
    Some(total_lines(zones))
}

/// Fills a Java bytecode zone on first draw (C++
/// `DrawDissasmJavaByteCodeZone`, `DissasmJClass.cpp:16-50`).
///
/// One pre-cache line per text line (`op_str` = text, no x86 decode),
/// then `AdjustZoneExtendedSize(zone, line count)` and `isInit`.
/// Returns `false` when the class file does not parse (the C++ draw
/// fails and the zone stays uninitialized).
pub fn init_jclass_zone(
    zones: &mut [ZoneEntry],
    zone_index: usize,
    pre_cache: &mut DissasmAsmPreCacheData,
    data: &[u8],
) -> bool {
    let already_init = matches!(zones.get(zone_index), Some(ZoneEntry::Code(z)) if z.is_init);
    if already_init {
        return true;
    }
    let Some(lines) = build_jclass_zone_lines(data) else {
        return false;
    };
    for text in &lines {
        pre_cache.cached_asm_lines.push(DissasmAsmPreCacheLine {
            op_str: text.clone(),
            ..DissasmAsmPreCacheLine::default()
        });
    }
    adjust_zone_extended_size(zones, zone_index, pre_cache.cached_asm_lines.len() as u32);
    if let Some(ZoneEntry::Code(zone)) = zones.get_mut(zone_index) {
        zone.is_init = true;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissasm_viewer::zone::{DissasmCodeZone, DissasmParseStructureZone};

    /// A minimal valid class: `Test extends Object` with a default
    /// constructor (`aload_0; invokespecial #8; return`).
    fn sample_class() -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
        c.extend_from_slice(&0_u16.to_be_bytes()); // minor
        c.extend_from_slice(&52_u16.to_be_bytes()); // major
        c.extend_from_slice(&10_u16.to_be_bytes()); // constant_pool_count = 9 + 1
        let utf8 = |c: &mut Vec<u8>, s: &[u8]| {
            c.push(1);
            c.extend_from_slice(&(s.len() as u16).to_be_bytes());
            c.extend_from_slice(s);
        };
        utf8(&mut c, b"Test"); // #1
        c.extend_from_slice(&[7, 0, 1]); // #2 Class -> #1
        utf8(&mut c, b"java/lang/Object"); // #3
        c.extend_from_slice(&[7, 0, 3]); // #4 Class -> #3
        utf8(&mut c, b"<init>"); // #5
        utf8(&mut c, b"()V"); // #6
        utf8(&mut c, b"Code"); // #7
        c.extend_from_slice(&[10, 0, 4, 0, 9]); // #8 Methodref #4.#9
        c.extend_from_slice(&[12, 0, 5, 0, 6]); // #9 NameAndType #5:#6
        c.extend_from_slice(&0x0021_u16.to_be_bytes()); // access flags
        c.extend_from_slice(&2_u16.to_be_bytes()); // this
        c.extend_from_slice(&4_u16.to_be_bytes()); // super
        c.extend_from_slice(&0_u16.to_be_bytes()); // interfaces
        c.extend_from_slice(&0_u16.to_be_bytes()); // fields
        c.extend_from_slice(&1_u16.to_be_bytes()); // methods
        c.extend_from_slice(&0x0001_u16.to_be_bytes()); // public
        c.extend_from_slice(&5_u16.to_be_bytes()); // name <init>
        c.extend_from_slice(&6_u16.to_be_bytes()); // descriptor ()V
        c.extend_from_slice(&1_u16.to_be_bytes()); // 1 attribute
        c.extend_from_slice(&7_u16.to_be_bytes()); // "Code"
        let code_body: Vec<u8> = {
            let mut b = Vec::new();
            b.extend_from_slice(&1_u16.to_be_bytes()); // max_stack
            b.extend_from_slice(&1_u16.to_be_bytes()); // max_locals
            b.extend_from_slice(&5_u32.to_be_bytes()); // code_length
            b.extend_from_slice(&[0x2a, 0xb7, 0x00, 0x08, 0xb1]);
            b.extend_from_slice(&0_u16.to_be_bytes()); // exception table
            b.extend_from_slice(&0_u16.to_be_bytes()); // attributes
            b
        };
        c.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
        c.extend_from_slice(&code_body);
        c.extend_from_slice(&0_u16.to_be_bytes()); // class attributes (unread)
        c
    }

    #[test]
    fn sample_class_golden_line_count() {
        let lines = build_jclass_zone_lines(&sample_class()).expect("parses");
        // "Constant data:" + 10 pool slots (seeded Nothing + 9 entries).
        assert_eq!(lines.len(), 11);
        assert_eq!(lines[0], CONSTANT_DATA_HEADER);
        assert_eq!(lines[1], "    Nothing");
        assert_eq!(lines[2], "    Utf8");
        assert_eq!(lines[3], "    Class");
        assert_eq!(lines[9], "    MethodRef");
        assert_eq!(lines[10], "    NameAndType");
    }

    /// A class whose pool is a single Double constant, with the given
    /// `constant_pool_count` and no members.
    fn double_only_class(constant_pool_count: u16) -> Vec<u8> {
        let mut c = sample_class();
        c.truncate(10);
        c[8..10].copy_from_slice(&constant_pool_count.to_be_bytes());
        c.push(6); // Double
        c.extend_from_slice(&0x3FF0_0000_0000_0000_u64.to_be_bytes());
        c.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // flags/this/super
        c.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // interfaces/fields/methods
        c
    }

    #[test]
    fn double_constant_occupies_two_slots() {
        // C++ quirk: the pool loop runs `count - 1` times regardless
        // of two-slot entries, so a JVM-conformant count (slots + 1 =
        // 3) makes the parser read the access flags as a second tag
        // and fail — as the C++ code does.
        assert!(build_jclass_zone_lines(&double_only_class(3)).is_none());
        // With count = 2 the single physical entry parses and the
        // Double is listed twice (its two slots).
        let lines = build_jclass_zone_lines(&double_only_class(2)).expect("parses");
        assert_eq!(
            lines,
            vec![
                CONSTANT_DATA_HEADER.to_owned(),
                "    Nothing".to_owned(),
                "    Double".to_owned(),
                "    Double".to_owned(),
            ]
        );
    }

    #[test]
    fn long_constant_fails_the_parse_like_cpp() {
        // Long is a valid tag but `unimplemented` in the C++ switch →
        // parse fails → no lines at all.
        let mut c = sample_class();
        c.truncate(10);
        c[8..10].copy_from_slice(&3_u16.to_be_bytes());
        c.push(5); // Long
        c.extend_from_slice(&[0; 8]);
        c.extend_from_slice(&[0; 12]);
        assert!(build_jclass_zone_lines(&c).is_none());
        // Invalid tag 2 fails too; truncated input fails.
        assert!(build_jclass_zone_lines(&sample_class()[..20]).is_none());
        assert!(build_jclass_zone_lines(&[]).is_none());
    }

    #[test]
    fn ast_failure_yields_single_message_line() {
        // Corrupt the method descriptor index to point at a Class
        // constant: get_utf8 fails → AST creation fails.
        let mut c = sample_class();
        // The method info's `name_index=5, descriptor_index=6` pair is
        // the LAST occurrence of these bytes (the NameAndType constant
        // #9 carries the same pair earlier in the pool).
        let pos = c
            .windows(4)
            .rposition(|w| w == [0, 5, 0, 6])
            .expect("method header");
        c[pos + 2..pos + 4].copy_from_slice(&2_u16.to_be_bytes());
        let lines = build_jclass_zone_lines(&c).expect("parses");
        assert_eq!(lines, vec![PARSE_FAILURE_MESSAGE.to_owned()]);
    }

    #[test]
    fn unknown_opcode_in_code_fails_ast() {
        let mut c = sample_class();
        let pos = c.windows(5).position(|w| w == [0x2a, 0xb7, 0x00, 0x08, 0xb1]).unwrap();
        c[pos] = 0xCA; // breakpoint — outside the 0..=201 table
        let lines = build_jclass_zone_lines(&c).expect("parses");
        assert_eq!(lines, vec![PARSE_FAILURE_MESSAGE.to_owned()]);
        // `wide` (196) is unimplemented as well.
        c[pos] = 196;
        assert_eq!(build_jclass_zone_lines(&c).unwrap().len(), 1);
    }

    #[test]
    fn opcode_decoding_matches_gen_table() {
        // bipush -5 → signed i8.
        let mut r = BufferReader::new(&[16, 0xFB]);
        let op = get_opcode(&mut r).unwrap();
        assert_eq!(op.name(), "bipush");
        assert_eq!(
            op.args[0],
            OpcodeArg {
                exists: true,
                is_unsigned: false,
                value: (-5_i32).cast_unsigned()
            }
        );
        // goto at offset 0 with rel -3 → -3 folded with the offset.
        let mut r = BufferReader::new(&[0, 167, 0xFF, 0xFD]);
        get_opcode(&mut r).unwrap(); // nop at 0
        let op = get_opcode(&mut r).unwrap(); // goto at offset 1
        assert_eq!(op.name(), "goto");
        assert_eq!(op.args[0].value, (-2_i32).cast_unsigned());
        // invokeinterface has 3 operands.
        let mut r = BufferReader::new(&[185, 0, 7, 2, 0]);
        let op = get_opcode(&mut r).unwrap();
        assert_eq!(op.args.iter().filter(|a| a.exists).count(), 3);
        assert_eq!(op.args[0].value, 7);
        // Truncated operand → None; tableswitch → None.
        assert!(get_opcode(&mut BufferReader::new(&[17, 0])).is_none());
        assert!(get_opcode(&mut BufferReader::new(&[170])).is_none());
        assert_eq!(OPCODE_NAMES.len(), 202);
    }

    #[test]
    fn demangler_handles_descriptors() {
        assert_eq!(Demangler::demangle_field(b"I"), Some(JType::Int));
        assert_eq!(
            Demangler::demangle_field(b"[Ljava/lang/String;"),
            Some(JType::Array(Box::new(JType::ClassRef("java.lang.String".to_owned()))))
        );
        assert_eq!(Demangler::demangle_field(b"Lno_semicolon"), None);
        assert_eq!(Demangler::demangle_field(b"Q"), None);
        let method = Demangler::demangle_method(b"(IJ)V").unwrap();
        assert_eq!(
            method,
            JType::Method { return_type: Box::new(JType::Void), args: vec![JType::Int, JType::Long] }
        );
        assert_eq!(Demangler::demangle_method(b"IV"), None); // no '('
        assert_eq!(Demangler::demangle_method(b"(I)"), None); // no return
        // 17 arguments exceed MAX_NUMBER_OF_ARGS.
        let too_many = format!("({})V", "I".repeat(17));
        assert_eq!(Demangler::demangle_method(too_many.as_bytes()), None);
        let sixteen = format!("({})V", "I".repeat(16));
        assert!(Demangler::demangle_method(sixteen.as_bytes()).is_some());
    }

    #[test]
    fn init_zone_populates_pre_cache_without_x86_decode() {
        let mut code = DissasmCodeZone::default();
        code.zone.start_line_index = 10;
        code.zone.ending_line_index = 12;
        code.zone.extended_size = 1;
        let mut after = DissasmParseStructureZone::default();
        after.zone.start_line_index = 12;
        after.zone.ending_line_index = 20;
        let mut zones = vec![ZoneEntry::Code(Box::new(code)), ZoneEntry::Structure(after)];
        let mut cache = DissasmAsmPreCacheData::default();
        assert!(init_jclass_zone(&mut zones, 0, &mut cache, &sample_class()));
        assert_eq!(cache.cached_asm_lines.len(), 11);
        assert_eq!(cache.cached_asm_lines[0].op_str, CONSTANT_DATA_HEADER);
        // No instruction data was produced: plain text lines only.
        assert!(cache.cached_asm_lines.iter().all(|l| l.size == 0 && l.mnemonic.is_empty()));
        // extendedSize became the line count and the layout shifted:
        // +10 lines, following zone moved.
        assert_eq!(zones[0].header().extended_size, 11);
        assert_eq!(zones[0].header().ending_line_index, 22);
        assert_eq!(zones[1].header().start_line_index, 22);
        assert!(matches!(&zones[0], ZoneEntry::Code(z) if z.is_init));
        // Second init is a no-op.
        assert!(init_jclass_zone(&mut zones, 0, &mut cache, &sample_class()));
        assert_eq!(cache.cached_asm_lines.len(), 11);
        // An unparsable class leaves the zone uninitialized.
        let mut bad = vec![ZoneEntry::Code(Box::default())];
        let mut bad_cache = DissasmAsmPreCacheData::default();
        assert!(!init_jclass_zone(&mut bad, 0, &mut bad_cache, b"junk"));
        assert!(bad_cache.cached_asm_lines.is_empty());
    }

    #[test]
    fn adjust_extended_size_collapsed_only_records() {
        let mut code = DissasmCodeZone::default();
        code.zone.start_line_index = 0;
        code.zone.ending_line_index = 1;
        code.zone.is_collapsed = true;
        let mut zones = vec![ZoneEntry::Code(Box::new(code))];
        assert_eq!(adjust_zone_extended_size(&mut zones, 0, 40), None);
        assert_eq!(zones[0].header().extended_size, 40);
        assert_eq!(zones[0].header().ending_line_index, 1);
        // Same size on an expanded zone: no-op.
        zones[0].header_mut().is_collapsed = false;
        assert_eq!(adjust_zone_extended_size(&mut zones, 0, 40), None);
    }
}

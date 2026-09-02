//! ELF enum name tables (C++ `Types/ELF/include/utils.hpp`).
//!
//! Transcribed verbatim from the helpers the `Information` panel
//! calls: `GetNameFromElfClass`, `GetNameFromElfData`,
//! `GetNameFromElfVersion`, `GetNameFromElfOsAbi`,
//! `GetNameFromElfAbiVersion`, `GetNameAndDecriptionFromElfType` and
//! `GetNameFromElfMachine`. Every function returns the C++ `default:`
//! string for a value the switch does not list, so a hostile header
//! never panics.
//!
//! The match arms keep the C++ `switch` order and its repetitions
//! (several `EM_*` values share a description, and the `Reserved`
//! ranges are split exactly as the C++ splits them), so the lints
//! below are silenced for the whole module rather than the tables
//! being rewritten into a shape that no longer reads against the
//! anchor.
#![allow(clippy::match_same_arms, clippy::too_many_lines)]

/// C++ `GetNameFromElfClass` — `e_ident[EI_CLASS]`.
#[must_use]
pub const fn class_name(value: u8) -> &'static str {
    match value {
        0 => "INVALID",
        1 => "32",
        2 => "64",
        _ => "UNKNOWN",
    }
}

/// C++ `GetNameFromElfData` — `e_ident[EI_DATA]`.
#[must_use]
pub const fn data_name(value: u8) -> &'static str {
    match value {
        0 => "INVALID",
        1 => "2LSB (Little)",
        2 => "2MSB (Big)",
        _ => "UNKNOWN",
    }
}

/// C++ `GetNameFromElfVersion` — `e_ident[EI_VERSION]` / `e_version`.
#[must_use]
pub const fn version_name(value: u8) -> &'static str {
    match value {
        0 => "INVALID",
        1 => "CURRENT",
        _ => "UNKNOWN",
    }
}

/// C++ `GetNameFromElfOsAbi` — `e_ident[EI_OSABI]`.
#[must_use]
pub const fn os_abi_name(value: u8) -> &'static str {
    match value {
        0 => "NONE",
        1 => "Hewlett-Packard HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Sun Solaris",
        7 => "AIX",
        8 => "IRIX",
        9 => "FreeBSD",
        10 => "Compaq TRU64 UNIX",
        11 => "Novell Modesto",
        12 => "Open BSD",
        13 => "Open VMS",
        17 => "Nuxi CloudABI",
        97 => "ARM",
        255 => "Standalone (embedded) application",
        14 => "Hewlett-Packard Non-Stop Kernel",
        15 => "Amiga Research OS",
        16 => "The FenixOS highly scalable multi-core OS",
        64 => "AMDGPU OS for HSA compatible compute kernels",
        65 => "AMDGPU OS for AMD PAL compatible graphics",
        66 => "AMDGPU OS for Mesa3D compatible graphics",
        _ => "UNKNOWN",
    }
}

/// C++ `GetNameFromElfAbiVersion` — only the AMDGPU HSA OS ABI
/// names its ABI versions; every other OS ABI is `UNKNOWN`.
#[must_use]
pub const fn abi_version_name(os_abi: u8, abi_version: u8) -> &'static str {
    match os_abi {
        64 => match abi_version {
            0 => "AMDGPU OS for HSA v2 compatible compute kernels",
            1 => "AMDGPU OS for HSA v3 compatible compute kernels",
            2 => "AMDGPU OS for HSA v4 compatible compute kernels",
            3 => "AMDGPU OS for HSA v5 compatible compute kernels",
            _ => "UNKNOWN",
        },
        _ => "UNKNOWN",
    }
}

/// C++ `GetNameAndDecriptionFromElfType` — `(name, description)`
/// for `e_type`.
#[must_use]
pub const fn type_name_and_description(e_type: u16) -> (&'static str, &'static str) {
    match e_type {
        0 => ("NONE", "An unknown type."),
        1 => ("REL", "A relocatable file."),
        2 => ("EXEC", "An executable file."),
        3 => ("DYN", "A shared object."),
        4 => ("CORE", "A core file."),
        _ => ("UNKNOWN", "An unknown type."),
    }
}

/// C++ `GetNameFromElfMachine` — `e_machine`.
#[must_use]
pub const fn machine_description(machine: u16) -> &'static str {
    match machine {
        0 => "An unknown machine.",
        1 => "AT&T WE 32100",
        2 => "SUN SPARC",
        3 => "Intel 80386",
        4 => "Motorola m68k family",
        5 => "Motorola m88k family",
        6 => "Intel 80486",
        7 => "Intel 80860",
        8 => "MIPS R3000 (officially, big-endian only)",
        9 => "IBM System/370",
        10 => "MIPS R3000 little-endian (Deprecated)",
        11..=14 => "Reserved",
        15 => "HPPA",
        16 => "Reserved",
        17 => "Fujitsu VPP500",
        18 => "Sun's \"v8plus\"",
        19 => "Intel 80960",
        20 => "PowerPC",
        21 => "64-bit PowerPC",
        22 => "IBM S/390",
        23 => "Sony/Toshiba/IBM SPU",
        24..=35 => "Reserved",
        36 => "NEC V800 series",
        37 => "Fujitsu FR20",
        38 => "TRW RH32",
        39 => "Motorola M*Core (May also be taken by Fujitsu MMA)",
        40 => "ARM",
        41 => "Digital Alpha",
        42 => "Renesas (formerly Hitachi) / SuperH SH",
        43 => "SPARC v9 64-bit",
        44 => "Siemens Tricore embedded processor",
        45 => "ARC Cores",
        46 => "Renesas (formerly Hitachi) H8/300",
        47 => "Renesas (formerly Hitachi) H8/300H",
        48 => "Renesas (formerly Hitachi) H8S",
        49 => "Renesas (formerly Hitachi) H8/500",
        50 => "Intel IA-64 Processor",
        51 => "Stanford MIPS-X",
        52 => "Motorola Coldfire",
        53 => "Motorola M68HC12",
        54 => "Fujitsu Multimedia Accelerator",
        55 => "Siemens PCP",
        56 => "Sony nCPU embedded RISC processor",
        57 => "Denso NDR1 microprocessor",
        58 => "Motorola Star*Core processor",
        59 => "Toyota ME16 processor",
        60 => "STMicroelectronics ST100 processor",
        61 => "Advanced Logic Corp. TinyJ embedded processor",
        62 => "Advanced Micro Devices X86-64 processor",
        63 => "Sony DSP Processor",
        64 => "Digital Equipment Corp. PDP-10",
        65 => "Digital Equipment Corp. PDP-11",
        66 => "Siemens FX66 microcontroller",
        67 => "STMicroelectronics ST9+ 8/16 bit microcontroller",
        68 => "STMicroelectronics ST7 8-bit microcontroller",
        69 => "Motorola MC68HC16 Microcontroller",
        70 => "Motorola MC68HC11 Microcontroller",
        71 => "Motorola MC68HC08 Microcontroller",
        72 => "Motorola MC68HC08 Microcontroller",
        73 => "Silicon Graphics SVx",
        74 => "STMicroelectronics ST19 8-bit cpu",
        75 => "Digital VAX",
        76 => "Axis Communications 32-bit embedded processor",
        77 => "Infineon Technologies 32-bit embedded cpu",
        78 => "Element 14 64-bit DSP processor",
        79 => "LSI Logic's 16-bit DSP processor",
        80 => "Donald Knuth's educational 64-bit processor",
        81 => "Harvard's machine-independent format",
        82 => "SiTera Prism",
        83 => "Atmel AVR 8-bit microcontroller",
        84 => "Fujitsu FR30",
        85 => "Mitsubishi D10V",
        86 => "Mitsubishi D30V",
        87 => "NEC v850",
        88 => "Renesas M32R (formerly Mitsubishi M32R)",
        89 => "Matsushita MN10300",
        90 => "Matsushita MN10200",
        91 => "picoJava",
        92 => "OpenRISC 32-bit embedded processor",
        93 => "ARC Cores Tangent-A5",
        94 => "Tensilica Xtensa Architecture",
        95 => "Alphamosaic VideoCore processor",
        96 => "Thompson Multimedia General Purpose Processor",
        97 => "National Semiconductor 32000 series",
        98 => "Tenor Network TPC processor",
        99 => "Trebia SNP 1000 processor",
        100 => "STMicroelectronics ST200 microcontroller",
        101 => "Ubicom IP2022 micro controller",
        102 => "MAX Processor",
        103 => "National Semiconductor CompactRISC",
        104 => "Fujitsu F2MC16",
        105 => "TI msp430 micro controller",
        106 => "ADI Blackfin",
        107 => "S1C33 Family of Seiko Epson processors",
        108 => "Sharp embedded microprocessor",
        109 => "Arca RISC Microprocessor",
        110 => "Microprocessor series from PKU-Unity Ltd.",
        111 => "eXcess: 16/32/64-bit configurable embedded CPU",
        112 => "Icera Semiconductor Inc. Deep Execution Processor",
        113 => "Altera Nios II soft-core processor",
        114 => "National Semiconductor CRX",
        115 => "Motorola XGATE embedded processor",
        116 => "Infineon C16x/XC16x processor",
        117 => "Renesas M16C series microprocessors",
        118 => "Microchip Technology dsPIC30F DSignal Controller",
        119 => "Freescale Communication Engine RISC core",
        120 => "Renesas M32C series microprocessors",
        121..=130 => "Reserved",
        131 => "Altium TSK3000 core",
        132 => "Freescale RS08 embedded processor",
        133 => "Reserved",
        134 => "Cyan Technology eCOG2 microprocessor",
        135 => "Sunplus Score",
        136 => "New Japan Radio (NJR) 24-bit DSP Processor",
        137 => "Broadcom VideoCore III processor",
        138 => "RISC processor for Lattice FPGA architecture",
        139 => "Seiko Epson C17 family",
        140 => "Texas Instruments TMS320C6000 DSP family",
        141 => "Texas Instruments TMS320C2000 DSP family",
        142 => "Texas Instruments TMS320C55x DSP family",
        143..=159 => "Reserved",
        160 => "STMicroelectronics 64bit VLIW Data Signal Processor",
        161 => "Cypress M8C microprocessor",
        162 => "Renesas R32C series microprocessors",
        163 => "NXP Semiconductors TriMedia architecture family",
        164 => "QUALCOMM DSP6 Processor",
        165 => "Intel 8051 and variants",
        166 => "STMicroelectronics STxP7x family",
        167 => "Andes Technology embedded RISC processor family",
        168 => "Cyan Technology eCOG1X family",
        169 => "Dallas Semiconductor MAXQ30 Core Micro-controllers",
        170 => "New Japan Radio (NJR) 16-bit DSP Processor",
        171 => "M2000 Reconfigurable RISC Microprocessor",
        172 => "Cray Inc. NV2 vector architecture",
        173 => "Renesas RX family",
        174 => "Imagination Technologies META processor architecture",
        175 => "MCST Elbrus general purpose hardware architecture",
        176 => "Cyan Technology eCOG16 family",
        177 => "National Semiconductor CompactRISC 16-bit processor",
        178 => "Freescale Extended Time Processing Unit",
        179 => "Infineon Technologies SLE9X core",
        180 => "Intel L1OM",
        181 => "Reserved by Intel",
        182 => "Reserved by Intel",
        183 => "ARM AArch64",
        184 => "Reserved by ARM",
        185 => "Atmel Corporation 32-bit microprocessor family",
        186 => "STMicroeletronics STM8 8-bit microcontroller",
        187 => "Tilera TILE64 multicore architecture family",
        188 => "Tilera TILEPro multicore architecture family",
        189 => "Xilinx MicroBlaze 32-bit RISC soft processor core",
        190 => "NVIDIA CUDA architecture",
        191 => "Tilera TILE-Gx multicore architecture family",
        192 => "CloudShield architecture family",
        193 => "KIPO-KAIST Core-A 1st generation processor family",
        194 => "KIPO-KAIST Core-A 2nd generation processor family",
        195 => "Synopsys ARCompact V2",
        196 => "Open8 8-bit RISC soft processor core",
        197 => "Renesas RL78 family",
        198 => "Broadcom VideoCore V processor",
        199 => "Renesas 78KOR family",
        200 => "Freescale 56800EX Digital Signal Controller (DSC)",
        201 => "Beyond BA1 CPU architecture",
        202 => "Beyond BA2 CPU architecture",
        203 => "XMOS xCORE processor family",
        204 => "Microchip 8-bit PIC(r) family",
        205..=209 => "Reserved by Intel",
        210 => "KM211 KM32 32-bit processor",
        211 => "KM211 KMX32 32-bit processor",
        212 => "KM211 KMX16 16-bit processor",
        213 => "KM211 KMX8 8-bit processor",
        214 => "KM211 KVARC processor",
        215 => "Paneve CDP architecture family",
        216 => "Cognitive Smart Memory Processor",
        217 => "iCelero CoolEngine",
        218 => "Nanoradio Optimized RISC",
        219 => "CSR Kalimba architecture family",
        220 => "Zilog Z80",
        221 => "Controls and Data Services VISIUMcore processor",
        222 => "FTDI Chip FT32 high performance 32-bit RISC architecture",
        223 => "Moxie processor family",
        224 => "AMD GPU architecture",
        243 => "RISC-V",
        244 => "Lanai processor",
        245 => "CEVA Processor Architecture Family",
        246 => "CEVA X2 Processor Family",
        247 => "Linux BPF � in-kernel virtual machine",
        248 => "Graphcore Intelligent Processing Unit",
        249 => "Imagination Technologies",
        250 => "Netronome Flow Processor (P)",
        252 => "C-SKY processor family",
        253 => "Synopsys ARCv2.3 64-bit",
        254 => "MOS Technology MCS 6502 processor",
        255 => "Synopsys ARCv2.3 32-bit",
        256 => "Kalray VLIW core of the MPPA processor family",
        257 => "WDC 65816/65C816",
        258 => "Loongson Loongarch",
        259 => "ChipON KungFu32",
        9520 => "Morpho Techologies MT processor",
        36902 => "Alpha",
        16727 => "Web Assembly",
        23205 => "OpenDLX",
        44357 => "Sanyo XStormy16 CPU core",
        65210 => "Vitesse IQ2000",
        4075 => "Renesas M32C series microprocessors",
        65211 => "Altera Nios",
        61453 => "Toshiba MeP Media Engine",
        4643 => "Adapteva EPIPHANY",
        21569 => "Fujitsu FR-V",
        19951 => "Freescale S12Z",
        _ => "UNKNOWN",
    }
}

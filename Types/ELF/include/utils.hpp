#pragma once

#include "elf_types.hpp"
#include <map>

namespace GView::Type::ELF
{
static std::string_view GetNameFromElfClass(uint8 elfClass)
{
    switch (elfClass)
    {
    case ELFCLASSNONE:
        return "INVALID";
    case ELFCLASS32:
        return "32";
    case ELFCLASS64:
        return "64";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfData(uint8 elfData)
{
    switch (elfData)
    {
    case ELFDATANONE:
        return "INVALID";
    case ELFDATA2LSB:
        return "2LSB (Little)";
    case ELFDATA2MSB:
        return "2MSB (Big)";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfVersion(uint8 elfVersion)
{
    switch (elfVersion)
    {
    case EV_NONE:
        return "INVALID";
    case EV_CURRENT:
        return "CURRENT";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfOsAbi(uint8 elfOsAbi)
{
    switch (elfOsAbi)
    {
    case ELFOSABI_NONE:
        return "NONE";
    case ELFOSABI_HPUX:
        return "Hewlett-Packard HP-UX";
    case ELFOSABI_NETBSD:
        return "NetBSD";
    case ELFOSABI_LINUX:
        return "Linux";
    case ELFOSABI_SOLARIS:
        return "Sun Solaris";
    case ELFOSABI_AIX:
        return "AIX";
    case ELFOSABI_IRIX:
        return "IRIX";
    case ELFOSABI_FREEBSD:
        return "FreeBSD";
    case ELFOSABI_TRU64:
        return "Compaq TRU64 UNIX";
    case ELFOSABI_MODESTO:
        return "Novell Modesto";
    case ELFOSABI_OPENBSD:
        return "Open BSD";
    case ELFOSABI_OPENVMS:
        return "Open VMS";
    case ELFOSABI_CLOUDABI:
        return "Nuxi CloudABI";
    case ELFOSABI_ARM:
        return "ARM";
    case ELFOSABI_STANDALONE:
        return "Standalone (embedded) application";
    case ELFOSABI_NSK:
        return "Hewlett-Packard Non-Stop Kernel";
    case ELFOSABI_AROS:
        return "Amiga Research OS";
    case ELFOSABI_FENIXOS:
        return "The FenixOS highly scalable multi-core OS";
    case ELFOSABI_AMDGPU_HSA:
        return "AMDGPU OS for HSA compatible compute kernels";
    case ELFOSABI_AMDGPU_PAL:
        return "AMDGPU OS for AMD PAL compatible graphics";
    case ELFOSABI_AMDGPU_MESA3D:
        return "AMDGPU OS for Mesa3D compatible graphics";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfAbiVersion(uint8 elfOsAbi, uint8 elfAbiVersion)
{
    switch (elfOsAbi)
    {
    case ELFOSABI_AMDGPU_HSA:
        switch (elfAbiVersion)
        {
        case ELFABIVERSION_AMDGPU_HSA_V2:
            return "AMDGPU OS for HSA v2 compatible compute kernels";
        case ELFABIVERSION_AMDGPU_HSA_V3:
            return "AMDGPU OS for HSA v3 compatible compute kernels";
        case ELFABIVERSION_AMDGPU_HSA_V4:
            return "AMDGPU OS for HSA v4 compatible compute kernels";
        case ELFABIVERSION_AMDGPU_HSA_V5:
            return "AMDGPU OS for HSA v5 compatible compute kernels";
        default:
            return "UNKNOWN";
        }
    default:
        return "UNKNOWN";
    }
}

static std::pair<std::string_view, std::string_view> GetNameAndDecriptionFromElfType(uint16 elfType)
{
    switch (elfType)
    {
    case ET_NONE:
        return { "NONE", "An unknown type." };
    case ET_REL:
        return { "REL", "A relocatable file." };
    case ET_EXEC:
        return { "EXEC", "An executable file." };
    case ET_DYN:
        return { "DYN", "A shared object." };
    case ET_CORE:
        return { "CORE", "A core file." };
    default:
        return { "UNKNOWN", "An unknown type." };
    }
}

static std::string_view GetNameFromElfMachine(uint16 elfMachine)
{
    switch (elfMachine)
    {
    case EM_NONE:
        return "An unknown machine.";
    case EM_M32:
        return "AT&T WE 32100";
    case EM_SPARC:
        return "SUN SPARC";
    case EM_386:
        return "Intel 80386";
    case EM_68K:
        return "Motorola m68k family";
    case EM_88K:
        return "Motorola m88k family";
    case EM_486:
        return "Intel 80486";
    case EM_860:
        return "Intel 80860";
    case EM_MIPS:
        return "MIPS R3000 (officially, big-endian only)";
    case EM_S370:
        return "IBM System/370";
    case EM_MIPS_RS3_LE:
        return "MIPS R3000 little-endian (Deprecated)";
    case EM_res011:
    case EM_res012:
    case EM_res013:
    case EM_res014:
        return "Reserved";
    case EM_PARISC:
        return "HPPA";
    case EM_res016:
        return "Reserved";
    case EM_VPP550:
        return "Fujitsu VPP500";
    case EM_SPARC32PLUS:
        return "Sun\'s \"v8plus\"";
    case EM_960:
        return "Intel 80960";
    case EM_PPC:
        return "PowerPC";
    case EM_PPC64:
        return "64-bit PowerPC";
    case EM_S390:
        return "IBM S/390";
    case EM_SPU:
        return "Sony/Toshiba/IBM SPU";
    case EM_res024:
    case EM_res025:
    case EM_res026:
    case EM_res027:
    case EM_res028:
    case EM_res029:
    case EM_res030:
    case EM_res031:
    case EM_res032:
    case EM_res033:
    case EM_res034:
    case EM_res035:
        return "Reserved";
    case EM_V800:
        return "NEC V800 series";
    case EM_FR20:
        return "Fujitsu FR20";
    case EM_RH32:
        return "TRW RH32";
    case EM_MCORE:
        return "Motorola M*Core (May also be taken by Fujitsu MMA)";
    case EM_ARM:
        return "ARM";
    case EM_OLD_ALPHA:
        return "Digital Alpha";
    case EM_SH:
        return "Renesas (formerly Hitachi) / SuperH SH";
    case EM_SPARCV9:
        return "SPARC v9 64-bit";
    case EM_TRICORE:
        return "Siemens Tricore embedded processor";
    case EM_ARC:
        return "ARC Cores";
    case EM_H8_300:
        return "Renesas (formerly Hitachi) H8/300";
    case EM_H8_300H:
        return "Renesas (formerly Hitachi) H8/300H";
    case EM_H8S:
        return "Renesas (formerly Hitachi) H8S";
    case EM_H8_500:
        return "Renesas (formerly Hitachi) H8/500";
    case EM_IA_64:
        return "Intel IA-64 Processor";
    case EM_MIPS_X:
        return "Stanford MIPS-X";
    case EM_COLDFIRE:
        return "Motorola Coldfire";
    case EM_68HC12:
        return "Motorola M68HC12";
    case EM_MMA:
        return "Fujitsu Multimedia Accelerator";
    case EM_PCP:
        return "Siemens PCP";
    case EM_NCPU:
        return "Sony nCPU embedded RISC processor";
    case EM_NDR1:
        return "Denso NDR1 microprocessor";
    case EM_STARCORE:
        return "Motorola Star*Core processor";
    case EM_ME16:
        return "Toyota ME16 processor";
    case EM_ST100:
        return "STMicroelectronics ST100 processor";
    case EM_TINYJ:
        return "Advanced Logic Corp. TinyJ embedded processor";
    case EM_X86_64:
        return "Advanced Micro Devices X86-64 processor";
    case EM_PDSP:
        return "Sony DSP Processor";
    case EM_PDP10:
        return "Digital Equipment Corp. PDP-10";
    case EM_PDP11:
        return "Digital Equipment Corp. PDP-11";
    case EM_FX66:
        return "Siemens FX66 microcontroller";
    case EM_ST9PLUS:
        return "STMicroelectronics ST9+ 8/16 bit microcontroller";
    case EM_ST7:
        return "STMicroelectronics ST7 8-bit microcontroller";
    case EM_68HC16:
        return "Motorola MC68HC16 Microcontroller";
    case EM_68HC11:
        return "Motorola MC68HC11 Microcontroller";
    case EM_68HC08:
        return "Motorola MC68HC08 Microcontroller";
    case EM_68HC05:
        return "Motorola MC68HC08 Microcontroller";
    case EM_SVX:
        return "Silicon Graphics SVx";
    case EM_ST19:
        return "STMicroelectronics ST19 8-bit cpu";
    case EM_VAX:
        return "Digital VAX";
    case EM_CRIS:
        return "Axis Communications 32-bit embedded processor";
    case EM_JAVELIN:
        return "Infineon Technologies 32-bit embedded cpu";
    case EM_FIREPATH:
        return "Element 14 64-bit DSP processor";
    case EM_ZSP:
        return "LSI Logic's 16-bit DSP processor";
    case EM_MMIX:
        return "Donald Knuth\'s educational 64-bit processor";
    case EM_HUANY:
        return "Harvard's machine-independent format";
    case EM_PRISM:
        return "SiTera Prism";
    case EM_AVR:
        return "Atmel AVR 8-bit microcontroller";
    case EM_FR30:
        return "Fujitsu FR30";
    case EM_D10V:
        return "Mitsubishi D10V";
    case EM_D30V:
        return "Mitsubishi D30V";
    case EM_V850:
        return "NEC v850";
    case EM_M32R:
        return "Renesas M32R (formerly Mitsubishi M32R)";
    case EM_MN10300:
        return "Matsushita MN10300";
    case EM_MN10200:
        return "Matsushita MN10200";
    case EM_PJ:
        return "picoJava";
    case EM_OPENRISC:
        return "OpenRISC 32-bit embedded processor";
    case EM_ARC_A5:
        return "ARC Cores Tangent-A5";
    case EM_XTENSA:
        return "Tensilica Xtensa Architecture";
    case EM_VIDEOCORE:
        return "Alphamosaic VideoCore processor";
    case EM_TMM_GPP:
        return "Thompson Multimedia General Purpose Processor";
    case EM_NS32K:
        return "National Semiconductor 32000 series";
    case EM_TPC:
        return "Tenor Network TPC processor";
    case EM_SNP1K:
        return "Trebia SNP 1000 processor";
    case EM_ST200:
        return "STMicroelectronics ST200 microcontroller";
    case EM_IP2K:
        return "Ubicom IP2022 micro controller";
    case EM_MAX:
        return "MAX Processor";
    case EM_CR:
        return "National Semiconductor CompactRISC";
    case EM_F2MC16:
        return "Fujitsu F2MC16";
    case EM_MSP430:
        return "TI msp430 micro controller";
    case EM_BLACKFIN:
        return "ADI Blackfin";
    case EM_SE_C33:
        return "S1C33 Family of Seiko Epson processors";
    case EM_SEP:
        return "Sharp embedded microprocessor";
    case EM_ARCA:
        return "Arca RISC Microprocessor";
    case EM_UNICORE:
        return "Microprocessor series from PKU-Unity Ltd.";
    case EM_EXCESS:
        return "eXcess: 16/32/64-bit configurable embedded CPU";
    case EM_DXP:
        return "Icera Semiconductor Inc. Deep Execution Processor";
    case EM_ALTERA_NIOS2:
        return "Altera Nios II soft-core processor";
    case EM_CRX:
        return "National Semiconductor CRX";
    case EM_XGATE:
        return "Motorola XGATE embedded processor";
    case EM_C166:
        return "Infineon C16x/XC16x processor";
    case EM_M16C:
        return "Renesas M16C series microprocessors";
    case EM_DSPIC30F:
        return "Microchip Technology dsPIC30F DSignal Controller";
    case EM_CE:
        return "Freescale Communication Engine RISC core";
    case EM_M32C:
        return "Renesas M32C series microprocessors";
    case EM_res121:
    case EM_res122:
    case EM_res123:
    case EM_res124:
    case EM_res125:
    case EM_res126:
    case EM_res127:
    case EM_res128:
    case EM_res129:
    case EM_res130:
        return "Reserved";
    case EM_TSK3000:
        return "Altium TSK3000 core";
    case EM_RS08:
        return "Freescale RS08 embedded processor";
    case EM_res133:
        return "Reserved";
    case EM_ECOG2:
        return "Cyan Technology eCOG2 microprocessor";
    case EM_SCORE:
        return "Sunplus Score";
    case EM_DSP24:
        return "New Japan Radio (NJR) 24-bit DSP Processor";
    case EM_VIDEOCORE3:
        return "Broadcom VideoCore III processor";
    case EM_LATTICEMICO32:
        return "RISC processor for Lattice FPGA architecture";
    case EM_SE_C17:
        return "Seiko Epson C17 family";
    case EM_TI_C6000:
        return "Texas Instruments TMS320C6000 DSP family";
    case EM_TI_C2000:
        return "Texas Instruments TMS320C2000 DSP family";
    case EM_TI_C5500:
        return "Texas Instruments TMS320C55x DSP family";
    case EM_res143:
    case EM_res144:
    case EM_res145:
    case EM_res146:
    case EM_res147:
    case EM_res148:
    case EM_res149:
    case EM_res150:
    case EM_res151:
    case EM_res152:
    case EM_res153:
    case EM_res154:
    case EM_res155:
    case EM_res156:
    case EM_res157:
    case EM_res158:
    case EM_res159:
        return "Reserved";
    case EM_MMDSP_PLUS:
        return "STMicroelectronics 64bit VLIW Data Signal Processor";
    case EM_CYPRESS_M8C:
        return "Cypress M8C microprocessor";
    case EM_R32C:
        return "Renesas R32C series microprocessors";
    case EM_TRIMEDIA:
        return "NXP Semiconductors TriMedia architecture family";
    case EM_QDSP6:
        return "QUALCOMM DSP6 Processor";
    case EM_8051:
        return "Intel 8051 and variants";
    case EM_STXP7X:
        return "STMicroelectronics STxP7x family";
    case EM_NDS32:
        return "Andes Technology embedded RISC processor family";
    case EM_ECOG1:
        return "Cyan Technology eCOG1X family";
    case EM_MAXQ30:
        return "Dallas Semiconductor MAXQ30 Core Micro-controllers";
    case EM_XIMO16:
        return "New Japan Radio (NJR) 16-bit DSP Processor";
    case EM_MANIK:
        return "M2000 Reconfigurable RISC Microprocessor";
    case EM_CRAYNV2:
        return "Cray Inc. NV2 vector architecture";
    case EM_RX:
        return "Renesas RX family";
    case EM_METAG:
        return "Imagination Technologies META processor architecture";
    case EM_MCST_ELBRUS:
        return "MCST Elbrus general purpose hardware architecture";
    case EM_ECOG16:
        return "Cyan Technology eCOG16 family";
    case EM_CR16:
        return "National Semiconductor CompactRISC 16-bit processor";
    case EM_ETPU:
        return "Freescale Extended Time Processing Unit";
    case EM_SLE9X:
        return "Infineon Technologies SLE9X core";
    case EM_L1OM:
        return "Intel L1OM";
    case EM_INTEL181:
        return "Reserved by Intel";
    case EM_INTEL182:
        return "Reserved by Intel";
    case EM_AARCH64:
        return "ARM AArch64";
    case EM_res184:
        return "Reserved by ARM";
    case EM_AVR32:
        return "Atmel Corporation 32-bit microprocessor family";
    case EM_STM8:
        return "STMicroeletronics STM8 8-bit microcontroller";
    case EM_TILE64:
        return "Tilera TILE64 multicore architecture family";
    case EM_TILEPRO:
        return "Tilera TILEPro multicore architecture family";
    case EM_MICROBLAZE:
        return "Xilinx MicroBlaze 32-bit RISC soft processor core";
    case EM_CUDA:
        return "NVIDIA CUDA architecture";
    case EM_TILEGX:
        return "Tilera TILE-Gx multicore architecture family";
    case EM_CLOUDSHIELD:
        return "CloudShield architecture family";
    case EM_COREA_1ST:
        return "KIPO-KAIST Core-A 1st generation processor family";
    case EM_COREA_2ND:
        return "KIPO-KAIST Core-A 2nd generation processor family";
    case EM_ARC_COMPACT2:
        return "Synopsys ARCompact V2";
    case EM_OPEN8:
        return "Open8 8-bit RISC soft processor core";
    case EM_RL78:
        return "Renesas RL78 family";
    case EM_VIDEOCORE5:
        return "Broadcom VideoCore V processor";
    case EM_78KOR:
        return "Renesas 78KOR family";
    case EM_56800EX:
        return "Freescale 56800EX Digital Signal Controller (DSC)";
    case EM_BA1:
        return "Beyond BA1 CPU architecture";
    case EM_BA2:
        return "Beyond BA2 CPU architecture";
    case EM_XCORE:
        return "XMOS xCORE processor family";
    case EM_MCHP_PIC:
        return "Microchip 8-bit PIC(r) family";
    case EM_INTEL205:
    case EM_INTEL206:
    case EM_INTEL207:
    case EM_INTEL208:
    case EM_INTEL209:
        return "Reserved by Intel";
    case EM_KM32:
        return "KM211 KM32 32-bit processor";
    case EM_KMX32:
        return "KM211 KMX32 32-bit processor";
    case EM_KMX16:
        return "KM211 KMX16 16-bit processor";
    case EM_KMX8:
        return "KM211 KMX8 8-bit processor";
    case EM_KVARC:
        return "KM211 KVARC processor";
    case EM_CDP:
        return "Paneve CDP architecture family";
    case EM_COGE:
        return "Cognitive Smart Memory Processor";
    case EM_COOL:
        return "iCelero CoolEngine";
    case EM_NORC:
        return "Nanoradio Optimized RISC";
    case EM_CSR_KALIMBA:
        return "CSR Kalimba architecture family";
    case EM_Z80:
        return "Zilog Z80";
    case EM_VISIUM:
        return "Controls and Data Services VISIUMcore processor";
    case EM_FT32:
        return "FTDI Chip FT32 high performance 32-bit RISC architecture";
    case EM_MOXIE:
        return "Moxie processor family";
    case EM_AMDGPU:
        return "AMD GPU architecture";
    case EM_RISCV:
        return "RISC-V";
    case EM_LANAI:
        return "Lanai processor";
    case EM_CEVA:
        return "CEVA Processor Architecture Family";
    case EM_CEVA_X2:
        return "CEVA X2 Processor Family";
    case EM_BPF:
        return "Linux BPF – in-kernel virtual machine";
    case EM_GRAPHCORE_IPU:
        return "Graphcore Intelligent Processing Unit";
    case EM_IMG1:
        return "Imagination Technologies";
    case EM_NFP:
        return "Netronome Flow Processor (P)";
    case EM_CSKY:
        return "C-SKY processor family";
    case EM_ARC_COMPACT3_64:
        return "Synopsys ARCv2.3 64-bit";
    case EM_MCS6502:
        return "MOS Technology MCS 6502 processor";
    case EM_ARC_COMPACT3:
        return "Synopsys ARCv2.3 32-bit";
    case EM_KVX:
        return "Kalray VLIW core of the MPPA processor family";
    case EM_65816:
        return "WDC 65816/65C816";
    case EM_LOONGARCH:
        return "Loongson Loongarch";
    case EM_KF32:
        return "ChipON KungFu32";

    case EM_MT:
        return "Morpho Techologies MT processor";
    case EM_ALPHA:
        return "Alpha";
    case EM_WEBASSEMBLY:
        return "Web Assembly";
    case EM_DLX:
        return "OpenDLX";
    case EM_XSTORMY16:
        return "Sanyo XStormy16 CPU core";
    case EM_IQ2000:
        return "Vitesse IQ2000";
    case EM_M32C_OLD:
        return "Renesas M32C series microprocessors";
    case EM_NIOS32:
        return "Altera Nios";
    case EM_CYGNUS_MEP:
        return "Toshiba MeP Media Engine";
    case EM_ADAPTEVA_EPIPHANY:
        return "Adapteva EPIPHANY";
    case EM_CYGNUS_FRV:
        return "Fujitsu FR-V";
    case EM_S12Z:
        return "Freescale S12Z";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfProgramHeaderType(uint32 programHeaderType)
{
    switch (programHeaderType)
    {
    case PT_NULL:
        return "UNDEFINED";
    case PT_LOAD:
        return "LOAD";
    case PT_DYNAMIC:
        return "DYNAMIC";
    case PT_INTERP:
        return "INTERP";
    case PT_NOTE:
        return "NOTE";
    case PT_SHLIB:
        return "SHLIB";
    case PT_PHDR:
        return "PHDR";
    case PT_TLS:
        return "TLS";
    case PT_LOOS:
        return "LOOS";
    case PT_GNU_EH_FRAME:
        return "EH_FRAME";
    case PT_GNU_STACK:
        return "GNU_STACK";
    case PT_GNU_RELRO:
        return "GNU_RELRO";
    case PT_GNU_PROPERTY:
        return "GNU_PROPERTY";
    case PT_GNU_MBIND_LO:
        return "GNU_MBIND_LO";
    case PT_GNU_MBIND_HI:
        return "GNU_MBIND_HI";
    case PT_PAX_FLAGS:
        return "PAX_FLAGS";
    case PT_OPENBSD_RANDOMIZE:
        return "OPENBSD_RANDOMIZ";
    case PT_OPENBSD_WXNEEDED:
        return "OPENBSD_WXNEEDED";
    case PT_OPENBSD_BOOTDATA:
        return "OPENBSD_BOOTDATA";
    case PT_SUNWSTACK:
        return "SUNWSTACK";
    case PT_HIOS:
        return "HIOS";
    case PT_LOPROC:
        return "LOPROC";
    case PT_HIPROC:
        return "HIPROC";
    default:
        return "UNKNOWN";
    }
}

static const std::string GetPermissionsFromSegmentFlags(uint32 segmentFlags)
{
    std::string permissions = "---";

    if (segmentFlags & PF_R)
    {
        permissions[0] = 'R';
    }

    if (segmentFlags & PF_W)
    {
        permissions[1] = 'W';
    }

    if (segmentFlags & PF_X)
    {
        permissions[2] = 'X';
    }

    return permissions;
}

static const std::string GetPermissionsFromSegmentPaxFlags(uint32 segmentPaxFlags)
{
    /*
        PF_PAGEEXEC PF_NOPAGEEXEC
        PF_SEGMEXEC PF_NOSEGMEXEC
        PF_EMUTRAMP PF_NOEMUTRAMP
        PF_MPROTECT PF_NOMPROTECT
        PF_RANDMMAP PF_NORANDMMAP
        PF_RANDEXEC PF_NORANDEXEC

        P	PAGEEXEC	Refuse code execution on writable pages based on the NX bit(or emulated NX bit)
        S	SEGMEXEC	Refuse code execution on writable pages based on the segmentation logic of IA - 32
        E	EMUTRAMP	Allow known code execution sequences on writable pages that should not cause any harm
        M	MPROTECT	Prevent the creation of new executable code to the process address space
        R	RANDMMAP	Randomize the stack base to prevent certain stack overflow attacks from being successful
        X	RANDEXEC	Randomize the address where the application maps to prevent certain attacks from being exploitable
    */

    static const std::initializer_list<uint32> types{ PF_PAGEEXEC, PF_NOPAGEEXEC, PF_SEGMEXEC, PF_NOSEGMEXEC, PF_EMUTRAMP, PF_NOEMUTRAMP,
                                                      PF_MPROTECT, PF_NOMPROTECT, PF_RANDMMAP, PF_NORANDMMAP, PF_RANDEXEC, PF_NORANDEXEC };

    static const std::map<uint32, std::string_view> PaxFlagsNames{
        { PF_PAGEEXEC, "PAGEEXEC" }, { PF_NOPAGEEXEC, "NOPAGEEXEC" }, { PF_SEGMEXEC, "SEGMEXEC" }, { PF_NOSEGMEXEC, "NOSEGMEXEC" },
        { PF_EMUTRAMP, "EMUTRAMP" }, { PF_NOEMUTRAMP, "NOEMUTRAMP" }, { PF_MPROTECT, "MPROTECT" }, { PF_NOMPROTECT, "NOMPROTECT" },
        { PF_RANDMMAP, "RANDMMAP" }, { PF_NORANDMMAP, "NORANDMMAP" }, { PF_RANDEXEC, "RANDEXEC" }, { PF_NORANDEXEC, "NORANDEXEC" }
    };

    std::string output;
    if (segmentPaxFlags == 0)
    {
        output = "NONE";
    }
    else
    {
        for (const auto& t : types)
        {
            if ((segmentPaxFlags & t) == t)
            {
                if (output.empty())
                {
                    output += PaxFlagsNames.at(t);
                }
                else
                {
                    output += " | ";
                    output += PaxFlagsNames.at(t);
                }
            }
        }
    }

    return "[" + output + "]";
};

static std::string_view GetNameFromSectionType(uint32 sectionType)
{
    switch (sectionType)
    {
    case SHT_NULL:
        return "NULL";
    case SHT_PROGBITS:
        return "PROGBITS";
    case SHT_SYMTAB:
        return "SYMTAB";
    case SHT_STRTAB:
        return "STRTAB";
    case SHT_RELA:
        return "RELA";
    case SHT_HASH:
        return "HASH";
    case SHT_DYNAMIC:
        return "DYNAMIC";
    case SHT_NOTE:
        return "NOTE";
    case SHT_NOBITS:
        return "NOBITS";
    case SHT_REL:
        return "REL";
    case SHT_SHLIB:
        return "SHLIB";
    case SHT_DYNSYM:
        return "DYNSYM";
    case SHT_INIT_ARRAY:
        return "INIT_ARRAY";
    case SHT_FINI_ARRAY:
        return "FINI_ARRAY";
    case SHT_PREINIT_ARRAY:
        return "PREINIT_ARRAY";
    case SHT_GROUP:
        return "GROUP";
    case SHT_SYMTAB_SHNDX:
        return "SYMTAB_SHNDX";
    case SHT_GNU_ATTRIBUTES:
        return "GNU_ATTRIBUTES";
    case SHT_GNU_HASH:
        return "GNU_HASH";
    case SHT_GNU_LIBLIST:
        return "GNU_LIBLIST";
    case SHT_CHECKSUM:
        return "CHECKSUM";
    case SHT_LOSUNW:
        return "LOSUNW";
    case SHT_SUNW_COMDAT:
        return "SUNW_COMDAT";
    case SHT_SUNW_syminfo:
        return "SUNW_syminfo";
    case SHT_GNU_verdef:
        return "GNU_verdef";
    case SHT_GNU_verneed:
        return "GNU_verneed";
    case SHT_GNU_versym:
        return "GNU_versym";
    case SHT_LOOS:
        return "LOOS";
    case SHT_LOPROC:
        return "LOPROC";
    case SHT_HIPROC:
        return "HIPROC";
    case SHT_LOUSER:
        return "LOUSER";
    case SHT_HIUSER:
        return "HIUSER";
    default:
        return "UNKNOWN";
    }
}

static const std::string GetNamesFromSectionFlags(uint64 sectionFlags)
{
    static const std::initializer_list<uint32> types{ SHF_WRITE,     SHF_ALLOC,      SHF_EXECINSTR,        SHF_MERGE, SHF_STRINGS,
                                                      SHF_INFO_LINK, SHF_LINK_ORDER, SHF_OS_NONCONFORMING, SHF_GROUP, SHF_TLS };

    static const std::map<uint64, std::string_view> FlagsNames{
        { SHF_WRITE, "WRITE" },           { SHF_ALLOC, "ALLOC" },
        { SHF_EXECINSTR, "EXECINSTR" },   { SHF_MERGE, "MERGE" },
        { SHF_STRINGS, "STRINGS" },       { SHF_INFO_LINK, "INFO_LINK" },
        { SHF_LINK_ORDER, "LINK_ORDER" }, { SHF_OS_NONCONFORMING, "OS_NONCONFORMING" },
        { SHF_GROUP, "GROUP" },           { SHF_TLS, "TLS" }
    };

    std::string output;
    if (sectionFlags == 0)
    {
        output = "NONE";
    }
    else
    {
        for (const auto& t : types)
        {
            if ((sectionFlags & t) == t)
            {
                if (output.empty())
                {
                    output += FlagsNames.at(t);
                }
                else
                {
                    output += " | ";
                    output += FlagsNames.at(t);
                }
            }
        }
    }

    return "[" + output + "]";
};
} // namespace GView::Type::ELF

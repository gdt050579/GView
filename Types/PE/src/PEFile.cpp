#include "pe.hpp"
#include "DigitalSignature.hpp"

using namespace GView::Type::PE;

struct CV_INFO_PDB20
{
    uint32 CvSignature;   // NBxx
    uint32 Offset;        // Always 0 for NB10
    uint32 Signature;     // seconds since 01.01.1970
    uint32 Age;           // an always-incrementing value
    uint8 PdbFileName[1]; // zero terminated string with the name of the PDB file
};

struct CV_INFO_PDB70
{
    uint32 CvSignature;
    Guid Signature;       // unique identifier
    uint32 Age;           // an always-incrementing value
    uint8 PdbFileName[1]; // zero terminated string with the name of the PDB file
};

#define CV_SIGNATURE_NB10 '01BN'
#define CV_SIGNATURE_RSDS 'SDSR'

#define ADD_PANEL(id) this->panelsMask |= (1ULL << (uint8) id);

static std::string_view peDirsNames[15] = { "Export",      "Import",       "Resource",     "Exceptions",        "Security",
                                            "Base Reloc",  "Debug",        "Architecture", "Global Ptr",        "TLS",
                                            "Load Config", "Bound Import", "IAT",          "Delay Import Desc", "COM+ Runtime" };

static std::map<uint32, std::string_view> languageCode = {
    { 0, "None" },
    { 1025, "Arabic (Saudi Arabia)" },
    { 1026, "Bulgarian" },
    { 1027, "Catalan" },
    { 1028, "Chinese (Taiwan)" },
    { 1029, "Czech" },
    { 1030, "Danish" },
    { 1031, "German (Germany)" },
    { 1032, "Greek" },
    { 1033, "English (United States)" },
    { 1034, "Spanish (Traditional Sort)" },
    { 1035, "Finnish" },
    { 1036, "French (France)" },
    { 1037, "Hebrew" },
    { 1038, "Hungarian" },
    { 1039, "Icelandic" },
    { 1040, "Italian (Italy)" },
    { 1041, "Japanese" },
    { 1042, "Korean" },
    { 1043, "Dutch (Netherlands)" },
    { 1044, "Norwegian (Bokmal)" },
    { 1045, "Polish" },
    { 1046, "Portuguese (Brazil)" },
    { 1047, "Rhaeto-Romanic" },
    { 1048, "Romanian" },
    { 1049, "Russian" },
    { 1050, "Croatian" },
    { 1051, "Slovak" },
    { 1052, "Albanian" },
    { 1053, "Swedish" },
    { 1054, "Thai" },
    { 1055, "Turkish" },
    { 1056, "Urdu" },
    { 1057, "Indonesian" },
    { 1058, "Ukrainian" },
    { 1059, "Belarusian" },
    { 1060, "Slovenian" },
    { 1061, "Estonian" },
    { 1062, "Latvian" },
    { 1063, "Lithuanian" },
    { 1064, "Tajik" },
    { 1065, "Farsi" },
    { 1066, "Vietnamese" },
    { 1067, "Armenian" },
    { 1068, "Azeri (Latin)" },
    { 1069, "Basque" },
    { 1070, "Sorbian" },
    { 1071, "FYRO Macedonian" },
    { 1072, "Sutu" },
    { 1072, "Sesotho" },
    { 1073, "Tsonga" },
    { 1074, "Tswana" },
    { 1075, "Venda" },
    { 1076, "Xhosa" },
    { 1077, "Zulu" },
    { 1078, "Afrikaans" },
    { 1079, "Georgian" },
    { 1080, "Faroese" },
    { 1081, "Hindi" },
    { 1082, "Maltese" },
    { 1083, "Sami Lappish" },
    { 1084, "Gaelic Scotland" },
    { 1085, "Yiddish" },
    { 1086, "Malay (Malaysia)" },
    { 1087, "Kazakh" },
    { 1088, "Kyrgyz (Cyrillic)" },
    { 1089, "Swahili" },
    { 1090, "Turkmen" },
    { 1091, "Uzbek (Latin)" },
    { 1092, "Tatar" },
    { 1093, "Bengali (India)" },
    { 1094, "Punjabi" },
    { 1095, "Gujarati" },
    { 1096, "Oriya" },
    { 1097, "Tamil" },
    { 1098, "Telugu" },
    { 1099, "Kannada" },
    { 1100, "Malayalam" },
    { 1101, "Assamese" },
    { 1102, "Marathi" },
    { 1103, "Sanskrit" },
    { 1104, "Mongolian (Cyrillic)" },
    { 1105, "Tibetan" },
    { 1106, "Welsh" },
    { 1107, "Khmer" },
    { 1108, "Lao" },
    { 1109, "Burmese" },
    { 1110, "Galician" },
    { 1111, "Konkani" },
    { 1112, "Manipuri" },
    { 1113, "Sindhi" },
    { 1114, "Syriac" },
    { 1115, "Sinhalese (Sri Lanka)" },
    { 1118, "Amharic (Ethiopia)" },
    { 1120, "Kashmiri" },
    { 1121, "Nepali" },
    { 1122, "Frisian (Netherlands)" },
    { 1124, "Filipino" },
    { 1125, "Divehi" },
    { 1126, "Edo" },
    { 1136, "Igbo (Nigeria)" },
    { 1140, "Guarani (Paraguay)" },
    { 1142, "Latin" },
    { 1143, "Somali" },
    { 1153, "Maori (New Zealand)" },
    { 1279, "HID (Human Interface Device)" },
    { 2049, "Arabic (Iraq)" },
    { 2052, "Chinese (PRC)" },
    { 2055, "German (Switzerland)" },
    { 2057, "English (United Kingdom)" },
    { 2058, "Spanish (Mexico)" },
    { 2060, "French (Belgium)" },
    { 2064, "Italian (Switzerland)" },
    { 2067, "Dutch (Belgium)" },
    { 2068, "Norwegian (Nynorsk)" },
    { 2070, "Portuguese (Portugal)" },
    { 2072, "Romanian (Moldova)" },
    { 2073, "Russian (Moldova)" },
    { 2074, "Serbian (Latin)" },
    { 2077, "Swedish (Finland)" },
    { 2092, "Azeri (Cyrillic)" },
    { 2108, "Gaelic Ireland" },
    { 2110, "Malay (Brunei Darussalam)" },
    { 2115, "Uzbek (Cyrillic)" },
    { 2117, "Bengali (Bangladesh)" },
    { 2128, "Mongolian (Mongolia)" },
    { 3073, "Arabic (Egypt)" },
    { 3076, "Chinese (Hong Kong S.A.R.)" },
    { 3079, "German (Austria)" },
    { 3081, "English (Australia)" },
    { 3082, "Spanish (International Sort)" },
    { 3084, "French (Canada)" },
    { 3098, "Serbian (Cyrillic)" },
    { 4097, "Arabic (Libya)" },
    { 4100, "Chinese (Singapore)" },
    { 4103, "German (Luxembourg)" },
    { 4105, "English (Canada)" },
    { 4106, "Spanish (Guatemala)" },
    { 4108, "French (Switzerland)" },
    { 4122, "Croatian (Bosnia/Herzegovina)" },
    { 5121, "Arabic (Algeria)" },
    { 5124, "Chinese (Macau S.A.R.)" },
    { 5127, "German (Liechtenstein)" },
    { 5129, "English (New Zealand)" },
    { 5130, "Spanish (Costa Rica)" },
    { 5132, "French (Luxembourg)" },
    { 5146, "Bosnian (Bosnia/Herzegovina)" },
    { 6145, "Arabic (Morocco)" },
    { 6153, "English (Ireland)" },
    { 6154, "Spanish (Panama)" },
    { 6156, "French (Monaco)" },
    { 7169, "Arabic (Tunisia)" },
    { 7177, "English (South Africa)" },
    { 7178, "Spanish (Dominican Republic)" },
    { 7180, "French (West Indies)" },
    { 8193, "Arabic (Oman)" },
    { 8201, "English (Jamaica)" },
    { 8202, "Spanish (Venezuela)" },
    { 9217, "Arabic (Yemen)" },
    { 9225, "English (Caribbean)" },
    { 9226, "Spanish (Colombia)" },
    { 9228, "French (Congo, DRC)" },
    { 10241, "Arabic (Syria)" },
    { 10249, "English (Belize)" },
    { 10250, "Spanish (Peru)" },
    { 10252, "French (Senegal)" },
    { 11265, "Arabic (Jordan)" },
    { 11273, "English (Trinidad)" },
    { 11274, "Spanish (Argentina)" },
    { 11276, "French (Cameroon)" },
    { 12289, "Arabic (Lebanon)" },
    { 12297, "English (Zimbabwe)" },
    { 12298, "Spanish (Ecuador)" },
    { 12300, "French (Cote d'Ivoire)" },
    { 13313, "Arabic (Kuwait)" },
    { 13321, "English (Philippines)" },
    { 13322, "Spanish (Chile)" },
    { 13324, "French (Mali)" },
    { 14337, "Arabic (U.A.E.)" },
    { 14346, "Spanish (Uruguay)" },
    { 14348, "French (Morocco)" },
    { 15361, "Arabic (Bahrain)" },
    { 15370, "Spanish (Paraguay)" },
    { 16385, "Arabic (Qatar)" },
    { 16393, "English (India)" },
    { 16394, "Spanish (Bolivia)" },
    { 17418, "Spanish (El Salvador)" },
    { 18442, "Spanish (Honduras)" },
    { 19466, "Spanish (Nicaragua)" },
    { 20490, "Spanish (Puerto Rico)" },
};

inline static uint32 SectionALIGN(uint32 value, uint32 alignValue)
{
    if (alignValue == 0)
        return value;
    if (value == 0)
        return alignValue;
    if ((value % alignValue) == 0)
        return value;
    return ((value / alignValue) + 1) * alignValue;
}

PEFile::PEFile()
{
    uint32_t tr;
    // creez vectorii pt. exporturi / importuri
    res.reserve(64);
    exp.reserve(64);
    debugData.reserve(16);
    impDLL.reserve(64);
    impFunc.reserve(128);

    peCols.colMZ      = ColorPair{ Color::Olive, Color::Transparent };
    peCols.colPE      = ColorPair{ Color::Magenta, Color::Transparent };
    peCols.colSectDef = ColorPair{ Color::DarkRed, Color::Transparent };
    peCols.colSect    = ColorPair{ Color::Silver, Color::Transparent };

    peCols.colDir[0] = ColorPair{ Color::Aqua, Color::Transparent };
    peCols.colDir[1] = ColorPair{ Color::Red, Color::Transparent };
    for (tr = 2; tr < 15; tr++)
        peCols.colDir[tr] = ColorPair{ Color::Green, Color::Transparent };
    peCols.colDir[(uint8_t) DirectoryType::Security] = ColorPair{ Color::Teal, Color::Transparent };

    asmShow    = 0xFF;
    panelsMask = 0;
}

std::string_view PEFile::ReadString(uint32 RVA, uint32 maxSize)
{
    const auto fa = RVAToFA(RVA);
    auto buf      = obj->GetData().Get(fa, maxSize, true);
    if (buf.IsValid() == false || buf.Empty())
    {
        return std::string_view{};
    }

    auto p       = buf.begin();
    const auto e = buf.end();
    while ((p < e) && (*p) && isprint(*p) != 0)
    {
        p++;
    }

    return std::string_view{ reinterpret_cast<const char*>(buf.GetData()), static_cast<size_t>(p - buf.GetData()) };
}

bool PEFile::ReadUnicodeLengthString(uint32 FileAddress, char* text, uint32 maxSize)
{
    uint16 sz, tr;
    uint8 val;
    uint64 addr = FileAddress;
    if ((obj->GetData().Copy<uint16>(addr, sz) == false) || (sz > 256))
        return false;

    for (tr = 0, addr += 2; (tr < sz) && ((uint32) tr < maxSize - 1U) && (obj->GetData().Copy<uint8>(addr, val)) && (val != 0); tr++, addr += 2)
        text[tr] = val;
    text[tr] = 0;

    return true;
}

uint64 PEFile::VAtoFA(uint64 va) const
{
    const auto rva = va - imageBase;

    CHECK(nrSections > 0, PE_INVALID_ADDRESS, "");
    CHECK(rva >= sect[0].VirtualAddress, PE_INVALID_ADDRESS, "");

    for (uint32 i = 0; i < nrSections; i++)
    {
        const auto start = sect[i].VirtualAddress;
        const auto end   = start + sect[i].Misc.VirtualSize;
        if (rva >= start && rva < end)
        {
            return rva - sect[i].VirtualAddress + sect[i].PointerToRawData;
        }
    }

    RETURNERROR(PE_INVALID_ADDRESS, "Address not found!");
}

uint64 PEFile::RVAToFA(uint64 RVA)
{
    if (RVA < sect[0].VirtualAddress)
        return PE_INVALID_ADDRESS;

    if (nrSections == 0)
        return PE_INVALID_ADDRESS;

    uint64 tr;
    uint64 fi = 0;
    for (tr = 0; tr < nrSections; tr++)
    {
        if (RVA < sect[tr].VirtualAddress && tr > 0)
        {
            fi = (uint64) sect[tr - 1].PointerToRawData + (RVA - (uint64) sect[tr - 1].VirtualAddress);
            break;
        };
    }

    if (tr == nrSections)
    {
        fi = (uint64) sect[tr - 1].PointerToRawData + ((uint64) RVA - (uint64) sect[tr - 1].VirtualAddress);
    }

    return fi;
}

int32 PEFile::RVAToSectionIndex(uint64 RVA)
{
    for (auto tr = 0U; tr < nrSections; tr++)
    {
        if ((RVA >= sect[tr].VirtualAddress) && (RVA < (uint64) sect[tr].VirtualAddress + sect[tr].Misc.VirtualSize))
        {
            return tr;
        }
    }

    return -1;
}

std::string_view PEFile::GetMachine()
{
    switch (static_cast<MachineType>(nth32.FileHeader.Machine))
    {
    case MachineType::ALPHA:
        return "ALPHA";
    case MachineType::ALPHA64:
        return "ALPHA 64";
    case MachineType::AM33:
        return "AM 33";
    case MachineType::AMD64:
        return "AMD 64";
    case MachineType::ARM:
        return "ARM";
    case MachineType::ARM64:
        return "ARM64";
    case MachineType::CEE:
        return "CEE";
    case MachineType::CEF:
        return "CEF";
    case MachineType::EBC:
        return "EBC";
    case MachineType::I386:
        return "Intel 386";
    case MachineType::IA64:
        return "Intel IA64";
    case MachineType::M32R:
        return "M 32R";
    case MachineType::MIPSFPU16:
        return "MIP SFPU 16";
    case MachineType::MIPS16:
        return "MIP 16";
    case MachineType::MIPSFPU:
        return "MIP SFPU";
    case MachineType::POWERPC:
        return "POWER PC";
    case MachineType::POWERPCFP:
        return "POWER PC (FP)";
    case MachineType::PPCBE:
        return "Xbox 360 (Xenon)";
    case MachineType::R10000:
        return "R 10000";
    case MachineType::R3000:
        return "R 3000";
    case MachineType::R4000:
        return "MIPS@ little indian";
    case MachineType::SH3:
        return "Hitachi SH3";
    case MachineType::SH3DSP:
        return "Hitachi SH3 (DSP)";
    case MachineType::SH3E:
        return "Hitachi SH2 (E)";
    case MachineType::SH4:
        return "Hitachi SH4";
    case MachineType::SH5:
        return "Hitachi SH5";
    case MachineType::THUMB:
        return "Thumb";
    case MachineType::TRICORE:
        return "Tricore";
    case MachineType::Unknown:
        return "Unknown";
    case MachineType::WCEMIPSV2:
        return "WCEMIPSV2";
    case MachineType::ARMNT:
        return "ARM Thumb-2";
    }
    return "";
}

std::string_view PEFile::GetSubsystem()
{
    switch (static_cast<SubsystemType>(nth32.OptionalHeader.Subsystem))
    {
    case SubsystemType::Unknown:
        return "Unknown";
    case SubsystemType::Native:
        return "Native";
    case SubsystemType::WindowGUI:
        return "Windows GUI (Graphics)";
    case SubsystemType::WindowsCUI:
        return "Windows CUI (Console)";
    case SubsystemType::WindowsCEGUI:
        return "Windows CE GUI (Graphics)";
    case SubsystemType::PosixCUI:
        return "Posix CUI (Console)";
    case SubsystemType::EFIApplication:
        return "EFI Applications";
    case SubsystemType::EFIBootServiceDriver:
        return "Boot Service Driver";
    case SubsystemType::EFIRuntimeDriver:
        return "EFI routine driver";
    case SubsystemType::EFIROM:
        return "EFI Rom";
    case SubsystemType::WindowsNative:
        return "Native Windows";
    case SubsystemType::OS2CUI:
        return "OS2 CUI (Console)";
    case SubsystemType::XBOX:
        return "XBOX";
    }
    return "";
}

uint64_t PEFile::FAToRVA(uint64_t fileAddress)
{
    uint32 tr;
    uint64_t temp;

    for (tr = 0; tr < nrSections; tr++)
    {
        if ((fileAddress >= sect[tr].PointerToRawData) && (fileAddress < sect[tr].PointerToRawData + sect[tr].SizeOfRawData) && (sect[tr].VirtualAddress > 0))
        {
            temp = fileAddress - sect[tr].PointerToRawData;
            if (temp < sect[tr].Misc.VirtualSize)
                return temp + sect[tr].VirtualAddress;
        }
    }

    return PE_INVALID_ADDRESS;
}

uint64 PEFile::FAToVA(uint64_t fileAddress)
{
    uint64 RVA;

    if ((RVA = FAToRVA(fileAddress)) != PE_INVALID_ADDRESS)
        return RVA + imageBase;

    return PE_INVALID_ADDRESS;
}

uint64_t PEFile::TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex)
{
    return ConvertAddress(value, static_cast<AddressType>(fromTranslationIndex), AddressType::FileOffset);
}
uint64_t PEFile::TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex)
{
    return ConvertAddress(value, AddressType::FileOffset, static_cast<AddressType>(toTranslationIndex));
}
uint64_t PEFile::ConvertAddress(uint64_t address, AddressType fromAddressType, AddressType toAddressType)
{
    switch (fromAddressType)
    {
    case AddressType::FileOffset:
        switch (toAddressType)
        {
        case AddressType::FileOffset:
            return address;
        case AddressType::VA:
            return FAToVA(address);
        case AddressType::RVA:
            return FAToRVA(address);
        };
        break;
    case AddressType::VA:
        switch (toAddressType)
        {
        case AddressType::FileOffset:
            if (address > imageBase)
            {
                return RVAToFA(address - imageBase);
            }
            break;
        case AddressType::VA:
            return address;
        case AddressType::RVA:
            if (address > imageBase)
            {
                return address - imageBase;
            }
            break;
        };
        break;
    case AddressType::RVA:
        switch (toAddressType)
        {
        case AddressType::FileOffset:
            return RVAToFA(address);
        case AddressType::VA:
            return address + imageBase;
        case AddressType::RVA:
            return address;
        };
        break;
    }
    return PE_INVALID_ADDRESS;
}

bool PEFile::BuildExport()
{
    uint64 faddr, oaddr, naddr;
    uint32 RVA, export_RVA;
    uint16 exportOrdinal;
    std::vector<bool> ordinals;

    exp.clear();

    RVA = dirs[(uint8) DirectoryType::Export].VirtualAddress; // export directory
    CHECK(RVA != 0, false, "")

    if ((faddr = RVAToFA(RVA)) == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid RVA for Export directory (0x%X)", (uint32) RVA);
        return false;
    }
    if (obj->GetData().Copy<ImageExportDirectory>(faddr, exportDir) == false)
    {
        errList.AddError("Unable to read full Export Directory structure from RVA (0x%X)", (uint32) RVA);
        return false;
    }
    if (exportDir.Name == 0)
    {
        errList.AddWarning("Invalid RVA for export name (0x%08X)", (uint32) exportDir.Name);
    }
    else
    {
        auto dllName = ReadString(exportDir.Name, MAX_DLL_NAME);
        if (dllName.empty())
        {
            errList.AddError("Unable to read export name from RVA (0x%X)", (uint32) exportDir.Name);
            return false;
        }
        this->dllName = dllName;
        for (auto ch : dllName)
            if ((ch < 32) || (ch > 127))
            {
                errList.AddWarning("Export name contains invalid characters !");
                break;
            }
    }
    if (exportDir.NumberOfFunctions == 0 && exportDir.NumberOfNames == 0) // no exports
    {
        errList.AddWarning("No functions in Export Directory");
        return false;
    }
    if (exportDir.NumberOfFunctions > 0xFFFF)
    {
        errList.AddError("Too many exported functions(0x % 08X).Maximum allowes is 0xFFFF. ", exportDir.NumberOfFunctions);
        return false;
    }

    if ((naddr = RVAToFA(exportDir.AddressOfNames)) == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid AddressOfNames (0x%x) from export directory", (uint32) exportDir.AddressOfNames);
        return false;
    }
    if ((oaddr = RVAToFA(exportDir.AddressOfNameOrdinals)) == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid AddressOfNameOrdinals (0x%x) from export directory", (uint32) exportDir.AddressOfNameOrdinals);
        return false;
    }
    if ((faddr = RVAToFA(exportDir.AddressOfFunctions)) == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid AddressOfFunctions (0x%x) from export directory", (uint32) exportDir.AddressOfFunctions);
        return false;
    }

    if (exportDir.NumberOfNames < exportDir.NumberOfFunctions)
    {
        ordinals.resize(exportDir.NumberOfFunctions);
        for (uint32 tr = 0; tr < exportDir.NumberOfFunctions; tr++)
            ordinals[tr] = false;
    }
    for (uint32 tr = 0; tr < exportDir.NumberOfNames; tr++, naddr += 4, oaddr += 2)
    {
        if (obj->GetData().Copy<uint32>(naddr, RVA) == false)
        {
            errList.AddError("Unable to read export function name");
            return false;
        }
        if (obj->GetData().Copy<uint16>(oaddr, exportOrdinal) == false)
        {
            errList.AddError("Unable to read export function ordinal");
            return false;
        }
        if (obj->GetData().Copy<uint32>(faddr + ((uint64) exportOrdinal) * 4, export_RVA) == false)
        {
            errList.AddError("Unable to read export function address");
            return false;
        }
        auto exportName = ReadString(RVA, MAX_EXPORTFNC_SIZE);
        if (exportName.empty())
        {
            errList.AddError("Unable to read export function name");
            return false;
        }
        exportOrdinal += exportDir.Base;
        if ((exportDir.NumberOfNames < exportDir.NumberOfFunctions) && (exportOrdinal < exportDir.NumberOfFunctions))
        {
            ordinals[exportOrdinal] = true;
        }

        // add to list
        auto& item   = exp.emplace_back();
        item.RVA     = export_RVA;
        item.Ordinal = exportOrdinal;
        if (GView::Utils::Demangle(exportName, item.Name) == false)
        {
            item.Name.Set(exportName.data(), (uint32) exportName.size());
        }
    }

    // adaug si ordinalii
    if (exportDir.NumberOfNames < exportDir.NumberOfFunctions)
    {
        LocalString<128> ordinal_name;
        for (uint32 tr = 0; tr < exportDir.NumberOfFunctions; tr++)
        {
            if (ordinals[tr] == false)
            {
                if (obj->GetData().Copy<uint32>(faddr + ((uint64) tr) * 4, export_RVA) == false)
                {
                    errList.AddError("Unable to read export function ordinal ID");
                    return false;
                }
                if (export_RVA > 0)
                {
                    exportOrdinal = tr;
                    if (!ordinal_name.SetFormat("_Ordinal_%u", tr))
                    {
                        errList.AddError("Fail to create ordinal name for ID");
                        return false;
                    }
                    auto& item   = exp.emplace_back();
                    item.RVA     = export_RVA;
                    item.Ordinal = exportOrdinal;
                    item.Name.Set(ordinal_name.GetText(), ordinal_name.Len());
                }
            }
        }
    }

    return true;
}

bool PEFile::BuildTLS()
{
    uint32_t RVA;
    uint64_t faddr;

    hasTLS   = false;
    auto dir = GetDirectory(DirectoryType::TLS);
    RVA      = dir.VirtualAddress;
    if ((RVA == 0) || (dir.Size == 0))
        return false;

    if ((faddr = RVAToFA(RVA)) == PE_INVALID_ADDRESS)
        return false;
    if (obj->GetData().Copy<ImageTLSDirectory32>(faddr, tlsDir) == false)
        return false;
    hasTLS = true;
    return true;
}

void PEFile::BuildVersionInfo()
{
    uint32 szRead;

    for (auto& ri : this->res)
    {
        if (ri.Type != ResourceType::Version)
            continue;
        if (ri.Start >= obj->GetData().GetSize())
            break;
        szRead = (uint32_t) ri.Size;
        if (szRead > MAX_VERSION_BUFFER)
            szRead = MAX_VERSION_BUFFER;
        if (ri.Start + szRead >= obj->GetData().GetSize())
            szRead = (uint32_t) (obj->GetData().GetSize() - ri.Start);

        auto buf = obj->GetData().Get(ri.Start, szRead, false);

        if (buf.Empty())
        {
            errList.AddWarning("Unable to read version infornation resource");
            break;
        }
        if (Ver.ComputeVersionInformation(buf.GetData(), (int32) buf.GetLength()) == false)
        {
            errList.AddWarning("Invalid version information resource.");
            break;
        }
    }
}

std::string_view PEFile::ResourceIDToName(ResourceType resType)
{
    switch (resType)
    {
    case ResourceType::Cursor:
        return "Cursor";
    case ResourceType::Bitmap:
        return "Button";
    case ResourceType::Icon:
        return "Icon";
    case ResourceType::Menu:
        return "Menu";
    case ResourceType::Dialog:
        return "Dialog";
    case ResourceType::String:
        return "String";
    case ResourceType::FontDir:
        return "FontDir";
    case ResourceType::Font:
        return "Font";
    case ResourceType::Accelerator:
        return "Accelerator";
    case ResourceType::RCData:
        return "RCData";
    case ResourceType::MessageTable:
        return "MessageTable";
    case ResourceType::CursorGroup:
        return "Cursor group";
    case ResourceType::IconGroup:
        return "Icon group";
    case ResourceType::Version:
        return "Version";
    case ResourceType::DLGInclude:
        return "DLG Include";
    case ResourceType::PlugPlay:
        return "Plug & Play";
    case ResourceType::VXD:
        return "VXD";
    case ResourceType::ANICursor:
        return "Animated cursor";
    case ResourceType::ANIIcon:
        return "Animated Icon";
    case ResourceType::HTML:
        return "HTML";
    case ResourceType::Manifest:
        return "Manifest";
    };
    return std::string_view{};
}

std::string_view PEFile::LanguageIDToName(uint32_t langID)
{
    const auto i = languageCode.find(langID);
    if (i != languageCode.cend())
        return i->second;
    return std::string_view{};
}

std::string_view PEFile::DirectoryIDToName(uint32_t dirID)
{
    if (dirID < 15)
        return peDirsNames[dirID];
    return std::string_view{};
}

bool PEFile::ProcessResourceImageInformation(ResourceInformation& r)
{
    DIBInfoHeader dibHeader{};
    r.Image.type = ImageType::Unknown;
    auto buf     = this->obj->GetData().Get(r.Start, sizeof(dibHeader), true);
    if (buf.Empty())
    {
        errList.AddWarning("Unable to read ICON header (%u bytes) from %llu offset", (uint32) (sizeof(dibHeader), r.Start));
        return false;
    }
    auto iconHeader = buf.GetObject<DIBInfoHeader>();
    // check if possible DIB
    if (iconHeader->sizeOfHeader == 40)
    {
        r.Image.type = ImageType::DIB;
        switch (iconHeader->bitsPerPixel)
        {
        case 1:
        case 4:
        case 8:
        case 16:
        case 24:
        case 32:
            r.Image.bitsPerPixel = (uint8_t) iconHeader->bitsPerPixel;
            break;
        default:
            errList.AddWarning(
                  "Invalid value for `bitsPerPixel` field in DIB header (%d) for image at %llu offset. Expected values are 1,4,8,16,24 or "
                  "32",
                  (int) iconHeader->bitsPerPixel,
                  r.Start);
            break;
        }
        r.Image.width  = iconHeader->width;
        r.Image.height = iconHeader->height;
        if (r.Type == ResourceType::Icon)
        {
            r.Image.height = r.Image.width;
            if (iconHeader->height != iconHeader->width * 2)
                errList.AddWarning(
                      "Invalid heigh (%u) for an ICON (it should be twice the width [%u]), for image at %llu offset",
                      iconHeader->width,
                      iconHeader->height,
                      r.Start);
        }
    }
    // check is possible PNG
    auto pngHeader = buf.GetObject<PNGHeader>();
    if ((pngHeader->magic == 0x474E5089) && (pngHeader->ihdrMagic == 0x52444849))
    {
        r.Image.type  = ImageType::PNG;
        r.Image.width = ((pngHeader->width & 0xFF) << 24) | ((pngHeader->width & 0xFF00) << 8) | ((pngHeader->width & 0xFF0000) >> 8) |
                        ((pngHeader->width & 0xFF000000) >> 24);
        r.Image.height = ((pngHeader->height & 0xFF) << 24) | ((pngHeader->height & 0xFF00) << 8) | ((pngHeader->height & 0xFF0000) >> 8) |
                         ((pngHeader->height & 0xFF000000) >> 24);
        r.Image.bitsPerPixel = 0;
    }
    // general checks
    if (r.Image.type == ImageType::Unknown)
    {
        errList.AddWarning("Unkown image resourse type (for resourse at offset %llu)", r.Start);
        return false;
    }
    if (r.Image.width == 0)
        errList.AddWarning("Invalid width (0) for image at offset %llu", r.Start);
    if (r.Image.height == 0)
        errList.AddWarning("Invalid height (0) for image at offset %llu", r.Start);
    if (r.Type == ResourceType::Icon)
    {
        if (r.Image.width != r.Image.height)
            errList.AddWarning(
                  "Invalid ICON (width should be equal to height) - icon size is %ux%u (for resource at offset %llu)", r.Image.width, r.Image.height, r.Start);
        switch (r.Image.width)
        {
        case 8:
        case 16:
        case 24:
        case 32:
        case 48:
        case 64:
        case 128:
        case 256:
            break;
        default:
            errList.AddWarning(
                  "Unusual ICON width (%u). Usual icons are 8x8, 16x16, 24x24, 32x32, 48x48, 64x64, 128x128 or 256x256 (for resource at "
                  "offset %llu)",
                  r.Image.width,
                  r.Start);
        }
    }
    return true;
}

bool PEFile::ProcessResourceDataEntry(uint64_t relAddress, uint64_t startRes, uint32_t* level, uint32_t indexLevel, char* resName)
{
    ImageResourceDataEntry resDE;
    uint64_t fileAddress;

    fileAddress = relAddress + startRes;

    if (obj->GetData().Copy<ImageResourceDataEntry>(fileAddress, resDE) == false)
    {
        errList.AddWarning("Unable to read Resource Data Entry from (0x%X)", (uint32_t) fileAddress);
        return false;
    }

    if ((fileAddress = RVAToFA(resDE.OffsetToData)) == PE_INVALID_ADDRESS)
    {
        errList.AddWarning("Invalid RVA for resource entry (0x%X)", (uint32_t) resDE.OffsetToData);
        return false;
    }

    auto& resInf = res.emplace_back();

    resInf.Type       = static_cast<ResourceType>(level[0]);
    resInf.ID         = level[1];
    resInf.Language   = level[2];
    resInf.Start      = fileAddress;
    resInf.Size       = resDE.Size;
    resInf.CodePage   = resDE.CodePage;
    resInf.Image.type = ImageType::Unknown;
    resInf.Name.Set(resName);

    if (resInf.Type == ResourceType::Icon)
    {
        ProcessResourceImageInformation(resInf);
    }

    return true;
}

bool PEFile::ProcessResourceDirTable(uint64_t relAddress, uint64_t startRes, uint32_t* level, uint32_t indexLevel, char* parentName)
{
    ImageResourceDirectory resDir;
    ImageResourceDirectoryEntry dirEnt;
    uint32_t nrEnt, tr;
    uint64_t fileAddress;
    char resName[256];

    fileAddress = relAddress + startRes;

    if (indexLevel > 3)
    {
        errList.AddError("Resource depth is too big (>3)");
        return false;
    }
    if (obj->GetData().Copy<ImageResourceDirectory>(fileAddress, resDir) == false)
    {
        errList.AddWarning("Unable to read Resource Structure from (0x%X)", (uint32_t) fileAddress);
        return false;
    }

    nrEnt = resDir.NumberOfIdEntries;
    if (indexLevel == 0)
        nrEnt += resDir.NumberOfNamedEntries;
    if (resDir.NumberOfNamedEntries > nrEnt)
        nrEnt = resDir.NumberOfNamedEntries;
    if (nrEnt > 1024)
    {
        errList.AddError("Too many resources (>1024)");
        return false;
    }
    // citesc intrarile
    if (resDir.Characteristics != 0)
    {
        errList.AddWarning("IMAGE_RESOURCE_DIRECTORY (Invalid Characteristics field)");
        return false;
    }

    fileAddress += sizeof(ImageResourceDirectory);
    for (tr = 0; tr < nrEnt; tr++, fileAddress += sizeof(ImageResourceDirectoryEntry))
    {
        if (obj->GetData().Copy<ImageResourceDirectoryEntry>(fileAddress, dirEnt) == false)
        {
            errList.AddWarning("Unable to read Resource Directory Entry from (0x%X)", (uint32_t) fileAddress);
            return false;
        }
        level[indexLevel] = dirEnt.Id;

        resName[0] = 0;
        if (dirEnt.NameIsString == 1)
        {
            if (ReadUnicodeLengthString(dirEnt.NameOffset + (uint32_t) startRes, resName, 255) == false)
                resName[0] = 0;
        }
        if (dirEnt.DataIsDirectory == 1)
        {
            if (ProcessResourceDirTable(dirEnt.OffsetToDirectory, startRes, level, indexLevel + 1, resName) == false)
            {
                // return false;
            }
        }
        else
        {
            if (ProcessResourceDataEntry(dirEnt.OffsetToData, startRes, level, indexLevel, parentName) == false)
            {
                // return false;
            }
        }
    }
    return true;
}

bool PEFile::BuildResources()
{
    uint64_t RVA, addr;
    uint32_t level[8];

    res.clear();
    RVA = dirs[2].VirtualAddress; // export directory
    if (RVA == 0)
        return false;
    if ((addr = RVAToFA(RVA)) == PE_INVALID_ADDRESS)
    {
        errList.AddWarning("Invalid RVA for Resource directory (0x%X)", (uint32_t) RVA);
        return false;
    }

    return ProcessResourceDirTable(0, addr, level, 0, (char*) "");
}

bool PEFile::BuildImportDLLFunctions(uint32_t index, ImageImportDescriptor* impD)
{
    uint64 addr, IATaddr;
    ImageThunkData32 rvaFName32;
    ImageThunkData64 rvaFName64;
    LocalString<64> tempStr;
    uint32 count_f = 0;

    if (impD->OriginalFirstThunk == 0)
    {
        addr = RVAToFA(impD->FirstThunk);
    }
    else
    {
        addr = RVAToFA(impD->OriginalFirstThunk);
    }
    if (addr == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid RVA for OriginalFirstThunk (0x%X)", (uint32_t) impD->OriginalFirstThunk);
        return false;
    }

    IATaddr = impD->FirstThunk;
    if (RVAToFA(impD->FirstThunk) == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid RVA for FirstThunk (0x%X)", (uint32_t) impD->FirstThunk);
        return false;
    }

    std::string_view importName;
    if (hdr64)
    {
        while ((obj->GetData().Copy<ImageThunkData64>(addr, rvaFName64)) && (rvaFName64.u1.AddressOfData != 0) && (count_f < MAX_IMPORTED_FUNCTIONS))
        {
            if ((rvaFName64.u1.AddressOfData & __IMAGE_ORDINAL_FLAG64) != 0) // imported by ordinal
            {
                tempStr.SetFormat("Ordinal:%u", (rvaFName64.u1.Ordinal - __IMAGE_ORDINAL_FLAG64));
                importName = tempStr.ToStringView();
            }
            else
            {
                importName = ReadString((uint32_t) (rvaFName64.u1.AddressOfData + 2), MAX_IMPORTFNC_SIZE);
                if (importName.empty())
                {
                    errList.AddError("Invalid RVA import name (0x%X)", (uint32_t) rvaFName64.u1.AddressOfData + 2);
                    return false;
                }
            }

            auto& item = impFunc.emplace_back();
            if (GView::Utils::Demangle(importName.data(), item.Name) == false)
            {
                item.Name = importName.data();
            }

            item.dllIndex = index;
            item.RVA      = IATaddr;
            count_f++;
            addr += sizeof(ImageThunkData64);
            IATaddr += sizeof(ImageThunkData64);
        }
    }
    else
    {
        while ((obj->GetData().Copy<ImageThunkData32>(addr, rvaFName32)) && (rvaFName32.u1.AddressOfData != 0) && (count_f < MAX_IMPORTED_FUNCTIONS))
        {
            if ((rvaFName32.u1.AddressOfData & __IMAGE_ORDINAL_FLAG32) != 0) // avem functie importata prin ordinal:
            {
                tempStr.SetFormat("Ordinal:%u", (rvaFName32.u1.Ordinal - __IMAGE_ORDINAL_FLAG32));
                importName = tempStr.ToStringView();
            }
            else
            {
                importName = ReadString(rvaFName32.u1.AddressOfData + 2, MAX_IMPORTFNC_SIZE);
                if (importName.empty())
                {
                    errList.AddError("Invalid RVA import name (0x%X)", (uint32_t) rvaFName32.u1.AddressOfData + 2);
                    return false;
                }
            }

            auto& item = impFunc.emplace_back();
            if (GView::Utils::Demangle(importName.data(), item.Name) == false)
            {
                item.Name = importName.data();
            }

            item.dllIndex = index;
            item.RVA      = IATaddr;
            count_f++;
            addr += sizeof(ImageThunkData32);
            IATaddr += sizeof(ImageThunkData32);
        }
    }
    if (count_f >= MAX_IMPORTED_FUNCTIONS)
    {
        errList.AddError("Too many imported functions (0x%X)", (uint32_t) rvaFName32.u1.AddressOfData + 2);
        return false;
    }
    return true;
}

bool PEFile::BuildImport()
{
    uint64_t RVA, addr;
    ImageImportDescriptor impD;
    uint32_t nrDLLs;
    LocalString<512> tempStr;
    bool result;

    impFunc.clear();
    impDLL.clear();
    RVA = dirs[1].VirtualAddress; // export directory
    if (RVA == 0)
        return false;
    if ((addr = RVAToFA(RVA)) == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid RVA for Import directory (0x%X)", (uint32_t) RVA);
        return false;
    }
    // citesc numele de DLL-uri , unul cate unu

    nrDLLs = 0;
    while ((result = obj->GetData().Copy<ImageImportDescriptor>(addr, impD)) == true)
    {
        if (impD.Name == 0)
            break;
        auto imp_name = ReadString(impD.Name, MAX_IMPORTFNC_SIZE);
        if (imp_name.empty())
            break;
        auto& item = impDLL.emplace_back();
        item.RVA   = impD.Name;
        item.Name  = imp_name;

        if (BuildImportDLLFunctions(nrDLLs, &impD) == false)
            break;
        nrDLLs++;
        addr += sizeof(ImageImportDescriptor);
    }
    if (!result)
    {
        errList.AddError("Unable to read import directory data from RVA (0x%X)", (uint32_t) RVA);
        return false;
    }

    return true;
}

bool PEFile::BuildDebugData()
{
    debugData.clear();
    pdbName.Clear();

    auto& dirDebug = dirs[(uint8) DirectoryType::Debug];
    CHECK(dirDebug.VirtualAddress != 0, false, "");

    uint64 faddr;
    if ((faddr = RVAToFA(dirDebug.VirtualAddress)) == PE_INVALID_ADDRESS)
    {
        errList.AddError("Invalid RVA for Debug directory (0x%X)", (uint32) dirDebug.VirtualAddress);
        return false;
    }

    const auto size = dirDebug.Size / sizeof(ImageDebugDirectory);
    if (((dirDebug.Size % sizeof(ImageDebugDirectory)) != 0) || (size == 0) || (size > 14))
    {
        errList.AddWarning("Invalid alignament for Debug directory (0x%X)", (uint32) dirDebug.Size);
    }

    for (auto tr = 0; tr < size; tr++, faddr += sizeof(ImageDebugDirectory))
    {
        ImageDebugDirectory imgd;
        if (obj->GetData().Copy<ImageDebugDirectory>(faddr, imgd) == false)
        {
            errList.AddError("Unable to read Debug structure from (0x%X)", (uint32) faddr);
            return false;
        }

        if (imgd.Type == __IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            uint32 bufSize;
            if (imgd.SizeOfData > (MAX_PDB_NAME + 64))
            {
                bufSize = (MAX_PDB_NAME + 64);
            }
            else
            {
                bufSize = imgd.SizeOfData;
            }

            auto buf = obj->GetData().Get(imgd.PointerToRawData, bufSize, false);
            if (buf.IsValid() && buf.GetLength() >= 5) // at least the first 32 bytes
            {
                std::string_view name = "";
                switch (*(uint32*) buf.GetData())
                {
                case CV_SIGNATURE_NB10:
                    name = std::string_view{ (const char*) ((CV_INFO_PDB20*) buf.GetData())->PdbFileName, MAX_PDB_NAME };
                    break;
                case CV_SIGNATURE_RSDS:
                    name = std::string_view{ (const char*) ((CV_INFO_PDB70*) buf.GetData())->PdbFileName, MAX_PDB_NAME };
                    break;
                default:
                    errList.AddWarning("Unknwon signature in IMAGE_DEBUG_TYPE_CODEVIEW => %08X", (*(uint32*) buf.GetData()));
                    break;
                }

                if (name.size() > 0)
                {
                    pdbName.Set(std::string_view{ name.data(), name.find_first_of('\0') });
                }
            }
            else
            {
                errList.AddError("Unable to read IMAGE_DEBUG_TYPE_CODEVIEW (%d bytes) from (0x%X)", bufSize, imgd.PointerToRawData);
            }
        }
    }
    return true;
}

void PEFile::CopySectionName(uint32 index, String& name)
{
    name.Clear();
    // else if ((uint16) index == IMAGE_SYM_UNDEFINED)
    // {
    //     name.Set("UNDEFINED");
    //     return;
    // }
    if ((uint16) index == IMAGE_SYM_ABSOLUTE)
    {
        name.Set("ABSOLUTE");
        return;
    }
    else if ((uint16) index == IMAGE_SYM_DEBUG)
    {
        name.Set("DEBUG");
        return;
    }
    else if (index >= nrSections)
    {
        return;
    }

    GetSectionName(index, name);
}

void PEFile::GetSectionName(uint32 index, String& sectionName)
{
    bool longSectionNameProcessed = false;

    if (sect[index].Name[0] == '/' && sect[index].Name[1] >= '0' && sect[index].Name[1] <= '9') // long name | eg.: /4, /9, etc
    {
        const auto& sectionHeader = sect[index];

        const auto symbolIndex = Number::ToUInt64((const char*) sectionHeader.Name + 1);
        if (symbolIndex.has_value())
        {
            auto strtableOffset = 0ULL;
            switch (nth32.OptionalHeader.Magic)
            {
            case __IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                strtableOffset = nth32.FileHeader.PointerToSymbolTable + nth32.FileHeader.NumberOfSymbols * sizeof(ImageSymbol);
                break;
            case __IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                strtableOffset = nth64.FileHeader.PointerToSymbolTable + nth64.FileHeader.NumberOfSymbols * sizeof(ImageSymbol);
                break;
            }

            auto bufferLongName = obj->GetData().CopyToBuffer(strtableOffset + *symbolIndex, __IMAGE_SIZEOF_SHORT_NAME * 2);
            if (bufferLongName.IsValid() && strtableOffset != 0ULL)
            {
                const auto length = (uint32) strnlen((char*) bufferLongName.GetData(), __IMAGE_SIZEOF_SHORT_NAME * 2);
                String name;
                if (name.Set((char*) bufferLongName.GetData(), length))
                {
                    String indexName;
                    if (indexName.Set((char*) sect[index].Name, __IMAGE_SIZEOF_SHORT_NAME))
                    {
                        longSectionNameProcessed = sectionName.Format("(%s) %s", indexName.GetText(), name.GetText()).size() != 0;
                    }
                }
            }
        }
    }

    if (longSectionNameProcessed == false)
    {
        sectionName.Set((char*) sect[index].Name, __IMAGE_SIZEOF_SHORT_NAME);
    }
}

bool PEFile::GetResourceImageInformation(const ResourceInformation& r, String& info)
{
    CHECK(r.Image.type != ImageType::Unknown, false, "Imvalid image type !");
    switch (r.Image.type)
    {
    case ImageType::DIB:
        info.Set("DIB:", 4);
        break;
    case ImageType::PNG:
        info.Set("PNG:", 4);
        break;
    default:
        info.Set("Unk:", 4);
        break;
    }
    info.AddFormat("%u x %u ", r.Image.width, r.Image.height);

    switch (r.Image.bitsPerPixel)
    {
    case 0:
        break; // don't add this informatioon
    case 1:
        info.Add("(monochrome)");
        break;
    case 4:
        info.Add("(16 colors)");
        break;
    case 8:
        info.Add("(256 colors)");
        break;
    case 24:
        info.Add("(RGB - 24bit)");
        break;
    case 32:
        info.Add("(RGBA - 32bit)");
        break;
    default:
        info.AddFormat("(%u bits/pixel)", r.Image.bitsPerPixel);
        break;
    }
    return true;
}

bool PEFile::LoadIcon(const ResourceInformation& res, Image& img)
{
    CHECK(res.Type == ResourceType::Icon, false, "Expecting a valid ICON resource !");
    auto buf = this->obj->GetData().CopyToBuffer(res.Start, (uint32) res.Size);
    CHECK(buf.IsValid(), false, "Fail to read %llu bytes from offset %llu", res.Size, res.Start);
    if (buf.IsValid())
    {
        auto iconHeader = buf.GetObject<DIBInfoHeader>();
        if (iconHeader.IsValid())
        {
            if (iconHeader->sizeOfHeader == 40)
            {
                CHECK(img.CreateFromDIB(buf.GetData(), (uint32) buf.GetLength(), true), false, "Fail to create icon from buffer !");
                return true;
            }
        }
        auto pngHeader = buf.GetObject<PNGHeader>();
        if ((pngHeader->magic == 0x474E5089) && (pngHeader->ihdrMagic == 0x52444849))
        {
            CHECK(img.Create(buf), false, "Fail to create an image from a PNG buffer !");
            return true;
        }
    }
    RETURNERROR(false, "Fail to load image from offset %llu", res.Start);
}

bool PEFile::HasPanel(Panels::IDs id)
{
    return (this->panelsMask & (1ULL << ((uint8) id))) != 0;
}

bool PEFile::Update()
{
    uint32_t tr, gr, tmp;
    uint64_t filePoz, poz;
    LocalString<128> tempStr;

    errList.Clear();
    isMetroApp       = false;
    this->panelsMask = 0;
    if (!obj->GetData().Copy<ImageDOSHeader>(0, dos))
        return false;
    if (!obj->GetData().Copy<ImageNTHeaders32>(dos.e_lfanew, nth32))
        return false;
    switch (nth32.OptionalHeader.Magic)
    {
    case __IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        hdr64         = false;
        dirs          = &nth32.OptionalHeader.DataDirectory[0];
        rvaEntryPoint = nth32.OptionalHeader.AddressOfEntryPoint;
        break;
    case __IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (!obj->GetData().Copy<ImageNTHeaders64>(dos.e_lfanew, nth64))
            return false;
        dirs  = &nth64.OptionalHeader.DataDirectory[0];
        hdr64 = true;
        break;
    case __IMAGE_ROM_OPTIONAL_HDR_MAGIC:
    default:
        // unsupported
        return false;
    }
    rvaEntryPoint = nth32.OptionalHeader.AddressOfEntryPoint; // same
    fileAlign     = nth32.OptionalHeader.FileAlignment;       // same,  BaseOfData missing on PE32+
    nrSections    = nth32.FileHeader.NumberOfSections;        // same

    poz = static_cast<uint64>(dos.e_lfanew) + nth32.FileHeader.SizeOfOptionalHeader + sizeof(((ImageNTHeaders32*) 0)->Signature) + sizeof(ImageFileHeader);
    sectStart    = static_cast<uint32>(poz);
    peStart      = dos.e_lfanew;
    computedSize = virtualComputedSize = 0;

    if ((nrSections > MAX_NR_SECTIONS) || (nrSections < 1))
    {
        errList.AddError("Invalid number of sections (%d)", nrSections);
        nrSections = 0;
    }
    if ((nth32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)) // same
    {
        errList.AddWarning("Image should execute in an AppContainer");
        isMetroApp = true;
    }

    if (hdr64)
        imageBase = nth64.OptionalHeader.ImageBase;
    else
        imageBase = nth32.OptionalHeader.ImageBase;

    /*obj->GetData().ResetBookmarks();
     */
    // b.AddZone(poz, poz + nrSections * sizeof(ImageSectionHeader) - 1, peCols.colSectDef, "SectDef");
    for (tr = 0; tr < nrSections; tr++, poz += sizeof(ImageSectionHeader))
    {
        if (!obj->GetData().Copy<ImageSectionHeader>(poz, sect[tr]))
        {
            memset(&sect[tr], 0, sizeof(ImageSectionHeader));
        }
        if ((sect[tr].SizeOfRawData > 0) && (sect[tr].PointerToRawData + sect[tr].SizeOfRawData > computedSize))
            computedSize = sect[tr].PointerToRawData + sect[tr].SizeOfRawData;
        if ((sect[tr].Misc.VirtualSize > 0) && (sect[tr].VirtualAddress + sect[tr].Misc.VirtualSize > virtualComputedSize))
            virtualComputedSize = sect[tr].VirtualAddress + sect[tr].Misc.VirtualSize;
        // if ((tr < 9) && (sect[tr].PointerToRawData != 0))
        //    FileInfo->Bookmarks.SetBookmark(tr + 1, sect[tr].PointerToRawData);
        /*if (obj->GetData().IsOnDisk())
        {
          if ((tr<9) && (sect[tr].PointerToRawData != 0)) obj->GetData().SetBookmark(tr + 1, sect[tr].PointerToRawData);
        } else {
          if ((tr<9) && (sect[tr].VirtualAddress != 0)) obj->GetData().SetBookmark(tr + 1, sect[tr].VirtualAddress);
        }*/
    }
    for (tr = 0; tr < nrSections; tr++)
    {
        if (tr + 1 < nrSections)
        {
            if (sect[tr].VirtualAddress + SectionALIGN(sect[tr].Misc.VirtualSize, nth32.OptionalHeader.SectionAlignment) != sect[tr + 1].VirtualAddress)
            {
                errList.AddError("Section %d and %d are not consecutive.", (tr + 1), (tr + 2));
            }
        }
        if ((tr > 0) && ((*(uint64*) &sect[tr - 1].Name) == (*(uint64*) &sect[tr].Name)))
        {
            tempStr.SetFormat("Sections %d and %d have the same name: [", (tr + 1), (tr + 2));
            for (gr = 0; gr < 8; gr++)
                if (sect[tr].Name[gr] != 0)
                    tempStr.AddChar(sect[tr].Name[gr]);
            tempStr.AddChar(']');
            errList.AddError("%s", tempStr.GetText());
        }
    }
    // recalculez :
    computedSize = sect[nrSections - 1].PointerToRawData + sect[nrSections - 1].SizeOfRawData;
    if (sect[nrSections - 1].SizeOfRawData == 0)
    {
        computedSize = obj->GetData().GetSize();
        errList.AddWarning("File is using LastSection.SizeOfRawData = 0 trick");
    }

    // if (computedSize < obj->GetData().GetSize())
    //{
    //    // obj->GetData().SetBookmark(0, computedSize);
    //    //FileInfo->Bookmarks.SetBookmark(0, computedSize);
    //}

    computedWithCertificate = computedSize;
    auto dirSec             = GetDirectory(DirectoryType::Security);
    if ((dirSec.VirtualAddress > 0) && (dirSec.Size > 0))
    {
        if (dirSec.VirtualAddress < computedWithCertificate)
        {
            errList.AddWarning("Security certificate starts within the file");
        }
        if ((dirSec.VirtualAddress + dirSec.Size) > computedWithCertificate)
        {
            computedWithCertificate = dirSec.VirtualAddress + dirSec.Size;
        }
    }

    if (computedSize > obj->GetData().GetSize())
    {
        errList.AddError(
              "File is truncated. Missing %d bytes (%3d%%)",
              (int) (computedSize - obj->GetData().GetSize()),
              (int) ((computedSize - obj->GetData().GetSize()) * 100) / computedSize);
    }

    tmp = sect[nrSections - 1].VirtualAddress + sect[nrSections - 1].Misc.VirtualSize;
    if (nth32.OptionalHeader.SectionAlignment > 0)
    {
        tmp += (nth32.OptionalHeader.SectionAlignment - tmp % nth32.OptionalHeader.SectionAlignment) % nth32.OptionalHeader.SectionAlignment;
    }
    if (tmp != nth32.OptionalHeader.SizeOfImage)
    {
        errList.AddError("SizeOfImage is invalid");
    }
    else
    {
        if ((nth32.OptionalHeader.SectionAlignment > 0) && (nth32.OptionalHeader.SizeOfImage % nth32.OptionalHeader.SectionAlignment) != 0)
        {
            errList.AddWarning("SizeOfImage unaligned");
        }
    }

    BuildResources();   // cu erori setate
    BuildExport();      // cu erori setate
    BuildImport();      // cu erori setate
    BuildVersionInfo(); // cu erori setate
    BuildTLS();
    BuildDebugData();

    // EP
    filePoz = RVAToFA(rvaEntryPoint);

    if (filePoz != PE_INVALID_ADDRESS)
    {
        // FileInfo->CursorPos = filePoz;
        // FileInfo->Bookmarks.SetBookmark(0, filePoz);
        if (filePoz >= obj->GetData().GetSize())
        {
            errList.AddError("Entry Point is outside the file RVA=(0x%x)", rvaEntryPoint);
        }
        else
        {
            auto buf = obj->GetData().Get(filePoz, 16, false);
            if (buf.Empty())
            {
                errList.AddError("Unable to read data from Entry Point RVA=(0x%x)", rvaEntryPoint);
            }
            else
            {
                tmp = 0;
                for (auto ch : buf)
                    tmp += ch;
                if (tmp == 0)
                {
                    errList.AddError("Invalid code at Entry Point RVA=(0x%x)", rvaEntryPoint);
                }
            }
        }
    }
    else
    {
        errList.AddError("Invalid Entry Point RVA (0x%x)", rvaEntryPoint);
        if (rvaEntryPoint < obj->GetData().GetSize())
        {
            errList.AddWarning("Entry Point is a File Address");
        }
    }
    int ep_sect = RVAToSectionIndex(rvaEntryPoint);
    if (rvaEntryPoint == 0)
    {
        errList.AddWarning("Posible executable resource file !");
        if ((nth32.FileHeader.Characteristics & __IMAGE_FILE_DLL) == 0)
            errList.AddWarning("NON-DLL file with EP RVA = 0");
    }
    if (ep_sect == -1)
    {
        if (rvaEntryPoint > 0)
            errList.AddWarning("EP is not inside any section");
    }
    else
    {
        if ((sect[ep_sect].Characteristics & __IMAGE_SCN_MEM_EXECUTE) == 0)
            errList.AddWarning("EP section without Executable characteristic");
        if ((sect[ep_sect].Characteristics & (__IMAGE_SCN_MEM_EXECUTE | __IMAGE_SCN_MEM_READ | __IMAGE_SCN_MEM_WRITE)) == 0)
            errList.AddError("EP section cannot be executed (missing Write,Read and Executable attributes)");
    }
    // directoare

    ImageDataDirectory *dr, *d2;
    for (tr = 0; tr < 15; tr++)
    {
        dr = &dirs[tr];
        if ((dr->VirtualAddress > 0) && (dr->Size > 0))
        {
            if (dr->Size > obj->GetData().GetSize())
            {
                errList.AddWarning("Directory '%s' (#%d) has an invalid Size (0x%08X)", peDirsNames[tr].data(), tr, dr->Size);
            }

            filePoz = RVAToFA(dr->VirtualAddress);
            if (filePoz == PE_INVALID_ADDRESS)
            {
                errList.AddWarning("Directory '%s' (#%d) has an invalid RVA address (0x%08X)", peDirsNames[tr].data(), tr, dr->VirtualAddress);
            }
            else
            {
                if (filePoz + dr->Size > obj->GetData().GetSize())
                {
                    errList.AddWarning(
                          "Directory '%s' (#%d) extends outside the file (to: 0x%08X)", peDirsNames[tr].data(), tr, (uint32_t) (dr->Size + filePoz));
                }
            }
        }
        if ((dr->VirtualAddress == 0) && (dr->Size > 0))
        {
            errList.AddWarning("Directory '%s' (#%d) has no address but size bigger than 0 (%d bytes)", peDirsNames[tr].data(), tr, dr->Size);
        }
        if ((dr->VirtualAddress > 0) && (dr->Size == 0))
        {
            errList.AddWarning("Directory '%s' (#%d) has size equal to 0 and a valid addrees (0x%08X)", peDirsNames[tr].data(), tr, dr->VirtualAddress);
        }
    }

    // overlap cases
    for (tr = 0; tr < 15; tr++)
    {
        if (tr == (uint8_t) DirectoryType::Security)
            continue;
        dr = &dirs[tr];
        if ((dr->VirtualAddress > 0) && (dr->Size > 0))
        {
            for (gr = tr + 1; gr < 15; gr++)
            {
                if (gr == (uint8_t) DirectoryType::Security)
                    continue;
                d2 = &dirs[gr];
                if ((d2->VirtualAddress > 0) && (dr->Size > 0))
                {
                    if ((dr->VirtualAddress <= d2->VirtualAddress) && (dr->VirtualAddress + dr->Size > d2->VirtualAddress))
                    {
                        errList.AddWarning("Directory '%s' and '%s' overlapp !", peDirsNames[tr].data(), peDirsNames[gr].data());
                        continue;
                    }
                    if ((d2->VirtualAddress <= dr->VirtualAddress) && (d2->VirtualAddress + d2->Size > dr->VirtualAddress))
                    {
                        errList.AddWarning("Directory '%s' and '%s' overlapp !", peDirsNames[tr].data(), peDirsNames[gr].data());
                        continue;
                    }
                }
            }
        }
    }

    hasOverlay = computedSize < obj->GetData().GetSize();

    for (auto i = 0U; i < nrSections; i++)
    {
        const auto& section = sect[i];
        if ((section.Characteristics & __IMAGE_SCN_MEM_EXECUTE) == __IMAGE_SCN_MEM_EXECUTE)
        {
            executableZonesFAs.emplace_back(std::pair<uint64, uint64>{ section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData });
        }
    }

    // Default panels
    ADD_PANEL(Panels::IDs::Information);
    ADD_PANEL(Panels::IDs::Directories);
    ADD_PANEL(Panels::IDs::Sections);
    ADD_PANEL(Panels::IDs::Headers);

    switch ((PE::MachineType) nth32.FileHeader.Machine)
    {
    case PE::MachineType::I386:
    case PE::MachineType::IA64:
    case PE::MachineType::AMD64:
        ADD_PANEL(Panels::IDs::OpCodes);
    default:
        break;
    }

    if (impDLL.size() > 0)
        ADD_PANEL(Panels::IDs::Imports);
    if (exp.size() > 0)
        ADD_PANEL(Panels::IDs::Exports);

    if (res.size() > 0)
        ADD_PANEL(Panels::IDs::Resources);

    for (auto& r : res)
    {
        if (r.Type == ResourceType::Icon)
        {
            ADD_PANEL(Panels::IDs::Icons);
            break;
        }
    }

    if (hasTLS)
        ADD_PANEL(Panels::IDs::TLS);

    if (this->hdr64)
    {
        if (nth64.FileHeader.PointerToSymbolTable != 0 && nth64.FileHeader.NumberOfSymbols != 0)
        {
            ADD_PANEL(Panels::IDs::Symbols);
            BuildSymbols();
        }
    }
    else
    {
        if (nth32.FileHeader.PointerToSymbolTable != 0 && nth32.FileHeader.NumberOfSymbols != 0)
        {
            ADD_PANEL(Panels::IDs::Symbols);
            BuildSymbols();
        }
    }

    if (ParseGoData())
    {
        ADD_PANEL(Panels::IDs::GoInformation);
    }

    return true;
}

bool PEFile::BuildSymbols()
{
    auto offset    = 0ULL;
    auto symbolsNo = 0ULL;

    if (this->hdr64)
    {
        offset    = nth64.FileHeader.PointerToSymbolTable;
        symbolsNo = nth64.FileHeader.NumberOfSymbols;
    }
    else
    {
        offset    = nth32.FileHeader.PointerToSymbolTable;
        symbolsNo = nth32.FileHeader.NumberOfSymbols;
    }

    CHECK(offset != 0, false, "");
    CHECK(symbolsNo != 0, false, "");

    const auto size          = symbolsNo * IMAGE_SIZEOF_SYMBOL;
    const auto symbolsBuffer = this->obj->GetData().CopyToBuffer(offset, (uint32) size);
    CHECK(symbolsBuffer.IsValid(), false, "");
    const auto endSymbolsBuffer = ((uint64) symbolsBuffer.GetData()) + offset + size;

    const auto strTableOffset = offset + symbolsNo * PE::IMAGE_SIZEOF_SYMBOL;
    uint32 strTableSize       = 0;
    CHECK(obj->GetData().Copy(strTableOffset, strTableSize), false, "");
    CHECK(strTableSize != 0, false, "");
    const auto stringsBuffer = this->obj->GetData().CopyToBuffer(strTableOffset, strTableSize);
    CHECK(stringsBuffer.IsValid(), false, "");

    this->symbols.reserve(symbolsNo);
    for (decltype(symbolsNo) i = 0ULL; i < symbolsNo; i++)
    {
        const auto is = (ImageSymbol*) (symbolsBuffer.GetData() + i * IMAGE_SIZEOF_SYMBOL);
        CHECKBK((uint64) (is) < endSymbolsBuffer - IMAGE_SIZEOF_SYMBOL, "");
        if (is->StorageClass == IMAGE_SYM_CLASS_NULL)
        {
            continue;
        }

        auto& s = this->symbols.emplace_back(SymbolInformation{ { /* symbol name */ }, *is });

        if (is->N.Name.Short != 0)
        {
            CHECK(s.name.Set((char*) is->N.ShortName, sizeof(is->N.ShortName) / sizeof(is->N.ShortName[0])), false, "");
        }
        else if (is->N.Name.Long >= sizeof(strTableSize) && is->N.Name.Long < strTableSize)
        {
            const auto name     = std::string_view{ (char*) (stringsBuffer.GetData() + is->N.Name.Long) };
            const auto dolarPos = name.find_first_of('$');
            if (dolarPos != std::string::npos)
            {
                const auto fname = std::string_view{ name.data() + dolarPos + 1, name.size() - 1 - dolarPos };
                String sName;
                if (GView::Utils::Demangle(fname.data(), sName))
                {
                    s.name.Format("[%.*s]: %s", dolarPos, name.data(), sName.GetText());
                }
                else
                {
                    s.name.Format("[%.*s]: %.*s", dolarPos, name.data(), name.size() - dolarPos + 1, name.data() + dolarPos + 1);
                }
            }
            else if (GView::Utils::Demangle(name.data(), s.name) == false)
            {
                s.name = name.data();
            }
        }
    }

    return true;
}

bool PEFile::ParseGoData()
{
    CHECK(ParseGoBuild(), false, "");
    ParseGoBuildInfo();

    // we assume we parsed the symbols first!
    if (symbols.empty() == false)
    {
        std::map<std::string_view, ImageSymbol> pclntabSymbols{
            { "runtime.pclntab", { 0 } }, { "runtime.epclntab", { 0 } }, { "pclntab", { 0 } }, { "epclntab", { 0 } }
        };

        for (const auto& symbol : symbols)
        {
            for (auto& [pclntabSymbol, value] : pclntabSymbols)
            {
                if (symbol.name.Equals(pclntabSymbol.data()))
                {
                    value = symbol.is;
                }
            }
        }

        auto& start = pclntabSymbols.at("runtime.pclntab");
        auto& end   = pclntabSymbols.at("runtime.epclntab");
        if (start.Value == 0 || end.Value == 0)
        {
            start = pclntabSymbols.at("pclntab");
            end   = pclntabSymbols.at("epclntab");
        }

        const auto cacheSize = obj->GetData().GetCacheSize();
        if (start.Value < end.Value && end.Value - start.Value < cacheSize && start.SectionNumber == end.SectionNumber)
        {
            const auto fa       = static_cast<uint64>(sect[start.SectionNumber - 1ULL].PointerToRawData);
            const auto fileView = obj->GetData().CopyToBuffer(fa + start.Value, static_cast<uint32>(fa + end.Value - start.Value), false);
            if (pcLnTab.Process(fileView, hdr64 ? Golang::Architecture::x64 : Golang::Architecture::x86))
            {
                return true;
            }
        }
    }

    // parse raw
    const auto pcLnTabSigsCandidates = FindPcLnTabSigsCandidates();
    CHECK(pcLnTabSigsCandidates.empty() == false, false, "");

    bool found = false;
    for (const auto& candidatesVA : pcLnTabSigsCandidates)
    {
        const auto cacheSize = obj->GetData().GetCacheSize();
        const auto fa        = VAtoFA(candidatesVA);
        const auto fileView  = obj->GetData().CopyToBuffer(fa, cacheSize, false);
        if (pcLnTab.Process(fileView, hdr64 ? Golang::Architecture::x64 : Golang::Architecture::x86))
        {
            return true;
        }
    }

    RETURNERROR(false, "Go PcLnTab not found!");
}

bool PEFile::ParseGoBuild()
{
    constexpr std::string_view goBuildPrefix{ "\xff Go build ID: \"" };
    constexpr std::string_view goBuildEnd{ "\"\n \xff" };

    const auto cacheSize = obj->GetData().GetCacheSize();
    const auto fileSize  = obj->GetData().GetSize();

    const auto fileViewBuildId = obj->GetData().CopyToBuffer(0, cacheSize, false);

    // we should find go build id at the start of the file
    const std::string_view bufferBuildId{ reinterpret_cast<char*>(fileViewBuildId.GetData()), fileViewBuildId.GetLength() }; // force for find
    const auto sPos = bufferBuildId.find(goBuildPrefix);
    CHECK(sPos != std::string::npos, false, "");

    const auto ePos = bufferBuildId.find(goBuildEnd, sPos + 1);
    CHECK(ePos != std::string::npos, false, "");

    const std::string_view buildID{ bufferBuildId.data() + sPos + goBuildPrefix.size(), ePos - sPos - goBuildPrefix.size() };
    pcLnTab.SetBuildId(buildID);

    return true;
}

bool PEFile::ParseGoBuildInfo()
{
    // we should find go build info at the start of the file .data section
    constexpr uint32 flags = __IMAGE_SCN_CNT_INITIALIZED_DATA | __IMAGE_SCN_MEM_READ | __IMAGE_SCN_MEM_WRITE;
    auto dataOffset        = 0ULL;
    for (auto i = 0U; i < nrSections; i++)
    {
        if (sect[i].VirtualAddress != 0 && (sect[i].Characteristics & flags) == flags)
        {
            dataOffset = static_cast<uint64>(sect[i].PointerToRawData);
            break;
        }
    }
    CHECK(dataOffset != 0, false, "");

    constexpr std::string_view buildInfoMagic{ "\xff Go buildinf:" };
    constexpr uint16 buildInfoAlign{ 16 };
    constexpr uint16 buildInfoSize{ 32 };

    const auto cacheSize = obj->GetData().GetCacheSize();
    const auto fileSize  = obj->GetData().GetSize();

    const auto fileViewBuildInfo = obj->GetData().CopyToBuffer(dataOffset, cacheSize, false);
    CHECK(fileViewBuildInfo.IsValid(), false, "");
    const std::string_view bufferBuildInfo{ reinterpret_cast<char*>(fileViewBuildInfo.GetData()), fileViewBuildInfo.GetLength() }; // force for find
    auto sPos = bufferBuildInfo.find(buildInfoMagic);
    CHECK(sPos != std::string::npos, false, "");

    CHECK(bufferBuildInfo.size() - sPos >= buildInfoSize, false, "");

    const std::string_view buildInfo{ bufferBuildInfo.data() + sPos + 1, buildInfoSize };

    constexpr auto ptrOffset = 13;
    const uint8 ptrSize      = buildInfo[ptrOffset];
    const uint8 endianess    = buildInfo[ptrOffset + 1];

    uint64 runtimeBuildVersionVA = 0;
    uint64 runtimeModInfoVA      = 0;
    if (ptrSize == 4)
    {
        runtimeBuildVersionVA = *reinterpret_cast<uint32*>(const_cast<char*>(buildInfo.data() + ptrOffset + 2));
        runtimeModInfoVA      = *reinterpret_cast<uint32*>(const_cast<char*>(buildInfo.data() + ptrOffset + 2 + ptrSize));
    }
    else
    {
        runtimeBuildVersionVA = *reinterpret_cast<uint64*>(const_cast<char*>(buildInfo.data() + ptrOffset + 2));
        runtimeModInfoVA      = *reinterpret_cast<uint64*>(const_cast<char*>(buildInfo.data() + ptrOffset + 2 + ptrSize));
    }

    const auto runtimeBuildVersionFA = VAtoFA(runtimeBuildVersionVA);
    const auto runtimeModInfoFA      = VAtoFA(runtimeModInfoVA);

    const auto ptrRuntimeBuildVersion = obj->GetData().CopyToBuffer(runtimeBuildVersionFA, ptrSize * 2, false);
    const auto ptrViewRuntimeModInfo  = obj->GetData().CopyToBuffer(runtimeModInfoFA, ptrSize * 2, false);
    CHECK(ptrRuntimeBuildVersion.IsValid(), false, "");
    CHECK(ptrViewRuntimeModInfo.IsValid(), false, "");

    uint64 strRuntimeBuildVersionVA     = 0;
    uint64 strRuntimeBuildVersionLength = 0;
    uint64 strViewRuntimeModInfoVA      = 0;
    uint64 strViewRuntimeModInfoLength  = 0;
    if (ptrSize == 4)
    {
        strRuntimeBuildVersionVA     = *reinterpret_cast<uint32*>(ptrRuntimeBuildVersion.GetData());
        strRuntimeBuildVersionLength = *reinterpret_cast<uint32*>(ptrRuntimeBuildVersion.GetData() + ptrSize);
        strViewRuntimeModInfoVA      = *reinterpret_cast<uint32*>(ptrViewRuntimeModInfo.GetData());
        strViewRuntimeModInfoLength  = *reinterpret_cast<uint32*>(ptrViewRuntimeModInfo.GetData() + ptrSize);
    }
    else
    {
        strRuntimeBuildVersionVA     = *reinterpret_cast<uint64*>(ptrRuntimeBuildVersion.GetData());
        strRuntimeBuildVersionLength = *reinterpret_cast<uint64*>(ptrRuntimeBuildVersion.GetData() + ptrSize);
        strViewRuntimeModInfoVA      = *reinterpret_cast<uint64*>(ptrViewRuntimeModInfo.GetData());
        strViewRuntimeModInfoLength  = *reinterpret_cast<uint64*>(ptrViewRuntimeModInfo.GetData() + ptrSize);
    }

    const auto strRuntimeBuildVersionFA = VAtoFA(strRuntimeBuildVersionVA);
    const auto strViewRuntimeModInfoFA  = VAtoFA(strViewRuntimeModInfoVA);

    const auto fileViewRuntimeBuildVersion = obj->GetData().CopyToBuffer(strRuntimeBuildVersionFA, static_cast<uint32>(strRuntimeBuildVersionLength), false);
    CHECK(fileViewRuntimeBuildVersion.IsValid(), false, "");
    const std::string_view runtimeBuildVersion{ reinterpret_cast<char*>(fileViewRuntimeBuildVersion.GetData()), strRuntimeBuildVersionLength };
    pcLnTab.SetRuntimeBuildVersion(runtimeBuildVersion);

    const auto fileViewRuntimeModInfo = obj->GetData().CopyToBuffer(strViewRuntimeModInfoFA, static_cast<uint32>(strViewRuntimeModInfoLength), false);
    CHECK(fileViewRuntimeModInfo.IsValid(), false, "");
    std::string_view runtimeModInfo{ reinterpret_cast<char*>(fileViewRuntimeModInfo.GetData()), strViewRuntimeModInfoLength };
    if (strViewRuntimeModInfoLength >= 33 && runtimeModInfo[strViewRuntimeModInfoLength - 17] == '\n')
    {
        runtimeModInfo = std::string_view{ runtimeModInfo.data() + 16, strViewRuntimeModInfoLength - 16 - 16 };
    }
    pcLnTab.SetRuntimeBuildModInfo(runtimeModInfo);

    return true;
}

std::vector<uint64> PEFile::FindPcLnTabSigsCandidates() const
{
    constexpr std::string_view pclntabSigs[6]{ { "\xFB\xFF\xFF\xFF\x00\x00", 6 }, { "\xFA\xFF\xFF\xFF\x00\x00", 6 }, { "\xF0\xFF\xFF\xFF\x00\x00", 6 },
                                               { "\xFF\xFF\xFF\xFB\x00\x00", 6 }, { "\xFF\xFF\xFF\xFA\x00\x00", 6 }, { "\xFF\xFF\xFF\xF0\x00\x00", 6 } };

    std::vector<uint64> indexes;
    indexes.reserve(10); // usually not that many sigs found matching

    for (uint32 i = 0; i < nrSections; i++)
    {
        const auto sectionBuffer = obj->GetData().CopyToBuffer(sect[i].PointerToRawData, sect[i].SizeOfRawData);
        CHECK(sectionBuffer.IsValid(), indexes, "");
        const auto section = std::string_view{ reinterpret_cast<char*>(sectionBuffer.GetData()), sectionBuffer.GetLength() };

        for (const auto& sig : pclntabSigs)
        {
            uint64 index = 0;
            while ((index = section.find(sig, index)) != std::string::npos)
            {
                if (index != std::string::npos && index < sect[i].SizeOfRawData)
                {
                    indexes.push_back(index + sect[i].VirtualAddress + imageBase);
                }
                index += sig.size();
            }
        }
    }

    return indexes;
}

bool PEFile::GetColorForBufferIntel(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result)
{
    const auto* p = buf.begin();
    switch (*p)
    {
    case 0xFF:
        if (buf.GetLength() >= 6)
        {
            if (p[1] == 0x15) // possible call to API
            {
                const auto addr = *reinterpret_cast<const uint32_t*>(p + 2);
                if (addr >= this->imageBase && addr <= this->imageBase + this->virtualComputedSize)
                {
                    result.start = offset;
                    result.end   = offset + 5;
                    result.color = INS_CALL_COLOR;
                    return true;
                }
            }
            else if (p[1] == 0x25) // possible jump to API
            {
                const auto addr = *reinterpret_cast<const uint32_t*>(p + 2);
                if (addr >= this->imageBase && addr <= this->imageBase + this->virtualComputedSize)
                {
                    result.start = offset;
                    result.end   = offset + 5;
                    result.color = INS_JUMP_COLOR;
                    return true;
                }
            }
            return false;
        }
        return false;
    case 0xCC: // INT 3
        result.start = result.end = offset;
        result.color              = INS_BREAKPOINT_COLOR;
        return true;
    case 0x55:
        if (buf.GetLength() >= 3)
        {
            if (*reinterpret_cast<const uint16_t*>(p + 1) == 0xEC8B) // possible `push EBP` followed by MOV ebp, sep
            {
                result.start = offset;
                result.end   = offset + 2;
                result.color = START_FUNCTION_COLOR;
                return true;
            }
        }
        return false;
    case 0x8B:
        if (buf.GetLength() >= 4)
        {
            if ((*reinterpret_cast<const uint16_t*>(p + 1) == 0x5DE5) && (p[3] == 0xC3)) // possible `MOV esp, EBP` followed by `POP ebp` and `RET`
            {
                result.start = offset;
                result.end   = offset + 3;
                result.color = END_FUNCTION_COLOR;
                return true;
            }
        }
        return false;
    }

    return false;
}

bool PEFile::GetColorForBuffer(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result)
{
    CHECK(buf.IsValid(), false, "");
    result.color = ColorPair{ Color::Transparent, Color::Transparent };
    CHECK(showOpcodesMask != 0, false, "");

    auto* p = buf.begin();
    switch (*p)
    {
    case 0x4D:
        if (((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::Header) == (uint32) GView::Dissasembly::Opcodes::Header))
        {
            if (buf.GetLength() >= 4)
            {
                if (*reinterpret_cast<const uint16*>(p) == 0x5A4D && (p[2] == 0x00 || p[2] == 0x90 || p[2] == 0x78) && p[3] == 0x00)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = END_FUNCTION_COLOR;
                    result.color = EXE_MARKER_COLOR;
                    return true;
                } // do not break
            }
        }
    case 0x50:
        if (((showOpcodesMask & (uint32) GView::Dissasembly::Opcodes::Header) == (uint32) GView::Dissasembly::Opcodes::Header))
        {
            if (buf.GetLength() >= 4)
            {
                if (*reinterpret_cast<const uint32*>(p) == 0x00004550)
                {
                    result.start = offset;
                    result.end   = offset + 3;
                    result.color = END_FUNCTION_COLOR;
                    result.color = EXE_MARKER_COLOR;
                    return true;
                } // do not break
            }
        }
    default:
        switch ((PE::MachineType) nth32.FileHeader.Machine)
        {
        case PE::MachineType::I386:
        case PE::MachineType::IA64:
        case PE::MachineType::AMD64:
            for (const auto& [start, end] : executableZonesFAs)
            {
                if (offset >= start && offset < end)
                {
                    return GetColorForBufferIntel(offset, buf, result);
                }
            }
            break;
        default:
            break;
        }
    }

    return false;
}

void PEFile::RunCommand(std::string_view commandName)
{
    if (commandName == "DigitalSignature")
    {
        while (!signatureChecked)
        {
            data.winTrust.errorMessage = "Digital signature not found!";

            const auto& securityDirectory = dirs[(uint32) DirectoryType::Security];

            WinCertificate cert{};
            CHECKBK(obj->GetData().Copy<WinCertificate>(securityDirectory.VirtualAddress, cert), "");
            CHECKBK(cert.wCertificateType == __WIN_CERT_TYPE_PKCS_SIGNED_DATA, "");

            CHECKBK(GView::DigitalSignature::VerifyEmbeddedSignature(data, obj->GetData()), "");
#ifdef BUILD_FOR_WINDOWS
            data.winTrust.callSuccessful = GView::DigitalSignature::VerifySignatureForPE(obj->GetPath(), obj->GetData(), data);
            CHECKBK(data.winTrust.errorCode != GView::DigitalSignature::SIGNATURE_NOT_FOUND, "");

            GView::DigitalSignature::GetSignaturesInformation(obj->GetPath(), data);
#endif

            while (!signatureChecked)
            {
                Buffer blob = obj->GetData().CopyToBuffer(securityDirectory.VirtualAddress + 8ULL, cert.dwLength - 8);
                GView::DigitalSignature::AuthenticodeToHumanReadable(blob, data.data.humanReadable);

                signatureChecked = true;

                break;
            }
        };

        if (signatureChecked)
        {
            PE::Commands::DigitalSignature(this).Show();
        }
        else
        {
            AppCUI::Dialogs::MessageBox::ShowError("Error", data.winTrust.errorMessage);
        }
    }
    else if (commandName == "AreaHighlighter")
    {
        static auto ah = PE::Commands::AreaHighlighter(this);
        ah.Show();
    }
}

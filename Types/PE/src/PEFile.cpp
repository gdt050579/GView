#include "pe.hpp"

using namespace GView::Type::PE;

struct CV_INFO_PDB20
{
    uint32_t CvSignature;   // NBxx
    uint32_t Offset;        // Always 0 for NB10
    uint32_t Signature;     // seconds since 01.01.1970
    uint32_t Age;           // an always-incrementing value
    uint8_t PdbFileName[1]; // zero terminated string with the name of the PDB file
};

struct CV_INFO_PDB70
{
    uint32_t CvSignature;
    Guid Signature;         // unique identifier
    uint32_t Age;           // an always-incrementing value
    uint8_t PdbFileName[1]; // zero terminated string with the name of the PDB file
};

#define CV_SIGNATURE_NB10 '01BN'
#define CV_SIGNATURE_RSDS 'SDSR'

#define ADD_PANEL(name)                                                                                                                    \
    {                                                                                                                                      \
        Panels[PanelsCount++] = name;                                                                                                      \
    }

static std::string_view peDirsNames[15] = { "Export",      "Import",       "Resource",     "Exceptions",        "Security",
                                           "Base Reloc",  "Debug",        "Architecture", "Global Ptr",        "TLS",
                                           "Load Config", "Bound Import", "IAT",          "Delay Import Desc", "COM+ Runtime" };

static std::map<uint32_t, std::string_view> languageCode = {
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

uint32_t SectionALIGN(uint32_t value, uint32_t alignValue)
{
    if (alignValue == 0)
        return value;
    if (value == 0)
        return alignValue;
    if ((value % alignValue) == 0)
        return value;
    return ((value / alignValue) + 1) * alignValue;
}

PEFile::PEFile(Reference<GView::Utils::FileCache> fileCache)
{
    uint32_t tr;
    // creez vectorii pt. exporturi / importuri
    res.reserve(64);
    exp.reserve(64);
    errList.reserve(8);
    debugData.reserve(16);
    impDLL.reserve(64);
    impFunc.reserve(128);

    file = fileCache;

    peCols.colMZ      = ColorPair{ Color::Olive, Color::Transparent };
    peCols.colPE      = ColorPair{ Color::Magenta, Color::Transparent };
    peCols.colSectDef = ColorPair{ Color::DarkRed, Color::Transparent };
    peCols.colSect    = ColorPair{ Color::Silver, Color::Transparent };

    peCols.colDir[0] = ColorPair{ Color::Aqua, Color::Transparent };
    peCols.colDir[1] = ColorPair{ Color::Red, Color::Transparent };
    for (tr = 2; tr < 15; tr++)
        peCols.colDir[tr] = ColorPair{ Color::Green, Color::Transparent };
    peCols.colDir[__IMAGE_DIRECTORY_ENTRY_SECURITY] = ColorPair{ Color::DarkGreen, Color::Transparent };

    asmShow = 0xFF;

    PanelsCount = 0;
}

bool PEFile::ReadBufferFromRVA(uint32_t RVA, void* Buffer, uint32_t BufferSize)
{
    uint64_t FA;
    if ((Buffer == nullptr) || (BufferSize == 0))
        return false;
    if ((FA = RVAtoFilePointer(RVA)) == PE_INVALID_ADDRESS)
        return false;
    return file->Copy(Buffer, FA, BufferSize);
}

std::string_view PEFile::ReadString(uint32_t RVA, unsigned int maxSize)
{
    auto buf = file->Get(RVAtoFilePointer(RVA), maxSize);
    if (buf.Empty())
        return std::string_view{};
    auto p = buf.data;
    auto e = p + buf.length;
    while ((p < e) && (*p))
        p++;
    return std::string_view{ reinterpret_cast<const char*>(buf.data), static_cast<size_t>(p - buf.data) };
}

bool PEFile::ReadUnicodeLengthString(uint32_t FileAddress, char* text, int maxSize)
{
    uint16_t sz, tr;
    uint8_t val;
    uint64_t addr = FileAddress;
    if ((file->Copy<uint16_t>(addr, sz) == false) || (sz > 256))
        return false;

    for (tr = 0, addr += 2; (tr < sz) && (tr < maxSize - 1) && (file->Copy<uint8_t>(addr, val)) && (val != 0); tr++, addr += 2)
        text[tr] = val;
    text[tr] = 0;

    return true;
}

void PEFile::AddError(ErrorType type, std::string_view message)
{
    auto& item = errList.emplace_back();
    item.type  = type;
    item.text  = message;
}

uint64_t PEFile::RVAtoFilePointer(uint64_t RVA)
{
    // uint64_t	sStart;
    // uint64_t	tr,sectSize;
    // int		min_sect=-1;

    uint64_t tr;
    uint64_t fi = 0;
    if (RVA < sect[0].VirtualAddress)
        return PE_INVALID_ADDRESS;
    for (tr = 0; tr < nrSections; tr++)
    {
        if ((RVA < sect[tr].VirtualAddress) && (tr > 0))
        {
            fi = sect[tr - 1].PointerToRawData + (RVA - sect[tr - 1].VirtualAddress);
            break;
        };
    }
    if (tr == nrSections)
        fi = sect[tr - 1].PointerToRawData + (RVA - sect[tr - 1].VirtualAddress);
    return fi;
}

int PEFile::RVAToSectionIndex(uint64_t RVA)
{
    uint32_t tr;
    for (tr = 0; tr < nrSections; tr++)
    {
        if ((RVA >= sect[tr].VirtualAddress) && (RVA < sect[tr].VirtualAddress + sect[tr].Misc.VirtualSize))
            return tr;
    }
    return -1;
}

std::string_view PEFile::GetMachine()
{
    switch (nth32.FileHeader.Machine)
    {
    case __IMAGE_FILE_MACHINE_ALPHA:
        return "ALPHA";
    case __IMAGE_FILE_MACHINE_ALPHA64:
        return "ALPHA 64";
    case __IMAGE_FILE_MACHINE_AM33:
        return "AM 33";
    case __IMAGE_FILE_MACHINE_AMD64:
        return "AMD 64";
    case __IMAGE_FILE_MACHINE_ARM:
        return "ARM";
    case __IMAGE_FILE_MACHINE_CEE:
        return "CEE";
    case __IMAGE_FILE_MACHINE_CEF:
        return "CEF";
    case __IMAGE_FILE_MACHINE_EBC:
        return "EBC";
    case __IMAGE_FILE_MACHINE_I386:
        return "Intel 386";
    case __IMAGE_FILE_MACHINE_IA64:
        return "Intel IA64";
    case __IMAGE_FILE_MACHINE_M32R:
        return "M 32R";
    case __IMAGE_FILE_MACHINE_MIPSFPU16:
        return "MIP SFPU 16";
    case __IMAGE_FILE_MACHINE_MIPS16:
        return "MIP 16";
    case __IMAGE_FILE_MACHINE_MIPSFPU:
        return "MIP SFPU";
    case __IMAGE_FILE_MACHINE_POWERPC:
        return "POWER PC";
    case __IMAGE_FILE_MACHINE_POWERPCFP:
        return "POWER PC (FP)";
    case __IMAGE_FILE_MACHINE_R10000:
        return "R 10000";
    case __IMAGE_FILE_MACHINE_R3000:
        return "R 3000";
    case __IMAGE_FILE_MACHINE_R4000:
        return "MIPS@ little indian";
    case __IMAGE_FILE_MACHINE_SH3:
        return "Hitachi SH3";
    case __IMAGE_FILE_MACHINE_SH3DSP:
        return "Hitachi SH3 (DSP)";
    case __IMAGE_FILE_MACHINE_SH3E:
        return "Hitachi SH2 (E)";
    case __IMAGE_FILE_MACHINE_SH4:
        return "Hitachi SH4";
    case __IMAGE_FILE_MACHINE_SH5:
        return "Hitachi SH5";
    case __IMAGE_FILE_MACHINE_THUMB:
        return "Thumb";
    case __IMAGE_FILE_MACHINE_TRICORE:
        return "Tricore";
    case __IMAGE_FILE_MACHINE_UNKNOWN:
        return "Unknown";
    case __IMAGE_FILE_MACHINE_WCEMIPSV2:
        return "WCEMIPSV2";
    case __IMAGE_FILE_MACHINE_ARMNT:
        return "ARM Thumb-2";
    }
    return "";
}

std::string_view PEFile::GetSubsystem()
{
    switch (nth32.OptionalHeader.Subsystem)
    {
    case __IMAGE_SUBSYSTEM_UNKNOWN:
        return "Unknown";
    case __IMAGE_SUBSYSTEM_NATIVE:
        return "Native";
    case __IMAGE_SUBSYSTEM_WINDOWS_GUI:
        return "Windows GUI (Graphics)";
    case __IMAGE_SUBSYSTEM_WINDOWS_CUI:
        return "Windows CUI (Console)";
    case __IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        return "Windows CE GUI (Graphics)";
    case __IMAGE_SUBSYSTEM_POSIX_CUI:
        return "Posix CUI (Console)";
    case __IMAGE_SUBSYSTEM_EFI_APPLICATION:
        return "EFI Applications";
    case __IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        return "Boot Service Driver";
    case __IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        return "EFI routine driver";
    case __IMAGE_SUBSYSTEM_EFI_ROM:
        return "EFI Rom";
    case __IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
        return "Native Windows";
    case __IMAGE_SUBSYSTEM_OS2_CUI:
        return "OS2 CUI (Console)";
    case __IMAGE_SUBSYSTEM_XBOX:
        return "XBOX";
    }
    return "";
}

uint64_t PEFile::FilePointerToRVA(uint64_t fileAddress)
{
    unsigned int tr;
    uint64_t temp;

    for (tr = 0; tr < nrSections; tr++)
    {
        if ((fileAddress >= sect[tr].PointerToRawData) && (fileAddress < sect[tr].PointerToRawData + sect[tr].SizeOfRawData) &&
            (sect[tr].VirtualAddress > 0))
        {
            temp = fileAddress - sect[tr].PointerToRawData;
            if (temp < sect[tr].Misc.VirtualSize)
                return temp + sect[tr].VirtualAddress;
        }
    }

    return PE_INVALID_ADDRESS;
}

uint64_t PEFile::FilePointerToVA(uint64_t fileAddress)
{
    uint64_t RVA;

    if ((RVA = FilePointerToRVA(fileAddress)) != PE_INVALID_ADDRESS)
        return RVA + imageBase;

    return PE_INVALID_ADDRESS;
}

uint64_t PEFile::ConvertAddress(uint64_t address, unsigned int fromAddressType, unsigned int toAddressType)
{
    switch (fromAddressType)
    {
    case ADDR_FA:
        switch (toAddressType)
        {
        case ADDR_FA:
            return address;
        case ADDR_VA:
            return FilePointerToVA(address);
        case ADDR_RVA:
            return FilePointerToRVA(address);
        };
        break;
    case ADDR_VA:
        switch (toAddressType)
        {
        case ADDR_FA:
            if (address > imageBase)
                return RVAtoFilePointer(address - imageBase);
            break;
        case ADDR_VA:
            return address;
        case ADDR_RVA:
            if (address > imageBase)
                return address - imageBase;
            break;
        };
        break;
    case ADDR_RVA:
        switch (toAddressType)
        {
        case ADDR_FA:
            return RVAtoFilePointer(address);
        case ADDR_VA:
            return address + imageBase;
        case ADDR_RVA:
            return address;
        };
        break;
    }
    return PE_INVALID_ADDRESS;
}

bool PEFile::BuildExport()
{
    uint64_t faddr, oaddr, naddr;
    uint32_t RVA, export_RVA;
    uint16_t export_ordinal;
    LocalString<256> tempStr;
    bool* ordinals;

    exp.clear();
    ordinals = nullptr;

    RVA = dirs[0].VirtualAddress; // export directory
    if (RVA == 0)
        return false;

    if ((faddr = RVAtoFilePointer(RVA)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid RVA for Export directory (0x%X)", (uint32_t) RVA);
        AddError(ErrorType::Error, tempStr);
        return false;
    }
    if (file->Copy<ImageExportDirectory>(faddr, exportDir) == false)
    {
        tempStr.SetFormat("Unable to read full Export Directory structure from RVA (0x%X)", (uint32_t) RVA);
        AddError(ErrorType::Error, tempStr);
        return false;
    }
    if (exportDir.Name == 0)
    {
        tempStr.SetFormat("Invalid RVA for export name (0x%08X)", (uint32_t) exportDir.Name);
        AddError(ErrorType::Warning, tempStr);
    }
    else
    {
        auto dll_name = ReadString(exportDir.Name, MAX_DLL_NAME);
        if (dll_name.empty())
        {
            tempStr.SetFormat("Unable to read export name from RVA (0x%X)", (uint32_t) exportDir.Name);
            AddError(ErrorType::Error, tempStr);
            return false;
        }
        this->dllName = dll_name;
        for (auto ch : dll_name)
            if ((ch < 32) || (ch > 127))
            {
                AddError(ErrorType::Warning, "Export name contains invalid characters !");
                break;
            }
    }
    if (exportDir.NumberOfFunctions == 0 && exportDir.NumberOfNames == 0) // no exports
    {
        AddError(ErrorType::Warning, "No functions in Export Directory");
        return false;
    }
    if (exportDir.NumberOfFunctions > 0xFFFF)
    {
        tempStr.SetFormat("Too many exported functions (0x%08X). Maximum allowes is 0xFFFF.", exportDir.NumberOfFunctions);
        AddError(ErrorType::Error, tempStr);
        return false;
    }

    if ((naddr = RVAtoFilePointer(exportDir.AddressOfNames)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid AddressOfNames (0x%x) from export directory", (uint32_t) exportDir.AddressOfNames);
        AddError(ErrorType::Error, tempStr);
        return false;
    }
    if ((oaddr = RVAtoFilePointer(exportDir.AddressOfNameOrdinals)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid AddressOfNameOrdinals (0x%x) from export directory", (uint32_t) exportDir.AddressOfNameOrdinals);
        AddError(ErrorType::Error, tempStr);
        return false;
    }
    if ((faddr = RVAtoFilePointer(exportDir.AddressOfFunctions)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid AddressOfFunctions (0x%x) from export directory", (uint32_t) exportDir.AddressOfFunctions);
        AddError(ErrorType::Error, tempStr);
        return false;
    }

    if (exportDir.NumberOfNames < exportDir.NumberOfFunctions)
    {
        ordinals = new bool[exportDir.NumberOfFunctions];
        for (uint32_t tr = 0; tr < exportDir.NumberOfFunctions; tr++)
            ordinals[tr] = false;
    }
    for (uint32_t tr = 0; tr < exportDir.NumberOfNames; tr++, naddr += 4, oaddr += 2)
    {
        if (file->Copy<uint32_t>(naddr, RVA) == false)
        {
            AddError(ErrorType::Error, "Unable to read export function name");
            return false;
        }
        if (file->Copy<uint16_t>(oaddr, export_ordinal) == false)
        {
            AddError(ErrorType::Error, "Unable to read export function ordinal");
            return false;
        }
        if (file->Copy<uint32_t>(faddr + ((uint64_t) export_ordinal) * 4, export_RVA) == false)
        {
            AddError(ErrorType::Error, "Unable to read export function address");
            return false;
        }
        auto export_name = ReadString(RVA, MAX_EXPORTFNC_SIZE);
        if (export_name.empty())
        {
            AddError(ErrorType::Error, "Unable to read export function name");
            return false;
        }
        export_ordinal += exportDir.Base;
        if ((exportDir.NumberOfNames < exportDir.NumberOfFunctions) && (export_ordinal < exportDir.NumberOfFunctions))
        {
            ordinals[export_ordinal] = true;
        }
        // add to list
        auto& item   = exp.emplace_back();
        item.RVA     = export_RVA;
        item.Ordinal = export_ordinal;
        item.Name    = export_name;
    }
    // adaug si ordinalii
    if (exportDir.NumberOfNames < exportDir.NumberOfFunctions)
    {
        LocalString<128> ordinal_name;
        for (uint32_t tr = 0; tr < exportDir.NumberOfFunctions; tr++)
        {
            if (ordinals[tr] == false)
            {
                if (file->Copy<uint32_t>(faddr + ((uint64_t) tr) * 4, export_RVA) == false)
                {
                    AddError(ErrorType::Error, "Unable to read export function ordinal ID");
                    return false;
                }
                if (export_RVA > 0)
                {
                    export_ordinal = tr;
                    if (!ordinal_name.SetFormat("_Ordinal_%u", tr))
                    {
                        AddError(ErrorType::Error, "Fail to create ordinal name for ID");
                        return false;
                    }
                    auto& item   = exp.emplace_back();
                    item.RVA     = export_RVA;
                    item.Ordinal = export_ordinal;
                    item.Name    = std::string_view{ ordinal_name.GetText(), ordinal_name.Len() };
                }
            }
        }
    }

    if (ordinals) // free memory
        delete[] ordinals;

    return true;
}

bool PEFile::BuildTLS()
{
    uint32_t RVA;
    uint64_t faddr;

    hasTLS = false;
    RVA    = dirs[__IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if ((RVA == 0) || (dirs[__IMAGE_DIRECTORY_ENTRY_TLS].Size == 0))
        return false;

    if ((faddr = RVAtoFilePointer(RVA)) == PE_INVALID_ADDRESS)
        return false;
    if (file->Copy<ImageTLSDirectory32>(faddr, tlsDir) == false)
        return false;
    hasTLS = true;
    return true;
}

void PEFile::BuildVersionInfo()
{
    uint32_t szRead;

    for (auto& ri : this->res)
    {
        if (ri.Type != (uint32_t) __RT_VERSION)
            continue;
        if (ri.Start >= file->GetSize())
            break;
        szRead = (uint32_t) ri.Size;
        if (szRead > MAX_VERSION_BUFFER)
            szRead = MAX_VERSION_BUFFER;
        if (ri.Start + szRead >= file->GetSize())
            szRead = (uint32_t) (file->GetSize() - ri.Start);

        auto buf = file->Get(ri.Start, szRead);

        if (buf.Empty())
        {
            AddError(ErrorType::Warning, "Unable to read version infornation resource");
            break;
        }
        if (Ver.ComputeVersionInformation(buf.data, buf.length) == false)
        {
            AddError(ErrorType::Warning, "Invalid version information resource.");
            break;
        }
    }
}

std::string_view PEFile::ResourceIDToName(uint32_t resID)
{
    switch (resID)
    {
    case __RT_CURSOR:
        return "Cursor";
    case __RT_BITMAP:
        return "Bitmap";
    case __RT_ICON:
        return "Icon";
    case __RT_MENU:
        return "Menu";
    case __RT_DIALOG:
        return "Dialog";
    case __RT_STRING:
        return "String";
    case __RT_FONTDIR:
        return "FontDir";
    case __RT_FONT:
        return "Font";
    case __RT_ACCELERATOR:
        return "Accelerator";
    case __RT_RCDATA:
        return "RCData";
    case __RT_MESSAGETABLE:
        return "MessageTable";
    case __RT_VERSION:
        return "Version";
    case __RT_DLGINCLUDE:
        return "DLG Include";
    case __RT_PLUGPLAY:
        return "Plug & Play";
    case __RT_VXD:
        return "VXD";
    case __RT_ANICURSOR:
        return "Animated Cursor";
    case __RT_ANIICON:
        return "Animated Icon";
    case __RT_HTML:
        return "Html";
    case __RT_MANIFEST:
        return "Manifest";
    case __RT_GROUP_CURSOR:
        return "Group Cursor";
    case __RT_GROUP_ICON:
        return "Group Icon";
    default:
        break;
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

bool PEFile::ProcessResourceDataEntry(uint64_t relAddress, uint64_t startRes, uint32_t* level, uint32_t indexLevel, char* resName)
{
    ImageResourceDataEntry resDE;
    uint64_t fileAddress;
    LocalString<512> tempStr;

    fileAddress = relAddress + startRes;

    if (file->Copy<ImageResourceDataEntry>(fileAddress, resDE) == false)
    {
        tempStr.SetFormat("Unable to read Resource Data Entry from (0x%X)", (uint32_t) fileAddress);
        AddError(ErrorType::Warning, tempStr);
        return false;
    }

    if ((fileAddress = RVAtoFilePointer(resDE.OffsetToData)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid RVA for resource entry (0x%X)", (uint32_t) resDE.OffsetToData);
        AddError(ErrorType::Warning, tempStr);
        return false;
    }

    auto& resInf = res.emplace_back();

    resInf.Type     = level[0];
    resInf.ID       = level[1];
    resInf.Language = level[2];
    resInf.Start    = fileAddress;
    resInf.Size     = resDE.Size;
    resInf.CodePage = resDE.CodePage;
    resInf.Name.Set(resName);

    return true;
}

bool PEFile::ProcessResourceDirTable(uint64_t relAddress, uint64_t startRes, uint32_t* level, uint32_t indexLevel, char* parentName)
{
    ImageResourceDirectory resDir;
    ImageResourceDirectoryEntry dirEnt;
    uint32_t nrEnt, tr;
    uint64_t fileAddress;
    char resName[256];
    char temp[512];
    String tempStr;
    tempStr.Create(temp, sizeof(temp), true);

    fileAddress = relAddress + startRes;

    if (indexLevel > 3)
    {
        tempStr.SetFormat("Resource depth is too big (>3)");
        // sprintf(temp, "Resource depth is too big (>3)");
        AddError(ErrorType::Error, temp);
        return false;
    }
    if (file->Copy<ImageResourceDirectory>(fileAddress, resDir) == false)
    {
        tempStr.SetFormat("Unable to read Resource Structure from (0x%X)", (uint32_t) fileAddress);
        // sprintf(temp, "Unable to read Resource Structure from (0x%X)", (uint32_t)fileAddress);
        AddError(ErrorType::Warning, temp);
        return false;
    }
    // info
    // char temp[256];
    // sprintf(temp,"[DIR: at [%X] Name:%d ,
    // ID:%d]",(uint32_t)relAddress,resDir.NumberOfNamedEntries,resDir.NumberOfIdEntries);OutputDebugString(temp);

    nrEnt = resDir.NumberOfIdEntries;
    if (indexLevel == 0)
        nrEnt += resDir.NumberOfNamedEntries;
    if (resDir.NumberOfNamedEntries > nrEnt)
        nrEnt = resDir.NumberOfNamedEntries;
    if (nrEnt > 1024)
    {
        tempStr.SetFormat("Too many resources (>1024)");
        // sprintf(temp, "Too many resources (>1024)");
        AddError(ErrorType::Warning, temp);
        return false;
    }
    // citesc intrarile
    if (resDir.Characteristics != 0)
    {
        tempStr.SetFormat("IMAGE_RESOURCE_DIRECTORY (Invalid Characteristics field)");
        // sprintf(temp, "IMAGE_RESOURCE_DIRECTORY (Invalid Characteristics field)");
        AddError(ErrorType::Warning, temp);
        return false;
    }

    fileAddress += sizeof(ImageResourceDirectory);
    for (tr = 0; tr < nrEnt; tr++, fileAddress += sizeof(ImageResourceDirectoryEntry))
    {
        if (file->Copy<ImageResourceDirectoryEntry>(fileAddress, dirEnt) == false)
        {
            tempStr.SetFormat("Unable to read Resource Directory Entry from (0x%X)", (uint32_t) fileAddress);
            // sprintf(temp, "Unable to read Resource Directory Entry from (0x%X)", (uint32_t)fileAddress);
            AddError(ErrorType::Warning, temp);
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
    char temp[512];
    String tempStr;
    tempStr.Create(temp, sizeof(temp), true);

    res.clear();
    RVA = dirs[2].VirtualAddress; // export directory
    if (RVA == 0)
        return false;
    if ((addr = RVAtoFilePointer(RVA)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid RVA for Resource directory (0x%X)", (uint32_t) RVA);
        // sprintf(temp, "Invalid RVA for Resource directory (0x%X)", (uint32_t)RVA);
        AddError(ErrorType::Warning, temp);
        return false;
    }

    return ProcessResourceDirTable(0, addr, level, 0, (char*) "");
}

bool PEFile::BuildImportDLLFunctions(uint32_t index, ImageImportDescriptor* impD)
{
    uint64_t addr, IATaddr;
    ImageThunkData32 rvaFName32;
    ImageThunkData64 rvaFName64;
    std::string_view import_name;
    LocalString<512> tempStr;
    unsigned int count_f = 0;

    if (impD->OriginalFirstThunk == 0)
        addr = RVAtoFilePointer(impD->FirstThunk);
    else
        addr = RVAtoFilePointer(impD->OriginalFirstThunk);
    if (addr == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid RVA for OriginalFirstThunk (0x%X)", (uint32_t) impD->OriginalFirstThunk);
        AddError(ErrorType::Error, tempStr);
        return false;
    }

    IATaddr = impD->FirstThunk;
    if (RVAtoFilePointer(impD->FirstThunk) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid RVA for FirstThunk (0x%X)", (uint32_t) impD->FirstThunk);
        AddError(ErrorType::Error, tempStr);
        return false;
    }

    if (hdr64)
    {
        while ((file->Copy<ImageThunkData64>(addr, rvaFName64)) && (rvaFName64.u1.AddressOfData != 0) && (count_f < MAX_IMPORTED_FUNCTIONS))
        {
            if ((rvaFName64.u1.AddressOfData & __IMAGE_ORDINAL_FLAG64) != 0) // imported by ordinal
            {
                tempStr.SetFormat("Ordinal:%u", (rvaFName64.u1.Ordinal - __IMAGE_ORDINAL_FLAG64));
                import_name = tempStr.ToStringView();
            }
            else
            {
                import_name = ReadString((uint32_t) (rvaFName64.u1.AddressOfData + 2), MAX_IMPORTFNC_SIZE);
                if (import_name.empty())
                {
                    tempStr.SetFormat("Invalid RVA import name (0x%X)", (uint32_t) rvaFName64.u1.AddressOfData + 2);
                    AddError(ErrorType::Error, tempStr);
                    return false;
                }
            }
            auto& item    = impFunc.emplace_back();
            item.dllIndex = index;
            item.RVA      = IATaddr;
            item.Name     = import_name;
            count_f++;
            addr += sizeof(ImageThunkData64);
            IATaddr += sizeof(ImageThunkData64);
        }
    }
    else
    {
        while ((file->Copy<ImageThunkData32>(addr, rvaFName32)) && (rvaFName32.u1.AddressOfData != 0) && (count_f < MAX_IMPORTED_FUNCTIONS))
        {
            if ((rvaFName32.u1.AddressOfData & __IMAGE_ORDINAL_FLAG32) != 0) // avem functie importata prin ordinal:
            {
                tempStr.SetFormat("Ordinal:%u", (rvaFName32.u1.Ordinal - __IMAGE_ORDINAL_FLAG32));
                import_name = tempStr.ToStringView();
            }
            else
            {
                import_name = ReadString(rvaFName32.u1.AddressOfData + 2, MAX_IMPORTFNC_SIZE);
                if (import_name.empty())
                {
                    tempStr.SetFormat("Invalid RVA import name (0x%X)", (uint32_t) rvaFName32.u1.AddressOfData + 2);
                    AddError(ErrorType::Error, tempStr);
                    return false;
                }
            }
            auto& item    = impFunc.emplace_back();
            item.dllIndex = index;
            item.RVA      = IATaddr;
            item.Name     = import_name;
            count_f++;
            addr += sizeof(ImageThunkData32);
            IATaddr += sizeof(ImageThunkData32);
        }
    }
    if (count_f >= MAX_IMPORTED_FUNCTIONS)
    {
        tempStr.SetFormat("Too many imported functions (0x%X)", (uint32_t) rvaFName32.u1.AddressOfData + 2);
        AddError(ErrorType::Error, tempStr);
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
    if ((addr = RVAtoFilePointer(RVA)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid RVA for Import directory (0x%X)", (uint32_t) RVA);
        AddError(ErrorType::Error, tempStr);
        return false;
    }
    // citesc numele de DLL-uri , unul cate unu

    nrDLLs = 0;
    while ((result = file->Copy<ImageImportDescriptor>(addr, impD)) == true)
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
        tempStr.SetFormat("Unable to read import directory data from RVA (0x%X)", (uint32_t) RVA);
        AddError(ErrorType::Error, tempStr);
        return false;
    }

    return true;
}

bool PEFile::BuildDebugData()
{
    uint64_t faddr;
    uint32_t tr, size, bufSize;
    LocalString<512> tempStr;
    ImageDebugDirectory imgd;
    uint8_t buf[MAX_PDB_NAME + 64];
    CV_INFO_PDB20* pdb20;
    CV_INFO_PDB70* pdb70;

    debugData.clear();
    pdb20 = (CV_INFO_PDB20*) &buf[0];
    pdb70 = (CV_INFO_PDB70*) &buf[0];
    pdbName.Clear();
    memset(buf, 0, MAX_PDB_NAME + 64);

    if (dirs[__IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == 0)
        return false;
    if ((faddr = RVAtoFilePointer(dirs[__IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress)) == PE_INVALID_ADDRESS)
    {
        tempStr.SetFormat("Invalid RVA for Debug directory (0x%X)", (uint32_t) dirs[__IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
        AddError(ErrorType::Error, tempStr);
        return false;
    }
    size = dirs[__IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(ImageDebugDirectory);
    if (((dirs[__IMAGE_DIRECTORY_ENTRY_DEBUG].Size % sizeof(ImageDebugDirectory)) != 0) || (size == 0) || (size > 14))
    {
        tempStr.SetFormat("Invalid alignament for Debug directory (0x%X)", (uint32_t) dirs[__IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
        AddError(ErrorType::Warning, tempStr);
    }
    for (tr = 0; tr < size; tr++, faddr += sizeof(ImageDebugDirectory))
    {
        if (file->Copy<ImageDebugDirectory>(faddr, imgd) == false)
        {
            tempStr.SetFormat("Unable to read Debug structure from (0x%X)", (uint32_t) faddr);
            AddError(ErrorType::Error, tempStr);
            return false;
        }
        if (imgd.Type == __IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            if (imgd.SizeOfData > (MAX_PDB_NAME + 64))
                bufSize = (MAX_PDB_NAME + 64);
            else
                bufSize = imgd.SizeOfData;

            auto buf = file->Get(imgd.PointerToRawData, bufSize);
            if (buf.length >= 5) // at least the first 32 bytes
            {
                const char* nm = nullptr;
                switch (*(uint32_t*) buf.data)
                {
                case CV_SIGNATURE_NB10:
                    nm = (const char*) pdb20->PdbFileName;
                    break;
                case CV_SIGNATURE_RSDS:
                    nm = (const char*) pdb70->PdbFileName;
                    break;
                default:
                    tempStr.SetFormat("Unknwon signature in IMAGE_DEBUG_TYPE_CODEVIEW => %08X", (*(uint32_t*) buf.data));
                    AddError(ErrorType::Warning, tempStr);
                    break;
                }
                if (nm)
                {
                    const char* e = (const char*) (buf.data + buf.length);
                    auto* p       = nm;
                    while ((p < e) && (*p))
                        p++;
                    pdbName = std::string_view{ nm, static_cast<size_t>(p - nm) };
                }
            }
            else
            {
                tempStr.SetFormat(
                      "Unable to read IMAGE_DEBUG_TYPE_CODEVIEW (%d bytes) from (0x%X)", bufSize, (uint32_t) imgd.PointerToRawData);
                AddError(ErrorType::Warning, tempStr);
            }
        }
    }
    return true;
}

void PEFile::CopySectionName(uint32_t index, String& name)
{
    int tr;
    name.Clear();
    if (index >= nrSections)
        return;
    for (tr = 0; (sect[index].Name[tr] != 0) && (tr < 8); tr++)
        name.AddChar(sect[index].Name[tr]);
}

bool PEFile::Update()
{
    uint32_t tr, gr, tmp;
    uint64_t filePoz, poz, bfSize;
    LocalString<128> tempStr;

    errList.clear();
    isMetroApp = false;
    if (!file->Copy<ImageDOSHeader>(0, dos))
        return false;
    if (!file->Copy<ImageNTHeaders32>(dos.e_lfanew, nth32))
        return false;
    switch (nth32.OptionalHeader.Magic)
    {
    case __IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        hdr64         = false;
        dirs          = &nth32.OptionalHeader.DataDirectory[0];
        rvaEntryPoint = nth32.OptionalHeader.AddressOfEntryPoint;
        break;
    case __IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (!file->Copy<ImageNTHeaders64>(dos.e_lfanew, nth64))
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
    // coloratie zone

    /*file->sel[SELECTION_ZONES].DeleteAll();
    file->AddZone(SELECTION_ZONES, 0, sizeof(dos) - 1, "DOS Header", peCols.colMZ);
    file->AddZone(SELECTION_ZONES, dos.e_lfanew, dos.e_lfanew + sizeof(nth32) - 1, "NT Header", peCols.colPE);*/
    // b.AddZone(0, sizeof(dos) - 1, peCols.colMZ, "DOS Header.");
    // b.AddZone(dos.e_lfanew, dos.e_lfanew + sizeof(nth32) - 1, peCols.colPE, "NT Header");

    nrSections = nth32.FileHeader.NumberOfSections; // same
    if ((nrSections > MAX_NR_SECTIONS) || (nrSections < 1))
    {
        tempStr.SetFormat("Invalid number of sections (%d)", (nrSections));
        AddError(ErrorType::Error, tempStr);
        nrSections = 0;
        // return false;
    }
    if ((nth32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)) // same
    {
        AddError(ErrorType::Warning, "Image should execute in an AppContainer");
        isMetroApp = true;
    }

    poz = dos.e_lfanew + nth32.FileHeader.SizeOfOptionalHeader + sizeof(((ImageNTHeaders32*) 0)->Signature) + sizeof(ImageFileHeader);

    sectStart    = (uint32_t) poz;
    peStart      = dos.e_lfanew;
    computedSize = virtualComputedSize = 0;
    if (hdr64)
        imageBase = nth64.OptionalHeader.ImageBase;
    else
        imageBase = nth32.OptionalHeader.ImageBase;

    /*file->ResetBookmarks();
    file->AddZone(SELECTION_ZONES, poz, poz + nrSections*sizeof(ImageSectionHeader) - 1, "SectDef", peCols.colSectDef);*/
    // b.AddZone(poz, poz + nrSections * sizeof(ImageSectionHeader) - 1, peCols.colSectDef, "SectDef");
    for (tr = 0; tr < nrSections; tr++, poz += sizeof(ImageSectionHeader))
    {
        if (!file->Copy<ImageSectionHeader>(poz, sect[tr]))
        {
            memset(&sect[tr], 0, sizeof(ImageSectionHeader));
        }
        if ((sect[tr].SizeOfRawData > 0) && (sect[tr].PointerToRawData + sect[tr].SizeOfRawData > computedSize))
            computedSize = sect[tr].PointerToRawData + sect[tr].SizeOfRawData;
        if ((sect[tr].Misc.VirtualSize > 0) && (sect[tr].VirtualAddress + sect[tr].Misc.VirtualSize > virtualComputedSize))
            virtualComputedSize = sect[tr].VirtualAddress + sect[tr].Misc.VirtualSize;
        // if ((tr < 9) && (sect[tr].PointerToRawData != 0))
        //    FileInfo->Bookmarks.SetBookmark(tr + 1, sect[tr].PointerToRawData);
        /*if (file->IsOnDisk())
        {
          if ((tr<9) && (sect[tr].PointerToRawData != 0)) file->SetBookmark(tr + 1, sect[tr].PointerToRawData);
        } else {
          if ((tr<9) && (sect[tr].VirtualAddress != 0)) file->SetBookmark(tr + 1, sect[tr].VirtualAddress);
        }*/

        // if ((sect[tr].PointerToRawData != 0) && (sect[tr].SizeOfRawData > 0))
        //{
        //    CopySectionName(tr, sectName);
        //    // file->AddZone(SELECTION_ZONES, sect[tr].PointerToRawData, sect[tr].PointerToRawData + sect[tr].SizeOfRawData - 1, sectName,
        //    // peCols.colSect);
        //    b.AddZone(sect[tr].PointerToRawData, sect[tr].PointerToRawData + sect[tr].SizeOfRawData - 1, peCols.colSect, sectName);
        //}
        /*if (file->IsOnDisk())
        {
          if ((sect[tr].PointerToRawData != 0) && (sect[tr].SizeOfRawData>0))
          {
            CopySectionName(tr, sectName);
            file->AddZone(SELECTION_ZONES, sect[tr].PointerToRawData, sect[tr].PointerToRawData + sect[tr].SizeOfRawData - 1, sectName,
        peCols.colSect);
          }
        } else {
          if ((sect[tr].VirtualAddress != 0) && (sect[tr].Misc.VirtualSize>0))
          {
            CopySectionName(tr, sectName);
            file->AddZone(SELECTION_ZONES, sect[tr].VirtualAddress, sect[tr].VirtualAddress + sect[tr].Misc.VirtualSize - 1, sectName,
        peCols.colSect);
          }
        }*/
    }
    for (tr = 0; tr < nrSections; tr++)
    {
        if (tr + 1 < nrSections)
        {
            if (sect[tr].VirtualAddress + SectionALIGN(sect[tr].Misc.VirtualSize, nth32.OptionalHeader.SectionAlignment) !=
                sect[tr + 1].VirtualAddress)
            {
                tempStr.SetFormat("Section %d and %d are not consecutive.", (tr + 1), (tr + 2));
                AddError(ErrorType::Error, tempStr);
            }
        }
        if ((tr > 0) && ((*(uint64_t*) &sect[tr - 1].Name) == (*(uint64_t*) &sect[tr].Name)))
        {
            tempStr.SetFormat("Sections %d and %d have the same name: [", (tr + 1), (tr + 2));
            for (gr = 0; gr < 8; gr++)
                if (sect[tr].Name[gr] != 0)
                    tempStr.AddChar(sect[tr].Name[gr]);
            tempStr.AddChar(']');
            AddError(ErrorType::Warning, tempStr);
        }
    }
    // recalculez :
    computedSize = sect[nrSections - 1].PointerToRawData + sect[nrSections - 1].SizeOfRawData;
    if (sect[nrSections - 1].SizeOfRawData == 0)
    {
        computedSize = file->GetSize();
        AddError(ErrorType::Warning, "File is using LastSection.SizeOfRawData = 0 trick");
    }

    // if (computedSize < file->GetSize())
    //{
    //    // file->SetBookmark(0, computedSize);
    //    //FileInfo->Bookmarks.SetBookmark(0, computedSize);
    //}

    computedWithCertificate = computedSize;
    if ((dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress > 0) && (dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0))
    {
        if (dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress < computedWithCertificate)
        {
            AddError(ErrorType::Warning, "Security certificate starts within the file");
        }
        if ((dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress + dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].Size) > computedWithCertificate)
        {
            computedWithCertificate = dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress + dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        }
    }

    if (computedSize > file->GetSize())
    {
        tempStr.SetFormat(
              "File is truncated. Missing %d bytes (%3d%%)",
              (int) (computedSize - file->GetSize()),
              (int) ((computedSize - file->GetSize()) * 100) / computedSize);
        AddError(ErrorType::Error, tempStr);
    }

    tmp = sect[nrSections - 1].VirtualAddress + sect[nrSections - 1].Misc.VirtualSize;
    if (nth32.OptionalHeader.SectionAlignment > 0)
    {
        tmp +=
              (nth32.OptionalHeader.SectionAlignment - tmp % nth32.OptionalHeader.SectionAlignment) % nth32.OptionalHeader.SectionAlignment;
    }
    if (tmp != nth32.OptionalHeader.SizeOfImage)
    {
        AddError(ErrorType::Error, "SizeOfImage is invalid");
    }
    else
    {
        if ((nth32.OptionalHeader.SectionAlignment > 0) && (nth32.OptionalHeader.SizeOfImage % nth32.OptionalHeader.SectionAlignment) != 0)
        {
            AddError(ErrorType::Warning, "SizeOfImage unaligned");
        }
    }

    BuildResources();   // cu erori setate
    BuildExport();      // cu erori setate
    BuildImport();      // cu erori setate
    BuildVersionInfo(); // cu erori setate
    BuildTLS();
    BuildDebugData();

    // EP
    filePoz = RVAtoFilePointer(rvaEntryPoint);

    if (filePoz != PE_INVALID_ADDRESS)
    {
        // FileInfo->CursorPos = filePoz;
        // FileInfo->Bookmarks.SetBookmark(0, filePoz);
        if (filePoz >= file->GetSize())
        {
            tempStr.SetFormat("Entry Point is outside the file RVA=(0x%x)", rvaEntryPoint);
            AddError(ErrorType::Error, tempStr);
        }
        else
        {
            bfSize = 16;
            if (filePoz + bfSize > file->GetSize())
                bfSize = file->GetSize() - filePoz;
            auto buf = file->Get(filePoz, 16);
            if (buf.Empty())
            {
                tempStr.SetFormat("Unable to read data from Entry Point RVA=(0x%x)", rvaEntryPoint);
                AddError(ErrorType::Error, tempStr);
            }
            else
            {
                for (tr = 0, tmp = 0; tr < buf.length; tr++)
                    tmp += buf[tr];
                if (tmp == 0)
                {
                    tempStr.SetFormat("Invalid code at Entry Point RVA=(0x%x)", rvaEntryPoint);
                    AddError(ErrorType::Error, tempStr);
                }
            }
        }
    }
    else
    {
        tempStr.SetFormat("Invalid Entry Point RVA (0x%x)", rvaEntryPoint);
        AddError(ErrorType::Error, tempStr);
        if (rvaEntryPoint < file->GetSize())
        {
            AddError(ErrorType::Warning, "Entry Point is a File Address");
            // FileInfo->CursorPos = rvaEntryPoint;
            // FileInfo->Bookmarks.SetBookmark(0, rvaEntryPoint);
        }
        else
        {
            // file->SetStartBookmark(0);
            // FileInfo->Bookmarks.SetBookmark(0, 0);
        }
    }
    int ep_sect = RVAToSectionIndex(rvaEntryPoint);
    if (rvaEntryPoint == 0)
    {
        AddError(ErrorType::Warning, "Posible executable resource file !");
        if ((nth32.FileHeader.Characteristics & __IMAGE_FILE_DLL) == 0)
            AddError(ErrorType::Warning, "NON-DLL file with EP RVA = 0");
    }
    if (ep_sect == -1)
    {
        if (rvaEntryPoint > 0)
            AddError(ErrorType::Warning, "EP is not inside any section");
    }
    else
    {
        if ((sect[ep_sect].Characteristics & __IMAGE_SCN_MEM_EXECUTE) == 0)
            AddError(ErrorType::Warning, "EP section without Executable characteristic");
        if ((sect[ep_sect].Characteristics & (__IMAGE_SCN_MEM_EXECUTE | __IMAGE_SCN_MEM_READ | __IMAGE_SCN_MEM_WRITE)) == 0)
            AddError(ErrorType::Error, "EP section cannot be executed (missing Write,Read and Executable attributes)");
    }
    // directoare

    ImageDataDirectory *dr, *d2;
    for (tr = 0; tr < 15; tr++)
    {
        dr = &dirs[tr];
        if ((dr->VirtualAddress > 0) && (dr->Size > 0))
        {
            if (dr->Size > file->GetSize())
            {
                tempStr.SetFormat("Directory '%s' (#%d) has an invalid Size (0x%08X)", peDirsNames[tr].data(), tr, dr->Size);
                AddError(ErrorType::Warning, tempStr);
            }
            if (tr == __IMAGE_DIRECTORY_ENTRY_SECURITY)
            {
                // file->AddZone(SELECTION_ZONES, dr->VirtualAddress, dr->VirtualAddress + dr->Size - 1, pedirNames[tr], peCols.colDir[tr]);
                // b.AddZone(dr->VirtualAddress, dr->VirtualAddress + dr->Size - 1, peCols.colDir[tr], pedirNames[tr]);
            }
            else
            {
                filePoz = RVAtoFilePointer(dr->VirtualAddress);
                if (filePoz != PE_INVALID_ADDRESS)
                {
                    // file->AddZone(SELECTION_ZONES, filePoz, filePoz + dr->Size - 1, pedirNames[tr], peCols.colDir[tr]);
                    // b.AddZone(filePoz, filePoz + dr->Size - 1, peCols.colDir[tr], pedirNames[tr]);
                    if (filePoz + dr->Size > file->GetSize())
                    {
                        tempStr.SetFormat(
                              "Directory '%s' (#%d) extends outside the file (to: 0x%08X)",
                              peDirsNames[tr].data(),
                              tr,
                              (uint32_t) (dr->Size + filePoz));
                        AddError(ErrorType::Warning, tempStr);
                    }
                }
                else
                {
                    tempStr.SetFormat(
                          "Directory '%s' (#%d) has an invalid RVA address (0x%08X)", peDirsNames[tr].data(), tr, dr->VirtualAddress);
                    AddError(ErrorType::Warning, tempStr);
                }
            }
        }
        if ((dr->VirtualAddress == 0) && (dr->Size > 0))
        {
            tempStr.SetFormat(
                  "Directory '%s' (#%d) has no address but size bigger than 0 (%d bytes)", peDirsNames[tr].data(), tr, dr->Size);
            AddError(ErrorType::Warning, tempStr);
        }
        if ((dr->VirtualAddress > 0) && (dr->Size == 0))
        {
            tempStr.SetFormat(
                  "Directory '%s' (#%d) has size equal to 0 and a valid addrees (0x%08X)", peDirsNames[tr].data(), tr, dr->VirtualAddress);
            AddError(ErrorType::Warning, tempStr);
        }
    }

    // cazuri de overlap
    for (tr = 0; tr < 15; tr++)
    {
        if (tr == __IMAGE_DIRECTORY_ENTRY_SECURITY)
            continue;
        dr = &dirs[tr];
        if ((dr->VirtualAddress > 0) && (dr->Size > 0))
        {
            for (gr = tr + 1; gr < 15; gr++)
            {
                if (gr == __IMAGE_DIRECTORY_ENTRY_SECURITY)
                    continue;
                d2 = &dirs[gr];
                if ((d2->VirtualAddress > 0) && (dr->Size > 0))
                {
                    if ((dr->VirtualAddress <= d2->VirtualAddress) && (dr->VirtualAddress + dr->Size > d2->VirtualAddress))
                    {
                        tempStr.SetFormat("Directory '%s' and '%s' overlapp !", peDirsNames[tr].data(), peDirsNames[gr].data());
                        AddError(ErrorType::Warning, tempStr);
                        continue;
                    }
                    if ((d2->VirtualAddress <= dr->VirtualAddress) && (d2->VirtualAddress + d2->Size > dr->VirtualAddress))
                    {
                        tempStr.SetFormat("Directory '%s' and '%s' overlapp !", peDirsNames[tr].data(), peDirsNames[gr].data());
                        AddError(ErrorType::Warning, tempStr);
                        continue;
                    }
                }
            }
        }
    }

    //// refac si panel-urile
    ADD_PANEL(PANEL_INFORMATIONS);
    ADD_PANEL(PANEL_DIRECTORIES);
    ADD_PANEL(PANEL_SECTIONS);
    ADD_PANEL(PANEL_HEADERS);
    ADD_PANEL(PANEL_OPCODES);

    if (impDLL.size() > 0)
        ADD_PANEL(PANEL_IMPORTS);
    if (exp.size() > 0)
        ADD_PANEL(PANEL_EXPORTS);

    if (res.size() > 0)
        ADD_PANEL(PANEL_RESOURCES);

    for (auto& r : res)
    {
        if (r.Type == (uint32_t) __RT_ICON)
        {
            ADD_PANEL(PANEL_ICONS);
            break;
        }
    }

    // if (tlsTable.GetSize()>0)
    if (hasTLS)
        ADD_PANEL(PANEL_TLS);

    return true;
}
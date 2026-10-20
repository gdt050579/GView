#include "DissasmViewer.hpp"

#include <algorithm>
#include <deque>

using namespace GView::View::DissasmViewer;

namespace
{
// The structures the APIs of DissasmApiPrototypes.cpp take by address (lpStartupInfo, lpFindFileData, ...): their fields as the SDK
// declares them, laid out for 32 and 64 bit code (the natural alignment of MSVC). A % in the name is the A and the W structure (LPTSTR /
// TCHAR become LPSTR / CHAR and LPWSTR / WCHAR); a line that starts with 32: / 64: is for that code only (a different order of the fields)
constexpr std::string_view STRUCTURES[] = {
    "FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; }",
    "SYSTEMTIME { WORD wYear; WORD wMonth; WORD wDayOfWeek; WORD wDay; WORD wHour; WORD wMinute; WORD wSecond; WORD wMilliseconds; }",
    "LARGE_INTEGER { DWORD LowPart; LONG HighPart; }",
    "LUID { DWORD LowPart; LONG HighPart; }",
    "LUID_AND_ATTRIBUTES { LUID Luid; DWORD Attributes; }",
    "TOKEN_PRIVILEGES { DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[1]; }",
    "POINT { LONG x; LONG y; }",
    "MSG { HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; POINT pt; }",
    "SECURITY_ATTRIBUTES { DWORD nLength; LPVOID lpSecurityDescriptor; BOOL bInheritHandle; }",
    "OVERLAPPED { ULONG_PTR Internal; ULONG_PTR InternalHigh; DWORD Offset; DWORD OffsetHigh; HANDLE hEvent; }",
    "CRITICAL_SECTION { PVOID DebugInfo; LONG LockCount; LONG RecursionCount; HANDLE OwningThread; HANDLE LockSemaphore; ULONG_PTR SpinCount; }",
    "STARTUPINFO% { DWORD cb; LPTSTR lpReserved; LPTSTR lpDesktop; LPTSTR lpTitle; DWORD dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize; DWORD dwXCountChars; "
    "DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags; WORD wShowWindow; WORD cbReserved2; LPBYTE lpReserved2; HANDLE hStdInput; HANDLE hStdOutput; "
    "HANDLE hStdError; }",
    "PROCESS_INFORMATION { HANDLE hProcess; HANDLE hThread; DWORD dwProcessId; DWORD dwThreadId; }",
    "WIN32_FIND_DATA% { DWORD dwFileAttributes; FILETIME ftCreationTime; FILETIME ftLastAccessTime; FILETIME ftLastWriteTime; DWORD nFileSizeHigh; "
    "DWORD nFileSizeLow; DWORD dwReserved0; DWORD dwReserved1; TCHAR cFileName[260]; TCHAR cAlternateFileName[14]; }",
    "PROCESSENTRY32 { DWORD dwSize; DWORD cntUsage; DWORD th32ProcessID; ULONG_PTR th32DefaultHeapID; DWORD th32ModuleID; DWORD cntThreads; "
    "DWORD th32ParentProcessID; LONG pcPriClassBase; DWORD dwFlags; CHAR szExeFile[260]; }",
    "PROCESSENTRY32W { DWORD dwSize; DWORD cntUsage; DWORD th32ProcessID; ULONG_PTR th32DefaultHeapID; DWORD th32ModuleID; DWORD cntThreads; "
    "DWORD th32ParentProcessID; LONG pcPriClassBase; DWORD dwFlags; WCHAR szExeFile[260]; }",
    "MODULEENTRY32 { DWORD dwSize; DWORD th32ModuleID; DWORD th32ProcessID; DWORD GlblcntUsage; DWORD ProccntUsage; BYTE* modBaseAddr; DWORD modBaseSize; "
    "HMODULE hModule; CHAR szModule[256]; CHAR szExePath[260]; }",
    "MODULEENTRY32W { DWORD dwSize; DWORD th32ModuleID; DWORD th32ProcessID; DWORD GlblcntUsage; DWORD ProccntUsage; BYTE* modBaseAddr; DWORD modBaseSize; "
    "HMODULE hModule; WCHAR szModule[256]; WCHAR szExePath[260]; }",
    "THREADENTRY32 { DWORD dwSize; DWORD cntUsage; DWORD th32ThreadID; DWORD th32OwnerProcessID; LONG tpBasePri; LONG tpDeltaPri; DWORD dwFlags; }",
    "MEMORY_BASIC_INFORMATION { PVOID BaseAddress; PVOID AllocationBase; DWORD AllocationProtect; SIZE_T RegionSize; DWORD State; DWORD Protect; DWORD Type; }",
    "SYSTEM_INFO { WORD wProcessorArchitecture; WORD wReserved; DWORD dwPageSize; LPVOID lpMinimumApplicationAddress; LPVOID lpMaximumApplicationAddress; "
    "DWORD_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors; DWORD dwProcessorType; DWORD dwAllocationGranularity; WORD wProcessorLevel; "
    "WORD wProcessorRevision; }",
    "SHELLEXECUTEINFO% { DWORD cbSize; ULONG fMask; HWND hwnd; LPCTSTR lpVerb; LPCTSTR lpFile; LPCTSTR lpParameters; LPCTSTR lpDirectory; int nShow; "
    "HINSTANCE hInstApp; void* lpIDList; LPCTSTR lpClass; HKEY hkeyClass; DWORD dwHotKey; HANDLE hIcon; HANDLE hProcess; }",
    "SERVICE_STATUS { DWORD dwServiceType; DWORD dwCurrentState; DWORD dwControlsAccepted; DWORD dwWin32ExitCode; DWORD dwServiceSpecificExitCode; "
    "DWORD dwCheckPoint; DWORD dwWaitHint; }",
    "DATA_BLOB { DWORD cbData; BYTE* pbData; }",
    "32: WSADATA { WORD wVersion; WORD wHighVersion; CHAR szDescription[257]; CHAR szSystemStatus[129]; unsigned short iMaxSockets; "
    "unsigned short iMaxUdpDg; char* lpVendorInfo; }",
    "64: WSADATA { WORD wVersion; WORD wHighVersion; unsigned short iMaxSockets; unsigned short iMaxUdpDg; char* lpVendorInfo; "
    "CHAR szDescription[257]; CHAR szSystemStatus[129]; }",
    "sockaddr { u_short sa_family; CHAR sa_data[14]; }",
    "UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }",
    "OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; "
    "PVOID SecurityQualityOfService; }",
    "IO_STATUS_BLOCK { NTSTATUS Status; ULONG_PTR Information; }",
    "CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; }",
};

struct StructureTable {
    std::deque<DissasmApiStructure> structures;
    std::unordered_map<std::string_view, const DissasmApiStructure*> byName;
};

std::string_view Trim(std::string_view text)
{
    while (!text.empty() && text.front() == ' ')
        text.remove_prefix(1);
    while (!text.empty() && text.back() == ' ')
        text.remove_suffix(1);
    return text;
}

std::string ReplaceAll(std::string text, std::string_view from, std::string_view to)
{
    for (size_t position = text.find(from); position != std::string::npos; position = text.find(from, position + to.size()))
        text.replace(position, from.size(), to);
    return text;
}

// the size (and the alignment) of a type of a field: a structure of the table, a scalar, a pointer / handle / pointer sized integer; 0
// when it is not known
uint32 TypeSize(std::string_view type, bool is64, const StructureTable& table, const DissasmApiStructure** structure)
{
    const uint32 pointer = is64 ? 8u : 4u;
    if (const auto found = table.byName.find(type); found != table.byName.end()) {
        *structure = found->second;
        return found->second->size;
    }
    static constexpr std::pair<std::string_view, uint32> SCALARS[] = {
        { "BYTE", 1 },     { "CHAR", 1 },      { "UCHAR", 1 },    { "BOOLEAN", 1 },  { "char", 1 },           { "WORD", 2 },
        { "SHORT", 2 },    { "USHORT", 2 },    { "WCHAR", 2 },    { "u_short", 2 },  { "unsigned short", 2 }, { "wchar_t", 2 },
        { "DWORD", 4 },    { "LONG", 4 },      { "ULONG", 4 },    { "BOOL", 4 },     { "INT", 4 },            { "UINT", 4 },
        { "int", 4 },      { "u_long", 4 },    { "NTSTATUS", 4 }, { "LONGLONG", 8 }, { "ULONGLONG", 8 },      { "DWORD64", 8 },
        { "SIZE_T", 0 },   { "ULONG_PTR", 0 }, { "DWORD_PTR", 0 }, { "LONG_PTR", 0 }, { "UINT_PTR", 0 },      { "WPARAM", 0 },
        { "LPARAM", 0 },
    };
    for (const auto& [name, size] : SCALARS)
        if (name == type)
            return size == 0 ? pointer : size;
    // the pointers: void* / char*, the Windows pointer types (LPBYTE, PVOID, PUNICODE_STRING) and the handles (HANDLE, HWND, HKEY)
    if (type.ends_with('*') || type == "HANDLE")
        return pointer;
    for (const std::string_view prefix : { "LP", "P", "H" })
        if (type.size() > prefix.size() && type.starts_with(prefix) && type[prefix.size()] >= 'A' && type[prefix.size()] <= 'Z')
            return pointer;
    return 0;
}

// "WIN32_FIND_DATAW { DWORD dwFileAttributes; ...; WCHAR cFileName[260]; ... }": the fields at their offsets
void AddStructure(StructureTable& table, std::string_view line, bool is64)
{
    const auto open  = line.find('{');
    const auto close = line.rfind('}');
    if (open == std::string_view::npos || close == std::string_view::npos || close < open)
        return;
    DissasmApiStructure structure;
    structure.name = std::string(Trim(line.substr(0, open)));
    uint32 offset = 0, alignment = 1;
    std::string_view fields = line.substr(open + 1, close - open - 1);
    while (!fields.empty()) {
        const auto end                = fields.find(';');
        const std::string_view text   = Trim(fields.substr(0, end));
        fields                        = end == std::string_view::npos ? std::string_view() : fields.substr(end + 1);
        if (text.empty())
            continue;
        const auto split = text.find_last_of(" *");
        if (split == std::string_view::npos)
            return;
        DissasmApiStructure::Field field;
        std::string_view name = text.substr(split + 1);
        uint32 count          = 1;
        if (const auto bracket = name.find('['); bracket != std::string_view::npos) {
            count = static_cast<uint32>(std::strtoul(std::string(name.substr(bracket + 1)).c_str(), nullptr, 10));
            name  = name.substr(0, bracket);
        }
        field.name              = std::string(name);
        field.type              = std::string(Trim(text.substr(0, split + 1)));
        const uint32 size       = TypeSize(field.type, is64, table, &field.structure);
        const uint32 fieldAlign = field.structure ? field.structure->alignment : size;
        if (size == 0 || count == 0)
            return; // a type of the table that is not known: the definition is wrong
        offset             = (offset + fieldAlign - 1) / fieldAlign * fieldAlign;
        field.offset       = offset;
        field.elementSize  = size;
        field.count        = count;
        offset            += size * count;
        alignment          = std::max(alignment, fieldAlign);
        structure.fields.push_back(std::move(field));
    }
    structure.alignment = alignment;
    structure.size      = (offset + alignment - 1) / alignment * alignment;
    auto& added         = table.structures.emplace_back(std::move(structure));
    table.byName.emplace(added.name, &added);
}

const StructureTable& GetStructureTable(bool is64)
{
    static const auto build = [](bool is64) {
        StructureTable result;
        for (std::string_view line : STRUCTURES) {
            if (line.starts_with("32: ") || line.starts_with("64: ")) {
                if (line.starts_with("64: ") != is64)
                    continue;
                line.remove_prefix(4);
            }
            if (line.find('%') == std::string_view::npos) {
                AddStructure(result, line, is64);
                continue;
            }
            const std::string text(line);
            AddStructure(result, ReplaceAll(ReplaceAll(ReplaceAll(ReplaceAll(text, "%", "A"), "LPCTSTR", "LPCSTR"), "LPTSTR", "LPSTR"), "TCHAR", "CHAR"), is64);
            AddStructure(result, ReplaceAll(ReplaceAll(ReplaceAll(ReplaceAll(text, "%", "W"), "LPCTSTR", "LPCWSTR"), "LPTSTR", "LPWSTR"), "TCHAR", "WCHAR"), is64);
        }
        return result;
    };
    static const StructureTable tables[2] = { build(false), build(true) };
    return tables[is64 ? 1 : 0];
}

std::string FormatOffset(uint32 offset)
{
    char buffer[16];
    snprintf(buffer, sizeof(buffer), offset <= 9 ? "+%u" : "+0x%x", offset);
    return buffer;
}

// the field at `offset` (inside the structure): .ftLastWriteTime.dwHighDateTime, .cFileName+2, +0x46 (the padding)
std::string FormatMember(const DissasmApiStructure& structure, uint32 offset)
{
    for (const auto& field : structure.fields) {
        if (offset < field.offset || offset >= field.offset + field.elementSize * field.count)
            continue;
        const uint32 inside = offset - field.offset;
        std::string text    = "." + field.name;
        if (field.structure && field.count == 1)
            return text + FormatMember(*field.structure, inside);
        if (field.structure) // an array of structures: Privileges[1].Attributes
            return text + "[" + std::to_string(inside / field.elementSize) + "]" + FormatMember(*field.structure, inside % field.elementSize);
        return inside == 0 ? text : text + FormatOffset(inside);
    }
    return FormatOffset(offset);
}
} // namespace

const DissasmApiStructure* GView::View::DissasmViewer::FindApiStructure(std::string_view name, bool is64)
{
    const auto& byName = GetStructureTable(is64).byName;
    const auto found   = byName.find(name);
    return found != byName.end() ? found->second : nullptr;
}

size_t GView::View::DissasmViewer::GetApiStructuresCount(bool is64)
{
    return GetStructureTable(is64).structures.size();
}

void GView::View::DissasmViewer::ForEachApiStructure(bool is64, const std::function<void(const DissasmApiStructure&)>& callback)
{
    for (const auto& structure : GetStructureTable(is64).structures)
        callback(structure);
}

std::string GView::View::DissasmViewer::FormatApiStructureMember(const DissasmApiStructure& structure, uint32 offset, bool memoryAccess)
{
    if (offset == 0 && !memoryAccess)
        return {};
    if (offset >= structure.size)
        return FormatOffset(offset);
    return FormatMember(structure, offset);
}

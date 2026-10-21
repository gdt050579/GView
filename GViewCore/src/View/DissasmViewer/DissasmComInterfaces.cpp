#include "DissasmViewer.hpp"

#include <array>
#include <cctype>
#include <unordered_map>

using namespace GView::View::DissasmViewer;

namespace
{
// the GUIDs the code passes to COM (IID_ / CLSID_) and to the shell (FOLDERID_): "IID_IWbemLocator" -> "DC12A687-737F-11CF-884D-00AA004B2E24"
constexpr std::pair<std::string_view, std::string_view> GUIDS[] = {
    // COM
    { "IID_IUnknown", "00000000-0000-0000-C000-000000000046" },
    { "IID_IClassFactory", "00000001-0000-0000-C000-000000000046" },
    { "IID_IMarshal", "00000003-0000-0000-C000-000000000046" },
    { "IID_IStorage", "0000000B-0000-0000-C000-000000000046" },
    { "IID_IStream", "0000000C-0000-0000-C000-000000000046" },
    { "IID_IBindCtx", "0000000E-0000-0000-C000-000000000046" },
    { "IID_IMoniker", "0000000F-0000-0000-C000-000000000046" },
    { "IID_IRunningObjectTable", "00000010-0000-0000-C000-000000000046" },
    { "IID_IEnumUnknown", "00000100-0000-0000-C000-000000000046" },
    { "IID_IEnumString", "00000101-0000-0000-C000-000000000046" },
    { "IID_IPersistStream", "00000109-0000-0000-C000-000000000046" },
    { "IID_IPersistFile", "0000010B-0000-0000-C000-000000000046" },
    { "IID_IPersist", "0000010C-0000-0000-C000-000000000046" },
    { "IID_IDataObject", "0000010E-0000-0000-C000-000000000046" },
    { "IID_IOleObject", "00000112-0000-0000-C000-000000000046" },
    { "IID_IOleWindow", "00000114-0000-0000-C000-000000000046" },
    { "IID_IOleClientSite", "00000118-0000-0000-C000-000000000046" },
    { "IID_IDropTarget", "00000122-0000-0000-C000-000000000046" },
    { "IID_IGlobalInterfaceTable", "00000146-0000-0000-C000-000000000046" },
    { "CLSID_StdGlobalInterfaceTable", "00000323-0000-0000-C000-000000000046" },
    { "IID_IDispatch", "00020400-0000-0000-C000-000000000046" },
    { "IID_ITypeInfo", "00020401-0000-0000-C000-000000000046" },
    { "IID_ITypeLib", "00020402-0000-0000-C000-000000000046" },
    { "IID_ISequentialStream", "0C733A30-2A1C-11CE-ADE5-00AA0044773D" },
    { "IID_IServiceProvider", "6D5140C1-7436-11CE-8034-00AA006009FA" },
    { "IID_IObjectWithSite", "FC4801A3-2BA9-11CF-A229-00AA003D7352" },
    { "IID_IOleCommandTarget", "B722BCCB-4E68-101B-A2BC-00AA00404770" },
    { "IID_IConnectionPointContainer", "B196B284-BAB4-101A-B69C-00AA00341D07" },
    { "IID_IConnectionPoint", "B196B286-BAB4-101A-B69C-00AA00341D07" },
    { "IID_IErrorInfo", "1CF2B120-547D-101B-8E65-08002B2BD119" },
    { "IID_ISupportErrorInfo", "DF0B3D60-548F-101B-8E65-08002B2BD119" },
    { "IID_IAgileObject", "94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90" },
    { "IID_IInspectable", "AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90" },
    // the shell
    { "CLSID_ShellLink", "00021401-0000-0000-C000-000000000046" },
    { "IID_IShellLinkA", "000214EE-0000-0000-C000-000000000046" },
    { "IID_IShellLinkW", "000214F9-0000-0000-C000-000000000046" },
    { "IID_IShellBrowser", "000214E2-0000-0000-C000-000000000046" },
    { "IID_IShellView", "000214E3-0000-0000-C000-000000000046" },
    { "IID_IContextMenu", "000214E4-0000-0000-C000-000000000046" },
    { "IID_IShellFolder", "000214E6-0000-0000-C000-000000000046" },
    { "IID_IShellExtInit", "000214E8-0000-0000-C000-000000000046" },
    { "IID_IEnumIDList", "000214F2-0000-0000-C000-000000000046" },
    { "IID_IContextMenu2", "000214F4-0000-0000-C000-000000000046" },
    { "IID_IExtractIconW", "000214FA-0000-0000-C000-000000000046" },
    { "IID_IContextMenu3", "BCFCE0A0-EC17-11D0-8D10-00A0C90F2719" },
    { "IID_IShellItem", "43826D1E-E718-42EE-BC55-A1E261C37BFE" },
    { "IID_IShellItem2", "7E9FB0D3-919F-4307-AB2E-9B1860310C93" },
    { "IID_IShellItemArray", "B63EA76D-1F85-456F-A19C-48159EFA858B" },
    { "IID_IPropertyStore", "886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99" },
    { "IID_IObjectArray", "92CA9DCD-5622-4BBA-A805-5E9F541BD8C9" },
    { "IID_IObjectCollection", "5632B1A4-E38A-400A-928A-D4CD63230295" },
    { "IID_IQueryAssociations", "C46CA590-3C3F-11D2-BEE6-0000F805CA57" },
    { "IID_IFileOperation", "947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8" },
    { "CLSID_FileOperation", "3AD05575-8857-4850-9277-11B85BDB8E09" },
    { "IID_IFileOpenDialog", "D57C7288-D4AD-4768-BE02-9D969532D960" },
    { "CLSID_FileOpenDialog", "DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7" },
    { "IID_IKnownFolderManager", "8BE2D872-86AA-4D47-B776-32CCA40C7018" },
    { "CLSID_KnownFolderManager", "4DF0C730-DF9D-4AE3-9153-AA6B82E9795A" },
    { "CLSID_ShellWindows", "9BA05972-F6A8-11CF-A442-00A0C90A8F39" },
    { "IID_IShellWindows", "85CB6900-4D95-11CF-960C-0080C7F4EE85" },
    { "CLSID_InternetExplorer", "0002DF01-0000-0000-C000-000000000046" },
    { "IID_IWebBrowser2", "D30C1661-CDAF-11D0-8A3E-00C04FC9E26E" },
    { "IID_IXMLHTTPRequest", "ED8C108D-4349-11D2-91A4-00C04F7969E8" },
    // WMI, the task scheduler, BITS, the firewall
    { "CLSID_WbemLocator", "4590F811-1D3A-11D0-891F-00AA004B2E24" },
    { "IID_IWbemLocator", "DC12A687-737F-11CF-884D-00AA004B2E24" },
    { "IID_IWbemServices", "9556DC99-828C-11CF-A37E-00AA003240C7" },
    { "IID_IWbemClassObject", "DC12A681-737F-11CF-884D-00AA004B2E24" },
    { "IID_IEnumWbemClassObject", "027947E1-D731-11CE-A357-000000000001" },
    { "CLSID_TaskScheduler", "0F87369F-A4E5-4CFC-BD3E-73E6154572DD" },
    { "IID_ITaskService", "2FABA4C7-4DA9-4013-9697-20CC3FD40F85" },
    { "IID_ITaskFolder", "8CFAC062-A080-4C15-9A88-AA7C2AF80DFC" },
    { "IID_ITaskDefinition", "F5BC8FC5-536D-4F77-B852-FBC1356FDEB6" },
    { "IID_IRegisteredTask", "9C86F320-DEE3-4DD1-B972-A303F26B061E" },
    { "CLSID_BackgroundCopyManager", "4991D34B-80A1-4291-83B6-3328366B9097" },
    { "IID_IBackgroundCopyManager", "5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C" },
    { "IID_IBackgroundCopyJob", "37668D37-507E-4160-9316-26306D150B12" },
    { "CLSID_NetFwPolicy2", "E2B3C97F-6AE1-41AC-817A-F6F92166D7DD" },
    { "IID_INetFwPolicy2", "98325047-C671-4174-8D81-DEFCD3F03186" },
    // the known folders (SHGetKnownFolderPath)
    { "FOLDERID_RoamingAppData", "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D" },
    { "FOLDERID_LocalAppData", "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" },
    { "FOLDERID_LocalAppDataLow", "A520A1A4-1780-4FF6-BD18-167343C5AF16" },
    { "FOLDERID_ProgramData", "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97" },
    { "FOLDERID_Startup", "B97D20BB-F46A-4C97-BA10-5E3608430854" },
    { "FOLDERID_CommonStartup", "82A5EA35-D9CD-47C5-9629-E15D2F714E6E" },
    { "FOLDERID_Programs", "A77F5D77-2E2B-44C3-A6A2-ABA601054A51" },
    { "FOLDERID_System", "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7" },
    { "FOLDERID_SystemX86", "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27" },
    { "FOLDERID_Windows", "F38BF404-1D43-42F2-9305-67DE0B28FC23" },
    { "FOLDERID_ProgramFiles", "905E63B6-C1BF-494E-B29C-65B732D3D21A" },
    { "FOLDERID_Desktop", "B4BFCC3A-DB2C-424C-B029-7FE99A87C641" },
    { "FOLDERID_Documents", "FDD39AD0-238F-46AF-ADB4-6C85480369C7" },
    { "FOLDERID_Downloads", "374DE290-123F-4565-9164-39C4925E467B" },
    { "FOLDERID_Profile", "5E6C858F-0E22-4760-9AFE-EA3317B67173" },
    { "FOLDERID_Recent", "AE50C081-EBD2-438A-8655-8A092E34987A" },
    { "FOLDERID_Favorites", "1777F761-68AD-4D8A-87BD-30B759FA33DD" },
    { "FOLDERID_Fonts", "FD228CB7-AE11-4AE3-864C-16F3910AB8FE" },
};

// the methods of the interfaces, in the order of their vtables (after the ones of the base); the ones that give an interface: the
// parameter of the result (after this, from 0) and its interface, or the parameter of the IID that says which one
struct InterfaceDefinition {
    std::string_view name;
    std::string_view base;
    std::vector<DissasmComMethod> methods;
};

DissasmComMethod Method(std::string_view name)
{
    return { name, -1, {}, -1 };
}
DissasmComMethod Gives(std::string_view name, int8 outParameter, std::string_view outInterface)
{
    return { name, outParameter, outInterface, -1 };
}
DissasmComMethod GivesIid(std::string_view name, int8 riidParameter, int8 outParameter)
{
    return { name, outParameter, {}, riidParameter };
}

const std::vector<InterfaceDefinition>& GetInterfaceDefinitions()
{
    static const std::vector<InterfaceDefinition> interfaces = {
        { "IUnknown", "", { GivesIid("QueryInterface", 0, 1), Method("AddRef"), Method("Release") } },
        { "IClassFactory", "IUnknown", { GivesIid("CreateInstance", 1, 2), Method("LockServer") } },
        { "IDispatch", "IUnknown", { Method("GetTypeInfoCount"), Method("GetTypeInfo"), Method("GetIDsOfNames"), Method("Invoke") } },
        { "ISequentialStream", "IUnknown", { Method("Read"), Method("Write") } },
        { "IStream",
          "ISequentialStream",
          { Method("Seek"), Method("SetSize"), Method("CopyTo"), Method("Commit"), Method("Revert"), Method("LockRegion"), Method("UnlockRegion"), Method("Stat"),
            Gives("Clone", 0, "IStream") } },
        { "IPersist", "IUnknown", { Method("GetClassID") } },
        { "IPersistFile", "IPersist", { Method("IsDirty"), Method("Load"), Method("Save"), Method("SaveCompleted"), Method("GetCurFile") } },
        { "IServiceProvider", "IUnknown", { GivesIid("QueryService", 1, 2) } },
        { "IObjectWithSite", "IUnknown", { Method("SetSite"), GivesIid("GetSite", 0, 1) } },
        { "IShellLinkW",
          "IUnknown",
          { Method("GetPath"), Method("GetIDList"), Method("SetIDList"), Method("GetDescription"), Method("SetDescription"), Method("GetWorkingDirectory"),
            Method("SetWorkingDirectory"), Method("GetArguments"), Method("SetArguments"), Method("GetHotkey"), Method("SetHotkey"), Method("GetShowCmd"),
            Method("SetShowCmd"), Method("GetIconLocation"), Method("SetIconLocation"), Method("SetRelativePath"), Method("Resolve"), Method("SetPath") } },
        { "IShellLinkA", "IShellLinkW", {} }, // the same methods, with the ANSI strings
        { "IShellItem",
          "IUnknown",
          { GivesIid("BindToHandler", 2, 3), Gives("GetParent", 0, "IShellItem"), Method("GetDisplayName"), Method("GetAttributes"), Method("Compare") } },
        { "IPropertyStore", "IUnknown", { Method("GetCount"), Method("GetAt"), Method("GetValue"), Method("SetValue"), Method("Commit") } },
        { "IFileOperation",
          "IUnknown",
          { Method("Advise"), Method("Unadvise"), Method("SetOperationFlags"), Method("SetProgressMessage"), Method("SetProgressDialog"), Method("SetProperties"),
            Method("SetOwnerWindow"), Method("ApplyPropertiesToItem"), Method("ApplyPropertiesToItems"), Method("RenameItem"), Method("RenameItems"),
            Method("MoveItem"), Method("MoveItems"), Method("CopyItem"), Method("CopyItems"), Method("DeleteItem"), Method("DeleteItems"), Method("NewItem"),
            Method("PerformOperations"), Method("GetAnyOperationsAborted") } },
        { "IKnownFolderManager",
          "IUnknown",
          { Method("FolderIdFromCsidl"), Method("FolderIdToCsidl"), Method("GetFolderIds"), Method("GetFolder"), Method("GetFolderByName"),
            Method("RegisterFolder"), Method("UnregisterFolder"), Method("FindFolderFromPath"), Method("FindFolderFromIDList"), Method("Redirect") } },
        { "IWbemLocator", "IUnknown", { Gives("ConnectServer", 7, "IWbemServices") } },
        { "IWbemServices",
          "IUnknown",
          { Gives("OpenNamespace", 3, "IWbemServices"), Method("CancelAsyncCall"), Method("QueryObjectSink"), Gives("GetObject", 3, "IWbemClassObject"),
            Method("GetObjectAsync"), Method("PutClass"), Method("PutClassAsync"), Method("DeleteClass"), Method("DeleteClassAsync"),
            Gives("CreateClassEnum", 3, "IEnumWbemClassObject"), Method("CreateClassEnumAsync"), Method("PutInstance"), Method("PutInstanceAsync"),
            Method("DeleteInstance"), Method("DeleteInstanceAsync"), Gives("CreateInstanceEnum", 3, "IEnumWbemClassObject"), Method("CreateInstanceEnumAsync"),
            Gives("ExecQuery", 4, "IEnumWbemClassObject"), Method("ExecQueryAsync"), Gives("ExecNotificationQuery", 4, "IEnumWbemClassObject"),
            Method("ExecNotificationQueryAsync"), Gives("ExecMethod", 5, "IWbemClassObject"), Method("ExecMethodAsync") } },
        { "IEnumWbemClassObject", "IUnknown", { Method("Reset"), Gives("Next", 2, "IWbemClassObject"), Method("NextAsync"), Gives("Clone", 0, "IEnumWbemClassObject"), Method("Skip") } },
        { "IWbemClassObject",
          "IUnknown",
          { Method("GetQualifierSet"), Method("Get"), Method("Put"), Method("Delete"), Method("GetNames"), Method("BeginEnumeration"), Method("Next"),
            Method("EndEnumeration"), Method("GetPropertyQualifierSet"), Gives("Clone", 0, "IWbemClassObject"), Method("GetObjectText"),
            Gives("SpawnDerivedClass", 1, "IWbemClassObject"), Gives("SpawnInstance", 1, "IWbemClassObject"), Method("CompareTo"), Method("GetPropertyOrigin"),
            Method("InheritsFrom"), Gives("GetMethod", 2, "IWbemClassObject"), Method("PutMethod"), Method("DeleteMethod"), Method("BeginMethodEnumeration"),
            Method("NextMethod"), Method("EndMethodEnumeration"), Method("GetMethodQualifierSet"), Method("GetMethodOrigin") } },
        { "ITaskService",
          "IDispatch",
          { Gives("GetFolder", 1, "ITaskFolder"), Method("GetRunningTasks"), Gives("NewTask", 1, "ITaskDefinition"), Method("Connect"), Method("get_Connected"),
            Method("get_TargetServer"), Method("get_ConnectedUser"), Method("get_ConnectedDomain"), Method("get_HighestVersion") } },
        { "ITaskFolder",
          "IDispatch",
          { Method("get_Name"), Method("get_Path"), Gives("GetFolder", 1, "ITaskFolder"), Method("GetFolders"), Gives("CreateFolder", 2, "ITaskFolder"),
            Method("DeleteFolder"), Gives("GetTask", 1, "IRegisteredTask"), Method("GetTasks"), Method("DeleteTask"), Gives("RegisterTask", 7, "IRegisteredTask"),
            Gives("RegisterTaskDefinition", 7, "IRegisteredTask"), Method("GetSecurityDescriptor"), Method("SetSecurityDescriptor") } },
        { "ITaskDefinition",
          "IDispatch",
          { Method("get_RegistrationInfo"), Method("put_RegistrationInfo"), Method("get_Triggers"), Method("put_Triggers"), Method("get_Settings"),
            Method("put_Settings"), Method("get_Data"), Method("put_Data"), Method("get_Principal"), Method("put_Principal"), Method("get_Actions"),
            Method("put_Actions"), Method("get_XmlText"), Method("put_XmlText") } },
        { "IRegisteredTask", "IDispatch", {} },
        { "IBackgroundCopyManager",
          "IUnknown",
          { Gives("CreateJob", 3, "IBackgroundCopyJob"), Gives("GetJob", 1, "IBackgroundCopyJob"), Method("EnumJobs"), Method("GetErrorDescription") } },
        { "IBackgroundCopyJob",
          "IUnknown",
          { Method("AddFileSet"), Method("AddFile"), Method("EnumFiles"), Method("Suspend"), Method("Resume"), Method("Cancel"), Method("Complete"),
            Method("GetId"), Method("GetType"), Method("GetProgress"), Method("GetTimes"), Method("GetState"), Method("GetError"), Method("GetOwner"),
            Method("SetDisplayName"), Method("GetDisplayName"), Method("SetDescription"), Method("GetDescription"), Method("SetPriority"), Method("GetPriority"),
            Method("SetNotifyFlags"), Method("GetNotifyFlags"), Method("SetNotifyInterface"), Method("GetNotifyInterface"), Method("SetMinimumRetryDelay"),
            Method("GetMinimumRetryDelay"), Method("SetNoProgressTimeout"), Method("GetNoProgressTimeout"), Method("GetErrorCount"), Method("SetProxySettings"),
            Method("GetProxySettings"), Method("TakeOwnership") } },
        // the other interfaces of the GUIDs: their methods are not known (the ones of IUnknown / IDispatch are)
        { "IMarshal", "IUnknown", {} },
        { "IStorage", "IUnknown", {} },
        { "IBindCtx", "IUnknown", {} },
        { "IMoniker", "IPersistStream", {} },
        { "IPersistStream", "IPersist", {} },
        { "IRunningObjectTable", "IUnknown", {} },
        { "IEnumUnknown", "IUnknown", {} },
        { "IEnumString", "IUnknown", {} },
        { "IDataObject", "IUnknown", {} },
        { "IOleObject", "IUnknown", {} },
        { "IOleWindow", "IUnknown", {} },
        { "IOleClientSite", "IUnknown", {} },
        { "IDropTarget", "IUnknown", {} },
        { "IGlobalInterfaceTable", "IUnknown", {} },
        { "ITypeInfo", "IUnknown", {} },
        { "ITypeLib", "IUnknown", {} },
        { "IOleCommandTarget", "IUnknown", {} },
        { "IConnectionPointContainer", "IUnknown", {} },
        { "IConnectionPoint", "IUnknown", {} },
        { "IErrorInfo", "IUnknown", {} },
        { "ISupportErrorInfo", "IUnknown", {} },
        { "IAgileObject", "IUnknown", {} },
        { "IInspectable", "IUnknown", {} },
        { "IShellBrowser", "IOleWindow", {} },
        { "IShellView", "IOleWindow", {} },
        { "IContextMenu", "IUnknown", {} },
        { "IContextMenu2", "IContextMenu", {} },
        { "IContextMenu3", "IContextMenu2", {} },
        { "IShellFolder", "IUnknown", {} },
        { "IShellExtInit", "IUnknown", {} },
        { "IEnumIDList", "IUnknown", {} },
        { "IExtractIconW", "IUnknown", {} },
        { "IShellItem2", "IShellItem", {} },
        { "IShellItemArray", "IUnknown", {} },
        { "IObjectArray", "IUnknown", {} },
        { "IObjectCollection", "IObjectArray", {} },
        { "IQueryAssociations", "IUnknown", {} },
        { "IFileOpenDialog", "IUnknown", {} },
        { "IShellWindows", "IDispatch", {} },
        { "IWebBrowser2", "IDispatch", {} },
        { "IXMLHTTPRequest", "IDispatch", {} },
        { "INetFwPolicy2", "IDispatch", {} },
    };
    return interfaces;
}

// the APIs that give an interface: the parameter of the IID that says which, or the interface they always give; through a parameter (the
// address of the variable that receives it) or as their return value
const std::unordered_map<std::string_view, DissasmComProducer>& GetProducers()
{
    static const std::unordered_map<std::string_view, DissasmComProducer> producers = {
        { "CoCreateInstance", { 3, 4, {} } },
        { "CoGetClassObject", { 3, 4, {} } },
        { "CoGetObject", { 2, 3, {} } },
        { "CoUnmarshalInterface", { 1, 2, {} } },
        { "SHCreateItemFromParsingName", { 2, 3, {} } },
        { "SHCreateStreamOnFileEx", { -1, 5, "IStream" } },
        { "SHCreateStreamOnFileW", { -1, 2, "IStream" } },
        { "SHCreateStreamOnFileA", { -1, 2, "IStream" } },
        { "CreateStreamOnHGlobal", { -1, 2, "IStream" } },
        { "CreateBindCtx", { -1, 1, "IBindCtx" } },
        { "SHCreateMemStream", { -1, -1, "IStream" } }, // its return value
    };
    return producers;
}

std::optional<std::array<uint8, 16>> ParseGuidText(std::string_view text)
{
    // XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX: Data1 (4 bytes), Data2, Data3 (little endian), Data4 (8 bytes in their order)
    std::array<uint8, 16> bytes{};
    std::string digits;
    for (const char c : text)
        if (c != '-')
            digits.push_back(c);
    if (digits.size() != 32)
        return std::nullopt;
    uint8 raw[16];
    for (size_t i = 0; i < 16; i++) {
        const auto nibble = [](char c) -> int { return std::isdigit(static_cast<unsigned char>(c)) ? c - '0' : (std::toupper(static_cast<unsigned char>(c)) - 'A' + 10); };
        raw[i] = static_cast<uint8>(nibble(digits[2 * i]) * 16 + nibble(digits[2 * i + 1]));
    }
    const uint8 order[16] = { 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 };
    for (size_t i = 0; i < 16; i++)
        bytes[i] = raw[order[i]];
    return bytes;
}

struct GuidKey {
    std::array<uint8, 16> bytes;
    bool operator==(const GuidKey& other) const
    {
        return bytes == other.bytes;
    }
};
struct GuidKeyHash {
    size_t operator()(const GuidKey& key) const
    {
        size_t hash = 0;
        for (const uint8 byte : key.bytes)
            hash = hash * 131 + byte;
        return hash;
    }
};

const std::unordered_map<GuidKey, std::string_view, GuidKeyHash>& GetGuidNames()
{
    static const std::unordered_map<GuidKey, std::string_view, GuidKeyHash> names = [] {
        std::unordered_map<GuidKey, std::string_view, GuidKeyHash> result;
        for (const auto& [name, text] : GUIDS)
            if (const auto bytes = ParseGuidText(text); bytes.has_value())
                result.emplace(GuidKey{ bytes.value() }, name);
        return result;
    }();
    return names;
}

const InterfaceDefinition* FindDefinition(std::string_view name)
{
    for (const auto& definition : GetInterfaceDefinitions())
        if (definition.name == name)
            return &definition;
    return nullptr;
}
} // namespace

std::string_view GView::View::DissasmViewer::FindGuidName(const uint8* bytes)
{
    if (!bytes)
        return {};
    GuidKey key;
    std::copy(bytes, bytes + 16, key.bytes.begin());
    const auto& names = GetGuidNames();
    const auto found  = names.find(key);
    return found != names.end() ? found->second : std::string_view();
}

std::string_view GView::View::DissasmViewer::FindInterfaceOfIid(const uint8* bytes)
{
    const std::string_view name = FindGuidName(bytes);
    if (!name.starts_with("IID_"))
        return {};
    const std::string_view interfaceName = name.substr(4);
    return FindDefinition(interfaceName) ? FindDefinition(interfaceName)->name : std::string_view();
}

bool GView::View::DissasmViewer::IsComInterface(std::string_view name)
{
    return FindDefinition(name) != nullptr;
}

std::optional<std::pair<std::string_view, DissasmComMethod>> GView::View::DissasmViewer::FindComMethod(std::string_view interfaceName, uint32 index)
{
    // the chain of the bases: IUnknown first, the methods of each after the ones of its base
    std::vector<const InterfaceDefinition*> chain;
    for (const auto* definition = FindDefinition(interfaceName); definition && chain.size() < 8; definition = FindDefinition(definition->base))
        chain.push_back(definition);
    uint32 first = 0;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        const auto& methods = (*it)->methods;
        if (index < first + methods.size()) // named after the interface of the object (IWbemServices::Release, as a decompiler shows it)
            return std::make_pair(chain.front()->name, methods[index - first]);
        first += static_cast<uint32>(methods.size());
    }
    return std::nullopt;
}

const DissasmComProducer* GView::View::DissasmViewer::FindComProducer(std::string_view function)
{
    const auto& producers = GetProducers();
    const auto found      = producers.find(function);
    return found != producers.end() ? &found->second : nullptr;
}

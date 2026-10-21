#include "DissasmViewer.hpp"

#include <array>
#include <memory>
#include <string>
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

// the parameters after This (null: no prototype, a VARIANT by value takes 4 pushes in 32 bit code)
DissasmComMethod Method(std::string_view name, const char* parameters)
{
    return { name, -1, {}, -1, parameters };
}
DissasmComMethod Gives(std::string_view name, int8 outParameter, std::string_view outInterface, const char* parameters)
{
    return { name, outParameter, outInterface, -1, parameters };
}
DissasmComMethod GivesIid(std::string_view name, int8 riidParameter, int8 outParameter, const char* parameters)
{
    return { name, outParameter, {}, riidParameter, parameters };
}

const std::vector<InterfaceDefinition>& GetInterfaceDefinitions()
{
    static const std::vector<InterfaceDefinition> interfaces = {
        { "IUnknown", "", { GivesIid("QueryInterface", 0, 1, "REFIID riid, void** ppvObject"), Method("AddRef", ""), Method("Release", "") } },
        { "IClassFactory", "IUnknown", { GivesIid("CreateInstance", 1, 2, "IUnknown* pUnkOuter, REFIID riid, void** ppvObject"), Method("LockServer", "BOOL fLock") } },
        { "IDispatch", "IUnknown", { Method("GetTypeInfoCount", "UINT* pctinfo"), Method("GetTypeInfo", "UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo"), Method("GetIDsOfNames", "REFIID riid, LPOLESTR* rgszNames, UINT cNames, LCID lcid, DISPID* rgDispId"), Method("Invoke", "DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr") } },
        { "ISequentialStream", "IUnknown", { Method("Read", "void* pv, ULONG cb, ULONG* pcbRead"), Method("Write", "const void* pv, ULONG cb, ULONG* pcbWritten") } },
        { "IStream",
          "ISequentialStream",
          { Method("Seek", "LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition"), Method("SetSize", "ULARGE_INTEGER libNewSize"), Method("CopyTo", "IStream* pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten"), Method("Commit", "DWORD grfCommitFlags"), Method("Revert", ""), Method("LockRegion", "ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType"), Method("UnlockRegion", "ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType"), Method("Stat", "STATSTG* pstatstg, DWORD grfStatFlag"),
            Gives("Clone", 0, "IStream", "IStream** ppstm") } },
        { "IPersist", "IUnknown", { Method("GetClassID", "CLSID* pClassID") } },
        { "IPersistFile", "IPersist", { Method("IsDirty", ""), Method("Load", "LPCOLESTR pszFileName, DWORD dwMode"), Method("Save", "LPCOLESTR pszFileName, BOOL fRemember"), Method("SaveCompleted", "LPCOLESTR pszFileName"), Method("GetCurFile", "LPOLESTR* ppszFileName") } },
        { "IServiceProvider", "IUnknown", { GivesIid("QueryService", 1, 2, "REFGUID guidService, REFIID riid, void** ppvObject") } },
        { "IObjectWithSite", "IUnknown", { Method("SetSite", "IUnknown* pUnkSite"), GivesIid("GetSite", 0, 1, "REFIID riid, void** ppvSite") } },
        { "IShellLinkW",
          "IUnknown",
          { Method("GetPath", "LPWSTR pszFile, int cch, WIN32_FIND_DATAW* pfd, DWORD fFlags"), Method("GetIDList", "PIDLIST_ABSOLUTE* ppidl"), Method("SetIDList", "PCIDLIST_ABSOLUTE pidl"), Method("GetDescription", "LPWSTR pszName, int cch"), Method("SetDescription", "LPCWSTR pszName"), Method("GetWorkingDirectory", "LPWSTR pszDir, int cch"),
            Method("SetWorkingDirectory", "LPCWSTR pszDir"), Method("GetArguments", "LPWSTR pszArgs, int cch"), Method("SetArguments", "LPCWSTR pszArgs"), Method("GetHotkey", "WORD* pwHotkey"), Method("SetHotkey", "WORD wHotkey"), Method("GetShowCmd", "int* piShowCmd"),
            Method("SetShowCmd", "int iShowCmd"), Method("GetIconLocation", "LPWSTR pszIconPath, int cch, int* piIcon"), Method("SetIconLocation", "LPCWSTR pszIconPath, int iIcon"), Method("SetRelativePath", "LPCWSTR pszPathRel, DWORD dwReserved"), Method("Resolve", "HWND hwnd, DWORD fFlags"), Method("SetPath", "LPCWSTR pszFile") } },
        { "IShellLinkA", "IShellLinkW", {} }, // the same methods, with the ANSI strings
        { "IShellItem",
          "IUnknown",
          { GivesIid("BindToHandler", 2, 3, "IBindCtx* pbc, REFGUID bhid, REFIID riid, void** ppv"), Gives("GetParent", 0, "IShellItem", "IShellItem** ppsi"), Method("GetDisplayName", "SIGDN sigdnName, LPWSTR* ppszName"), Method("GetAttributes", "SFGAOF sfgaoMask, SFGAOF* psfgaoAttribs"), Method("Compare", "IShellItem* psi, SICHINTF hint, int* piOrder") } },
        { "IPropertyStore", "IUnknown", { Method("GetCount", "DWORD* cProps"), Method("GetAt", "DWORD iProp, PROPERTYKEY* pkey"), Method("GetValue", "REFPROPERTYKEY key, PROPVARIANT* pv"), Method("SetValue", "REFPROPERTYKEY key, REFPROPVARIANT propvar"), Method("Commit", "") } },
        { "IFileOperation",
          "IUnknown",
          { Method("Advise", "IFileOperationProgressSink* pfops, DWORD* pdwCookie"), Method("Unadvise", "DWORD dwCookie"), Method("SetOperationFlags", "DWORD dwOperationFlags"), Method("SetProgressMessage", "LPCWSTR pszMessage"), Method("SetProgressDialog", "IOperationsProgressDialog* popd"), Method("SetProperties", "IPropertyChangeArray* pproparray"),
            Method("SetOwnerWindow", "HWND hwndOwner"), Method("ApplyPropertiesToItem", "IShellItem* psiItem"), Method("ApplyPropertiesToItems", "IUnknown* punkItems"), Method("RenameItem", "IShellItem* psiItem, LPCWSTR pszNewName, IFileOperationProgressSink* pfopsItem"), Method("RenameItems", "IUnknown* pUnkItems, LPCWSTR pszNewName"),
            Method("MoveItem", "IShellItem* psiItem, IShellItem* psiDestinationFolder, LPCWSTR pszNewName, IFileOperationProgressSink* pfopsItem"), Method("MoveItems", "IUnknown* punkItems, IShellItem* psiDestinationFolder"), Method("CopyItem", "IShellItem* psiItem, IShellItem* psiDestinationFolder, LPCWSTR pszCopyName, IFileOperationProgressSink* pfopsItem"), Method("CopyItems", "IUnknown* punkItems, IShellItem* psiDestinationFolder"), Method("DeleteItem", "IShellItem* psiItem, IFileOperationProgressSink* pfopsItem"), Method("DeleteItems", "IUnknown* punkItems"), Method("NewItem", "IShellItem* psiDestinationFolder, DWORD dwFileAttributes, LPCWSTR pszName, LPCWSTR pszTemplateName, IFileOperationProgressSink* pfopsItem"),
            Method("PerformOperations", ""), Method("GetAnyOperationsAborted", "BOOL* pfAnyOperationsAborted") } },
        { "IKnownFolderManager",
          "IUnknown",
          { Method("FolderIdFromCsidl", "int nCsidl, KNOWNFOLDERID* pfid"), Method("FolderIdToCsidl", "REFKNOWNFOLDERID rfid, int* pnCsidl"), Method("GetFolderIds", "KNOWNFOLDERID** ppKFId, UINT* pCount"), Method("GetFolder", "REFKNOWNFOLDERID rfid, IKnownFolder** ppkf"), Method("GetFolderByName", "LPCWSTR pszCanonicalName, IKnownFolder** ppkf"),
            Method("RegisterFolder", "REFKNOWNFOLDERID rfid, const KNOWNFOLDER_DEFINITION* pKFD"), Method("UnregisterFolder", "REFKNOWNFOLDERID rfid"), Method("FindFolderFromPath", "LPCWSTR pszPath, FFFP_MODE mode, IKnownFolder** ppkf"), Method("FindFolderFromIDList", "PCIDLIST_ABSOLUTE pidl, IKnownFolder** ppkf"), Method("Redirect", "REFKNOWNFOLDERID rfid, HWND hwnd, KF_REDIRECT_FLAGS flags, LPCWSTR pszTargetPath, UINT cFolders, const KNOWNFOLDERID* pExclusion, LPWSTR* ppszError") } },
        { "IWbemLocator", "IUnknown", { Gives("ConnectServer", 7, "IWbemServices", "const BSTR strNetworkResource, const BSTR strUser, const BSTR strPassword, const BSTR strLocale, long lSecurityFlags, const BSTR strAuthority, IWbemContext* pCtx, IWbemServices** ppNamespace") } },
        { "IWbemServices",
          "IUnknown",
          { Gives("OpenNamespace", 3, "IWbemServices", "const BSTR strNamespace, long lFlags, IWbemContext* pCtx, IWbemServices** ppWorkingNamespace, IWbemCallResult** ppResult"), Method("CancelAsyncCall", "IWbemObjectSink* pSink"), Method("QueryObjectSink", "long lFlags, IWbemObjectSink** ppResponseHandler"), Gives("GetObject", 3, "IWbemClassObject", "const BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemClassObject** ppObject, IWbemCallResult** ppCallResult"),
            Method("GetObjectAsync", "const BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"), Method("PutClass", "IWbemClassObject* pObject, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult"), Method("PutClassAsync", "IWbemClassObject* pObject, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"), Method("DeleteClass", "const BSTR strClass, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult"), Method("DeleteClassAsync", "const BSTR strClass, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"),
            Gives("CreateClassEnum", 3, "IEnumWbemClassObject", "const BSTR strSuperclass, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum"), Method("CreateClassEnumAsync", "const BSTR strSuperclass, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"), Method("PutInstance", "IWbemClassObject* pInst, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult"), Method("PutInstanceAsync", "IWbemClassObject* pInst, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"),
            Method("DeleteInstance", "const BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemCallResult** ppCallResult"), Method("DeleteInstanceAsync", "const BSTR strObjectPath, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"), Gives("CreateInstanceEnum", 3, "IEnumWbemClassObject", "const BSTR strFilter, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum"), Method("CreateInstanceEnumAsync", "const BSTR strFilter, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"),
            Gives("ExecQuery", 4, "IEnumWbemClassObject", "const BSTR strQueryLanguage, const BSTR strQuery, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum"), Method("ExecQueryAsync", "const BSTR strQueryLanguage, const BSTR strQuery, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"), Gives("ExecNotificationQuery", 4, "IEnumWbemClassObject", "const BSTR strQueryLanguage, const BSTR strQuery, long lFlags, IWbemContext* pCtx, IEnumWbemClassObject** ppEnum"),
            Method("ExecNotificationQueryAsync", "const BSTR strQueryLanguage, const BSTR strQuery, long lFlags, IWbemContext* pCtx, IWbemObjectSink* pResponseHandler"), Gives("ExecMethod", 5, "IWbemClassObject", "const BSTR strObjectPath, const BSTR strMethodName, long lFlags, IWbemContext* pCtx, IWbemClassObject* pInParams, IWbemClassObject** ppOutParams, IWbemCallResult** ppCallResult"), Method("ExecMethodAsync", "const BSTR strObjectPath, const BSTR strMethodName, long lFlags, IWbemContext* pCtx, IWbemClassObject* pInParams, IWbemObjectSink* pResponseHandler") } },
        { "IEnumWbemClassObject", "IUnknown", { Method("Reset", ""), Gives("Next", 2, "IWbemClassObject", "long lTimeout, ULONG uCount, IWbemClassObject** apObjects, ULONG* puReturned"), Method("NextAsync", "ULONG uCount, IWbemObjectSink* pSink"), Gives("Clone", 0, "IEnumWbemClassObject", "IEnumWbemClassObject** ppEnum"), Method("Skip", "long lTimeout, ULONG nCount") } },
        { "IWbemClassObject",
          "IUnknown",
          { Method("GetQualifierSet", "IWbemQualifierSet** ppQualSet"), Method("Get", "LPCWSTR wszName, long lFlags, VARIANT* pVal, CIMTYPE* pType, long* plFlavor"), Method("Put", "LPCWSTR wszName, long lFlags, VARIANT* pVal, CIMTYPE Type"), Method("Delete", "LPCWSTR wszName"), Method("GetNames", "LPCWSTR wszQualifierName, long lFlags, VARIANT* pQualifierVal, SAFEARRAY** pNames"), Method("BeginEnumeration", "long lEnumFlags"), Method("Next", "long lFlags, BSTR* strName, VARIANT* pVal, CIMTYPE* pType, long* plFlavor"),
            Method("EndEnumeration", ""), Method("GetPropertyQualifierSet", "LPCWSTR wszProperty, IWbemQualifierSet** ppQualSet"), Gives("Clone", 0, "IWbemClassObject", "IWbemClassObject** ppCopy"), Method("GetObjectText", "long lFlags, BSTR* pstrObjectText"),
            Gives("SpawnDerivedClass", 1, "IWbemClassObject", "long lFlags, IWbemClassObject** ppNewClass"), Gives("SpawnInstance", 1, "IWbemClassObject", "long lFlags, IWbemClassObject** ppNewInstance"), Method("CompareTo", "long lFlags, IWbemClassObject* pCompareTo"), Method("GetPropertyOrigin", "LPCWSTR wszName, BSTR* pstrClassName"),
            Method("InheritsFrom", "LPCWSTR strAncestor"), Gives("GetMethod", 2, "IWbemClassObject", "LPCWSTR wszName, long lFlags, IWbemClassObject** ppInSignature, IWbemClassObject** ppOutSignature"), Method("PutMethod", "LPCWSTR wszName, long lFlags, IWbemClassObject* pInSignature, IWbemClassObject* pOutSignature"), Method("DeleteMethod", "LPCWSTR wszName"), Method("BeginMethodEnumeration", "long lEnumFlags"),
            Method("NextMethod", "long lFlags, BSTR* pstrName, IWbemClassObject** ppInSignature, IWbemClassObject** ppOutSignature"), Method("EndMethodEnumeration", ""), Method("GetMethodQualifierSet", "LPCWSTR wszMethod, IWbemQualifierSet** ppQualSet"), Method("GetMethodOrigin", "LPCWSTR wszMethodName, BSTR* pstrClassName") } },
        { "ITaskService",
          "IDispatch",
          { Gives("GetFolder", 1, "ITaskFolder", "BSTR path, ITaskFolder** ppFolder"), Method("GetRunningTasks", "LONG flags, IRunningTaskCollection** ppRunningTasks"), Gives("NewTask", 1, "ITaskDefinition", "DWORD flags, ITaskDefinition** ppDefinition"), Method("Connect", nullptr), Method("get_Connected", "VARIANT_BOOL* pConnected"),
            Method("get_TargetServer", "BSTR* pServer"), Method("get_ConnectedUser", "BSTR* pUser"), Method("get_ConnectedDomain", "BSTR* pDomain"), Method("get_HighestVersion", "DWORD* pVersion") } },
        { "ITaskFolder",
          "IDispatch",
          { Method("get_Name", "BSTR* pName"), Method("get_Path", "BSTR* pPath"), Gives("GetFolder", 1, "ITaskFolder", "BSTR path, ITaskFolder** ppFolder"), Method("GetFolders", "LONG flags, ITaskFolderCollection** ppFolders"), Gives("CreateFolder", 2, "ITaskFolder", nullptr),
            Method("DeleteFolder", "BSTR subFolderName, LONG flags"), Gives("GetTask", 1, "IRegisteredTask", "BSTR path, IRegisteredTask** ppTask"), Method("GetTasks", "LONG flags, IRegisteredTaskCollection** ppTasks"), Method("DeleteTask", "BSTR name, LONG flags"), Gives("RegisterTask", 7, "IRegisteredTask", nullptr),
            Gives("RegisterTaskDefinition", 7, "IRegisteredTask", nullptr), Method("GetSecurityDescriptor", "LONG securityInformation, BSTR* pSddl"), Method("SetSecurityDescriptor", "BSTR sddl, LONG flags") } },
        { "ITaskDefinition",
          "IDispatch",
          { Method("get_RegistrationInfo", "IRegistrationInfo** ppRegistrationInfo"), Method("put_RegistrationInfo", "IRegistrationInfo* pRegistrationInfo"), Method("get_Triggers", "ITriggerCollection** ppTriggers"), Method("put_Triggers", "ITriggerCollection* pTriggers"), Method("get_Settings", "ITaskSettings** ppSettings"),
            Method("put_Settings", "ITaskSettings* pSettings"), Method("get_Data", "BSTR* pData"), Method("put_Data", "BSTR data"), Method("get_Principal", "IPrincipal** ppPrincipal"), Method("put_Principal", "IPrincipal* pPrincipal"), Method("get_Actions", "IActionCollection** ppActions"),
            Method("put_Actions", "IActionCollection* pActions"), Method("get_XmlText", "BSTR* pXml"), Method("put_XmlText", "BSTR xml") } },
        { "IRegisteredTask", "IDispatch", {} },
        { "IBackgroundCopyManager",
          "IUnknown",
          { Gives("CreateJob", 3, "IBackgroundCopyJob", "LPCWSTR DisplayName, BG_JOB_TYPE Type, GUID* pJobId, IBackgroundCopyJob** ppJob"), Gives("GetJob", 1, "IBackgroundCopyJob", "REFGUID jobID, IBackgroundCopyJob** ppJob"), Method("EnumJobs", "DWORD dwFlags, IEnumBackgroundCopyJobs** ppEnum"), Method("GetErrorDescription", "HRESULT hResult, DWORD LanguageId, LPWSTR* pErrorDescription") } },
        { "IBackgroundCopyJob",
          "IUnknown",
          { Method("AddFileSet", "ULONG cFileCount, BG_FILE_INFO* pFileSet"), Method("AddFile", "LPCWSTR RemoteUrl, LPCWSTR LocalName"), Method("EnumFiles", "IEnumBackgroundCopyFiles** pEnum"), Method("Suspend", ""), Method("Resume", ""), Method("Cancel", ""), Method("Complete", ""),
            Method("GetId", "GUID* pVal"), Method("GetType", "BG_JOB_TYPE* pVal"), Method("GetProgress", "BG_JOB_PROGRESS* pVal"), Method("GetTimes", "BG_JOB_TIMES* pVal"), Method("GetState", "BG_JOB_STATE* pVal"), Method("GetError", "IBackgroundCopyError** ppError"), Method("GetOwner", "LPWSTR* pVal"),
            Method("SetDisplayName", "LPCWSTR Val"), Method("GetDisplayName", "LPWSTR* pVal"), Method("SetDescription", "LPCWSTR Val"), Method("GetDescription", "LPWSTR* pVal"), Method("SetPriority", "BG_JOB_PRIORITY Val"), Method("GetPriority", "BG_JOB_PRIORITY* pVal"),
            Method("SetNotifyFlags", "ULONG Val"), Method("GetNotifyFlags", "ULONG* pVal"), Method("SetNotifyInterface", "IUnknown* Val"), Method("GetNotifyInterface", "IUnknown** pVal"), Method("SetMinimumRetryDelay", "ULONG Seconds"),
            Method("GetMinimumRetryDelay", "ULONG* Seconds"), Method("SetNoProgressTimeout", "ULONG Seconds"), Method("GetNoProgressTimeout", "ULONG* Seconds"), Method("GetErrorCount", "ULONG* Errors"), Method("SetProxySettings", "BG_JOB_PROXY_USAGE ProxyUsage, const WCHAR* ProxyList, const WCHAR* ProxyBypassList"),
            Method("GetProxySettings", "BG_JOB_PROXY_USAGE* pProxyUsage, LPWSTR* pProxyList, LPWSTR* pProxyBypassList"), Method("TakeOwnership", "") } },
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

const AsmFunctionDetails* GView::View::DissasmViewer::FindComMethodPrototype(std::string_view qualifiedName)
{
    static std::unordered_map<std::string, std::shared_ptr<const DissasmUserPrototype>> prototypes; // the parsed ones (null: none)
    const auto separator = qualifiedName.find("::");
    if (separator == std::string_view::npos)
        return nullptr;
    const std::string key(qualifiedName);
    if (const auto known = prototypes.find(key); known != prototypes.end())
        return known->second ? &known->second->details : nullptr;
    const std::string_view interfaceName = qualifiedName.substr(0, separator);
    const std::string_view methodName    = qualifiedName.substr(separator + 2);
    std::shared_ptr<const DissasmUserPrototype> parsed;
    for (uint32 index = 0; index < 256; index++) {
        const auto method = FindComMethod(interfaceName, index);
        if (!method.has_value())
            break;
        if (method->second.name != methodName)
            continue;
        if (method->second.parameters) {
            const bool counted   = methodName == "AddRef" || methodName == "Release"; // ULONG: the count of the references
            std::string text     = std::string(counted ? "ULONG " : "HRESULT ") + key + "(" + std::string(interfaceName) + "* This";
            if (method->second.parameters[0])
                text += std::string(", ") + method->second.parameters;
            parsed = ParseApiPrototype(text + ")");
        }
        break;
    }
    prototypes.emplace(key, parsed);
    return parsed ? &parsed->details : nullptr;
}

const DissasmComProducer* GView::View::DissasmViewer::FindComProducer(std::string_view function)
{
    const auto& producers = GetProducers();
    const auto found      = producers.find(function);
    return found != producers.end() ? &found->second : nullptr;
}

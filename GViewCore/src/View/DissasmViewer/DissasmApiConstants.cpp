#include "DissasmViewer.hpp"

#include <cctype>
#include <cstdio>
#include <span>
#include <unordered_map>

using namespace GView::View::DissasmViewer;

namespace
{
// a name of a constant: a flag (mask 0: the bits of its value), a value of a field (the bits of its mask: MB_ICONERROR in the 0xF0 of the
// icons), a value of an enumeration (the whole value)
struct ConstantName {
    uint32 value;
    std::string_view name;
    uint32 mask = 0;
};

enum class ConstantKind : uint8 { Enumeration, Flags };

struct ConstantSet {
    ConstantKind kind;
    std::span<const ConstantName> names;
};

constexpr uint32 FIELD_BUTTONS = 0xF, FIELD_ICONS = 0xF0, FIELD_DEFAULT_BUTTON = 0xF00, FIELD_MODALITY = 0x3000;

// the access rights: the generic and the standard ones (every object), then the ones of the files, the processes, the threads, the keys,
// the services
#define STANDARD_RIGHTS                                                                                                                          \
    { 0x80000000, "GENERIC_READ" }, { 0x40000000, "GENERIC_WRITE" }, { 0x20000000, "GENERIC_EXECUTE" }, { 0x10000000, "GENERIC_ALL" },       \
          { 0x02000000, "MAXIMUM_ALLOWED" }, { 0x01000000, "ACCESS_SYSTEM_SECURITY" }, { 0x00100000, "SYNCHRONIZE" },                       \
          { 0x00080000, "WRITE_OWNER" }, { 0x00040000, "WRITE_DAC" }, { 0x00020000, "READ_CONTROL" }, { 0x00010000, "DELETE" }

constexpr ConstantName ACCESS_RIGHTS[] = { STANDARD_RIGHTS };
constexpr ConstantName FILE_RIGHTS[]   = { { 0x1F01FF, "FILE_ALL_ACCESS" },
                                           STANDARD_RIGHTS,
                                           { 0x1, "FILE_READ_DATA" },
                                           { 0x2, "FILE_WRITE_DATA" },
                                           { 0x4, "FILE_APPEND_DATA" },
                                           { 0x8, "FILE_READ_EA" },
                                           { 0x10, "FILE_WRITE_EA" },
                                           { 0x20, "FILE_EXECUTE" },
                                           { 0x80, "FILE_READ_ATTRIBUTES" },
                                           { 0x100, "FILE_WRITE_ATTRIBUTES" } };
constexpr ConstantName PROCESS_RIGHTS[] = { { 0x1FFFFF, "PROCESS_ALL_ACCESS" },
                                            STANDARD_RIGHTS,
                                            { 0x1, "PROCESS_TERMINATE" },
                                            { 0x2, "PROCESS_CREATE_THREAD" },
                                            { 0x4, "PROCESS_SET_SESSIONID" },
                                            { 0x8, "PROCESS_VM_OPERATION" },
                                            { 0x10, "PROCESS_VM_READ" },
                                            { 0x20, "PROCESS_VM_WRITE" },
                                            { 0x40, "PROCESS_DUP_HANDLE" },
                                            { 0x80, "PROCESS_CREATE_PROCESS" },
                                            { 0x100, "PROCESS_SET_QUOTA" },
                                            { 0x200, "PROCESS_SET_INFORMATION" },
                                            { 0x400, "PROCESS_QUERY_INFORMATION" },
                                            { 0x800, "PROCESS_SUSPEND_RESUME" },
                                            { 0x1000, "PROCESS_QUERY_LIMITED_INFORMATION" } };
constexpr ConstantName THREAD_RIGHTS[] = { { 0x1FFFFF, "THREAD_ALL_ACCESS" },
                                           STANDARD_RIGHTS,
                                           { 0x1, "THREAD_TERMINATE" },
                                           { 0x2, "THREAD_SUSPEND_RESUME" },
                                           { 0x8, "THREAD_GET_CONTEXT" },
                                           { 0x10, "THREAD_SET_CONTEXT" },
                                           { 0x20, "THREAD_SET_INFORMATION" },
                                           { 0x40, "THREAD_QUERY_INFORMATION" },
                                           { 0x80, "THREAD_SET_THREAD_TOKEN" },
                                           { 0x100, "THREAD_IMPERSONATE" },
                                           { 0x200, "THREAD_DIRECT_IMPERSONATION" },
                                           { 0x800, "THREAD_QUERY_LIMITED_INFORMATION" } };
constexpr ConstantName KEY_RIGHTS[] = { { 0xF003F, "KEY_ALL_ACCESS" },
                                        { 0x20019, "KEY_READ" },
                                        { 0x20006, "KEY_WRITE" },
                                        STANDARD_RIGHTS,
                                        { 0x1, "KEY_QUERY_VALUE" },
                                        { 0x2, "KEY_SET_VALUE" },
                                        { 0x4, "KEY_CREATE_SUB_KEY" },
                                        { 0x8, "KEY_ENUMERATE_SUB_KEYS" },
                                        { 0x10, "KEY_NOTIFY" },
                                        { 0x20, "KEY_CREATE_LINK" },
                                        { 0x100, "KEY_WOW64_64KEY" },
                                        { 0x200, "KEY_WOW64_32KEY" } };
constexpr ConstantName SC_MANAGER_RIGHTS[] = { { 0xF003F, "SC_MANAGER_ALL_ACCESS" },
                                               STANDARD_RIGHTS,
                                               { 0x1, "SC_MANAGER_CONNECT" },
                                               { 0x2, "SC_MANAGER_CREATE_SERVICE" },
                                               { 0x4, "SC_MANAGER_ENUMERATE_SERVICE" },
                                               { 0x8, "SC_MANAGER_LOCK" },
                                               { 0x10, "SC_MANAGER_QUERY_LOCK_STATUS" },
                                               { 0x20, "SC_MANAGER_MODIFY_BOOT_CONFIG" } };
constexpr ConstantName SERVICE_RIGHTS[] = { { 0xF01FF, "SERVICE_ALL_ACCESS" },
                                            STANDARD_RIGHTS,
                                            { 0x1, "SERVICE_QUERY_CONFIG" },
                                            { 0x2, "SERVICE_CHANGE_CONFIG" },
                                            { 0x4, "SERVICE_QUERY_STATUS" },
                                            { 0x8, "SERVICE_ENUMERATE_DEPENDENTS" },
                                            { 0x10, "SERVICE_START" },
                                            { 0x20, "SERVICE_STOP" },
                                            { 0x40, "SERVICE_PAUSE_CONTINUE" },
                                            { 0x80, "SERVICE_INTERROGATE" },
                                            { 0x100, "SERVICE_USER_DEFINED_CONTROL" } };
#undef STANDARD_RIGHTS

// the files
constexpr ConstantName SHARE_MODES[]  = { { 0x1, "FILE_SHARE_READ" }, { 0x2, "FILE_SHARE_WRITE" }, { 0x4, "FILE_SHARE_DELETE" } };
constexpr ConstantName DISPOSITIONS[] = { { 1, "CREATE_NEW" }, { 2, "CREATE_ALWAYS" }, { 3, "OPEN_EXISTING" }, { 4, "OPEN_ALWAYS" }, { 5, "TRUNCATE_EXISTING" } };
constexpr ConstantName FILE_ATTRIBUTES[] = { { 0x1, "FILE_ATTRIBUTE_READONLY" },
                                             { 0x2, "FILE_ATTRIBUTE_HIDDEN" },
                                             { 0x4, "FILE_ATTRIBUTE_SYSTEM" },
                                             { 0x10, "FILE_ATTRIBUTE_DIRECTORY" },
                                             { 0x20, "FILE_ATTRIBUTE_ARCHIVE" },
                                             { 0x80, "FILE_ATTRIBUTE_NORMAL" },
                                             { 0x100, "FILE_ATTRIBUTE_TEMPORARY" },
                                             { 0x400, "FILE_ATTRIBUTE_REPARSE_POINT" },
                                             { 0x800, "FILE_ATTRIBUTE_COMPRESSED" },
                                             { 0x2000, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED" },
                                             { 0x4000, "FILE_ATTRIBUTE_ENCRYPTED" },
                                             { 0x80000000, "FILE_FLAG_WRITE_THROUGH" },
                                             { 0x40000000, "FILE_FLAG_OVERLAPPED" },
                                             { 0x20000000, "FILE_FLAG_NO_BUFFERING" },
                                             { 0x10000000, "FILE_FLAG_RANDOM_ACCESS" },
                                             { 0x08000000, "FILE_FLAG_SEQUENTIAL_SCAN" },
                                             { 0x04000000, "FILE_FLAG_DELETE_ON_CLOSE" },
                                             { 0x02000000, "FILE_FLAG_BACKUP_SEMANTICS" },
                                             { 0x01000000, "FILE_FLAG_POSIX_SEMANTICS" },
                                             { 0x00200000, "FILE_FLAG_OPEN_REPARSE_POINT" },
                                             { 0x00100000, "FILE_FLAG_OPEN_NO_RECALL" } };
constexpr ConstantName MOVE_METHODS[]    = { { 0, "FILE_BEGIN" }, { 1, "FILE_CURRENT" }, { 2, "FILE_END" } };
constexpr ConstantName MOVE_FILE_FLAGS[] = {
    { 0x1, "MOVEFILE_REPLACE_EXISTING" }, { 0x2, "MOVEFILE_COPY_ALLOWED" }, { 0x4, "MOVEFILE_DELAY_UNTIL_REBOOT" }, { 0x8, "MOVEFILE_WRITE_THROUGH" }
};
constexpr ConstantName STD_HANDLES[] = { { 0xFFFFFFF6, "STD_INPUT_HANDLE" }, { 0xFFFFFFF5, "STD_OUTPUT_HANDLE" }, { 0xFFFFFFF4, "STD_ERROR_HANDLE" } };

// the memory
constexpr ConstantName PAGE_PROTECTIONS[] = { { 0x1, "PAGE_NOACCESS" },
                                              { 0x2, "PAGE_READONLY" },
                                              { 0x4, "PAGE_READWRITE" },
                                              { 0x8, "PAGE_WRITECOPY" },
                                              { 0x10, "PAGE_EXECUTE" },
                                              { 0x20, "PAGE_EXECUTE_READ" },
                                              { 0x40, "PAGE_EXECUTE_READWRITE" },
                                              { 0x80, "PAGE_EXECUTE_WRITECOPY" },
                                              { 0x100, "PAGE_GUARD" },
                                              { 0x200, "PAGE_NOCACHE" },
                                              { 0x400, "PAGE_WRITECOMBINE" },
                                              { 0x01000000, "SEC_IMAGE" },
                                              { 0x04000000, "SEC_RESERVE" },
                                              { 0x08000000, "SEC_COMMIT" } };
constexpr ConstantName ALLOCATION_TYPES[] = { { 0x1000, "MEM_COMMIT" },       { 0x2000, "MEM_RESERVE" },   { 0x80000, "MEM_RESET" },
                                              { 0x100000, "MEM_TOP_DOWN" },   { 0x400000, "MEM_PHYSICAL" }, { 0x20000000, "MEM_LARGE_PAGES" } };
constexpr ConstantName FREE_TYPES[]       = { { 0x4000, "MEM_DECOMMIT" }, { 0x8000, "MEM_RELEASE" } };
constexpr ConstantName HEAP_FLAGS[]       = { { 0x1, "HEAP_NO_SERIALIZE" },
                                              { 0x4, "HEAP_GENERATE_EXCEPTIONS" },
                                              { 0x8, "HEAP_ZERO_MEMORY" },
                                              { 0x10, "HEAP_REALLOC_IN_PLACE_ONLY" },
                                              { 0x40000, "HEAP_CREATE_ENABLE_EXECUTE" } };
constexpr ConstantName LOCAL_FLAGS[]      = { { 0x42, "LHND" }, { 0x40, "LPTR" }, { 0x2, "LMEM_MOVEABLE" }, { 0x0, "LMEM_FIXED" } };
constexpr ConstantName GLOBAL_FLAGS[]     = { { 0x42, "GHND" }, { 0x40, "GPTR" }, { 0x2, "GMEM_MOVEABLE" }, { 0x0, "GMEM_FIXED" } };

// the registry
constexpr ConstantName PREDEFINED_KEYS[] = { { 0x80000000, "HKEY_CLASSES_ROOT" },     { 0x80000001, "HKEY_CURRENT_USER" },
                                             { 0x80000002, "HKEY_LOCAL_MACHINE" },    { 0x80000003, "HKEY_USERS" },
                                             { 0x80000004, "HKEY_PERFORMANCE_DATA" }, { 0x80000005, "HKEY_CURRENT_CONFIG" } };
constexpr ConstantName VALUE_TYPES[]     = { { 0, "REG_NONE" },  { 1, "REG_SZ" },        { 2, "REG_EXPAND_SZ" }, { 3, "REG_BINARY" },
                                             { 4, "REG_DWORD" }, { 5, "REG_DWORD_BIG_ENDIAN" }, { 6, "REG_LINK" }, { 7, "REG_MULTI_SZ" },
                                             { 11, "REG_QWORD" } };
constexpr ConstantName KEY_OPTIONS[]     = { { 0x0, "REG_OPTION_NON_VOLATILE" }, { 0x1, "REG_OPTION_VOLATILE" }, { 0x4, "REG_OPTION_BACKUP_RESTORE" } };

// the processes, the threads, the waits
constexpr ConstantName PROCESS_CREATION_FLAGS[] = { { 0x1, "DEBUG_PROCESS" },
                                                    { 0x2, "DEBUG_ONLY_THIS_PROCESS" },
                                                    { 0x4, "CREATE_SUSPENDED" },
                                                    { 0x8, "DETACHED_PROCESS" },
                                                    { 0x10, "CREATE_NEW_CONSOLE" },
                                                    { 0x20, "NORMAL_PRIORITY_CLASS" },
                                                    { 0x40, "IDLE_PRIORITY_CLASS" },
                                                    { 0x80, "HIGH_PRIORITY_CLASS" },
                                                    { 0x200, "CREATE_NEW_PROCESS_GROUP" },
                                                    { 0x400, "CREATE_UNICODE_ENVIRONMENT" },
                                                    { 0x40000, "CREATE_PROTECTED_PROCESS" },
                                                    { 0x80000, "EXTENDED_STARTUPINFO_PRESENT" },
                                                    { 0x1000000, "CREATE_BREAKAWAY_FROM_JOB" },
                                                    { 0x4000000, "CREATE_DEFAULT_ERROR_MODE" },
                                                    { 0x8000000, "CREATE_NO_WINDOW" } };
constexpr ConstantName THREAD_CREATION_FLAGS[]  = { { 0x4, "CREATE_SUSPENDED" }, { 0x10000, "STACK_SIZE_PARAM_IS_A_RESERVATION" } };
constexpr ConstantName WAIT_TIMES[]             = { { 0xFFFFFFFF, "INFINITE" } };
constexpr ConstantName DUPLICATE_OPTIONS[]      = { { 0x1, "DUPLICATE_CLOSE_SOURCE" }, { 0x2, "DUPLICATE_SAME_ACCESS" } };
constexpr ConstantName SNAPSHOT_FLAGS[]         = { { 0xF, "TH32CS_SNAPALL" },      { 0x1, "TH32CS_SNAPHEAPLIST" }, { 0x2, "TH32CS_SNAPPROCESS" },
                                                    { 0x4, "TH32CS_SNAPTHREAD" },   { 0x8, "TH32CS_SNAPMODULE" },   { 0x10, "TH32CS_SNAPMODULE32" },
                                                    { 0x80000000, "TH32CS_INHERIT" } };
constexpr ConstantName ERROR_MODES[]            = { { 0x1, "SEM_FAILCRITICALERRORS" },
                                                    { 0x2, "SEM_NOGPFAULTERRORBOX" },
                                                    { 0x4, "SEM_NOALIGNMENTFAULTEXCEPT" },
                                                    { 0x8000, "SEM_NOOPENFILEERRORBOX" } };
constexpr ConstantName LOAD_LIBRARY_FLAGS[]     = { { 0x1, "DONT_RESOLVE_DLL_REFERENCES" },
                                                    { 0x2, "LOAD_LIBRARY_AS_DATAFILE" },
                                                    { 0x8, "LOAD_WITH_ALTERED_SEARCH_PATH" },
                                                    { 0x10, "LOAD_IGNORE_CODE_AUTHZ_LEVEL" },
                                                    { 0x20, "LOAD_LIBRARY_AS_IMAGE_RESOURCE" },
                                                    { 0x40, "LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE" },
                                                    { 0x100, "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR" },
                                                    { 0x200, "LOAD_LIBRARY_SEARCH_APPLICATION_DIR" },
                                                    { 0x400, "LOAD_LIBRARY_SEARCH_USER_DIRS" },
                                                    { 0x800, "LOAD_LIBRARY_SEARCH_SYSTEM32" },
                                                    { 0x1000, "LOAD_LIBRARY_SEARCH_DEFAULT_DIRS" } };
constexpr ConstantName MODULE_HANDLE_FLAGS[]    = { { 0x1, "GET_MODULE_HANDLE_EX_FLAG_PIN" },
                                                    { 0x2, "GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT" },
                                                    { 0x4, "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS" } };
constexpr ConstantName FORMAT_MESSAGE_FLAGS[]   = { { 0x100, "FORMAT_MESSAGE_ALLOCATE_BUFFER" }, { 0x200, "FORMAT_MESSAGE_IGNORE_INSERTS" },
                                                    { 0x400, "FORMAT_MESSAGE_FROM_STRING" },     { 0x800, "FORMAT_MESSAGE_FROM_HMODULE" },
                                                    { 0x1000, "FORMAT_MESSAGE_FROM_SYSTEM" },    { 0x2000, "FORMAT_MESSAGE_ARGUMENT_ARRAY" } };
constexpr ConstantName CODE_PAGES[] = { { 0, "CP_ACP" }, { 1, "CP_OEMCP" }, { 2, "CP_MACCP" }, { 3, "CP_THREAD_ACP" }, { 65000, "CP_UTF7" }, { 65001, "CP_UTF8" } };
constexpr ConstantName LOCALES[]    = { { 0x400, "LOCALE_USER_DEFAULT" }, { 0x800, "LOCALE_SYSTEM_DEFAULT" }, { 0x7F, "LOCALE_INVARIANT" } };

// the windows
constexpr ConstantName MESSAGE_BOX_TYPES[] = { { 0x0, "MB_OK", FIELD_BUTTONS },
                                               { 0x1, "MB_OKCANCEL", FIELD_BUTTONS },
                                               { 0x2, "MB_ABORTRETRYIGNORE", FIELD_BUTTONS },
                                               { 0x3, "MB_YESNOCANCEL", FIELD_BUTTONS },
                                               { 0x4, "MB_YESNO", FIELD_BUTTONS },
                                               { 0x5, "MB_RETRYCANCEL", FIELD_BUTTONS },
                                               { 0x6, "MB_CANCELTRYCONTINUE", FIELD_BUTTONS },
                                               { 0x10, "MB_ICONERROR", FIELD_ICONS },
                                               { 0x20, "MB_ICONQUESTION", FIELD_ICONS },
                                               { 0x30, "MB_ICONWARNING", FIELD_ICONS },
                                               { 0x40, "MB_ICONINFORMATION", FIELD_ICONS },
                                               { 0x100, "MB_DEFBUTTON2", FIELD_DEFAULT_BUTTON },
                                               { 0x200, "MB_DEFBUTTON3", FIELD_DEFAULT_BUTTON },
                                               { 0x300, "MB_DEFBUTTON4", FIELD_DEFAULT_BUTTON },
                                               { 0x1000, "MB_SYSTEMMODAL", FIELD_MODALITY },
                                               { 0x2000, "MB_TASKMODAL", FIELD_MODALITY },
                                               { 0x10000, "MB_SETFOREGROUND" },
                                               { 0x40000, "MB_TOPMOST" },
                                               { 0x80000, "MB_RIGHT" },
                                               { 0x200000, "MB_SERVICE_NOTIFICATION" } };
constexpr ConstantName SHOW_COMMANDS[]     = { { 0, "SW_HIDE" },          { 1, "SW_SHOWNORMAL" },  { 2, "SW_SHOWMINIMIZED" }, { 3, "SW_SHOWMAXIMIZED" },
                                               { 4, "SW_SHOWNOACTIVATE" }, { 5, "SW_SHOW" },       { 6, "SW_MINIMIZE" },      { 7, "SW_SHOWMINNOACTIVE" },
                                               { 8, "SW_SHOWNA" },         { 9, "SW_RESTORE" },    { 10, "SW_SHOWDEFAULT" },  { 11, "SW_FORCEMINIMIZE" } };
constexpr ConstantName WINDOW_MESSAGES[]   = {
    { 0x0, "WM_NULL" },           { 0x1, "WM_CREATE" },         { 0x2, "WM_DESTROY" },        { 0x3, "WM_MOVE" },           { 0x5, "WM_SIZE" },
    { 0x6, "WM_ACTIVATE" },       { 0x7, "WM_SETFOCUS" },       { 0x8, "WM_KILLFOCUS" },      { 0xA, "WM_ENABLE" },         { 0xB, "WM_SETREDRAW" },
    { 0xC, "WM_SETTEXT" },        { 0xD, "WM_GETTEXT" },        { 0xE, "WM_GETTEXTLENGTH" },  { 0xF, "WM_PAINT" },          { 0x10, "WM_CLOSE" },
    { 0x12, "WM_QUIT" },          { 0x14, "WM_ERASEBKGND" },    { 0x18, "WM_SHOWWINDOW" },    { 0x20, "WM_SETCURSOR" },     { 0x24, "WM_GETMINMAXINFO" },
    { 0x30, "WM_SETFONT" },       { 0x31, "WM_GETFONT" },       { 0x4A, "WM_COPYDATA" },      { 0x4E, "WM_NOTIFY" },        { 0x7B, "WM_CONTEXTMENU" },
    { 0x7F, "WM_GETICON" },       { 0x80, "WM_SETICON" },       { 0x82, "WM_NCDESTROY" },     { 0xB0, "EM_GETSEL" },        { 0xB1, "EM_SETSEL" },
    { 0xC5, "EM_LIMITTEXT" },     { 0xCF, "EM_SETREADONLY" },   { 0xF0, "BM_GETCHECK" },      { 0xF1, "BM_SETCHECK" },      { 0x100, "WM_KEYDOWN" },
    { 0x101, "WM_KEYUP" },        { 0x102, "WM_CHAR" },         { 0x110, "WM_INITDIALOG" },   { 0x111, "WM_COMMAND" },      { 0x112, "WM_SYSCOMMAND" },
    { 0x113, "WM_TIMER" },        { 0x114, "WM_HSCROLL" },      { 0x115, "WM_VSCROLL" },      { 0x117, "WM_INITMENUPOPUP" }, { 0x200, "WM_MOUSEMOVE" },
    { 0x201, "WM_LBUTTONDOWN" },  { 0x202, "WM_LBUTTONUP" },    { 0x204, "WM_RBUTTONDOWN" },  { 0x205, "WM_RBUTTONUP" },    { 0x20A, "WM_MOUSEWHEEL" },
    { 0x233, "WM_DROPFILES" },    { 0x400, "WM_USER" },         { 0x8000, "WM_APP" }
};
constexpr ConstantName WINDOW_LONG_INDEXES[] = { { 0xFFFFFFFC, "GWLP_WNDPROC" }, { 0xFFFFFFFA, "GWLP_HINSTANCE" }, { 0xFFFFFFF8, "GWLP_HWNDPARENT" },
                                                 { 0xFFFFFFF4, "GWLP_ID" },      { 0xFFFFFFF0, "GWL_STYLE" },      { 0xFFFFFFEC, "GWL_EXSTYLE" },
                                                 { 0xFFFFFFEB, "GWLP_USERDATA" } };
constexpr ConstantName WINDOW_POSITION_FLAGS[] = { { 0x1, "SWP_NOSIZE" },       { 0x2, "SWP_NOMOVE" },      { 0x4, "SWP_NOZORDER" },
                                                   { 0x8, "SWP_NOREDRAW" },     { 0x10, "SWP_NOACTIVATE" }, { 0x20, "SWP_FRAMECHANGED" },
                                                   { 0x40, "SWP_SHOWWINDOW" },  { 0x80, "SWP_HIDEWINDOW" }, { 0x200, "SWP_NOOWNERZORDER" } };
constexpr ConstantName INSERT_AFTER[] = { { 0, "HWND_TOP" }, { 1, "HWND_BOTTOM" }, { 0xFFFFFFFF, "HWND_TOPMOST" }, { 0xFFFFFFFE, "HWND_NOTOPMOST" } };
constexpr ConstantName WINDOW_RELATIONS[] = { { 0, "GW_HWNDFIRST" }, { 1, "GW_HWNDLAST" }, { 2, "GW_HWNDNEXT" }, { 3, "GW_HWNDPREV" }, { 4, "GW_OWNER" }, { 5, "GW_CHILD" } };
constexpr ConstantName MENU_FLAGS[]      = { { 0x400, "MF_BYPOSITION" }, { 0x1, "MF_GRAYED" }, { 0x2, "MF_DISABLED" }, { 0x8, "MF_CHECKED" },
                                             { 0x10, "MF_POPUP" },       { 0x800, "MF_SEPARATOR" }, { 0x0, "MF_BYCOMMAND" } };
constexpr ConstantName BUTTON_STATES[]   = { { 0, "BST_UNCHECKED" }, { 1, "BST_CHECKED" }, { 2, "BST_INDETERMINATE" } };
constexpr ConstantName HOOK_TYPES[]      = { { 0, "WH_JOURNALRECORD" }, { 1, "WH_JOURNALPLAYBACK" }, { 2, "WH_KEYBOARD" }, { 3, "WH_GETMESSAGE" },
                                             { 4, "WH_CALLWNDPROC" },  { 5, "WH_CBT" },             { 6, "WH_SYSMSGFILTER" }, { 7, "WH_MOUSE" },
                                             { 9, "WH_DEBUG" },        { 10, "WH_SHELL" },          { 11, "WH_FOREGROUNDIDLE" }, { 12, "WH_CALLWNDPROCRET" },
                                             { 13, "WH_KEYBOARD_LL" }, { 14, "WH_MOUSE_LL" } };
constexpr ConstantName BACKGROUND_MODES[] = { { 1, "TRANSPARENT" }, { 2, "OPAQUE" } };
constexpr ConstantName FOLDERS[]          = { { 0x0, "CSIDL_DESKTOP", 0xFF },         { 0x2, "CSIDL_PROGRAMS", 0xFF },    { 0x5, "CSIDL_PERSONAL", 0xFF },
                                              { 0x7, "CSIDL_STARTUP", 0xFF },         { 0x1A, "CSIDL_APPDATA", 0xFF },    { 0x1C, "CSIDL_LOCAL_APPDATA", 0xFF },
                                              { 0x23, "CSIDL_COMMON_APPDATA", 0xFF }, { 0x24, "CSIDL_WINDOWS", 0xFF },    { 0x25, "CSIDL_SYSTEM", 0xFF },
                                              { 0x26, "CSIDL_PROGRAM_FILES", 0xFF },  { 0x8000, "CSIDL_FLAG_CREATE" } };

// COM, the services, the internet, the sockets, the cryptography
constexpr ConstantName CLASS_CONTEXTS[] = { { 0x17, "CLSCTX_ALL" },          { 0x15, "CLSCTX_SERVER" },        { 0x1, "CLSCTX_INPROC_SERVER" },
                                            { 0x2, "CLSCTX_INPROC_HANDLER" }, { 0x4, "CLSCTX_LOCAL_SERVER" }, { 0x10, "CLSCTX_REMOTE_SERVER" } };
constexpr ConstantName COM_INIT_FLAGS[] = { { 0x2, "COINIT_APARTMENTTHREADED" }, { 0x4, "COINIT_DISABLE_OLE1DDE" }, { 0x8, "COINIT_SPEED_OVER_MEMORY" },
                                            { 0x0, "COINIT_MULTITHREADED" } };
constexpr ConstantName SERVICE_TYPES[]  = { { 0x1, "SERVICE_KERNEL_DRIVER" },        { 0x2, "SERVICE_FILE_SYSTEM_DRIVER" },
                                            { 0x10, "SERVICE_WIN32_OWN_PROCESS" },   { 0x20, "SERVICE_WIN32_SHARE_PROCESS" },
                                            { 0x100, "SERVICE_INTERACTIVE_PROCESS" } };
constexpr ConstantName START_TYPES[]    = { { 0, "SERVICE_BOOT_START" }, { 1, "SERVICE_SYSTEM_START" }, { 2, "SERVICE_AUTO_START" }, { 3, "SERVICE_DEMAND_START" },
                                            { 4, "SERVICE_DISABLED" } };
constexpr ConstantName ERROR_CONTROLS[] = { { 0, "SERVICE_ERROR_IGNORE" }, { 1, "SERVICE_ERROR_NORMAL" }, { 2, "SERVICE_ERROR_SEVERE" }, { 3, "SERVICE_ERROR_CRITICAL" } };
constexpr ConstantName SERVICE_CONTROLS[] = { { 1, "SERVICE_CONTROL_STOP" }, { 2, "SERVICE_CONTROL_PAUSE" }, { 3, "SERVICE_CONTROL_CONTINUE" }, { 4, "SERVICE_CONTROL_INTERROGATE" } };
constexpr ConstantName ACCESS_TYPES[]     = { { 0, "INTERNET_OPEN_TYPE_PRECONFIG" }, { 1, "INTERNET_OPEN_TYPE_DIRECT" }, { 3, "INTERNET_OPEN_TYPE_PROXY" },
                                              { 4, "INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY" } };
constexpr ConstantName INTERNET_SERVICES[] = { { 1, "INTERNET_SERVICE_FTP" }, { 2, "INTERNET_SERVICE_GOPHER" }, { 3, "INTERNET_SERVICE_HTTP" } };
constexpr ConstantName ADDRESS_FAMILIES[]  = { { 0, "AF_UNSPEC" }, { 1, "AF_UNIX" }, { 2, "AF_INET" } };
constexpr ConstantName SOCKET_TYPES[]      = { { 1, "SOCK_STREAM" }, { 2, "SOCK_DGRAM" }, { 3, "SOCK_RAW" } };
constexpr ConstantName PROTOCOLS[]         = { { 1, "IPPROTO_ICMP" }, { 6, "IPPROTO_TCP" }, { 17, "IPPROTO_UDP" } };
constexpr ConstantName PROVIDER_TYPES[]    = { { 1, "PROV_RSA_FULL" }, { 2, "PROV_RSA_SIG" }, { 3, "PROV_DSS" }, { 12, "PROV_RSA_SCHANNEL" }, { 13, "PROV_DSS_DH" },
                                               { 24, "PROV_RSA_AES" } };
constexpr ConstantName CONTEXT_FLAGS[]     = { { 0xF0000000, "CRYPT_VERIFYCONTEXT" }, { 0x8, "CRYPT_NEWKEYSET" }, { 0x10, "CRYPT_DELETEKEYSET" },
                                               { 0x20, "CRYPT_MACHINE_KEYSET" },      { 0x40, "CRYPT_SILENT" } };
constexpr ConstantName ALGORITHMS[]        = { { 0x8001, "CALG_MD2" },     { 0x8003, "CALG_MD5" },     { 0x8004, "CALG_SHA1" },    { 0x800C, "CALG_SHA_256" },
                                               { 0x800D, "CALG_SHA_384" }, { 0x800E, "CALG_SHA_512" }, { 0x8009, "CALG_HMAC" },    { 0x6801, "CALG_RC4" },
                                               { 0x6602, "CALG_RC2" },     { 0x6601, "CALG_DES" },     { 0x6603, "CALG_3DES" },    { 0x660E, "CALG_AES_128" },
                                               { 0x660F, "CALG_AES_192" }, { 0x6610, "CALG_AES_256" }, { 0xA400, "CALG_RSA_KEYX" }, { 0x2400, "CALG_RSA_SIGN" } };
constexpr ConstantName ENCODING_TYPES[]    = { { 0x1, "X509_ASN_ENCODING" }, { 0x10000, "PKCS_7_ASN_ENCODING" } };

// the kernel
constexpr ConstantName POOL_TYPES[]    = { { 0, "NonPagedPool" },  { 1, "PagedPool" }, { 2, "NonPagedPoolMustSucceed" }, { 4, "NonPagedPoolCacheAligned" },
                                           { 5, "PagedPoolCacheAligned" }, { 0x200, "NonPagedPoolNx" } };
constexpr ConstantName WAIT_REASONS[]  = { { 0, "Executive" }, { 6, "UserRequest" } };
constexpr ConstantName PROCESSOR_MODES[] = { { 0, "KernelMode" }, { 1, "UserMode" } };
constexpr ConstantName EVENT_TYPES[]   = { { 0, "NotificationEvent" }, { 1, "SynchronizationEvent" } };

// POSIX (the values of Linux, the same for macOS where they are named)
constexpr ConstantName OPEN_FLAGS[]   = { { 0x0, "O_RDONLY", 0x3 },  { 0x1, "O_WRONLY", 0x3 },  { 0x2, "O_RDWR", 0x3 },    { 0x40, "O_CREAT" },
                                          { 0x80, "O_EXCL" },        { 0x100, "O_NOCTTY" },     { 0x200, "O_TRUNC" },      { 0x400, "O_APPEND" },
                                          { 0x800, "O_NONBLOCK" },   { 0x80000, "O_CLOEXEC" } };
constexpr ConstantName PROTECTIONS[]  = { { 0x1, "PROT_READ" }, { 0x2, "PROT_WRITE" }, { 0x4, "PROT_EXEC" }, { 0x0, "PROT_NONE" } };
constexpr ConstantName MAP_FLAGS[]    = { { 0x1, "MAP_SHARED" }, { 0x2, "MAP_PRIVATE" }, { 0x10, "MAP_FIXED" }, { 0x20, "MAP_ANONYMOUS" } };
constexpr ConstantName SEEK_ORIGINS[] = { { 0, "SEEK_SET" }, { 1, "SEEK_CUR" }, { 2, "SEEK_END" } };
constexpr ConstantName SIGNALS[]      = { { 1, "SIGHUP" },  { 2, "SIGINT" },  { 3, "SIGQUIT" }, { 4, "SIGILL" },  { 5, "SIGTRAP" },  { 6, "SIGABRT" },
                                          { 8, "SIGFPE" },  { 9, "SIGKILL" }, { 11, "SIGSEGV" }, { 13, "SIGPIPE" }, { 14, "SIGALRM" }, { 15, "SIGTERM" } };

template <size_t N>
constexpr ConstantSet Enumeration(const ConstantName (&names)[N])
{
    return { ConstantKind::Enumeration, std::span<const ConstantName>(names, N) };
}
template <size_t N>
constexpr ConstantSet Flags(const ConstantName (&names)[N])
{
    return { ConstantKind::Flags, std::span<const ConstantName>(names, N) };
}

// the sets: by "Function:parameter" (the A / W ending of the function dropped), else by the name of a parameter that means the same in
// every API (dwShareMode, flProtect, hKey, dwMilliseconds)
const std::unordered_map<std::string_view, ConstantSet>& GetConstantSets()
{
    static const std::unordered_map<std::string_view, ConstantSet> sets = {
        { "dwDesiredAccess", Flags(ACCESS_RIGHTS) },
        { "CreateFile:dwDesiredAccess", Flags(FILE_RIGHTS) },
        { "OpenProcess:dwDesiredAccess", Flags(PROCESS_RIGHTS) },
        { "OpenThread:dwDesiredAccess", Flags(THREAD_RIGHTS) },
        { "OpenSCManager:dwDesiredAccess", Flags(SC_MANAGER_RIGHTS) },
        { "OpenService:dwDesiredAccess", Flags(SERVICE_RIGHTS) },
        { "CreateService:dwDesiredAccess", Flags(SERVICE_RIGHTS) },
        { "samDesired", Flags(KEY_RIGHTS) },
        { "dwShareMode", Flags(SHARE_MODES) },
        { "dwCreationDisposition", Enumeration(DISPOSITIONS) },
        { "dwFlagsAndAttributes", Flags(FILE_ATTRIBUTES) },
        { "dwFileAttributes", Flags(FILE_ATTRIBUTES) },
        { "dwMoveMethod", Enumeration(MOVE_METHODS) },
        { "MoveFileEx:dwFlags", Flags(MOVE_FILE_FLAGS) },
        { "nStdHandle", Enumeration(STD_HANDLES) },
        { "flProtect", Flags(PAGE_PROTECTIONS) },
        { "flNewProtect", Flags(PAGE_PROTECTIONS) },
        { "flAllocationType", Flags(ALLOCATION_TYPES) },
        { "dwFreeType", Flags(FREE_TYPES) },
        { "HeapAlloc:dwFlags", Flags(HEAP_FLAGS) },
        { "HeapReAlloc:dwFlags", Flags(HEAP_FLAGS) },
        { "HeapFree:dwFlags", Flags(HEAP_FLAGS) },
        { "HeapCreate:flOptions", Flags(HEAP_FLAGS) },
        { "LocalAlloc:uFlags", Flags(LOCAL_FLAGS) },
        { "LocalReAlloc:uFlags", Flags(LOCAL_FLAGS) },
        { "GlobalAlloc:uFlags", Flags(GLOBAL_FLAGS) },
        { "hKey", Enumeration(PREDEFINED_KEYS) },
        { "hkey", Enumeration(PREDEFINED_KEYS) },
        { "RegSetValueEx:dwType", Enumeration(VALUE_TYPES) },
        { "RegSetKeyValue:dwType", Enumeration(VALUE_TYPES) },
        { "SHSetValue:dwType", Enumeration(VALUE_TYPES) },
        { "RegCreateKeyEx:dwOptions", Flags(KEY_OPTIONS) },
        { "dwCreationFlags", Flags(PROCESS_CREATION_FLAGS) },
        { "CreateThread:dwCreationFlags", Flags(THREAD_CREATION_FLAGS) },
        { "CreateRemoteThread:dwCreationFlags", Flags(THREAD_CREATION_FLAGS) },
        { "dwMilliseconds", Enumeration(WAIT_TIMES) },
        { "DuplicateHandle:dwOptions", Flags(DUPLICATE_OPTIONS) },
        { "CreateToolhelp32Snapshot:dwFlags", Flags(SNAPSHOT_FLAGS) },
        { "SetErrorMode:uMode", Flags(ERROR_MODES) },
        { "LoadLibraryEx:dwFlags", Flags(LOAD_LIBRARY_FLAGS) },
        { "GetModuleHandleEx:dwFlags", Flags(MODULE_HANDLE_FLAGS) },
        { "FormatMessage:dwFlags", Flags(FORMAT_MESSAGE_FLAGS) },
        { "CodePage", Enumeration(CODE_PAGES) },
        { "Locale", Enumeration(LOCALES) },
        { "MessageBox:uType", Flags(MESSAGE_BOX_TYPES) },
        { "MessageBoxEx:uType", Flags(MESSAGE_BOX_TYPES) },
        { "MessageBeep:uType", Flags(MESSAGE_BOX_TYPES) },
        { "nCmdShow", Enumeration(SHOW_COMMANDS) },
        { "nShowCmd", Enumeration(SHOW_COMMANDS) },
        { "uCmdShow", Enumeration(SHOW_COMMANDS) },
        { "Msg", Enumeration(WINDOW_MESSAGES) },
        { "GetWindowLong:nIndex", Enumeration(WINDOW_LONG_INDEXES) },
        { "GetWindowLongPtr:nIndex", Enumeration(WINDOW_LONG_INDEXES) },
        { "SetWindowLong:nIndex", Enumeration(WINDOW_LONG_INDEXES) },
        { "SetWindowLongPtr:nIndex", Enumeration(WINDOW_LONG_INDEXES) },
        { "SetWindowPos:uFlags", Flags(WINDOW_POSITION_FLAGS) },
        { "SetWindowPos:hWndInsertAfter", Enumeration(INSERT_AFTER) },
        { "GetWindow:uCmd", Enumeration(WINDOW_RELATIONS) },
        { "EnableMenuItem:uEnable", Flags(MENU_FLAGS) },
        { "DeleteMenu:uFlags", Flags(MENU_FLAGS) },
        { "InsertMenu:uFlags", Flags(MENU_FLAGS) },
        { "CheckDlgButton:uCheck", Enumeration(BUTTON_STATES) },
        { "idHook", Enumeration(HOOK_TYPES) },
        { "SetBkMode:mode", Enumeration(BACKGROUND_MODES) },
        { "csidl", Flags(FOLDERS) },
        { "dwClsContext", Flags(CLASS_CONTEXTS) },
        { "dwCoInit", Flags(COM_INIT_FLAGS) },
        { "dwServiceType", Flags(SERVICE_TYPES) },
        { "dwStartType", Enumeration(START_TYPES) },
        { "dwErrorControl", Enumeration(ERROR_CONTROLS) },
        { "ControlService:dwControl", Enumeration(SERVICE_CONTROLS) },
        { "InternetOpen:dwAccessType", Enumeration(ACCESS_TYPES) },
        { "InternetConnect:dwService", Enumeration(INTERNET_SERVICES) },
        { "socket:af", Enumeration(ADDRESS_FAMILIES) },
        { "socket:type", Enumeration(SOCKET_TYPES) },
        { "socket:protocol", Enumeration(PROTOCOLS) },
        { "dwProvType", Enumeration(PROVIDER_TYPES) },
        { "CryptAcquireContext:dwFlags", Flags(CONTEXT_FLAGS) },
        { "Algid", Enumeration(ALGORITHMS) },
        { "dwEncodingType", Flags(ENCODING_TYPES) },
        { "dwCertEncodingType", Flags(ENCODING_TYPES) },
        { "dwMsgAndCertEncodingType", Flags(ENCODING_TYPES) },
        { "PoolType", Enumeration(POOL_TYPES) },
        { "WaitReason", Enumeration(WAIT_REASONS) },
        { "WaitMode", Enumeration(PROCESSOR_MODES) },
        { "AccessMode", Enumeration(PROCESSOR_MODES) },
        { "KeInitializeEvent:Type", Enumeration(EVENT_TYPES) },
        { "open:flags", Flags(OPEN_FLAGS) },
        { "openat:flags", Flags(OPEN_FLAGS) },
        { "mmap:prot", Flags(PROTECTIONS) },
        { "mprotect:prot", Flags(PROTECTIONS) },
        { "mmap:flags", Flags(MAP_FLAGS) },
        { "whence", Enumeration(SEEK_ORIGINS) },
        { "fseek:origin", Enumeration(SEEK_ORIGINS) },
        { "signum", Enumeration(SIGNALS) },
        { "kill:sig", Enumeration(SIGNALS) },
        { "raise:sig", Enumeration(SIGNALS) },
    };
    return sets;
}

std::string Hex(uint32 value)
{
    char text[16];
    snprintf(text, sizeof(text), "0x%X", value);
    return text;
}

// a pool tag ('NtFs': the characters in memory order, as the pool tools show them); empty when they are not printable
std::string FormatPoolTag(uint32 value)
{
    std::string text = "'";
    for (uint32 i = 0; i < 4; i++) {
        const char c = static_cast<char>((value >> (8 * i)) & 0xFF);
        if (c < 0x20 || c > 0x7E)
            return {};
        text += c;
    }
    return text + "'";
}

// CTL_CODE(DeviceType, Function, Method, Access) of an I/O control code
std::string FormatControlCode(uint32 value)
{
    static constexpr std::string_view METHODS[]  = { "METHOD_BUFFERED", "METHOD_IN_DIRECT", "METHOD_OUT_DIRECT", "METHOD_NEITHER" };
    static constexpr std::string_view ACCESSES[] = { "FILE_ANY_ACCESS", "FILE_READ_ACCESS", "FILE_WRITE_ACCESS", "FILE_READ_ACCESS | FILE_WRITE_ACCESS" };
    if (value == 0)
        return {};
    return "CTL_CODE(" + Hex(value >> 16) + ", " + Hex((value >> 2) & 0xFFF) + ", " + std::string(METHODS[value & 3]) + ", " +
           std::string(ACCESSES[(value >> 14) & 3]) + ")";
}

std::string FormatConstant(const ConstantSet& set, uint32 value)
{
    constexpr size_t MAX_PARTS = 8;
    if (set.kind == ConstantKind::Enumeration) {
        for (const auto& constant : set.names)
            if (constant.value == value)
                return std::string(constant.name);
        return {};
    }
    // the value 0: the name of 0 (LMEM_FIXED, COINIT_MULTITHREADED, MB_OK); no name for a set of flags without one
    if (value == 0) {
        for (const auto& constant : set.names)
            if (constant.value == 0)
                return std::string(constant.name);
        return {};
    }
    // the fields (once each: MB_YESNO | MB_ICONQUESTION, O_RDONLY | O_CREAT) and the flags, in their order (the combinations before their
    // bits: KEY_READ before KEY_QUERY_VALUE); the bits without a name in hexadecimal
    std::string text;
    size_t parts     = 0;
    uint32 remaining = value, fields = 0;
    for (const auto& constant : set.names) {
        if (constant.mask != 0) {
            if ((fields & constant.mask) != 0 || (value & constant.mask) != constant.value)
                continue;
            fields |= constant.mask;
            remaining &= ~constant.mask;
        } else {
            if (constant.value == 0 || (remaining & constant.value) != constant.value)
                continue;
            remaining &= ~constant.value;
        }
        if (!text.empty())
            text += " | ";
        text += constant.name;
        if (++parts > MAX_PARTS)
            return {};
    }
    if (remaining == value)
        return {}; // no bit of it has a name
    if (remaining != 0)
        text += " | " + Hex(remaining);
    return text;
}
} // namespace

std::string GView::View::DissasmViewer::FormatApiConstant(std::string_view function, std::string_view parameter, uint64 value)
{
    // a 32 bit constant, sign extended in a 64 bit register (mov rcx, 0xffffffff80000002: HKEY_LOCAL_MACHINE)
    if ((value >> 32) != 0 && (value >> 32) != 0xFFFFFFFF)
        return {};
    const auto constant = static_cast<uint32>(value);
    if (parameter == "Tag" || parameter == "PoolTag")
        return FormatPoolTag(constant);
    if (parameter == "dwIoControlCode" || parameter == "IoControlCode")
        return FormatControlCode(constant);
    // the A / W functions share their constants (CreateFileW -> CreateFile)
    std::string_view base = function;
    if (base.size() > 2 && (base.back() == 'A' || base.back() == 'W') && std::islower(static_cast<unsigned char>(base[base.size() - 2])))
        base.remove_suffix(1);
    const auto& sets = GetConstantSets();
    for (const std::string_view name : { function, base }) {
        const std::string key = std::string(name) + ":" + std::string(parameter);
        if (const auto found = sets.find(key); found != sets.end())
            return FormatConstant(found->second, constant);
    }
    if (const auto found = sets.find(parameter); found != sets.end())
        return FormatConstant(found->second, constant);
    return {};
}

#include "DissasmViewer.hpp"
#include "DissasmFunctionUtils.hpp"

#include <algorithm>
#include <deque>
#include <map>
#include <memory>
#include <mutex>

using namespace GView::View::DissasmViewer;

namespace
{
// The prototypes of the common APIs: the Windows API (kernel32, advapi32, user32, gdi32, uxtheme, shell32, shlwapi, ole32, propsys, WinRT,
// ws2_32, wininet, winhttp, crypt32, bcrypt, ntdll, the kernel) and the C run-time / POSIX / the GNU C library (a literal each: MSVC limits a literal to 16 KB). A % in the name is the A and the W function (LPCTSTR / LPTSTR become
// LPCSTR / LPSTR and LPCWSTR / LPWSTR)
constexpr std::string_view PROTOTYPES[] = {
    "HANDLE CreateFile%(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)",
    "BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)",
    "BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)",
    "BOOL CloseHandle(HANDLE hObject)",
    "BOOL DeleteFile%(LPCTSTR lpFileName)",
    "BOOL CopyFile%(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL bFailIfExists)",
    "BOOL MoveFile%(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName)",
    "BOOL MoveFileEx%(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, DWORD dwFlags)",
    "HANDLE FindFirstFile%(LPCTSTR lpFileName, LPWIN32_FIND_DATA% lpFindFileData)",
    "BOOL FindNextFile%(HANDLE hFindFile, LPWIN32_FIND_DATA% lpFindFileData)",
    "BOOL FindClose(HANDLE hFindFile)",
    "DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)",
    "BOOL GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)",
    "DWORD SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)",
    "BOOL SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)",
    "DWORD GetFileAttributes%(LPCTSTR lpFileName)",
    "BOOL SetFileAttributes%(LPCTSTR lpFileName, DWORD dwFileAttributes)",
    "BOOL CreateDirectory%(LPCTSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)",
    "BOOL RemoveDirectory%(LPCTSTR lpPathName)",
    "DWORD GetTempPath%(DWORD nBufferLength, LPTSTR lpBuffer)",
    "UINT GetTempFileName%(LPCTSTR lpPathName, LPCTSTR lpPrefixString, UINT uUnique, LPTSTR lpTempFileName)",
    "DWORD GetModuleFileName%(HMODULE hModule, LPTSTR lpFilename, DWORD nSize)",
    "HMODULE GetModuleHandle%(LPCTSTR lpModuleName)",
    "BOOL GetModuleHandleEx%(DWORD dwFlags, LPCTSTR lpModuleName, HMODULE* phModule)",
    "HMODULE LoadLibrary%(LPCTSTR lpLibFileName)",
    "HMODULE LoadLibraryEx%(LPCTSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)",
    "FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)",
    "BOOL FreeLibrary(HMODULE hLibModule)",
    "DWORD GetCurrentDirectory%(DWORD nBufferLength, LPTSTR lpBuffer)",
    "BOOL SetCurrentDirectory%(LPCTSTR lpPathName)",
    "UINT GetSystemDirectory%(LPTSTR lpBuffer, UINT uSize)",
    "UINT GetWindowsDirectory%(LPTSTR lpBuffer, UINT uSize)",
    "DWORD GetEnvironmentVariable%(LPCTSTR lpName, LPTSTR lpBuffer, DWORD nSize)",
    "BOOL SetEnvironmentVariable%(LPCTSTR lpName, LPCTSTR lpValue)",
    "DWORD ExpandEnvironmentStrings%(LPCTSTR lpSrc, LPTSTR lpDst, DWORD nSize)",
    "UINT GetDriveType%(LPCTSTR lpRootPathName)",
    "DWORD GetLogicalDrives()",
    "BOOL GetVolumeInformation%(LPCTSTR lpRootPathName, LPTSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPTSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)",
    "BOOL GetComputerName%(LPTSTR lpBuffer, LPDWORD nSize)",
    "BOOL DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)",
    "HANDLE CreateFileMapping%(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName)",
    "LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)",
    "BOOL UnmapViewOfFile(LPCVOID lpBaseAddress)",
    "BOOL FlushFileBuffers(HANDLE hFile)",
    "BOOL CreateProcess%(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO% lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)",
    "BOOL CreateProcessAsUser%(HANDLE hToken, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO% lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)",
    "HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)",
    "BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)",
    "VOID ExitProcess(UINT uExitCode)",
    "VOID ExitThread(DWORD dwExitCode)",
    "HANDLE GetCurrentProcess()",
    "DWORD GetCurrentProcessId()",
    "HANDLE GetCurrentThread()",
    "DWORD GetCurrentThreadId()",
    "HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)",
    "HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)",
    "HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)",
    "DWORD SuspendThread(HANDLE hThread)",
    "DWORD ResumeThread(HANDLE hThread)",
    "BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)",
    "BOOL SetThreadContext(HANDLE hThread, const CONTEXT* lpContext)",
    "DWORD QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)",
    "DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)",
    "DWORD WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds)",
    "VOID Sleep(DWORD dwMilliseconds)",
    "DWORD SleepEx(DWORD dwMilliseconds, BOOL bAlertable)",
    "BOOL GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode)",
    "HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)",
    "BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)",
    "BOOL Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)",
    "BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)",
    "BOOL Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)",
    "BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme)",
    "BOOL Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)",
    "BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme)",
    "BOOL Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)",
    "BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte)",
    "BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte)",
    "BOOL IsWow64Process(HANDLE hProcess, PBOOL Wow64Process)",
    "UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)",
    "LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)",
    "LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)",
    "BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)",
    "BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)",
    "BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)",
    "BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)",
    "SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)",
    "SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)",
    "BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)",
    "BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)",
    "HANDLE GetProcessHeap()",
    "LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)",
    "LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)",
    "BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)",
    "HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes)",
    "HLOCAL LocalFree(HLOCAL hMem)",
    "HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes)",
    "HGLOBAL GlobalFree(HGLOBAL hMem)",
    "HANDLE CreateMutex%(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCTSTR lpName)",
    "HANDLE OpenMutex%(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCTSTR lpName)",
    "BOOL ReleaseMutex(HANDLE hMutex)",
    "HANDLE CreateEvent%(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCTSTR lpName)",
    "BOOL SetEvent(HANDLE hEvent)",
    "VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "VOID GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)",
    "DWORD GetTickCount()",
    "ULONGLONG GetTickCount64()",
    "BOOL QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)",
    "VOID GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)",
    "VOID GetLocalTime(LPSYSTEMTIME lpSystemTime)",
    "DWORD GetLastError()",
    "VOID SetLastError(DWORD dwErrCode)",
    "BOOL IsDebuggerPresent()",
    "BOOL CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)",
    "VOID OutputDebugString%(LPCTSTR lpOutputString)",
    "DWORD FormatMessage%(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list* Arguments)",
    "int MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)",
    "int WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)",
    "int lstrlen%(LPCTSTR lpString)",
    "int lstrcmp%(LPCTSTR lpString1, LPCTSTR lpString2)",
    "int lstrcmpi%(LPCTSTR lpString1, LPCTSTR lpString2)",
    "LPTSTR lstrcpy%(LPTSTR lpString1, LPCTSTR lpString2)",
    "LPTSTR lstrcat%(LPTSTR lpString1, LPCTSTR lpString2)",
    "LPTSTR GetCommandLine%()",
    "BOOL DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)",
    "BOOL CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize)",
    "HANDLE CreateNamedPipe%(LPCTSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)",
    "BOOL ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)",
    "HRSRC FindResource%(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType)",
    "HGLOBAL LoadResource(HMODULE hModule, HRSRC hResInfo)",
    "LPVOID LockResource(HGLOBAL hResData)",
    "DWORD SizeofResource(HMODULE hModule, HRSRC hResInfo)",
    "LSTATUS RegOpenKeyEx%(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)",
    "LSTATUS RegCreateKeyEx%(HKEY hKey, LPCTSTR lpSubKey, DWORD Reserved, LPTSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)",
    "LSTATUS RegSetValueEx%(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)",
    "LSTATUS RegQueryValueEx%(HKEY hKey, LPCTSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)",
    "LSTATUS RegGetValue%(HKEY hkey, LPCTSTR lpSubKey, LPCTSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)",
    "LSTATUS RegDeleteKey%(HKEY hKey, LPCTSTR lpSubKey)",
    "LSTATUS RegDeleteValue%(HKEY hKey, LPCTSTR lpValueName)",
    "LSTATUS RegEnumKeyEx%(HKEY hKey, DWORD dwIndex, LPTSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPTSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)",
    "LSTATUS RegEnumValue%(HKEY hKey, DWORD dwIndex, LPTSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)",
    "LSTATUS RegCloseKey(HKEY hKey)",
    "SC_HANDLE OpenSCManager%(LPCTSTR lpMachineName, LPCTSTR lpDatabaseName, DWORD dwDesiredAccess)",
    "SC_HANDLE CreateService%(SC_HANDLE hSCManager, LPCTSTR lpServiceName, LPCTSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCTSTR lpBinaryPathName, LPCTSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCTSTR lpDependencies, LPCTSTR lpServiceStartName, LPCTSTR lpPassword)",
    "SC_HANDLE OpenService%(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess)",
    "BOOL StartService%(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR* lpServiceArgVectors)",
    "BOOL ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus)",
    "BOOL DeleteService(SC_HANDLE hService)",
    "BOOL CloseServiceHandle(SC_HANDLE hSCObject)",
    "BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)",
    "BOOL LookupPrivilegeValue%(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid)",
    "BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)",
    "BOOL GetUserName%(LPTSTR lpBuffer, LPDWORD pcbBuffer)",
    "BOOL GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength)",
    "BOOL CryptAcquireContext%(HCRYPTPROV* phProv, LPCTSTR szContainer, LPCTSTR szProvider, DWORD dwProvType, DWORD dwFlags)",
    "BOOL CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags)",
    "BOOL CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash)",
    "BOOL CryptHashData(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags)",
    "BOOL CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags)",
    "BOOL CryptDestroyHash(HCRYPTHASH hHash)",
    "BOOL CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY* phKey)",
    "BOOL CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey)",
    "BOOL CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey)",
    "BOOL CryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen)",
    "BOOL CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen)",
    "BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen)",
    "BOOL CryptDestroyKey(HCRYPTKEY hKey)",
    "BOOL CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer)",
    "BOOL CryptProtectData(DATA_BLOB* pDataIn, LPCWSTR szDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut)",
    "BOOL CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut)",
    "BOOL CryptStringToBinary%(LPCTSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags)",
    "BOOL CryptBinaryToString%(const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPTSTR pszString, DWORD* pcchString)",
    "NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags)",
    "NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags)",
    "NTSTATUS BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags)",
    "NTSTATUS BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)",
    "NTSTATUS BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)",
    "NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags)",
    "NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags)",
    "NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)",
    "NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags)",
    "NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey)",
    "NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash)",
    "NTSTATUS BCryptGetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)",
    "NTSTATUS BCryptSetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)",
    "int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)",
    "int WSACleanup()",
    "int WSAGetLastError()",
    "SOCKET WSASocket%(int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo, GROUP g, DWORD dwFlags)",
    "SOCKET socket(int af, int type, int protocol)",
    "int connect(SOCKET s, const sockaddr* name, int namelen)",
    "int bind(SOCKET s, const sockaddr* name, int namelen)",
    "int listen(SOCKET s, int backlog)",
    "SOCKET accept(SOCKET s, sockaddr* addr, int* addrlen)",
    "int send(SOCKET s, const char* buf, int len, int flags)",
    "int recv(SOCKET s, char* buf, int len, int flags)",
    "int sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)",
    "int recvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)",
    "int closesocket(SOCKET s)",
    "int shutdown(SOCKET s, int how)",
    "int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const timeval* timeout)",
    "int setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen)",
    "int getsockopt(SOCKET s, int level, int optname, char* optval, int* optlen)",
    "int ioctlsocket(SOCKET s, long cmd, u_long* argp)",
    "hostent* gethostbyname(const char* name)",
    "int gethostname(char* name, int namelen)",
    "int getaddrinfo(const char* pNodeName, const char* pServiceName, const addrinfo* pHints, addrinfo** ppResult)",
    "void freeaddrinfo(addrinfo* pAddrInfo)",
    "unsigned long inet_addr(const char* cp)",
    "char* inet_ntoa(in_addr in)",
    "u_short htons(u_short hostshort)",
    "u_long htonl(u_long hostlong)",
    "u_short ntohs(u_short netshort)",
    "u_long ntohl(u_long netlong)",
    "HINTERNET InternetOpen%(LPCTSTR lpszAgent, DWORD dwAccessType, LPCTSTR lpszProxy, LPCTSTR lpszProxyBypass, DWORD dwFlags)",
    "HINTERNET InternetConnect%(HINTERNET hInternet, LPCTSTR lpszServerName, INTERNET_PORT nServerPort, LPCTSTR lpszUserName, LPCTSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)",
    "HINTERNET InternetOpenUrl%(HINTERNET hInternet, LPCTSTR lpszUrl, LPCTSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)",
    "BOOL InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)",
    "BOOL InternetCloseHandle(HINTERNET hInternet)",
    "HINTERNET HttpOpenRequest%(HINTERNET hConnect, LPCTSTR lpszVerb, LPCTSTR lpszObjectName, LPCTSTR lpszVersion, LPCTSTR lpszReferrer, LPCTSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)",
    "BOOL HttpSendRequest%(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)",
    "BOOL HttpQueryInfo%(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)",
    "HRESULT URLDownloadToFile%(LPUNKNOWN pCaller, LPCTSTR szURL, LPCTSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB)",
    "HINTERNET WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags)",
    "HINTERNET WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)",
    "HINTERNET WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags)",
    "BOOL WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext)",
    "BOOL WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved)",
    "BOOL WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)",
    "int MessageBox%(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)",
    "HWND FindWindow%(LPCTSTR lpClassName, LPCTSTR lpWindowName)",
    "HWND GetForegroundWindow()",
    "int GetWindowText%(HWND hWnd, LPTSTR lpString, int nMaxCount)",
    "BOOL ShowWindow(HWND hWnd, int nCmdShow)",
    "HHOOK SetWindowsHookEx%(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)",
    "BOOL UnhookWindowsHookEx(HHOOK hhk)",
    "LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam)",
    "SHORT GetAsyncKeyState(int vKey)",
    "SHORT GetKeyState(int nVirtKey)",
    "BOOL GetKeyboardState(PBYTE lpKeyState)",
    "HKL GetKeyboardLayout(DWORD idThread)",
    "int GetKeyboardLayoutList(int nBuff, HKL* lpList)",
    "BOOL GetMessage%(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)",
    "BOOL PeekMessage%(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)",
    "BOOL TranslateMessage(const MSG* lpMsg)",
    "LRESULT DispatchMessage%(const MSG* lpMsg)",
    "LRESULT SendMessage%(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)",
    "BOOL PostMessage%(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)",
    "BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)",
    "DWORD GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId)",
    "HDC GetDC(HWND hWnd)",
    "int ReleaseDC(HWND hWnd, HDC hDC)",
    "int GetSystemMetrics(int nIndex)",
    "BOOL OpenClipboard(HWND hWndNewOwner)",
    "HANDLE GetClipboardData(UINT uFormat)",
    "BOOL CloseClipboard()",
    "HWND CreateWindowEx%(DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)",
    "HDC CreateCompatibleDC(HDC hdc)",
    "HBITMAP CreateCompatibleBitmap(HDC hdc, int cx, int cy)",
    "HGDIOBJ SelectObject(HDC hdc, HGDIOBJ h)",
    "BOOL BitBlt(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop)",
    "BOOL DeleteObject(HGDIOBJ ho)",
    "BOOL DeleteDC(HDC hdc)",
    "HINSTANCE ShellExecute%(HWND hwnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory, INT nShowCmd)",
    "BOOL ShellExecuteEx%(LPSHELLEXECUTEINFO% pExecInfo)",
    "HRESULT SHGetFolderPath%(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPTSTR pszPath)",
    "HRESULT SHGetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PWSTR* ppszPath)",
    "HRESULT CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit)",
    "HRESULT CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv)",
    "NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)",
    "NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)",
    "NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)",
    "NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)",
    "NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)",
    "NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)",
    "NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)",
    "NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)",
    "NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)",
    "NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)",
    "NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)",
    "NTSTATUS NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)",
    "NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)",
    "NTSTATUS NtClose(HANDLE Handle)",
    "VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)",
    "PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)",
    "VOID ExFreePoolWithTag(PVOID P, ULONG Tag)",
    "NTSTATUS IoCreateDevice(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT* DeviceObject)",
    "NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName)",
    "VOID KeBugCheckEx(ULONG BugCheckCode, ULONG_PTR BugCheckParameter1, ULONG_PTR BugCheckParameter2, ULONG_PTR BugCheckParameter3, ULONG_PTR BugCheckParameter4)",
    "VOID ExRaiseStatus(NTSTATUS Status)",
    "void* malloc(size_t size)",
    "void* calloc(size_t num, size_t size)",
    "void* realloc(void* ptr, size_t size)",
    "void free(void* ptr)",
    "void* memcpy(void* dest, const void* src, size_t count)",
    "void* memmove(void* dest, const void* src, size_t count)",
    "void* memset(void* dest, int c, size_t count)",
    "int memcmp(const void* buf1, const void* buf2, size_t count)",
    "void* memchr(const void* buf, int c, size_t count)",
    "size_t strlen(const char* str)",
    "size_t wcslen(const wchar_t* str)",
    "char* strcpy(char* dest, const char* src)",
    "char* strncpy(char* dest, const char* src, size_t count)",
    "char* strcat(char* dest, const char* src)",
    "char* strncat(char* dest, const char* src, size_t count)",
    "int strcmp(const char* str1, const char* str2)",
    "int strncmp(const char* str1, const char* str2, size_t count)",
    "int strcasecmp(const char* str1, const char* str2)",
    "int _stricmp(const char* str1, const char* str2)",
    "int _wcsicmp(const wchar_t* str1, const wchar_t* str2)",
    "char* strchr(const char* str, int c)",
    "char* strrchr(const char* str, int c)",
    "char* strstr(const char* str, const char* substr)",
    "char* strdup(const char* str)",
    "char* strtok(char* str, const char* delim)",
    "wchar_t* wcscpy(wchar_t* dest, const wchar_t* src)",
    "int wcscmp(const wchar_t* str1, const wchar_t* str2)",
    "int printf(const char* format, ...)",
    "int sprintf(char* buffer, const char* format, ...)",
    "int snprintf(char* buffer, size_t count, const char* format, ...)",
    "int fprintf(FILE* stream, const char* format, ...)",
    "int vsnprintf(char* buffer, size_t count, const char* format, va_list argptr)",
    "int sscanf(const char* buffer, const char* format, ...)",
    "int puts(const char* str)",
    "int putchar(int c)",
    "FILE* fopen(const char* filename, const char* mode)",
    "int fclose(FILE* stream)",
    "size_t fread(void* buffer, size_t size, size_t count, FILE* stream)",
    "size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream)",
    "int fseek(FILE* stream, long offset, int origin)",
    "long ftell(FILE* stream)",
    "char* fgets(char* str, int numChars, FILE* stream)",
    "int fputs(const char* str, FILE* stream)",
    "int fflush(FILE* stream)",
    "int open(const char* pathname, int flags, ...)",
    "int openat(int dirfd, const char* pathname, int flags, ...)",
    "ssize_t read(int fd, void* buf, size_t count)",
    "ssize_t write(int fd, const void* buf, size_t count)",
    "int close(int fd)",
    "off_t lseek(int fd, off_t offset, int whence)",
    "int unlink(const char* pathname)",
    "int rename(const char* oldpath, const char* newpath)",
    "int stat(const char* pathname, stat* statbuf)",
    "int mkdir(const char* pathname, mode_t mode)",
    "int chmod(const char* pathname, mode_t mode)",
    "int access(const char* pathname, int mode)",
    "ssize_t readlink(const char* pathname, char* buf, size_t bufsiz)",
    "DIR* opendir(const char* name)",
    "dirent* readdir(DIR* dirp)",
    "int closedir(DIR* dirp)",
    "char* getenv(const char* name)",
    "int setenv(const char* name, const char* value, int overwrite)",
    "pid_t fork()",
    "int execve(const char* pathname, char* const* argv, char* const* envp)",
    "int execvp(const char* file, char* const* argv)",
    "int system(const char* command)",
    "FILE* popen(const char* command, const char* type)",
    "int pclose(FILE* stream)",
    "pid_t waitpid(pid_t pid, int* wstatus, int options)",
    "int kill(pid_t pid, int sig)",
    "pid_t getpid()",
    "uid_t getuid()",
    "void exit(int status)",
    "void _exit(int status)",
    "void abort()",
    "int atexit(void* function)",
    "void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)",
    "int munmap(void* addr, size_t length)",
    "int mprotect(void* addr, size_t len, int prot)",
    "long ptrace(int request, pid_t pid, void* addr, void* data)",
    "void* dlopen(const char* filename, int flags)",
    "void* dlsym(void* handle, const char* symbol)",
    "int dlclose(void* handle)",
    "long syscall(long number, ...)",
    "int ioctl(int fd, unsigned long request, ...)",
    "int fcntl(int fd, int cmd, ...)",
    "int pipe(int* pipefd)",
    "int dup2(int oldfd, int newfd)",
    "int pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* start_routine, void* arg)",
    "int pthread_join(pthread_t thread, void** retval)",
    "int pthread_mutex_lock(pthread_mutex_t* mutex)",
    "int pthread_mutex_unlock(pthread_mutex_t* mutex)",
    "unsigned int sleep(unsigned int seconds)",
    "int usleep(useconds_t usec)",
    "time_t time(time_t* tloc)",
    "int rand()",
    "void srand(unsigned int seed)",
    "int atoi(const char* str)",
    "long strtol(const char* str, char** endptr, int base)",
    "unsigned long strtoul(const char* str, char** endptr, int base)",
    "void qsort(void* base, size_t num, size_t width, void* compare)",    // the window manager (user32), GDI, the themes
    "HWND GetDlgItem(HWND hDlg, int nIDDlgItem)",
    "BOOL EnableWindow(HWND hWnd, BOOL bEnable)",
    "LONG_PTR SetWindowLongPtrW(HWND hWnd, int nIndex, LONG_PTR dwNewLong)",
    "LONG_PTR GetWindowLongPtrW(HWND hWnd, int nIndex)",
    "LONG SetWindowLongW(HWND hWnd, int nIndex, LONG dwNewLong)",
    "LONG GetWindowLongW(HWND hWnd, int nIndex)",
    "UINT_PTR SetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)",
    "BOOL KillTimer(HWND hWnd, UINT_PTR uIDEvent)",
    "BOOL SetDlgItemTextW(HWND hDlg, int nIDDlgItem, LPCWSTR lpString)",
    "UINT GetDlgItemTextW(HWND hDlg, int nIDDlgItem, LPWSTR lpString, int cchMax)",
    "LRESULT SendDlgItemMessageW(HWND hDlg, int nIDDlgItem, UINT Msg, WPARAM wParam, LPARAM lParam)",
    "BOOL CheckDlgButton(HWND hDlg, int nIDButton, UINT uCheck)",
    "UINT IsDlgButtonChecked(HWND hDlg, int nIDButton)",
    "BOOL EndDialog(HWND hDlg, INT_PTR nResult)",
    "BOOL DestroyWindow(HWND hWnd)",
    "BOOL SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags)",
    "BOOL GetClientRect(HWND hWnd, LPRECT lpRect)",
    "BOOL GetWindowRect(HWND hWnd, LPRECT lpRect)",
    "int MapWindowPoints(HWND hWndFrom, HWND hWndTo, LPPOINT lpPoints, UINT cPoints)",
    "BOOL ScreenToClient(HWND hWnd, LPPOINT lpPoint)",
    "BOOL GetCursorPos(LPPOINT lpPoint)",
    "BOOL InvalidateRect(HWND hWnd, const RECT* lpRect, BOOL bErase)",
    "BOOL RedrawWindow(HWND hWnd, const RECT* lprcUpdate, HRGN hrgnUpdate, UINT flags)",
    "BOOL UpdateWindow(HWND hWnd)",
    "BOOL OffsetRect(LPRECT lprc, int dx, int dy)",
    "BOOL CopyRect(LPRECT lprcDst, const RECT* lprcSrc)",
    "HWND GetParent(HWND hWnd)",
    "HWND GetWindow(HWND hWnd, UINT uCmd)",
    "HWND GetDesktopWindow()",
    "HWND GetFocus()",
    "HWND SetFocus(HWND hWnd)",
    "BOOL SetForegroundWindow(HWND hWnd)",
    "BOOL IsWindow(HWND hWnd)",
    "BOOL IsWindowVisible(HWND hWnd)",
    "BOOL IsChild(HWND hWndParent, HWND hWnd)",
    "BOOL SetWindowTextW(HWND hWnd, LPCWSTR lpString)",
    "int GetWindowTextLengthW(HWND hWnd)",
    "int GetClassNameW(HWND hWnd, LPWSTR lpClassName, int nMaxCount)",
    "LRESULT DefWindowProcW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)",
    "ATOM RegisterClassW(const WNDCLASSW* lpWndClass)",
    "UINT RegisterWindowMessageW(LPCWSTR lpString)",
    "UINT RegisterClipboardFormatW(LPCWSTR lpszFormat)",
    "BOOL SetPropW(HWND hWnd, LPCWSTR lpString, HANDLE hData)",
    "HANDLE GetPropW(HWND hWnd, LPCWSTR lpString)",
    "HCURSOR SetCursor(HCURSOR hCursor)",
    "HCURSOR LoadCursorW(HINSTANCE hInstance, LPCWSTR lpCursorName)",
    "BOOL DestroyIcon(HICON hIcon)",
    "DWORD GetSysColor(int nIndex)",
    "BOOL SystemParametersInfoW(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)",
    "HMONITOR MonitorFromWindow(HWND hwnd, DWORD dwFlags)",
    "BOOL GetMonitorInfoW(HMONITOR hMonitor, LPMONITORINFO lpmi)",
    "BOOL MessageBeep(UINT uType)",
    "void NotifyWinEvent(DWORD event, HWND hwnd, LONG idObject, LONG idChild)",
    "DPI_AWARENESS_CONTEXT SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT dpiContext)",
    "int LoadStringW(HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax)",
    "LPWSTR CharUpperW(LPWSTR lpsz)",
    "LPWSTR CharNextW(LPCWSTR lpsz)",
    "HMENU CreatePopupMenu()",
    "BOOL DestroyMenu(HMENU hMenu)",
    "BOOL DeleteMenu(HMENU hMenu, UINT uPosition, UINT uFlags)",
    "BOOL InsertMenuW(HMENU hMenu, UINT uPosition, UINT uFlags, UINT_PTR uIDNewItem, LPCWSTR lpNewItem)",
    "BOOL InsertMenuItemW(HMENU hmenu, UINT item, BOOL fByPosition, LPCMENUITEMINFOW lpmi)",
    "BOOL GetMenuItemInfoW(HMENU hmenu, UINT item, BOOL fByPosition, LPMENUITEMINFOW lpmii)",
    "BOOL SetMenuItemInfoW(HMENU hmenu, UINT item, BOOL fByPosition, LPCMENUITEMINFOW lpmii)",
    "BOOL EnableMenuItem(HMENU hMenu, UINT uIDEnableItem, UINT uEnable)",
    "int GetMenuItemCount(HMENU hMenu)",
    "HMENU GetSubMenu(HMENU hMenu, int nPos)",
    "UINT GetMenuDefaultItem(HMENU hMenu, UINT fByPos, UINT gmdiFlags)",
    "int GetDeviceCaps(HDC hdc, int index)",
    "int GetObjectW(HANDLE h, int c, LPVOID pv)",
    "COLORREF SetTextColor(HDC hdc, COLORREF color)",
    "int SetBkMode(HDC hdc, int mode)",
    "HFONT CreateFontIndirectW(const LOGFONTW* lplf)",
    "DWORD GetLayout(HDC hdc)",
    "HTHEME OpenThemeData(HWND hwnd, LPCWSTR pszClassList)",
    "HRESULT CloseThemeData(HTHEME hTheme)",
    "HRESULT SetWindowTheme(HWND hwnd, LPCWSTR pszSubAppName, LPCWSTR pszSubIdList)",
    "HRESULT GetThemeColor(HTHEME hTheme, int iPartId, int iStateId, int iPropId, COLORREF* pColor)",
    "HRESULT DrawThemeBackground(HTHEME hTheme, HDC hdc, int iPartId, int iStateId, LPCRECT pRect, LPCRECT pClipRect)",
    // COM, the property system, the strings of WinRT
    "void CoTaskMemFree(LPVOID pv)",
    "LPVOID CoTaskMemAlloc(SIZE_T cb)",
    "LPVOID CoTaskMemRealloc(LPVOID pv, SIZE_T cb)",
    "void CoUninitialize()",
    "HRESULT CreateBindCtx(DWORD reserved, LPBC* ppbc)",
    "void ReleaseStgMedium(LPSTGMEDIUM pmedium)",
    "int StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, int cchMax)",
    "HRESULT CLSIDFromString(LPCOLESTR lpsz, LPCLSID pclsid)",
    "HRESULT CoGetInterfaceAndReleaseStream(LPSTREAM pStm, REFIID iid, LPVOID* ppv)",
    "HRESULT CoCreateFreeThreadedMarshaler(LPUNKNOWN punkOuter, LPUNKNOWN* ppunkMarshal)",
    "HRESULT PropVariantClear(PROPVARIANT* pvar)",
    "HRESULT PropVariantToStringAlloc(REFPROPVARIANT propvar, PWSTR* ppszOut)",
    "PCWSTR PropVariantToStringWithDefault(REFPROPVARIANT propvarIn, LPCWSTR pszDefault)",
    "int PropVariantCompareEx(REFPROPVARIANT propvar1, REFPROPVARIANT propvar2, PROPVAR_COMPARE_UNIT unit, PROPVAR_COMPARE_FLAGS flags)",
    "HRESULT PSCreateMemoryPropertyStore(REFIID riid, void** ppv)",
    "HRESULT PSGetPropertyDescription(REFPROPERTYKEY propkey, REFIID riid, void** ppv)",
    "HRESULT PSPropertyBag_ReadDWORD(IPropertyBag* propBag, LPCWSTR propName, DWORD* value)",
    "HRESULT PSPropertyBag_WriteDWORD(IPropertyBag* propBag, LPCWSTR propName, DWORD value)",
    "HRESULT PSPropertyBag_ReadBOOL(IPropertyBag* propBag, LPCWSTR propName, BOOL* value)",
    "HRESULT PSPropertyBag_WriteBOOL(IPropertyBag* propBag, LPCWSTR propName, BOOL value)",
    "HRESULT PSPropertyBag_ReadStr(IPropertyBag* propBag, LPCWSTR propName, LPWSTR value, int characterCount)",
    "HRESULT PSPropertyBag_ReadStrAlloc(IPropertyBag* propBag, LPCWSTR propName, PWSTR* value)",
    "HRESULT PSPropertyBag_WriteStr(IPropertyBag* propBag, LPCWSTR propName, LPCWSTR value)",
    "HRESULT PSPropertyBag_WriteInt(IPropertyBag* propBag, LPCWSTR propName, INT value)",
    "HRESULT QISearch(void* that, LPCQITAB pqit, REFIID riid, void** ppv)",
    "HRESULT IUnknown_QueryService(IUnknown* punk, REFGUID guidService, REFIID riid, void** ppvOut)",
    "HRESULT IUnknown_SetSite(IUnknown* punk, IUnknown* punkSite)",
    "void IUnknown_Set(IUnknown** ppunk, IUnknown* punk)",
    "HRESULT IUnknown_Exec(IUnknown* punk, const GUID* pguidCmdGroup, DWORD nCmdID, DWORD nCmdexecopt, VARIANT* pvarargIn, VARIANT* pvarargOut)",
    "HRESULT IStream_Read(IStream* pstm, void* pv, ULONG cb)",
    "HRESULT IStream_Write(IStream* pstm, const void* pv, ULONG cb)",
    "HRESULT IStream_Reset(IStream* pstm)",
    "HRESULT ConnectToConnectionPoint(IUnknown* punk, REFIID riidEvent, BOOL fConnect, IUnknown* punkTarget, DWORD* pdwCookie, IConnectionPoint** ppcpOut)",
    "IStream* SHCreateMemStream(const BYTE* pInit, UINT cbInit)",
    "HRESULT SHCreateStreamOnFileEx(LPCWSTR pszFile, DWORD grfMode, DWORD dwAttributes, BOOL fCreate, IStream* pstmTemplate, IStream** ppstm)",
    "HRESULT SHCoCreateInstance(PCWSTR pszCLSID, const CLSID* pclsid, IUnknown* pUnkOuter, REFIID riid, void** ppv)",
    "HRESULT RoGetActivationFactory(HSTRING activatableClassId, REFIID iid, void** factory)",
    "BOOL RoOriginateError(HRESULT error, HSTRING message)",
    "HRESULT WindowsCreateString(PCNZWCH sourceString, UINT32 length, HSTRING* string)",
    "HRESULT WindowsCreateStringReference(PCWSTR sourceString, UINT32 length, HSTRING_HEADER* hstringHeader, HSTRING* string)",
    "HRESULT WindowsDuplicateString(HSTRING string, HSTRING* newString)",
    "HRESULT WindowsDeleteString(HSTRING string)",
    "PCWSTR WindowsGetStringRawBuffer(HSTRING string, UINT32* length)",
    // the automation types (oleaut32: BSTR, VARIANT, SAFEARRAY; imported by ordinal), the LDAP client (wldap32: by ordinal), the
    // subclassing of comctl32 (by ordinal)
    "BSTR SysAllocString(const OLECHAR* psz)",
    "BSTR SysAllocStringLen(const OLECHAR* strIn, UINT ui)",
    "BSTR SysAllocStringByteLen(LPCSTR psz, UINT len)",
    "INT SysReAllocString(BSTR* pbstr, const OLECHAR* psz)",
    "void SysFreeString(BSTR bstrString)",
    "UINT SysStringLen(BSTR pbstr)",
    "UINT SysStringByteLen(BSTR bstr)",
    "void VariantInit(VARIANTARG* pvarg)",
    "HRESULT VariantClear(VARIANTARG* pvarg)",
    "HRESULT VariantCopy(VARIANTARG* pvargDest, const VARIANTARG* pvargSrc)",
    "HRESULT VariantChangeType(VARIANTARG* pvargDest, const VARIANTARG* pvarSrc, USHORT wFlags, VARTYPE vt)",
    "INT VariantTimeToSystemTime(DOUBLE vtime, LPSYSTEMTIME lpSystemTime)",
    "INT SystemTimeToVariantTime(LPSYSTEMTIME lpSystemTime, DOUBLE* pvtime)",
    "SAFEARRAY* SafeArrayCreate(VARTYPE vt, UINT cDims, SAFEARRAYBOUND* rgsabound)",
    "SAFEARRAY* SafeArrayCreateVector(VARTYPE vt, LONG lLbound, ULONG cElements)",
    "HRESULT SafeArrayDestroy(SAFEARRAY* psa)",
    "HRESULT SafeArrayPutElement(SAFEARRAY* psa, LONG* rgIndices, void* pv)",
    "HRESULT SafeArrayGetElement(SAFEARRAY* psa, LONG* rgIndices, void* pv)",
    "HRESULT SafeArrayGetLBound(SAFEARRAY* psa, UINT nDim, LONG* plLbound)",
    "HRESULT SafeArrayGetUBound(SAFEARRAY* psa, UINT nDim, LONG* plUbound)",
    "HRESULT SafeArrayAccessData(SAFEARRAY* psa, void** ppvData)",
    "HRESULT SafeArrayUnaccessData(SAFEARRAY* psa)",
    "HRESULT GetErrorInfo(ULONG dwReserved, IErrorInfo** pperrinfo)",
    "HRESULT SetErrorInfo(ULONG dwReserved, IErrorInfo* perrinfo)",
    "LDAP* ldap_initW(PWSTR HostName, ULONG PortNumber)",
    "LDAP* ldap_init(PSTR HostName, ULONG PortNumber)",
    "ULONG ldap_bind_sW(LDAP* ld, PWSTR dn, PWCHAR cred, ULONG method)",
    "ULONG ldap_unbind(LDAP* ld)",
    "ULONG ldap_set_optionW(LDAP* ld, int option, const void* invalue)",
    "ULONG ldap_get_optionW(LDAP* ld, int option, void* outvalue)",
    "ULONG ldap_search_sW(LDAP* ld, PWSTR base, ULONG scope, PWSTR filter, PZPWSTR attrs, ULONG attrsonly, PLDAPMessage* res)",
    "ULONG ldap_search_stW(LDAP* ld, PWSTR base, ULONG scope, PWSTR filter, PZPWSTR attrs, ULONG attrsonly, struct l_timeval* timeout, PLDAPMessage* res)",
    "ULONG ldap_msgfree(LDAPMessage* res)",
    "LDAPMessage* ldap_first_entry(LDAP* ld, LDAPMessage* res)",
    "LDAPMessage* ldap_next_entry(LDAP* ld, LDAPMessage* entry)",
    "PWCHAR* ldap_get_valuesW(LDAP* ld, LDAPMessage* entry, PWSTR attr)",
    "ULONG ldap_value_freeW(PWCHAR* vals)",
    "ULONG ldap_count_entries(LDAP* ld, LDAPMessage* res)",
    "ULONG LdapGetLastError()",
    "BOOL SetWindowSubclass(HWND hWnd, SUBCLASSPROC pfnSubclass, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)",
    "BOOL RemoveWindowSubclass(HWND hWnd, SUBCLASSPROC pfnSubclass, UINT_PTR uIdSubclass)",
    "LRESULT DefSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)",
    // the shell light-weight API (shlwapi, the paths)
    "int StrCmpW(LPCWSTR psz1, LPCWSTR psz2)",
    "int StrCmpIW(LPCWSTR psz1, LPCWSTR psz2)",
    "int StrCmpCW(LPCWSTR pszStr1, LPCWSTR pszStr2)",
    "int StrCmpICW(LPCWSTR pszStr1, LPCWSTR pszStr2)",
    "int StrCmpNICW(LPCWSTR pszStr1, LPCWSTR pszStr2, int nChar)",
    "PWSTR StrDupW(PCWSTR pszSrch)",
    "int StrToIntW(PCWSTR pszSrc)",
    "HRESULT SHStrDupW(LPCWSTR psz, LPWSTR* ppwsz)",
    "int SHAnsiToUnicode(PCSTR pszSrc, PWSTR pwszDst, int cwchBuf)",
    "int SHUnicodeToAnsi(PCWSTR pwszSrc, PSTR pszDst, int cchBuf)",
    "LSTATUS SHGetValueW(HKEY hkey, LPCWSTR pszSubKey, LPCWSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData)",
    "LSTATUS SHSetValueW(HKEY hkey, LPCWSTR pszSubKey, LPCWSTR pszValue, DWORD dwType, LPCVOID pvData, DWORD cbData)",
    "LSTATUS SHDeleteKeyW(HKEY hkey, LPCWSTR pszSubKey)",
    "LSTATUS SHQueryValueExW(HKEY hkey, LPCWSTR pszValue, DWORD* pdwReserved, DWORD* pdwType, void* pvData, DWORD* pcbData)",
    "LSTATUS SHRegGetValueFromHKCUHKLM(PCWSTR pwszKey, PCWSTR pwszValue, int srrfFlags, DWORD* pdwType, void* pvData, DWORD* pcbData)",
    "LSTATUS SHRegQueryUSValueW(HUSKEY hUSKey, LPCWSTR pszValue, DWORD* pdwType, void* pvData, DWORD* pcbData, BOOL fIgnoreHKCU, void* pvDefaultData, DWORD dwDefaultDataSize)",
    "DWORD SHExpandEnvironmentStringsW(LPCWSTR pszSrc, LPWSTR pszDst, DWORD cchSize)",
    "HRESULT SHLoadIndirectString(PCWSTR pszSource, PWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved)",
    "BOOL SHCreateThread(LPTHREAD_START_ROUTINE pfnThreadProc, void* pData, SHCT_FLAGS flags, LPTHREAD_START_ROUTINE pfnCallback)",
    "LPWSTR PathFindFileNameW(LPCWSTR pszPath)",
    "LPWSTR PathFindExtensionW(LPCWSTR pszPath)",
    "BOOL PathFileExistsW(LPCWSTR pszPath)",
    "BOOL PathRemoveFileSpecW(LPWSTR pszPath)",
    "BOOL PathIsUNCW(LPCWSTR pszPath)",
    "BOOL PathIsRootW(LPCWSTR pszPath)",
    "int PathGetDriveNumberW(LPCWSTR pszPath)",
    "int PathParseIconLocationW(LPWSTR pszIconFile)",
    "HRESULT PathCchCombine(PWSTR pszPathOut, size_t cchPathOut, PCWSTR pszPathIn, PCWSTR pszMore)",
    "HRESULT PathCchAppend(PWSTR pszPath, size_t cchPath, PCWSTR pszMore)",
    "HRESULT PathCchAddBackslash(PWSTR pszPath, size_t cchPath)",
    // the base API: the locks, the one time initializations, the times, the console, the threadpool, the security descriptors
    "void AcquireSRWLockExclusive(PSRWLOCK SRWLock)",
    "void ReleaseSRWLockExclusive(PSRWLOCK SRWLock)",
    "void AcquireSRWLockShared(PSRWLOCK SRWLock)",
    "void ReleaseSRWLockShared(PSRWLOCK SRWLock)",
    "BOOL InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags)",
    "void InitializeSListHead(PSLIST_HEADER ListHead)",
    "BOOL InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, LPVOID* lpContext)",
    "BOOL InitOnceComplete(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext)",
    "BOOL InitOnceExecuteOnce(PINIT_ONCE InitOnce, PINIT_ONCE_FN InitFn, PVOID Parameter, LPVOID* Context)",
    "BOOL ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount)",
    "BOOL ResetEvent(HANDLE hEvent)",
    "DWORD WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable)",
    "LPVOID TlsGetValue(DWORD dwTlsIndex)",
    "BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)",
    "BOOL TlsFree(DWORD dwTlsIndex)",
    "PTP_TIMER CreateThreadpoolTimer(PTP_TIMER_CALLBACK pfnti, PVOID pv, PTP_CALLBACK_ENVIRON pcbe)",
    "void SetThreadpoolTimer(PTP_TIMER pti, PFILETIME pftDueTime, DWORD msPeriod, DWORD msWindowLength)",
    "LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)",
    "LONG UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)",
    "void RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments)",
    "UINT SetErrorMode(UINT uMode)",
    "void DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList)",
    "int MulDiv(int nNumber, int nNumerator, int nDenominator)",
    "UINT GetACP()",
    "int CompareStringW(LCID Locale, DWORD dwCmpFlags, PCNZWCH lpString1, int cchCount1, PCNZWCH lpString2, int cchCount2)",
    "int CompareStringOrdinal(LPCWCH lpString1, int cchCount1, LPCWCH lpString2, int cchCount2, BOOL bIgnoreCase)",
    "int GetLocaleInfoW(LCID Locale, LCTYPE LCType, LPWSTR lpLCData, int cchData)",
    "LPVOID GlobalLock(HGLOBAL hMem)",
    "BOOL GlobalUnlock(HGLOBAL hMem)",
    "SIZE_T GlobalSize(HGLOBAL hMem)",
    "HLOCAL LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags)",
    "void GetSystemTime(LPSYSTEMTIME lpSystemTime)",
    "BOOL SystemTimeToFileTime(const SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime)",
    "BOOL FileTimeToSystemTime(const FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime)",
    "LONG CompareFileTime(const FILETIME* lpFileTime1, const FILETIME* lpFileTime2)",
    "HANDLE GetStdHandle(DWORD nStdHandle)",
    "BOOL SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode)",
    "DWORD GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart)",
    "BOOL GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)",
    "LSTATUS RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName)",
    "DWORD GetLengthSid(PSID pSid)",
    "BOOL GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID* pAce)",
    "DWORD GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR pSecurityDescriptor)",
    "ULONG EventWriteTransfer(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)",
    // the certificates (crypt32), CryptoAPI, CNG keys
    "HCERTSTORE CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void* pvPara)",
    "BOOL CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags)",
    "PCCERT_CONTEXT CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext)",
    "PCCERT_CONTEXT CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void* pvFindPara, PCCERT_CONTEXT pPrevCertContext)",
    "PCCERT_CONTEXT CertCreateCertificateContext(DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded)",
    "PCCERT_CONTEXT CertDuplicateCertificateContext(PCCERT_CONTEXT pCertContext)",
    "BOOL CertFreeCertificateContext(PCCERT_CONTEXT pCertContext)",
    "BOOL CertAddCertificateContextToStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext, DWORD dwAddDisposition, PCCERT_CONTEXT* ppStoreContext)",
    "BOOL CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void* pvData, DWORD* pcbData)",
    "BOOL CertSetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, DWORD dwFlags, const void* pvData)",
    "PCERT_EXTENSION CertFindExtension(LPCSTR pszObjId, DWORD cExtensions, CERT_EXTENSION* rgExtensions)",
    "BOOL CertCompareCertificateName(DWORD dwCertEncodingType, PCERT_NAME_BLOB pCertName1, PCERT_NAME_BLOB pCertName2)",
    "void CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT pChainContext)",
    "PCCRYPT_OID_INFO CryptFindOIDInfo(DWORD dwKeyType, void* pvKey, DWORD dwGroupId)",
    "BOOL CryptDecodeObject(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, void* pvStructInfo, DWORD* pcbStructInfo)",
    "BOOL CryptGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags)",
    "BOOL CryptGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY* phUserKey)",
    "BOOL NCryptIsKeyHandle(NCRYPT_KEY_HANDLE hKey)",
    "SECURITY_STATUS NCryptFreeObject(NCRYPT_HANDLE hObject)",
    // the kernel: the resources, the push locks, the mutexes, the events, the lookaside lists, the cache manager, the MDLs, the IRPs
    "BOOLEAN ExAcquireResourceExclusiveLite(PERESOURCE Resource, BOOLEAN Wait)",
    "BOOLEAN ExAcquireResourceSharedLite(PERESOURCE Resource, BOOLEAN Wait)",
    "void ExReleaseResourceLite(PERESOURCE Resource)",
    "BOOLEAN ExIsResourceAcquiredExclusiveLite(PERESOURCE Resource)",
    "ULONG ExIsResourceAcquiredSharedLite(PERESOURCE Resource)",
    "NTSTATUS ExInitializeResourceLite(PERESOURCE Resource)",
    "NTSTATUS ExDeleteResourceLite(PERESOURCE Resource)",
    "void ExAcquirePushLockExclusiveEx(PEX_PUSH_LOCK PushLock, ULONG Flags)",
    "void ExAcquirePushLockSharedEx(PEX_PUSH_LOCK PushLock, ULONG Flags)",
    "void ExReleasePushLockEx(PEX_PUSH_LOCK PushLock, ULONG Flags)",
    "void ExAcquireFastMutex(PFAST_MUTEX FastMutex)",
    "void ExReleaseFastMutex(PFAST_MUTEX FastMutex)",
    "void ExAcquireFastMutexUnsafe(PFAST_MUTEX FastMutex)",
    "void ExReleaseFastMutexUnsafe(PFAST_MUTEX FastMutex)",
    "NTSTATUS ExInitializeLookasideListEx(PLOOKASIDE_LIST_EX Lookaside, PALLOCATE_FUNCTION_EX Allocate, PFREE_FUNCTION_EX Free, POOL_TYPE PoolType, ULONG Flags, SIZE_T Size, ULONG Tag, USHORT Depth)",
    "PVOID ExAllocateFromLookasideListEx(PLOOKASIDE_LIST_EX Lookaside)",
    "void ExFreeToLookasideListEx(PLOOKASIDE_LIST_EX Lookaside, PVOID Entry)",
    "void ExFreeToNPagedLookasideList(PNPAGED_LOOKASIDE_LIST Lookaside, PVOID Entry)",
    "PVOID ExAllocatePool2(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag)",
    "void ExQueueWorkItem(PWORK_QUEUE_ITEM WorkItem, WORK_QUEUE_TYPE QueueType)",
    "NTSTATUS KeWaitForSingleObject(PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout)",
    "void KeAcquireGuardedMutex(PKGUARDED_MUTEX Mutex)",
    "void KeReleaseGuardedMutex(PKGUARDED_MUTEX Mutex)",
    "LONG KeReleaseMutex(PRKMUTEX Mutex, BOOLEAN Wait)",
    "void KeInitializeEvent(PRKEVENT Event, EVENT_TYPE Type, BOOLEAN State)",
    "LONG KeSetEvent(PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait)",
    "void KeClearEvent(PRKEVENT Event)",
    "void KeEnterCriticalRegion()",
    "void KeLeaveCriticalRegion()",
    "KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock)",
    "void KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql)",
    "void KeAcquireInStackQueuedSpinLock(PKSPIN_LOCK SpinLock, PKLOCK_QUEUE_HANDLE LockHandle)",
    "void KeReleaseInStackQueuedSpinLock(PKLOCK_QUEUE_HANDLE LockHandle)",
    "NTSTATUS KeDelayExecutionThread(KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval)",
    "LARGE_INTEGER KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency)",
    "ULONGLONG KeQueryUnbiasedInterruptTime()",
    "KIRQL KeGetCurrentIrql()",
    "NTSTATUS KeExpandKernelStackAndCalloutEx(PEXPAND_STACK_CALLOUT Callout, PVOID Parameter, SIZE_T Size, BOOLEAN Wait, PVOID Context)",
    "LONG_PTR ObfReferenceObject(PVOID Object)",
    "LONG_PTR ObfDereferenceObject(PVOID Object)",
    "PIRP IoGetTopLevelIrp()",
    "void IoSetTopLevelIrp(PIRP Irp)",
    "void IoFreeIrp(PIRP Irp)",
    "PMDL IoAllocateMdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp)",
    "void IoFreeMdl(PMDL Mdl)",
    "void IoGetStackLimits(PULONG_PTR LowLimit, PULONG_PTR HighLimit)",
    "PEPROCESS IoGetCurrentProcess()",
    "PGENERIC_MAPPING IoGetFileObjectGenericMapping()",
    "IO_PRIORITY_HINT IoGetIoPriorityHint(PIRP Irp)",
    "LPCGUID IoGetActivityIdThread()",
    "LPCGUID IoSetActivityIdThread(LPCGUID ActivityId)",
    "void IoClearActivityIdThread(LPCGUID OriginalId)",
    "NTSTATUS IoGetActivityIdIrp(PIRP Irp, LPGUID Guid)",
    "PVOID MmMapLockedPagesSpecifyCache(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)",
    "void MmUnmapLockedPages(PVOID BaseAddress, PMDL MemoryDescriptorList)",
    "BOOLEAN MmCanFileBeTruncated(PSECTION_OBJECT_POINTERS SectionPointer, PLARGE_INTEGER NewFileSize)",
    "BOOLEAN CcMapData(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG Flags, PVOID* Bcb, PVOID* Buffer)",
    "BOOLEAN CcPinMappedData(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG Flags, PVOID* Bcb)",
    "void CcUnpinData(PVOID Bcb)",
    "void CcSetDirtyPinnedData(PVOID BcbVoid, PLARGE_INTEGER Lsn)",
    "void CcFlushCache(PSECTION_OBJECT_POINTERS SectionObjectPointer, PLARGE_INTEGER FileOffset, ULONG Length, PIO_STATUS_BLOCK IoStatus)",
    "BOOLEAN CcUninitializeCacheMap(PFILE_OBJECT FileObject, PLARGE_INTEGER TruncateSize, PCACHE_UNINITIALIZE_EVENT UninitializeEvent)",
    "BOOLEAN FsRtlIsNtstatusExpected(NTSTATUS Exception)",
    "BOOLEAN FsRtlOplockIsFastIoPossible(POPLOCK Oplock)",
    "BOOLEAN FsRtlAreNamesEqual(PCUNICODE_STRING ConstantNameA, PCUNICODE_STRING ConstantNameB, BOOLEAN IgnoreCase, PCWCH UpcaseTable)",
    "BOOLEAN FsRtlLookupBaseMcbEntry(PBASE_MCB Mcb, LONGLONG Vbn, PLONGLONG Lbn, PLONGLONG SectorCountFromLbn, PLONGLONG StartingLbn, PLONGLONG SectorCountFromStartingLbn, PULONG StartingIndex)",
    "void FsRtlUninitializeBaseMcb(PBASE_MCB Mcb)",
    "void SeCaptureSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)",
    "void SeReleaseSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)",
    "void SeUnlockSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)",
    "PCHAR PsGetProcessImageFileName(PEPROCESS Process)",
    "void RtlFreeUnicodeString(PUNICODE_STRING UnicodeString)",
    "NTSTATUS RtlAppendUnicodeStringToString(PUNICODE_STRING Destination, PCUNICODE_STRING Source)",
    "NTSTATUS RtlAppendUnicodeToString(PUNICODE_STRING Destination, PCWSTR Source)",
    "SIZE_T RtlCompareMemory(const void* Source1, const void* Source2, SIZE_T Length)",
    "void RtlInitializeBitMap(PRTL_BITMAP BitMapHeader, PULONG BitMapBuffer, ULONG SizeOfBitMap)",
    "BOOLEAN RtlDeleteElementGenericTableAvl(PRTL_AVL_TABLE Table, PVOID Buffer)",
    "NTSTATUS EtwEventWriteTransfer(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)",
    "NTSTATUS EtwEventActivityIdControl(ULONG ControlCode, LPGUID ActivityId)",
    "ULONG DbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, ...)",
    // the C run-time: the wide strings, the file descriptors (the _o_ forwarders of the UCRT: FindApiPrototype)
    "wchar_t* wcschr(const wchar_t* str, wchar_t c)",
    "wchar_t* wcsrchr(const wchar_t* str, wchar_t c)",
    "wchar_t* wcsstr(const wchar_t* str, const wchar_t* strSearch)",
    "size_t wcscspn(const wchar_t* str, const wchar_t* strCharSet)",
    "int _wcsnicmp(const wchar_t* string1, const wchar_t* string2, size_t count)",
    "long wcstol(const wchar_t* strSource, wchar_t** endptr, int base)",
    "int _wtoi(const wchar_t* str)",
    "int iswdigit(wint_t c)",
    "int iswspace(wint_t c)",
    "wint_t towupper(wint_t c)",
    "int fwprintf(FILE* stream, const wchar_t* format, ...)",
    "int* _errno()",
    "intptr_t _get_osfhandle(int fd)",
    "int _close(int fd)",
    "int _set_new_mode(int newhandlermode)",
    "void longjmp(jmp_buf env, int value)",
    "int setjmp(jmp_buf env)",
    // the GNU C library: the checked functions, the locales, the users
    "int* __errno_location()",
    "void __stack_chk_fail()",
    "void __assert_fail(const char* assertion, const char* file, unsigned int line, const char* function)",
    "void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen)",
    "void* __memmove_chk(void* dest, const void* src, size_t len, size_t destlen)",
    "char* __strcpy_chk(char* dest, const char* src, size_t destlen)",
    "int __printf_chk(int flag, const char* format, ...)",
    "int __snprintf_chk(char* s, size_t maxlen, int flag, size_t slen, const char* format, ...)",
    "size_t __fpending(FILE* stream)",
    "size_t __ctype_get_mb_cur_max()",
    "int isatty(int fd)",
    "size_t strspn(const char* s, const char* accept)",
    "size_t strcspn(const char* s, const char* reject)",
    "size_t strnlen(const char* s, size_t maxlen)",
    "int strcoll(const char* s1, const char* s2)",
    "void* rawmemchr(const void* s, int c)",
    "void* mempcpy(void* dest, const void* src, size_t n)",
    "char* strerror_r(int errnum, char* buf, size_t buflen)",
    "int fputs_unlocked(const char* s, FILE* stream)",
    "size_t fwrite_unlocked(const void* ptr, size_t size, size_t n, FILE* stream)",
    "char* getcwd(char* buf, size_t size)",
    "int dirfd(DIR* dirp)",
    "int statx(int dirfd, const char* pathname, int flags, unsigned int mask, struct statx* statxbuf)",
    "int fnmatch(const char* pattern, const char* string, int flags)",
    "int getopt_long(int argc, char* const* argv, const char* optstring, const struct option* longopts, int* longindex)",
    "struct passwd* getpwuid(uid_t uid)",
    "struct group* getgrgid(gid_t gid)",
    "int unsetenv(const char* name)",
    "char* setlocale(int category, const char* locale)",
    "locale_t uselocale(locale_t newloc)",
    "char* nl_langinfo(nl_item item)",
    "char* textdomain(const char* domainname)",
    "char* bindtextdomain(const char* domainname, const char* dirname)",
    "char* dcgettext(const char* domainname, const char* msgid, int category)",
    "int wcwidth(wchar_t c)",
    "int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)",
    "int sigprocmask(int how, const sigset_t* set, sigset_t* oldset)",
    "int sigemptyset(sigset_t* set)",
    "sighandler_t signal(int signum, sighandler_t handler)",
    "int clock_gettime(clockid_t clockid, struct timespec* tp)",
    "struct tm* gmtime_r(const time_t* timep, struct tm* result)",
    "time_t mktime(struct tm* tm)",
    "size_t strftime(char* s, size_t max, const char* format, const struct tm* tm)",
    "void tzset()",
    "pid_t tcgetpgrp(int fd)",
    // the shell: the item ID lists, the shell items and folders, the notifications, the known folders, the property bags and variants,
    // COM
    "void ILFree(PIDLIST_RELATIVE pidl)",
    "HRESULT SHGetIDListFromObject(IUnknown* punk, PIDLIST_ABSOLUTE* ppidl)",
    "HRESULT SHCreateItemFromIDList(PCIDLIST_ABSOLUTE pidl, REFIID riid, void** ppv)",
    "void SHChangeNotify(LONG wEventId, UINT uFlags, LPCVOID dwItem1, LPCVOID dwItem2)",
    "HRESULT SHBindToObject(IShellFolder* psf, PCUIDLIST_RELATIVE pidl, IBindCtx* pbc, REFIID riid, void** ppv)",
    "DWORD SHRestricted(RESTRICTIONS rest)",
    "PIDLIST_RELATIVE ILClone(PCUIDLIST_RELATIVE pidl)",
    "PCWSTR StrChrW(PCWSTR pszStart, WCHAR wMatch)",
    "HRESULT SHParseDisplayName(PCWSTR pszName, IBindCtx* pbc, PIDLIST_ABSOLUTE* ppidl, SFGAOF sfgaoIn, SFGAOF* psfgaoOut)",
    "PUITEMID_CHILD ILFindLastID(PCUIDLIST_RELATIVE pidl)",
    "int ShellMessageBoxW(HINSTANCE hAppInst, HWND hWnd, LPCWSTR lpcText, LPCWSTR lpcTitle, UINT fuStyle, ...)",
    "BOOL ILIsEqual(PCIDLIST_ABSOLUTE pidl1, PCIDLIST_ABSOLUTE pidl2)",
    "HRESULT SHBindToParent(PCIDLIST_ABSOLUTE pidl, REFIID riid, void** ppv, PCUITEMID_CHILD* ppidlLast)",
    "HRESULT IUnknown_GetWindow(IUnknown* punk, HWND* phwnd)",
    "HRESULT SHGetKnownFolderIDList(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PIDLIST_ABSOLUTE* ppidl)",
    "HRESULT SHCreateItemFromParsingName(PCWSTR pszPath, IBindCtx* pbc, REFIID riid, void** ppv)",
    "PITEMID_CHILD ILCloneFirst(PCUIDLIST_RELATIVE pidl)",
    "void SHGetSetSettings(LPSHELLSTATE lpss, DWORD dwMask, BOOL bSet)",
    "HRESULT SHCreateItemWithParent(PCIDLIST_ABSOLUTE pidlParent, IShellFolder* psfParent, PCUITEMID_CHILD pidl, REFIID riid, void** ppvItem)",
    "HRESULT SHGetKnownFolderItem(REFKNOWNFOLDERID rfid, KNOWN_FOLDER_FLAG flags, HANDLE hToken, REFIID riid, void** ppv)",
    "UINT ILGetSize(PCUIDLIST_RELATIVE pidl)",
    "PCWSTR StrStrIW(PCWSTR pszFirst, PCWSTR pszSrch)",
    "int Shell_GetCachedImageIndexW(LPCWSTR pszIconPath, int iIconIndex, UINT uIconFlags)",
    "BOOL ILIsParent(PCIDLIST_ABSOLUTE pidl1, PCIDLIST_ABSOLUTE pidl2, BOOL fImmediate)",
    "BOOL ILRemoveLastID(PUIDLIST_RELATIVE pidl)",
    "DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW* psfi, UINT cbFileInfo, UINT uFlags)",
    "PIDLIST_ABSOLUTE ILCombine(PCIDLIST_ABSOLUTE pidl1, PCUIDLIST_RELATIVE pidl2)",
    "BOOL SHGetPathFromIDListW(PCIDLIST_ABSOLUTE pidl, LPWSTR pszPath)",
    "HRESULT SHCreateDefaultContextMenu(const DEFCONTEXTMENU* pdcm, REFIID riid, void** ppv)",
    "HRESULT SHGetItemFromObject(IUnknown* punk, REFIID riid, void** ppv)",
    "HRESULT SHCLSIDFromString(PCWSTR psz, CLSID* pclsid)",
    "UINT Shell_MergeMenus(HMENU hmDst, HMENU hmSrc, UINT uInsert, UINT uIDAdjust, UINT uIDAdjustMax, ULONG uFlags)",
    "int StrCmpNIW(PCWSTR psz1, PCWSTR psz2, int nChar)",
    "HRESULT SHCreateShellItemArrayFromShellItem(IShellItem* psi, REFIID riid, void** ppv)",
    "int StrCmpNW(PCWSTR psz1, PCWSTR psz2, int nChar)",
    "LSTATUS SHRegGetValueW(HKEY hkey, LPCWSTR pszSubKey, LPCWSTR pszValue, SRRF srrfFlags, DWORD* pdwType, void* pvData, DWORD* pcbData)",
    "HRESULT SHGetSpecialFolderLocation(HWND hwnd, int csidl, PIDLIST_ABSOLUTE* ppidl)",
    "HRESULT SHBindToFolderIDListParent(IShellFolder* psfRoot, PCUIDLIST_RELATIVE pidl, REFIID riid, void** ppv, PCUITEMID_CHILD* ppidlLast)",
    "HRESULT SHCreateShellFolderView(const SFV_CREATE* pcsfv, IShellView** ppsv)",
    "HRESULT PSGetPropertyDescriptionListFromString(LPCWSTR pszPropList, REFIID riid, void** ppv)",
    "HRESULT CoWaitForMultipleHandles(DWORD dwFlags, DWORD dwTimeout, ULONG cHandles, LPHANDLE pHandles, LPDWORD lpdwindex)",
    "UINT DragQueryFileW(HDROP hDrop, UINT iFile, LPWSTR lpszFile, UINT cch)",
    "HRESULT SHGetImageList(int iImageList, REFIID riid, void** ppvObj)",
    "HRESULT PropVariantToUInt32(REFPROPVARIANT propvarIn, ULONG* pulRet)",
    "BOOL PathUnquoteSpacesW(LPWSTR lpsz)",
    "HRESULT RoGetAgileReference(enum AgileReferenceOptions options, REFIID riid, IUnknown* pUnk, IAgileReference** ppAgileReference)",
    "WCHAR SHStripMneumonicW(LPWSTR pszMenu)",
    "HRESULT SHGetViewStatePropertyBag(PCIDLIST_ABSOLUTE pidl, PCWSTR pszBagName, DWORD dwFlags, REFIID riid, void** ppv)",
    "HRESULT SHCreateDataObject(PCIDLIST_ABSOLUTE pidlFolder, UINT cidl, PCUITEMID_CHILD_ARRAY apidl, IDataObject* pdtInner, REFIID riid, void** ppv)",
    "HRESULT CoMarshalInterThreadInterfaceInStream(REFIID riid, LPUNKNOWN pUnk, LPSTREAM* ppStm)",
    "HRESULT PSPropertyBag_ReadGUID(IPropertyBag* propBag, LPCWSTR propName, GUID* value)",
    "HRESULT IUnknown_GetSite(IUnknown* punk, REFIID riid, void** ppv)",
    "HRESULT DevGetObjectProperties(DEV_OBJECT_TYPE ObjectType, PCWSTR pszObjectId, ULONG QueryFlags, ULONG cRequestedProperties, const DEVPROPCOMPKEY* pRequestedProperties, PULONG pcPropertyCount, const DEVPROPERTY** ppProperties)",
    "HRESULT SHCreateItemInKnownFolder(REFKNOWNFOLDERID kfid, DWORD dwKFFlags, PCWSTR pszItem, REFIID riid, void** ppv)",
    "BOOL PathIsURLW(LPCWSTR pszPath)",
    "HRESULT PathAllocCombine(PCWSTR pszPathIn, PCWSTR pszMore, ULONG dwFlags, PWSTR* ppszPathOut)",
    "HRESULT SHILCreateFromPath(PCWSTR pszPath, PIDLIST_ABSOLUTE* ppidl, DWORD* rgfInOut)",
    "PWSTR StrFormatByteSizeW(LONGLONG qdw, PWSTR pszBuf, UINT cchBuf)",
    "void DevFreeObjectProperties(ULONG cPropertyCount, const DEVPROPERTY* pProperties)",
    "HRESULT CoAllowSetForegroundWindow(IUnknown* pUnk, LPVOID lpvReserved)",
    "LSTATUS SHDeleteValueW(HKEY hkey, LPCWSTR pszSubKey, LPCWSTR pszValue)",
    "HRESULT CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM* ppstm)",
    "HRESULT SHCreateShellItemArrayFromIDLists(UINT cidl, PCIDLIST_ABSOLUTE_ARRAY rgpidl, IShellItemArray** ppsiItemArray)",
    "BOOL SHChangeNotifyDeregister(ULONG ulID)",
    "BOOL PathQuoteSpacesW(LPWSTR lpsz)",
    "BOOL Shell_GetImageLists(HIMAGELIST* phiml, HIMAGELIST* phimlSmall)",
    "BOOL PathIsFileSpecW(LPCWSTR pszPath)",
    "HRESULT StringFromCLSID(REFCLSID rclsid, LPOLESTR* lplpsz)",
    "HRESULT SHGetThreadRef(IUnknown** ppunk)",
    "HRESULT PSPropertyBag_ReadInt(IPropertyBag* propBag, LPCWSTR propName, INT* value)",
    "HRESULT CoGetApartmentType(APTTYPE* pAptType, APTTYPEQUALIFIER* pAptQualifier)",
    "PUIDLIST_RELATIVE ILFindChild(PIDLIST_ABSOLUTE pidlParent, PCIDLIST_ABSOLUTE pidlChild)",
    "HRESULT SHGetNameFromIDList(PCIDLIST_ABSOLUTE pidl, SIGDN sigdnName, PWSTR* ppszName)",
    "IStream* SHOpenRegStream2W(HKEY hkey, LPCWSTR pszSubkey, LPCWSTR pszValue, DWORD grfMode)",
    "void SHChangeNotifyRegisterThread(SCNRT_STATUS status)",
    "void PathRemoveExtensionW(LPWSTR pszPath)",
    "BOOL VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen)",
    "HRESULT SHGetItemFromDataObject(IDataObject* pdtobj, DATAOBJ_GET_ITEM_FLAGS dwFlags, REFIID riid, void** ppv)",
    "HRESULT PropVariantCopy(PROPVARIANT* pvarDest, const PROPVARIANT* pvarSrc)",
    "HRESULT PropVariantToBoolean(REFPROPVARIANT propvarIn, BOOL* pfRet)",
    "HRESULT AssocQueryStringW(ASSOCF flags, ASSOCSTR str, LPCWSTR pszAssoc, LPCWSTR pszExtra, LPWSTR pszOut, DWORD* pcchOut)",
    "HRESULT PropVariantChangeType(PROPVARIANT* ppropvarDest, REFPROPVARIANT propvarSrc, PROPVAR_CHANGE_FLAGS flags, VARTYPE vt)",
    "HRESULT OleInitialize(LPVOID pvReserved)",
    "HRESULT SHGetStockIconInfo(SHSTOCKICONID siid, UINT uFlags, SHSTOCKICONINFO* psii)",
    "BOOL StrTrimW(PWSTR psz, PCWSTR pszTrimChars)",
    "BOOL Shell_NotifyIconW(DWORD dwMessage, PNOTIFYICONDATAW lpData)",
    "void OleUninitialize()",
    "HRESULT PSPropertyBag_Delete(IPropertyBag* propBag, LPCWSTR propName)",
    "LPCWSTR PathGetArgsW(LPCWSTR pszPath)",
    "void PathRemoveArgsW(LPWSTR pszPath)",
    "int StrCmpICA(LPCSTR pszStr1, LPCSTR pszStr2)",
    "void PathRemoveBlanksW(LPWSTR pszPath)",
    "ULONG SHChangeNotifyRegister(HWND hwnd, int fSources, LONG fEvents, UINT wMsg, int cEntries, const SHChangeNotifyEntry* pshcne)",
    "LRESULT LresultFromObject(REFIID riid, WPARAM wParam, LPUNKNOWN punk)",
    "HRESULT VariantToString(REFVARIANT varIn, PWSTR pszBuf, UINT cchBuf)",
    "HRESULT PSGetPropertyFromPropertyStorage(PCUSERIALIZEDPROPSTORAGE psps, DWORD cb, REFPROPERTYKEY rpkey, PROPVARIANT* ppropvar)",
    "HRESULT CoInitialize(LPVOID pvReserved)",
    "HRESULT CoCreateGuid(GUID* pguid)",
    "HRESULT SHGetFolderPathEx(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, LPWSTR pszPath, UINT cchPath)",
    // the windows, the menus, the painting (user32, gdi32, uxtheme, dwmapi, the image lists of comctl32)
    "HANDLE RemovePropW(HWND hWnd, LPCWSTR lpString)",
    "BOOL StretchBlt(HDC hdcDest, int xDest, int yDest, int wDest, int hDest, HDC hdcSrc, int xSrc, int ySrc, int wSrc, int hSrc, DWORD rop)",
    "int GetMenuPosFromID(HMENU hmenu, UINT id)",
    "DWORD CommDlgExtendedError()",
    "HWND GetAncestor(HWND hwnd, UINT gaFlags)",
    "ATOM RegisterClassExW(const WNDCLASSEXW* lpwcx)",
    "BOOL GetTextExtentPoint32W(HDC hdc, LPCWSTR lpString, int c, LPSIZE psizl)",
    "HBRUSH CreateSolidBrush(COLORREF color)",
    "int FillRect(HDC hDC, const RECT* lprc, HBRUSH hbr)",
    "UINT GetMenuItemID(HMENU hMenu, int nPos)",
    "HWND GetShellWindow()",
    "BOOL DrawEdge(HDC hdc, LPRECT qrc, UINT edge, UINT grfFlags)",
    "DWORD CheckMenuItem(HMENU hMenu, UINT uIDCheckItem, UINT uCheck)",
    "void PostQuitMessage(int nExitCode)",
    "BOOL EqualRect(const RECT* lprc1, const RECT* lprc2)",
    "BOOL InflateRect(LPRECT lprc, int dx, int dy)",
    "HBRUSH GetSysColorBrush(int nIndex)",
    "HDC BeginPaint(HWND hWnd, LPPAINTSTRUCT lpPaint)",
    "BOOL EndPaint(HWND hWnd, const PAINTSTRUCT* lpPaint)",
    "HANDLE LoadImageW(HINSTANCE hInst, LPCWSTR name, UINT type, int cx, int cy, UINT fuLoad)",
    "UINT GetDoubleClickTime()",
    "HGDIOBJ GetStockObject(int i)",
    "BOOL IntersectRect(LPRECT lprcDst, const RECT* lprcSrc1, const RECT* lprcSrc2)",
    "HRESULT DwmSetWindowAttribute(HWND hwnd, DWORD dwAttribute, LPCVOID pvAttribute, DWORD cbAttribute)",
    "BOOL GetTextMetricsW(HDC hdc, LPTEXTMETRICW lptm)",
    "BOOL PatBlt(HDC hdc, int x, int y, int w, int h, DWORD rop)",
    "int GetClipBox(HDC hdc, LPRECT lprect)",
    "LRESULT CallWindowProcW(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)",
    "BOOL AppendMenuW(HMENU hMenu, UINT uFlags, UINT_PTR uIDNewItem, LPCWSTR lpNewItem)",
    "HWND GetCapture()",
    "BOOL MoveToEx(HDC hdc, int x, int y, LPPOINT lppt)",
    "BOOL LineTo(HDC hdc, int x, int y)",
    "DWORD CharLowerBuffW(LPWSTR lpsz, DWORD cchLength)",
    "BOOL SubtractRect(LPRECT lprcDst, const RECT* lprcSrc1, const RECT* lprcSrc2)",
    "HRESULT GetThemePartSize(HTHEME hTheme, HDC hdc, int iPartId, int iStateId, LPCRECT prc, enum THEMESIZE eSize, SIZE* psz)",
    "BOOL MoveWindow(HWND hWnd, int X, int Y, int nWidth, int nHeight, BOOL bRepaint)",
    "UINT GetDpiForWindow(HWND hwnd)",
    "LPWSTR CharLowerW(LPWSTR lpsz)",
    "int ImageList_ReplaceIcon(HIMAGELIST himl, int i, HICON hicon)",
    "BOOL IsDialogMessageW(HWND hDlg, LPMSG lpMsg)",
    "HACCEL LoadAcceleratorsW(HINSTANCE hInstance, LPCWSTR lpTableName)",
    "BOOL TextOutW(HDC hdc, int x, int y, LPCWSTR lpString, int c)",
    "BOOL ImageList_Destroy(HIMAGELIST himl)",
    "HICON LoadIconW(HINSTANCE hInstance, LPCWSTR lpIconName)",
    "BOOL IsIconic(HWND hWnd)",
    "int TranslateAcceleratorW(HWND hWnd, HACCEL hAccTable, LPMSG lpMsg)",
    "BOOL GetWindowPlacement(HWND hWnd, WINDOWPLACEMENT* lpwndpl)",
    "HMENU GetSystemMenu(HWND hWnd, BOOL bRevert)",
    "HDC CreateDCW(LPCWSTR pwszDriver, LPCWSTR pwszDevice, LPCWSTR pszPort, const DEVMODEW* pdm)",
    "int EndPage(HDC hdc)",
    "COLORREF SetBkColor(HDC hdc, COLORREF color)",
    "BOOL SetMenuDefaultItem(HMENU hMenu, UINT uItem, UINT fByPos)",
    "BOOL SetRect(LPRECT lprc, int xLeft, int yTop, int xRight, int yBottom)",
    "DWORD SetLayout(HDC hdc, DWORD l)",
    "BOOL ExtTextOutW(HDC hdc, int x, int y, UINT options, const RECT* lprect, LPCWSTR lpString, UINT c, const INT* lpDx)",
    "HWND SetParent(HWND hWndChild, HWND hWndNewParent)",
    "BOOL SetViewportOrgEx(HDC hdc, int x, int y, LPPOINT lppt)",
    "BOOL SetRectEmpty(LPRECT lprc)",
    "UINT SetTextAlign(HDC hdc, UINT align)",
    "BOOL SendNotifyMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)",
    "int SetMapMode(HDC hdc, int iMode)",
    "BOOL PtInRect(const RECT* lprc, POINT pt)",
    "HMONITOR MonitorFromPoint(POINT pt, DWORD dwFlags)",
    "int DrawText%(HDC hdc, LPCTSTR lpchText, int cchText, LPRECT lprc, UINT format)",
    "HBITMAP CreateDIBSection(HDC hdc, const BITMAPINFO* pbmi, UINT usage, void** ppvBits, HANDLE hSection, DWORD offset)",
    "BOOL GdiAlphaBlend(HDC hdcDest, int xoriginDest, int yoriginDest, int wDest, int hDest, HDC hdcSrc, int xoriginSrc, int yoriginSrc, int wSrc, int hSrc, BLENDFUNCTION ftn)",
    // the kernel: the file system run-time library (the MCBs, the oplocks, the extra create parameters), the cache manager, the generic
    // tables, the bitmaps, the IRPs and the MDLs, the SIDs, CLFS, ETW
    "BOOLEAN ClfsLsnLess(const CLFS_LSN* plsn1, const CLFS_LSN* plsn2)",
    "BOOLEAN ClfsLsnGreater(const CLFS_LSN* plsn1, const CLFS_LSN* plsn2)",
    "BOOLEAN ClfsLsnNull(const CLFS_LSN* plsn)",
    "BOOLEAN ClfsLsnInvalid(const CLFS_LSN* plsn)",
    "void ProbeForRead(const void* Address, SIZE_T Length, ULONG Alignment)",
    "BOOLEAN EtwEventEnabled(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor)",
    "void MmBuildMdlForNonPagedPool(PMDL MemoryDescriptorList)",
    "void IofCompleteRequest(PIRP Irp, CCHAR PriorityBoost)",
    "NTSTATUS FsRtlCheckOplock(POPLOCK Oplock, PIRP Irp, PVOID Context, POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine, POPLOCK_FS_PREPOST_IRP PostIrpRoutine)",
    "PVOID RtlEnumerateGenericTableAvl(PRTL_AVL_TABLE Table, BOOLEAN Restart)",
    "void RtlSetBits(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG NumberToSet)",
    "NTSTATUS FsRtlCheckOplockEx(POPLOCK Oplock, PIRP Irp, ULONG Flags, PVOID Context, POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine, POPLOCK_FS_PREPOST_IRP PostIrpRoutine)",
    "BOOLEAN FsRtlGetNextBaseMcbEntry(PBASE_MCB Mcb, ULONG RunIndex, PLONGLONG Vbn, PLONGLONG Lbn, PLONGLONG SectorCount)",
    "BOOLEAN MmFlushImageSection(PSECTION_OBJECT_POINTERS SectionObjectPointer, MMFLUSH_TYPE FlushType)",
    "void MmUnlockPages(PMDL MemoryDescriptorList)",
    "PVOID RtlInsertElementGenericTableAvl(PRTL_AVL_TABLE Table, PVOID Buffer, CLONG BufferSize, PBOOLEAN NewElement)",
    "void KeInitializeGuardedMutex(PKGUARDED_MUTEX Mutex)",
    "BOOLEAN IoIsOperationSynchronous(PIRP Irp)",
    "void ExConvertExclusiveToSharedLite(PERESOURCE Resource)",
    "BOOLEAN FsRtlInitializeBaseMcbEx(PBASE_MCB Mcb, POOL_TYPE PoolType, USHORT Flags)",
    "void ObDereferenceObjectDeferDelete(PVOID Object)",
    "ULONG RtlLengthSid(PSID Sid)",
    "PVOID RtlLookupElementGenericTableAvl(PRTL_AVL_TABLE Table, PVOID Buffer)",
    "void ProbeForWrite(void* Address, SIZE_T Length, ULONG Alignment)",
    "NTSTATUS FsRtlNormalizeNtstatus(NTSTATUS Exception, NTSTATUS GenericException)",
    "ULONG FsRtlNumberOfRunsInBaseMcb(PBASE_MCB Mcb)",
    "BOOLEAN RtlIsGenericTableEmptyAvl(PRTL_AVL_TABLE Table)",
    "void RtlCopyUnicodeString(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString)",
    "NTSTATUS FsRtlNotifyVolumeEvent(PFILE_OBJECT FileObject, ULONG EventCode)",
    "NTSTATUS ClfsTerminateReadLog(PVOID pvCursorContext)",
    "NTSTATUS RtlDuplicateUnicodeString(ULONG Flags, PCUNICODE_STRING StringIn, PUNICODE_STRING StringOut)",
    "void IoBuildPartialMdl(PMDL SourceMdl, PMDL TargetMdl, PVOID VirtualAddress, ULONG Length)",
    "BOOLEAN FsRtlRemoveBaseMcbEntry(PBASE_MCB Mcb, LONGLONG Vbn, LONGLONG SectorCount)",
    "KPRIORITY KeSetPriorityThread(PKTHREAD Thread, KPRIORITY Priority)",
    "NTSTATUS EtwWriteTransfer(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)",
    "void RtlInitializeGenericTableAvl(PRTL_AVL_TABLE Table, PRTL_AVL_COMPARE_ROUTINE CompareRoutine, PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine, PRTL_AVL_FREE_ROUTINE FreeRoutine, PVOID TableContext)",
    "ULONG RtlFindClearBits(PRTL_BITMAP BitMapHeader, ULONG NumberToFind, ULONG HintIndex)",
    "NTSTATUS ClfsMgmtInstallPolicy(PLOG_FILE_OBJECT LogFile, PCLFS_MGMT_POLICY Policy, ULONG PolicyLength)",
    "BOOLEAN FsRtlIsTotalDeviceFailure(NTSTATUS Status)",
    "NTSTATUS IofCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)",
    "MM_MDL_PAGE_CONTENTS_STATE MmMdlPageContentsState(PMDL MemoryDescriptorList, MM_MDL_PAGE_CONTENTS_STATE State)",
    "BOOLEAN ClfsLsnEqual(const CLFS_LSN* plsn1, const CLFS_LSN* plsn2)",
    "BOOLEAN CcPinRead(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG Flags, PVOID* Bcb, PVOID* Buffer)",
    "void SeLockSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)",
    "BOOLEAN CcPreparePinWrite(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Zero, ULONG Flags, PVOID* Bcb, PVOID* Buffer)",
    "PVOID ExAllocateFromNPagedLookasideList(PNPAGED_LOOKASIDE_LIST Lookaside)",
    "NTSTATUS ClfsReserveAndAppendLog(PVOID pvMarshalContext, PCLFS_WRITE_ENTRY rgWriteEntries, ULONG cWriteEntries, PCLFS_LSN plsnUndoNext, PCLFS_LSN plsnPrevious, ULONG cReserveRecords, PLONGLONG rgcbReservation, ULONG fFlags, PCLFS_LSN plsn)",
    "void RtlInitAnsiString(PANSI_STRING DestinationString, PCSZ SourceString)",
    "LONG KeResetEvent(PRKEVENT Event)",
    "NTSTATUS EtwUnregister(REGHANDLE RegHandle)",
    "NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation)",
    "BOOLEAN FsRtlIsNonEmptyDirectoryReparsePointAllowed(ULONG ReparseTag)",
    "NTSTATUS RtlCheckRegistryKey(ULONG RelativeTo, PWSTR Path)",
    "void ExReleaseResourceForThreadLite(PERESOURCE Resource, ERESOURCE_THREAD ResourceThreadId)",
    "BOOLEAN CcCopyReadEx(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, PVOID Buffer, PIO_STATUS_BLOCK IoStatus, PETHREAD IoIssuerThread)",
    "void IoReleaseCancelSpinLock(KIRQL Irql)",
    "BOOLEAN CcCopyWriteEx(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, PVOID Buffer, PETHREAD IoIssuerThread)",
    "PIRP IoBuildDeviceIoControlRequest(ULONG IoControlCode, PDEVICE_OBJECT DeviceObject, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, BOOLEAN InternalDeviceIoControl, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock)",
    "NTSTATUS SeDeassignSecurity(PSECURITY_DESCRIPTOR* SecurityDescriptor)",
    "NTSTATUS IoSetInformation(PFILE_OBJECT FileObject, FILE_INFORMATION_CLASS FileInformationClass, ULONG Length, PVOID FileInformation)",
    "NTSTATUS ZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)",
    "BOOLEAN RtlAreBitsSet(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG Length)",
    "NTSTATUS EtwWrite(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)",
    "NTSTATUS FsRtlFindExtraCreateParameter(PECP_LIST EcpList, LPCGUID EcpType, PVOID* EcpContext, ULONG* EcpContextSize)",
    "NTSTATUS IoRetrievePriorityInfo(PIRP Irp, PFILE_OBJECT FileObject, PETHREAD Thread, PIO_PRIORITY_INFO PriorityInfo)",
    "void MmProbeAndLockPages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation)",
    "BOOLEAN FsRtlLookupLastBaseMcbEntry(PBASE_MCB Mcb, PLONGLONG Vbn, PLONGLONG Lbn)",
    "PVOID RtlEnumerateGenericTableLikeADirectory(PRTL_AVL_TABLE Table, PRTL_AVL_MATCH_FUNCTION MatchFunction, PVOID MatchData, ULONG NextFlag, PVOID* RestartKey, PULONG DeleteCount, PVOID Buffer)",
    "void MmUnmapReservedMapping(PVOID BaseAddress, ULONG PoolTag, PMDL MemoryDescriptorList)",
    "BOOLEAN RtlEqualUnicodeString(PCUNICODE_STRING String1, PCUNICODE_STRING String2, BOOLEAN CaseInSensitive)",
    "NTSTATUS ClfsMgmtQueryPolicy(PLOG_FILE_OBJECT LogFile, CLFS_MGMT_POLICY_TYPE PolicyType, PCLFS_MGMT_POLICY Policy, PULONG PolicyLength)",
    "NTSTATUS IoCreateFileSpecifyDeviceObjectHint(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, CREATE_FILE_TYPE CreateFileType, PVOID InternalParameters, ULONG Options, PVOID DeviceObject)",
    "CLFS_CONTAINER_ID ClfsLsnContainer(const CLFS_LSN* plsn)",
    "void KeInitializeSpinLock(PKSPIN_LOCK SpinLock)",
    "BOOLEAN CcIsCacheManagerCallbackNeeded(NTSTATUS Status)",
    "void ExSetResourceOwnerPointerEx(PERESOURCE Resource, PVOID OwnerPointer, ULONG Flags)",
    "BOOLEAN FsRtlAddBaseMcbEntry(PBASE_MCB Mcb, LONGLONG Vbn, LONGLONG Lbn, LONGLONG SectorCount)",
    "BOOLEAN IoIsSystemThread(PETHREAD Thread)",
    "PIRP IoBuildAsynchronousFsdRequest(ULONG MajorFunction, PDEVICE_OBJECT DeviceObject, PVOID Buffer, ULONG Length, PLARGE_INTEGER StartingOffset, PIO_STATUS_BLOCK IoStatusBlock)",
    "PULONG RtlSubAuthoritySid(PSID Sid, ULONG SubAuthority)",
    "NTSTATUS ExUuidCreate(UUID* Uuid)",
    "NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process)",
    "NTSTATUS SeQueryInformationToken(PACCESS_TOKEN Token, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID* TokenInformation)",
    "NTSTATUS RtlAnsiStringToUnicodeString(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString)",
    "PEPROCESS IoGetRequestorProcess(PIRP Irp)",
    "BOOLEAN IoIs32bitProcess(PIRP Irp)",
    "HANDLE PsGetCurrentProcessId()",
    "void FsRtlTruncateLargeMcb(PLARGE_MCB Mcb, LONGLONG Vbn)",
    "PEPROCESS PsGetThreadProcess(PETHREAD Thread)",
    "void FsRtlUpdateDiskCounters(ULONG64 BytesRead, ULONG64 BytesWritten)",
    "NTSTATUS PsCreateSystemThread(PHANDLE ThreadHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PKSTART_ROUTINE StartRoutine, PVOID StartContext)",
    "NTSTATUS FsRtlAddBaseMcbEntryEx(PBASE_MCB Mcb, LONGLONG Vbn, LONGLONG Lbn, LONGLONG SectorCount)",
    "ULONG RtlLengthRequiredSid(ULONG SubAuthorityCount)",
    "ULONG RtlLengthSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor)",
    "LONG RtlCompareUnicodeString(PCUNICODE_STRING String1, PCUNICODE_STRING String2, BOOLEAN CaseInSensitive)",
    "NTSTATUS FsRtlCancellableWaitForSingleObject(PVOID Object, PLARGE_INTEGER Timeout, PIRP Irp)",
    "void ExInitializeNPagedLookasideList(PNPAGED_LOOKASIDE_LIST Lookaside, PALLOCATE_FUNCTION Allocate, PFREE_FUNCTION Free, ULONG Flags, SIZE_T Size, ULONG Tag, USHORT Depth)",
    "void RtlInitString(PSTRING DestinationString, PCSZ SourceString)",
    "void RtlClearBits(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG NumberToClear)",
    "void RtlSetBit(PRTL_BITMAP BitMapHeader, ULONG BitNumber)",
    "BOOLEAN SeAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext, BOOLEAN SubjectContextLocked, ACCESS_MASK DesiredAccess, ACCESS_MASK PreviouslyGrantedAccess, PPRIVILEGE_SET* Privileges, PGENERIC_MAPPING GenericMapping, KPROCESSOR_MODE AccessMode, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus)",
    "BOOLEAN KeAreAllApcsDisabled()",
    "BOOLEAN MmForceSectionClosed(PSECTION_OBJECT_POINTERS SectionObjectPointer, BOOLEAN DelayClose)",
    "NTSTATUS IoSetIoPriorityHint(PIRP Irp, IO_PRIORITY_HINT PriorityHint)",
    "void FsRtlUninitializeLargeMcb(PLARGE_MCB Mcb)",
    "NTSTATUS IoGetIrpExtraCreateParameter(PIRP Irp, struct LIST** ExtraCreateParameter)",
    "BOOLEAN SeValidSecurityDescriptor(ULONG Length, PSECURITY_DESCRIPTOR SecurityDescriptor)",
    "void KeInitializeMutex(PRKMUTEX Mutex, ULONG Level)",
    "NTSTATUS RtlGetCompressionWorkSpaceSize(USHORT CompressionFormatAndEngine, PULONG CompressBufferWorkSpaceSize, PULONG CompressFragmentWorkSpaceSize)",
    "void CcSetAdditionalCacheAttributesEx(PFILE_OBJECT FileObject, ULONG Flags)",
    "BOOLEAN CcCanIWrite(PFILE_OBJECT FileObject, ULONG BytesToWrite, BOOLEAN Wait, UCHAR Retrying)",
    "BOOLEAN ExAcquireSharedStarveExclusive(PERESOURCE Resource, BOOLEAN Wait)",
    "PVOID MmMapLockedPagesWithReservedMapping(PVOID MappingAddress, ULONG PoolTag, PMDL MemoryDescriptorList, MEMORY_CACHING_TYPE CacheType)",
    "NTSTATUS ExReinitializeResourceLite(PERESOURCE Resource)",
    "BOOLEAN MmSetAddressRangeModified(PVOID Address, SIZE_T Length)",
    "ULONG ExGetExclusiveWaiterCount(PERESOURCE Resource)",
    "NTSTATUS RtlInitializeSid(PSID Sid, PSID_IDENTIFIER_AUTHORITY IdentifierAuthority, UCHAR SubAuthorityCount)",
    "NTSTATUS RtlAddAccessAllowedAce(PACL Acl, ULONG AceRevision, ACCESS_MASK AccessMask, PSID Sid)",
    "void KeFlushIoBuffers(PMDL Mdl, BOOLEAN ReadOperation, BOOLEAN DmaOperation)",
    "NTSTATUS EtwRegister(LPCGUID ProviderId, PETWENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle)",
    "BOOLEAN CcZeroData(PFILE_OBJECT FileObject, PLARGE_INTEGER StartOffset, PLARGE_INTEGER EndOffset, BOOLEAN Wait)",
    "BOOLEAN FsRtlCurrentOplock(POPLOCK Oplock)",
    "BOOLEAN IoCancelIrp(PIRP Irp)",
    "ULONG RtlNumberOfClearBits(PRTL_BITMAP BitMapHeader)",
    "void ExFreeToPagedLookasideList(PPAGED_LOOKASIDE_LIST Lookaside, PVOID Entry)",
    "ULONG RtlFindClearRuns(PRTL_BITMAP BitMapHeader, PRTL_BITMAP_RUN RunArray, ULONG SizeOfRunArray, BOOLEAN LocateLongestRuns)",
    "void ExWaitForRundownProtectionRelease(PEX_RUNDOWN_REF RunRef)",
    "void ExRundownCompleted(PEX_RUNDOWN_REF RunRef)",
    "void CcMdlWriteComplete(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PMDL MdlChain)",
    "void CcMdlReadComplete(PFILE_OBJECT FileObject, PMDL MdlChain)",
    "BOOLEAN PsIsThreadTerminating(PETHREAD Thread)",
    "NTSTATUS FsRtlValidateReparsePointBuffer(ULONG BufferLength, PREPARSE_DATA_BUFFER ReparseBuffer)",
    "NTSTATUS ClfsGetLogFileInformation(PLOG_FILE_OBJECT plfoLog, PCLFS_INFORMATION pinfoBuffer, PULONG pcbInfoBuffer)",
    "BOOLEAN CcPurgeCacheSection(PSECTION_OBJECT_POINTERS SectionObjectPointer, PLARGE_INTEGER FileOffset, ULONG Length, ULONG Flags)",
    "NTSTATUS ClfsReadLogRecord(PVOID pvMarshalContext, PCLFS_LSN plsnFirst, CLFS_CONTEXT_MODE peContextMode, PVOID* ppvReadBuffer, PULONG pcbReadBuffer, PCLFS_RECORD_TYPE peRecordType, PCLFS_LSN plsnUndoNext, PCLFS_LSN plsnPrevious, PVOID* ppvReadContext)",
    "ULONG RtlFindLastBackwardRunClear(PRTL_BITMAP BitMapHeader, ULONG FromIndex, PULONG StartingRunIndex)",
    "PVOID RtlLookupFirstMatchingElementGenericTableAvl(PRTL_AVL_TABLE Table, PVOID Buffer, PVOID* RestartKey)",
    "PVOID RtlEnumerateGenericTableWithoutSplayingAvl(PRTL_AVL_TABLE Table, PVOID* RestartKey)",
    "void FsRtlAddToTunnelCacheEx(TUNNEL* Cache, ULONGLONG DirectoryKey, UNICODE_STRING* ShortName, UNICODE_STRING* LongName, ULONG Flags, ULONG DataLength, void* Data)",
    "ULONG MmDoesFileHaveUserWritableReferences(PSECTION_OBJECT_POINTERS SectionPointer)",
    "BOOLEAN FsRtlCurrentBatchOplock(POPLOCK Oplock)",
    "void FsRtlInitializeLargeMcb(PLARGE_MCB Mcb, POOL_TYPE PoolType)",
    "PTXN_PARAMETER_BLOCK IoGetTransactionParameterBlock(PFILE_OBJECT FileObject)",
    "NTSTATUS FsRtlChangeBackingFileObject(PFILE_OBJECT CurrentFileObject, PFILE_OBJECT NewFileObject, FSRTL_CHANGE_BACKING_TYPE ChangeBackingType, ULONG Flags)",
    "void SeFreePrivileges(PPRIVILEGE_SET Privileges)",
    "BOOLEAN FsRtlIsNameInUnUpcasedExpression(PUNICODE_STRING Expression, PUNICODE_STRING Name, BOOLEAN IgnoreCase, PWCH UpcaseTable)",
    "PIRP IoAllocateIrpEx(PDEVICE_OBJECT DeviceObject, CCHAR StackSize, BOOLEAN ChargeQuota)",
    "void PsUpdateDiskCounters(PEPROCESS Process, ULONG64 BytesRead, ULONG64 BytesWritten, ULONG ReadOperationCount, ULONG WriteOperationCount, ULONG FlushOperationCount)",
    "LOGICAL IoWithinStackLimits(ULONG_PTR RegionStart, SIZE_T RegionSize)",
    "BOOLEAN IoIrpHasFsTrackOffsetExtensionType(PIRP Irp)",
    "NTSTATUS IoClearFsTrackOffsetState(PIRP Irp)",
    "void CcMdlRead(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, PMDL* MdlChain, PIO_STATUS_BLOCK IoStatus)",
    "void CcPrepareMdlWrite(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, PMDL* MdlChain, PIO_STATUS_BLOCK IoStatus)",
    "void FsRtlTruncateBaseMcb(PBASE_MCB Mcb, LONGLONG Vbn)",
    "void KeReleaseQueuedSpinLock(KSPIN_LOCK_QUEUE_NUMBER Number, KIRQL OldIrql)",
    "void ExReleasePushLockExclusiveEx(PEX_PUSH_LOCK PushLock, ULONG Flags)",
    "PVOID ExAllocateFromPagedLookasideList(PPAGED_LOOKASIDE_LIST Lookaside)",
    "void MmUnmapIoSpace(PVOID BaseAddress, SIZE_T NumberOfBytes)",
    "void MmFreeMappingAddress(PVOID BaseAddress, ULONG PoolTag)",
    "NTSTATUS CcWaitForCurrentLazyWriterActivity()",
    "NTSTATUS EtwActivityIdControl(ULONG ControlCode, LPGUID ActivityId)",
    "BOOLEAN RtlValidSid(PSID Sid)",
    "BOOLEAN RtlEqualSid(PSID Sid1, PSID Sid2)",
    "void CcSetAdditionalCacheAttributes(PFILE_OBJECT FileObject, BOOLEAN DisableReadAhead, BOOLEAN DisableWriteBehind)",
    "void ExInitializePagedLookasideList(PPAGED_LOOKASIDE_LIST Lookaside, PALLOCATE_FUNCTION Allocate, PFREE_FUNCTION Free, ULONG Flags, SIZE_T Size, ULONG Tag, USHORT Depth)",
    "BOOLEAN TmIsTransactionActive(PKTRANSACTION Transaction)",
    "BOOLEAN FsRtlCurrentOplockH(POPLOCK Oplock)",
    "ULONG RtlFindNextForwardRunClear(PRTL_BITMAP BitMapHeader, ULONG FromIndex, PULONG StartingRunIndex)",
    "NTSTATUS ClfsReadNextLogRecord(PVOID pvReadContext, PVOID* ppvBuffer, PULONG pcbBuffer, PCLFS_RECORD_TYPE peRecordType, PCLFS_LSN plsnUser, PCLFS_LSN plsnUndoNext, PCLFS_LSN plsnPrevious, PCLFS_LSN plsnRecord)",
    "BOOLEAN RtlPrefixString(const STRING* String1, const STRING* String2, BOOLEAN CaseInSensitive)",
    "void FsRtlAcknowledgeEcp(PVOID EcpContext)",
    "void RtlCaptureContext(PCONTEXT ContextRecord)",
    "PRUNTIME_FUNCTION RtlLookupFunctionEntry(ULONG64 ControlPc, PULONG64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable)",
    "PEXCEPTION_ROUTINE RtlVirtualUnwind(ULONG HandlerType, ULONG64 ImageBase, ULONG64 ControlPc, PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord, PVOID* HandlerData, PULONG64 EstablisherFrame, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)",
    "NTSTATUS NtQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength)",
    "ULONG RtlNtStatusToDosError(NTSTATUS Status)",
    "NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)",
    // the base API: the console, the registry, the activation contexts, the security, the certificates (crypt32), CNG, the smart
    // cards, the XML reader of the web services
    "BOOL ConvertSidToStringSidW(PSID Sid, LPWSTR* StringSid)",
    "BOOL ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD RequestedStringSDRevision, SECURITY_INFORMATION SecurityInformation, LPWSTR* StringSecurityDescriptor, PULONG StringSecurityDescriptorLen)",
    "BOOL ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision, PSECURITY_DESCRIPTOR* SecurityDescriptor, PULONG SecurityDescriptorSize)",
    "BOOL SetupFindNextLine(PINFCONTEXT ContextIn, PINFCONTEXT ContextOut)",
    "BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add)",
    "DWORD SetupGetFieldCount(PINFCONTEXT Context)",
    "BOOL SetConsoleTitleW(LPCWSTR lpConsoleTitle)",
    "DWORD SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart)",
    "BOOL SetConsoleCursorPosition(HANDLE hConsoleOutput, COORD dwCursorPosition)",
    "BOOL SetEndOfFile(HANDLE hFile)",
    "BOOL SetFileTime(HANDLE hFile, const FILETIME* lpCreationTime, const FILETIME* lpLastAccessTime, const FILETIME* lpLastWriteTime)",
    "BOOL SetLocalTime(const SYSTEMTIME* lpSystemTime)",
    "PSLIST_ENTRY InterlockedPushEntrySList(PSLIST_HEADER ListHead, PSLIST_ENTRY ListEntry)",
    "LSTATUS RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime)",
    "BOOL CryptEncodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const void* pvStructInfo, DWORD dwFlags, PCRYPT_ENCODE_PARA pEncodePara, void* pvEncoded, DWORD* pcbEncoded)",
    "BOOL CertGetCertificateChain(HCERTCHAINENGINE hChainEngine, PCCERT_CONTEXT pCertContext, LPFILETIME pTime, HCERTSTORE hAdditionalStore, PCERT_CHAIN_PARA pChainPara, DWORD dwFlags, LPVOID pvReserved, PCCERT_CHAIN_CONTEXT* ppChainContext)",
    "BOOL GetVersionExW(LPOSVERSIONINFOW lpVersionInformation)",
    "LSTATUS RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved)",
    "BOOL IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor)",
    "HRESULT WsFindAttribute(WS_XML_READER* reader, const WS_XML_STRING* localName, const WS_XML_STRING* ns, BOOL required, ULONG* attributeIndex, WS_ERROR* error)",
    "BOOL RevertToSelf()",
    "void InitializeSRWLock(PSRWLOCK SRWLock)",
    "BOOL CertFreeCRLContext(PCCRL_CONTEXT pCrlContext)",
    "LSTATUS RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey)",
    "PCCRL_CONTEXT CertEnumCRLsInStore(HCERTSTORE hCertStore, PCCRL_CONTEXT pPrevCrlContext)",
    "LONG SCardFreeMemory(SCARDCONTEXT hContext, LPCVOID pvMem)",
    "BOOL GetConsoleScreenBufferInfo(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo)",
    "BOOL GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode)",
    "BOOL LocalUnlock(HLOCAL hMem)",
    "BOOL CryptVerifyCertificateSignature(HCRYPTPROV_LEGACY hCryptProv, DWORD dwCertEncodingType, const BYTE* pbEncoded, DWORD cbEncoded, PCERT_PUBLIC_KEY_INFO pPublicKey)",
    "BOOL WriteConsoleW(HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved)",
    "BOOL GetVolumeNameForVolumeMountPointW(LPCWSTR lpszVolumeMountPoint, LPWSTR lpszVolumeName, DWORD cchBufferLength)",
    "BOOL CryptHashCertificate2(LPCWSTR pwszCNGHashAlgid, DWORD dwFlags, void* pvReserved, const BYTE* pbEncoded, DWORD cbEncoded, BYTE* pbComputedHash, DWORD* pcbComputedHash)",
    "BOOL CryptMsgClose(HCRYPTMSG hCryptMsg)",
    "DWORD GetFileType(HANDLE hFile)",
    "DWORD GetPrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpDefault, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName)",
    "void ReleaseActCtx(HANDLE hActCtx)",
    "int FindStringOrdinal(DWORD dwFindStringOrdinalFlags, LPCWSTR lpStringSource, int cchSource, LPCWSTR lpStringValue, int cchValue, BOOL bIgnoreCase)",
    "ATOM GlobalDeleteAtom(ATOM nAtom)",
    "HANDLE FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)",
    "LPVOID LocalLock(HLOCAL hMem)",
    "BOOL LookupAccountNameW(LPCWSTR lpSystemName, LPCWSTR lpAccountName, PSID Sid, LPDWORD cbSid, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse)",
    "NET_API_STATUS NetApiBufferFree(LPVOID Buffer)",
    "SECURITY_STATUS NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE* phProvider, LPCWSTR pszProviderName, DWORD dwFlags)",
    "PVOID EncodePointer(PVOID Ptr)",
    "BOOL GetAclInformation(PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass)",
    "HANDLE CreateActCtxW(PCACTCTXW pActCtx)",
    "BOOL DeactivateActCtx(DWORD dwFlags, ULONG_PTR ulCookie)",
    "BOOL CryptHashCertificate(HCRYPTPROV_LEGACY hCryptProv, ALG_ID Algid, DWORD dwFlags, const BYTE* pbEncoded, DWORD cbEncoded, BYTE* pbComputedHash, DWORD* pcbComputedHash)",
    "SECURITY_STATUS NCryptGetProperty(NCRYPT_HANDLE hObject, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags)",
    "void BCryptFreeBuffer(PVOID pvBuffer)",
    "PVOID DecodePointer(PVOID Ptr)",
    "BOOL CertFreeCTLContext(PCCTL_CONTEXT pCtlContext)",
    "BOOL CertComparePublicKeyInfo(DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pPublicKey1, PCERT_PUBLIC_KEY_INFO pPublicKey2)",
    "BOOL CryptSetProvParam(HCRYPTPROV hProv, DWORD dwParam, const BYTE* pbData, DWORD dwFlags)",
    "BOOL CertAddEncodedCertificateToStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext)",
    "BOOL ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL ImpersonationLevel)",
    "PCRYPT_ATTRIBUTE CertFindAttribute(LPCSTR pszObjId, DWORD cAttr, PCRYPT_ATTRIBUTE rgAttr)",
    "BOOL CertDeleteCertificateFromStore(PCCERT_CONTEXT pCertContext)",
    "PCCTL_CONTEXT CertEnumCTLsInStore(HCERTSTORE hCertStore, PCCTL_CONTEXT pPrevCtlContext)",
    "BOOL CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, DWORD dwFlags, void* pvParameters, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE* phCryptProvOrNCryptKey, DWORD* pdwKeySpec, BOOL* pfCallerFreeProvOrNCryptKey)",
    "BOOL CertAddStoreToCollection(HCERTSTORE hCollectionStore, HCERTSTORE hSiblingStore, DWORD dwUpdateFlags, DWORD dwPriority)",
    "HRESULT WsMoveReader(WS_XML_READER* reader, WS_MOVE_TO moveTo, BOOL* found, WS_ERROR* error)",
    "HRESULT WsXmlStringEquals(const WS_XML_STRING* string1, const WS_XML_STRING* string2, WS_ERROR* error)",
    "HRESULT WsSetReaderPosition(WS_XML_READER* reader, const WS_XML_NODE_POSITION* nodePosition, WS_ERROR* error)",
    "NTSTATUS BCryptExportKey(BCRYPT_KEY_HANDLE hKey, BCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags)",
    "void WaitForThreadpoolTimerCallbacks(PTP_TIMER pti, BOOL fCancelPendingCallbacks)",
    "SECURITY_STATUS NCryptOpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)",
    "BOOL CryptMsgGetParam(HCRYPTMSG hCryptMsg, DWORD dwParamType, DWORD dwIndex, void* pvData, DWORD* pcbData)",
    "BOOL CertSaveStore(HCERTSTORE hCertStore, DWORD dwEncodingType, DWORD dwSaveAs, DWORD dwSaveTo, void* pvSaveToPara, DWORD dwFlags)",
    "BOOL CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags)",
    "UINT GetConsoleOutputCP()",
    "BOOL GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)",
    "DWORD GetConsoleTitleW(LPWSTR lpConsoleTitle, DWORD nSize)",
    "void CloseThreadpoolTimer(PTP_TIMER pti)",
    "int GetDateFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME* lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate)",
    "PCCRL_CONTEXT CertCreateCRLContext(DWORD dwCertEncodingType, const BYTE* pbCrlEncoded, DWORD cbCrlEncoded)",
    "DWORD DsGetDcNameW(LPCWSTR ComputerName, LPCWSTR DomainName, GUID* DomainGuid, LPCWSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOW* DomainControllerInfo)",
    "BOOL LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse)",
    "SECURITY_STATUS NCryptImportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, NCryptBufferDesc* pParameterList, NCRYPT_KEY_HANDLE* phKey, PBYTE pbData, DWORD cbData, DWORD dwFlags)",
    "BOOL PFXIsPFXBlob(CRYPT_DATA_BLOB* pPFX)",
    "BOOL CryptDecodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const BYTE* pbEncoded, DWORD cbEncoded, DWORD dwFlags, PCRYPT_DECODE_PARA pDecodePara, void* pvStructInfo, DWORD* pcbStructInfo)",
    "BOOLEAN GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize)",
    "LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext)",
    "LONG SCardListReaders%(SCARDCONTEXT hContext, LPCTSTR mszGroups, LPTSTR mszReaders, LPDWORD pcchReaders)",
    "ULONG ldap_modify_ext_sW(LDAP* ld, PWSTR dn, LDAPModW** mods, PLDAPControlW* ServerControls, PLDAPControlW* ClientControls)",
    "struct berval** ldap_get_values_lenW(LDAP* ExternalHandle, LDAPMessage* Message, PWSTR attr)",
    "ULONG ldap_value_free_len(struct berval** vals)",
    "ULONG ldap_search_ext_sW(LDAP* ld, PWSTR base, ULONG scope, PWSTR filter, PZPWSTR attrs, ULONG attrsonly, PLDAPControlW* ServerControls, PLDAPControlW* ClientControls, struct l_timeval* timeout, ULONG SizeLimit, PLDAPMessage* res)",
    // the debug helpers of the certificate services (certcli: certutil, certsrv; no header of the SDK): the place of an error (its line and
    // file: __LINE__ << 16 | __dwFILE__) and its HRESULT; the subsystems of the debug output
    "void CSPrintErrorLineFile(DWORD dwLineFile, HRESULT hr)",
    "void CSPrintErrorLineFile2(DWORD dwLineFile, HRESULT hr, HRESULT hrQuiet)",
    "void CSPrintErrorLineFileData(LPCWSTR pwszData, DWORD dwLineFile, HRESULT hr)",
    "void CSPrintErrorLineFileData2(LPCWSTR pwszData, DWORD dwLineFile, HRESULT hr, HRESULT hrQuiet)",
    // the certificate templates and the CAs of the directory (certca.h)
    "HRESULT CAFindByName(LPCWSTR wszCAName, LPCWSTR wszScope, DWORD dwFlags, HCAINFO* phCAInfo)",
    "HRESULT CAFindByCertType(LPCWSTR wszCertType, LPCWSTR wszScope, DWORD dwFlags, HCAINFO* phCAInfo)",
    "HRESULT CAEnumFirstCA(LPCWSTR wszScope, DWORD dwFlags, HCAINFO* phCAInfo)",
    "HRESULT CAEnumNextCA(HCAINFO hPrevCA, HCAINFO* phCAInfo)",
    "HRESULT CACreateNewCA(LPCWSTR wszCAName, LPCWSTR wszScope, DWORD dwFlags, HCAINFO* phCAInfo)",
    "HRESULT CAUpdateCA(HCAINFO hCAInfo)",
    "DWORD CACountCAs(HCAINFO hCAInfo)",
    "HRESULT CACloseCA(HCAINFO hCA)",
    "HRESULT CAGetCAProperty(HCAINFO hCAInfo, LPCWSTR wszPropertyName, LPWSTR** pawszPropertyValue)",
    "HRESULT CAFreeCAProperty(HCAINFO hCAInfo, LPWSTR* awszPropertyValue)",
    "HRESULT CASetCAProperty(HCAINFO hCAInfo, LPCWSTR wszPropertyName, LPWSTR* awszPropertyValue)",
    "HRESULT CAGetCAFlags(HCAINFO hCAInfo, DWORD* pdwFlags)",
    "HRESULT CASetCAFlags(HCAINFO hCAInfo, DWORD dwFlags)",
    "HRESULT CAGetCACertificate(HCAINFO hCAInfo, PCCERT_CONTEXT* ppCert)",
    "HRESULT CASetCACertificate(HCAINFO hCAInfo, PCCERT_CONTEXT pCert)",
    "HRESULT CAGetCAExpiration(HCAINFO hCAInfo, DWORD* pdwExpiration, DWORD* pdwUnits)",
    "HRESULT CAGetCASecurity(HCAINFO hCAInfo, PSECURITY_DESCRIPTOR* ppSD)",
    "HRESULT CASetCASecurity(HCAINFO hCAInfo, PSECURITY_DESCRIPTOR pSD)",
    "HRESULT CAAccessCheck(HCAINFO hCAInfo, HANDLE ClientToken)",
    "HRESULT CAEnumCertTypesForCA(HCAINFO hCAInfo, DWORD dwFlags, HCERTTYPE* phCertType)",
    "HRESULT CAEnumCertTypesForCAEx(HCAINFO hCAInfo, LPCWSTR wszScope, DWORD dwFlags, HCERTTYPE* phCertType)",
    "HRESULT CAEnumCertTypesEx(LPCWSTR wszScope, DWORD dwFlags, HCERTTYPE* phCertType)",
    "HRESULT CAFindCertTypeByName(LPCWSTR wszCertType, HCAINFO hCAInfo, DWORD dwFlags, HCERTTYPE* phCertType)",
    "HRESULT CAEnumNextCertType(HCERTTYPE hPrevCertType, HCERTTYPE* phCertType)",
    "DWORD CACountCertTypes(HCERTTYPE hCertType)",
    "HRESULT CACloseCertType(HCERTTYPE hCertType)",
    "HRESULT CAGetCertTypeProperty(HCERTTYPE hCertType, LPCWSTR wszPropertyName, LPWSTR** pawszPropertyValue)",
    "HRESULT CAGetCertTypePropertyEx(HCERTTYPE hCertType, LPCWSTR wszPropertyName, LPVOID pPropertyValue)",
    "HRESULT CAFreeCertTypeProperty(HCERTTYPE hCertType, LPWSTR* awszPropertyValue)",
    "HRESULT CAGetCertTypeExtensions(HCERTTYPE hCertType, PCERT_EXTENSIONS* ppCertExtensions)",
    "HRESULT CAFreeCertTypeExtensions(HCERTTYPE hCertType, PCERT_EXTENSIONS pCertExtensions)",
    "HRESULT CAGetCertTypeFlagsEx(HCERTTYPE hCertType, DWORD dwOption, DWORD* pdwFlags)",
    "HRESULT CAGetCertTypeKeySpec(HCERTTYPE hCertType, DWORD* pdwKeySpec)",
    "HRESULT CAGetCertTypeExpiration(HCERTTYPE hCertType, FILETIME* pftExpiration, FILETIME* pftOverlap)",
    "HRESULT CACertTypeGetSecurity(HCERTTYPE hCertType, PSECURITY_DESCRIPTOR* ppSD)",
    "HRESULT CACertTypeAccessCheck(HCERTTYPE hCertType, HANDLE ClientToken)",
    "HRESULT CACertTypeAccessCheckEx(HCERTTYPE hCertType, HANDLE ClientToken, DWORD dwOption)",
    "BOOL DbgIsSSActive(DWORD dwSSMask)",
    "int DbgPrintf(DWORD dwSubSystemId, LPCSTR lpFmt, ...)",
    "BOOL GetComputerNameExW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize)",
    "BOOL CertGetEnhancedKeyUsage(PCCERT_CONTEXT pCertContext, DWORD dwFlags, PCERT_ENHKEY_USAGE pUsage, DWORD* pcbUsage)",
    "HRESULT WsReadStartAttribute(WS_XML_READER* reader, ULONG attributeIndex, WS_ERROR* error)",
    "HRESULT WsReadEndAttribute(WS_XML_READER* reader, WS_ERROR* error)",
    "HRESULT WsGetReaderNode(WS_XML_READER* xmlReader, const WS_XML_NODE** node, WS_ERROR* error)",
    "BOOL OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle)",
    "DWORD GetProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault, LPSTR lpReturnedString, DWORD nSize)",
    "int _initialize_onexit_table(_onexit_table_t* table)",
    "void GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)",
    "HANDLE CreateMutexExW(LPSECURITY_ATTRIBUTES lpMutexAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess)",
    "BOOL DeleteUrlCacheEntryW(LPCWSTR lpszUrlName)",
    "BOOL CryptEnumOIDInfo(DWORD dwGroupId, DWORD dwFlags, void* pvArg, PFN_CRYPT_ENUM_OID_INFO pfnEnumOIDInfo)",
    "DWORD DsUnBindW(HANDLE* phDS)",
    "BOOL CryptGetKeyParam(HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags)",
    "SECURITY_STATUS NCryptSetProperty(NCRYPT_HANDLE hObject, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags)",
    "SECURITY_STATUS NCryptFinalizeKey(NCRYPT_KEY_HANDLE hKey, DWORD dwFlags)",
    "BOOL CryptMsgGetAndVerifySigner(HCRYPTMSG hCryptMsg, DWORD cSignerStore, HCERTSTORE* rghSignerStore, DWORD dwFlags, PCCERT_CONTEXT* ppSigner, DWORD* pdwSignerIndex)",
    "BOOL CryptQueryObject(DWORD dwObjectType, const void* pvObject, DWORD dwExpectedContentTypeFlags, DWORD dwExpectedFormatTypeFlags, DWORD dwFlags, DWORD* pdwMsgAndCertEncodingType, DWORD* pdwContentType, DWORD* pdwFormatType, HCERTSTORE* phCertStore, HCRYPTMSG* phMsg, const void** ppvContext)",
    "LONG SCardReleaseContext(SCARDCONTEXT hContext)",
    "BOOL CryptExportPublicKeyInfo(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey, DWORD dwKeySpec, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, DWORD* pcbInfo)",
    "BOOL CryptImportPublicKeyInfo(HCRYPTPROV hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HCRYPTKEY* phKey)",
    "DWORD CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void* pvTypePara, LPWSTR pszNameString, DWORD cchNameString)",
    "BOOL CryptDuplicateKey(HCRYPTKEY hKey, DWORD* pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey)",
    "HCERTSTORE CertDuplicateStore(HCERTSTORE hCertStore)",
    "BOOL EqualSid(PSID pSid1, PSID pSid2)",
    "BOOL AddAce(PACL pAcl, DWORD dwAceRevision, DWORD dwStartingAceIndex, LPVOID pAceList, DWORD nAceListLength)",
    "BOOL UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize)",
    "BOOL FlushConsoleInputBuffer(HANDLE hConsoleInput)",
    "HANDLE CreateEventExW(LPSECURITY_ATTRIBUTES lpEventAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess)",
    "HANDLE CreateSemaphoreExW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess)",
    "HANDLE OpenSemaphoreW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)",
    "int GetTimeFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME* lpTime, LPCWSTR lpFormat, LPWSTR lpTimeStr, int cchTime)",
    "BOOL InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize)",
    "BOOL IsTextUnicode(const void* lpv, int iSize, LPINT lpiResult)",
    "LSTATUS RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)",
    "int FindNLSString(LCID Locale, DWORD dwFindNLSStringFlags, LPCWSTR lpStringSource, int cchSource, LPCWSTR lpStringValue, int cchValue, LPINT pcchFound)",
    "BOOL GetPrinterDriverW(HANDLE hPrinter, LPWSTR pEnvironment, DWORD Level, LPBYTE pDriverInfo, DWORD cbBuf, LPDWORD pcbNeeded)",
    "BOOL ClosePrinter(HANDLE hPrinter)",
    "HRSRC FindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage)",
    "BOOL FileTimeToLocalFileTime(const FILETIME* lpFileTime, LPFILETIME lpLocalFileTime)",
    "BOOL GetNumaHighestNodeNumber(PULONG HighestNodeNumber)",
    "BOOL GetFileInformationByHandleEx(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize)",
    "BOOL GetVolumePathNameW(LPCWSTR lpszFileName, LPWSTR lpszVolumePathName, DWORD cchBufferLength)",
    "BOOL FillConsoleOutputCharacterW(HANDLE hConsoleOutput, WCHAR cCharacter, DWORD nLength, COORD dwWriteCoord, LPDWORD lpNumberOfCharsWritten)",
    "BOOL ReadConsoleW(HANDLE hConsoleInput, LPVOID lpBuffer, DWORD nNumberOfCharsToRead, LPDWORD lpNumberOfCharsRead, PCONSOLE_READCONSOLE_CONTROL pInputControl)",
    // the C run-time: the characters, the strings, the streams, the exceptions of C++ (the _o_ forwarders of the UCRT: FindApiPrototype)
    "wint_t towlower(wint_t c)",
    "int iswalpha(wint_t c)",
    "int iswxdigit(wint_t c)",
    "int wcsncmp(const wchar_t* string1, const wchar_t* string2, size_t count)",
    "unsigned long wcstoul(const wchar_t* strSource, wchar_t** endptr, int base)",
    "long _wtol(const wchar_t* str)",
    "wchar_t* _wcslwr(wchar_t* str)",
    "wchar_t* _wcsupr(wchar_t* str)",
    "size_t wcsnlen(const wchar_t* str, size_t numberOfElements)",
    "char* strpbrk(const char* str, const char* strCharSet)",
    "int _open_osfhandle(intptr_t osfhandle, int flags)",
    "int _getch()",
    "int feof(FILE* stream)",
    "wchar_t* _wsetlocale(int category, const wchar_t* locale)",
    "errno_t memcpy_s(void* dest, size_t destSize, const void* src, size_t count)",
    "errno_t wcscpy_s(wchar_t* dest, size_t destSize, const wchar_t* src)",
    "errno_t strcat_s(char* dest, size_t destSize, const char* src)",
    "int _vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr)",
    "int _snwprintf_s(wchar_t* buffer, size_t sizeOfBuffer, size_t count, const wchar_t* format, ...)",
    "FILE* __acrt_iob_func(unsigned int index)",
    "void _CxxThrowException(void* pExceptionObject, _ThrowInfo* pThrowInfo)",
    "void __std_exception_copy(const __std_exception_data* from, __std_exception_data* to)",
    "void __std_exception_destroy(__std_exception_data* data)",
    // the C run-time: the secure functions (the sizes of the buffers), the paths, the printf / scanf of the UCRT that its inline functions
    // call (sprintf_s, swprintf: the options, the locale, the va_list)
    "errno_t wcsncpy_s(wchar_t* dest, size_t destSize, const wchar_t* src, size_t count)",
    "errno_t strncpy_s(char* dest, size_t destSize, const char* src, size_t count)",
    "errno_t strcpy_s(char* dest, size_t destSize, const char* src)",
    "errno_t wcscat_s(wchar_t* dest, size_t destSize, const wchar_t* src)",
    "errno_t wcsncat_s(wchar_t* dest, size_t destSize, const wchar_t* src, size_t count)",
    "wchar_t* wcstok_s(wchar_t* str, const wchar_t* delimiters, wchar_t** context)",
    "errno_t _itoa_s(int value, char* buffer, size_t size, int radix)",
    "errno_t _wsplitpath_s(const wchar_t* path, wchar_t* drive, size_t driveSize, wchar_t* dir, size_t dirSize, wchar_t* fname, size_t fnameSize, wchar_t* ext, size_t extSize)",
    "errno_t _splitpath_s(const char* path, char* drive, size_t driveSize, char* dir, size_t dirSize, char* fname, size_t fnameSize, char* ext, size_t extSize)",
    "errno_t _wmakepath_s(wchar_t* path, size_t sizeInWords, const wchar_t* drive, const wchar_t* dir, const wchar_t* fname, const wchar_t* ext)",
    "wchar_t* _wfullpath(wchar_t* absPath, const wchar_t* relPath, size_t maxLength)",
    "errno_t _wfopen_s(FILE** pFile, const wchar_t* filename, const wchar_t* mode)",
    "FILE* _wfsopen(const wchar_t* filename, const wchar_t* mode, int shflag)",
    "wchar_t* _wgetenv(const wchar_t* varname)",
    "wchar_t* _wcsdup(const wchar_t* strSource)",
    "int _memicmp(const void* buffer1, const void* buffer2, size_t count)",
    "int _strnicmp(const char* string1, const char* string2, size_t count)",
    "char* _strlwr(char* str)",
    "wchar_t* _ultow(unsigned long value, wchar_t* str, int radix)",
    "void* bsearch(const void* key, const void* base, size_t num, size_t width, void* compare)",
    "int __stdio_common_vsprintf(unsigned long long options, char* buffer, size_t bufferCount, const char* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vsprintf_s(unsigned long long options, char* buffer, size_t bufferCount, const char* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vsnprintf_s(unsigned long long options, char* buffer, size_t bufferCount, size_t maxCount, const char* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vswprintf(unsigned long long options, wchar_t* buffer, size_t bufferCount, const wchar_t* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vswprintf_s(unsigned long long options, wchar_t* buffer, size_t bufferCount, const wchar_t* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vsnwprintf_s(unsigned long long options, wchar_t* buffer, size_t bufferCount, size_t maxCount, const wchar_t* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vfprintf(unsigned long long options, FILE* stream, const char* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vfwprintf(unsigned long long options, FILE* stream, const wchar_t* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vsscanf(unsigned long long options, const char* buffer, size_t bufferCount, const char* format, _locale_t locale, va_list argList)",
    "int __stdio_common_vswscanf(unsigned long long options, const wchar_t* buffer, size_t bufferCount, const wchar_t* format, _locale_t locale, va_list argList)",
    // the GNU C library: the streams and their internals, the checked functions, the wide characters, the files, the threads
    "int __fprintf_chk(FILE* stream, int flag, const char* format, ...)",
    "int __sprintf_chk(char* s, int flag, size_t slen, const char* format, ...)",
    "int __asprintf_chk(char** strp, int flag, const char* format, ...)",
    "int __vfprintf_chk(FILE* stream, int flag, const char* format, va_list ap)",
    "void* __mempcpy_chk(void* dest, const void* src, size_t len, size_t destlen)",
    "void* __memset_chk(void* dest, int c, size_t len, size_t destlen)",
    "ssize_t __readlink_chk(const char* path, char* buf, size_t len, size_t buflen)",
    "int __overflow(FILE* stream, int c)",
    "int __uflow(FILE* stream)",
    "wint_t __woverflow(FILE* stream, wint_t wc)",
    "wint_t __wuflow(FILE* stream)",
    "int _IO_sputbackc(FILE* stream, int c)",
    "wint_t _IO_sputbackwc(FILE* stream, wint_t c)",
    "int _IO_fwide(FILE* stream, int mode)",
    "const unsigned short** __ctype_b_loc()",
    "const int32_t** __ctype_toupper_loc()",
    "const int32_t** __ctype_tolower_loc()",
    "int fputc_unlocked(int c, FILE* stream)",
    "int fflush_unlocked(FILE* stream)",
    "char* fgets_unlocked(char* s, int size, FILE* stream)",
    "size_t fread_unlocked(void* ptr, size_t size, size_t n, FILE* stream)",
    "int fileno_unlocked(FILE* stream)",
    "FILE* fopen64(const char* pathname, const char* mode)",
    "ssize_t getline(char** lineptr, size_t* n, FILE* stream)",
    "void perror(const char* s)",
    "wint_t towlower_l(wint_t c, locale_t locale)",
    "wint_t towupper_l(wint_t c, locale_t locale)",
    "wint_t towctrans(wint_t c, wctrans_t desc)",
    "int iswprint(wint_t c)",
    "int iswxdigit_l(wint_t c, locale_t locale)",
    "int wcsncasecmp_l(const wchar_t* s1, const wchar_t* s2, size_t n, locale_t locale)",
    "wchar_t* wmemcpy(wchar_t* dest, const wchar_t* src, size_t n)",
    "size_t wcrtomb(char* s, wchar_t wc, mbstate_t* ps)",
    "size_t mbrtowc(wchar_t* pwc, const char* s, size_t n, mbstate_t* ps)",
    "size_t mbrtoc32(char32_t* pc32, const char* s, size_t n, mbstate_t* ps)",
    "size_t mbsrtowcs(wchar_t* dest, const char** src, size_t len, mbstate_t* ps)",
    "int mbsinit(const mbstate_t* ps)",
    "int strncasecmp_l(const char* s1, const char* s2, size_t n, locale_t locale)",
    "int __strcasecmp(const char* s1, const char* s2)",
    "int __strcasecmp_l(const char* s1, const char* s2, locale_t locale)",
    "char* __stpcpy(char* dest, const char* src)",
    "char* strchrnul(const char* s, int c)",
    "char* rindex(const char* s, int c)",
    "int bcmp(const void* s1, const void* s2, size_t n)",
    "char* strndup(const char* s, size_t n)",
    "unsigned long long __isoc23_strtoull(const char* nptr, char** endptr, int base)",
    "intmax_t __isoc23_strtoimax(const char* nptr, char** endptr, int base)",
    "uintmax_t __isoc23_strtoumax(const char* nptr, char** endptr, int base)",
    "int fstat64(int fd, struct stat64* statbuf)",
    "int fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags)",
    "int lstat(const char* pathname, struct stat* statbuf)",
    "int open64(const char* pathname, int flags, ...)",
    "off64_t lseek64(int fd, off64_t offset, int whence)",
    "int fchdir(int fd)",
    "void* mmap64(void* addr, size_t length, int prot, int flags, int fd, off64_t offset)",
    "int madvise(void* addr, size_t length, int advice)",
    "long sysconf(int name)",
    "int getpagesize()",
    "int getrlimit(int resource, struct rlimit* rlim)",
    "uid_t geteuid()",
    "int poll(struct pollfd* fds, nfds_t nfds, int timeout)",
    "int getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen)",
    "int inet_pton(int af, const char* src, void* dst)",
    "void globfree(glob_t* pglob)",
    "void* tsearch(const void* key, void** rootp, __compar_fn_t compar)",
    "void* tfind(const void* key, void* const* rootp, __compar_fn_t compar)",
    "int sigismember(const sigset_t* set, int signum)",
    "int sigaddset(sigset_t* set, int signum)",
    "int raise(int sig)",
    "struct lconv* localeconv()",
    "char* nl_langinfo_l(nl_item item, locale_t locale)",
    "struct tm* localtime_r(const time_t* timep, struct tm* result)",
    "time_t timegm(struct tm* tm)",
    "void __cxa_finalize(void* d)",
    "int pthread_rwlock_unlock(pthread_rwlock_t* rwlock)",
    "int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock)",
    "int pthread_setcancelstate(int state, int* oldstate)",
    "int pthread_once(pthread_once_t* once_control, void* init_routine)",
    "int pthread_attr_init(pthread_attr_t* attr)",
    "int pthread_attr_destroy(pthread_attr_t* attr)",
    "int pthread_attr_setdetachstate(pthread_attr_t* attr, int detachstate)",
    "void freecon(char* con)",
    "int getfilecon(const char* path, char** con)",
    "int lgetfilecon(const char* path, char** con)",
    "int cap_free(void* obj_d)",
    "cap_t cap_get_file(const char* path_p)",
    "char* cap_to_text(cap_t caps, ssize_t* length_p)",
    // the internal functions of the GNU C library its own code calls most (the assertions, the locks of its streams, the calls that are no
    // cancellation points)
    "void __libc_assert_fail(const char* assertion, const char* file, unsigned int line, const char* function)",
    "void __lll_lock_wait_private(int* futex)",
    "void __lll_lock_wake_private(int* futex)",
    "void __libc_fatal(const char* message)",
    "void __chk_fail()",
    "void __fortify_fail(const char* msg)",
    "void malloc_printerr(const char* str)",
    "void _Unwind_Resume(struct _Unwind_Exception* exception_object)",
    "int __fxprintf(FILE* stream, const char* format, ...)",
    "int __close_nocancel(int fd)",
    "void __close_nocancel_nostatus(int fd)",
    "int __open64_nocancel(const char* pathname, int flags, ...)",
    "ssize_t __read_nocancel(int fd, void* buf, size_t count)",
    "ssize_t __write_nocancel(int fd, const void* buf, size_t count)",
    "void* __libc_dlsym(void* map, const char* name)",
    "int __libc_dlclose(void* map)",
    "int __libc_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)",
    // the internal functions of the GNU C library (2): its scratch / dynamic arrays, the cancellable system calls, the buffers of printf, the
    // integers of many limbs of the conversions of the floats (mpn), the streams, argp, the resolver, NSS, Sun RPC / XDR, iconv
    "void _dl_mcount_wrapper_check(void* selfpc)",
    "void _IO_vtable_check()",
    "bool __libc_scratch_buffer_grow(struct scratch_buffer* buffer)",
    "bool __libc_scratch_buffer_grow_preserve(struct scratch_buffer* buffer)",
    "bool __libc_scratch_buffer_set_array_size(struct scratch_buffer* buffer, size_t nelem, size_t size)",
    "bool __libc_dynarray_emplace_enlarge(struct dynarray_header* list, void* scratch, size_t element_size)",
    "int __libc_alloca_cutoff(size_t size)",
    "void __libc_cleanup_push_defer(struct _pthread_cleanup_buffer* buffer)",
    "void __libc_cleanup_pop_restore(struct _pthread_cleanup_buffer* buffer)",
    "long __syscall_cancel(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long nr)",
    "void __printf_buffer(struct __printf_buffer* buf, const char* format, va_list ap, unsigned int mode_flags)",
    "void __printf_buffer_putc_1(struct __printf_buffer* buf, char ch)",
    "void __printf_buffer_puts_1(struct __printf_buffer* buf, const char* s)",
    "void __printf_buffer_pad_1(struct __printf_buffer* buf, char ch, size_t count)",
    "void __printf_buffer_write(struct __printf_buffer* buf, const char* s, size_t count)",
    "void __wprintf_buffer_putc_1(struct __wprintf_buffer* buf, wchar_t ch)",
    "void __wprintf_buffer_pad_1(struct __wprintf_buffer* buf, wchar_t ch, size_t count)",
    "void __wprintf_buffer_write(struct __wprintf_buffer* buf, const wchar_t* s, size_t count)",
    "char* _itoa_word(unsigned long value, char* buflim, unsigned int base, int upper_case)",
    "mp_limb_t __mpn_lshift(mp_ptr wp, mp_srcptr up, mp_size_t usize, unsigned int cnt)",
    "mp_limb_t __mpn_rshift(mp_ptr wp, mp_srcptr up, mp_size_t usize, unsigned int cnt)",
    "mp_limb_t __mpn_mul(mp_ptr prodp, mp_srcptr up, mp_size_t usize, mp_srcptr vp, mp_size_t vsize)",
    "mp_limb_t __mpn_mul_1(mp_ptr res_ptr, mp_srcptr s1_ptr, mp_size_t s1_size, mp_limb_t s2_limb)",
    "mp_limb_t __mpn_add_n(mp_ptr res_ptr, mp_srcptr s1_ptr, mp_srcptr s2_ptr, mp_size_t size)",
    "mp_limb_t __mpn_sub_n(mp_ptr res_ptr, mp_srcptr s1_ptr, mp_srcptr s2_ptr, mp_size_t size)",
    "int __mpn_cmp(mp_srcptr op1_ptr, mp_srcptr op2_ptr, mp_size_t size)",
    "void _IO_no_init(FILE* fp, int flags, int orientation, struct _IO_wide_data* wd, const struct _IO_jump_t* jmp)",
    "void _IO_switch_to_main_get_area(FILE* fp)",
    "bool __argp_fmtstream_ensure(argp_fmtstream_t fs, size_t amount)",
    "void __argp_fmtstream_update(argp_fmtstream_t fs)",
    "ssize_t __argp_fmtstream_printf(argp_fmtstream_t fs, const char* fmt, ...)",
    "struct resolv_context* __resolv_context_get()",
    "void __resolv_context_put(struct resolv_context* ctx)",
    "void __res_iclose(res_state statp, bool free_addr)",
    "int __nss_next2(nss_action_list* ni, const char* fct_name, const char* fct2_name, void** fctp, int status, int all_values)",
    "int __nss_lookup(nss_action_list* ni, const char* fct_name, const char* fct2_name, void** fctp)",
    "void* __nss_lookup_function(nss_action_list ni, const char* fct_name)",
    "bool __nss_database_get(enum nss_database db, nss_action_list* actions)",
    "FILE* __nss_files_fopen(const char* path)",
    "struct rpc_thread_variables* __rpc_thread_variables()",
    "struct rpc_createerr* __rpc_thread_createerr()",
    "bool_t xdr_u_long(XDR* xdrs, u_long* ulp)",
    "bool_t xdr_enum(XDR* xdrs, enum_t* ep)",
    "void xdrmem_create(XDR* xdrs, const caddr_t addr, u_int size, enum xdr_op xop)",
    "char* __tzstring(const char* s)",
    "int __gconv_transliterate(struct __gconv_step* step, struct __gconv_step_data* step_data, const unsigned char* inbufstart, const unsigned char** inbufp, const unsigned char* inbufend, unsigned char** outbufstart, size_t* irreversible)",
    // the internal functions of the GNU C library (3): the regular expressions, wordexp, fnmatch, scanf / strptime, the futexes and the locks,
    // the collation tables, NSS, Sun RPC / XDR, the streams, mpn, malloc, the resolver (their calls checked: the argument registers they set)
    "bin_tree_t* create_token_tree(re_dfa_t* dfa, bin_tree_t* left, bin_tree_t* right, const re_token_t* token)",
    "int peek_token(re_token_t* token, re_string_t* input, reg_syntax_t syntax)",
    "void free_charset(re_charset_t* cset)",
    "char* w_addchar(char* buffer, size_t* actlen, size_t* maxlen, char ch)",
    "char* w_addmem(char* buffer, size_t* actlen, size_t* maxlen, const char* str, size_t len)",
    "int w_addword(wordexp_t* pwordexp, char* word)",
    "int __futex_abstimed_wait64(unsigned int* futex_word, unsigned int expected, clockid_t clockid, const struct __timespec64* abstime, int private)",
    "int __futex_abstimed_wait_cancelable64(unsigned int* futex_word, unsigned int expected, clockid_t clockid, const struct __timespec64* abstime, int private)",
    "void __lll_lock_wait(int* futex, int private)",
    "void __lll_lock_wake(int* futex, int private)",
    "int __fcntl64_nocancel(int fd, int cmd, ...)",
    "void __tunable_get_val(tunable_id_t id, void* valp, tunable_callback_t callback)",
    "int32_t __collidx_table_lookup(const char* table, uint32_t wc)",
    "uint32_t __collseq_table_lookup(const char* table, uint32_t wc)",
    "void __wcsmbs_load_conv(struct __locale_data* new_category)",
    "int internal_fnmatch(const char* pattern, const char* string, const char* string_end, bool no_leading_period, int flags, struct fnmatch_struct* ends)",
    "int internal_fnwmatch(const wchar_t* pattern, const wchar_t* string, const wchar_t* string_end, bool no_leading_period, int flags, struct fnwmatch_struct* ends)",
    "int __vfscanf_internal(FILE* s, const char* format, va_list argptr, unsigned int mode_flags)",
    "int __vfwscanf_internal(FILE* s, const wchar_t* format, va_list argptr, unsigned int mode_flags)",
    "char* __strptime_internal(const char* rp, const char* fmt, struct tm* tmp, void* statep, locale_t locale)",
    "char* __strstr_generic(const char* haystack, const char* needle)",
    "int __popcountdi2(long a)",
    "int _nl_parse_alt_digit(const char** strp, struct __locale_data* current)",
    "int __nss_readline(FILE* fp, char* buf, size_t len, off64_t* poffset)",
    "int __nss_parse_line_result(FILE* fp, off64_t offset, int parse_line_result)",
    "enum nss_status __nss_files_data_open(struct nss_files_per_file_data** pdata, enum nss_files_file file, const char* path, int* errnop, int* herrnop)",
    "void __nss_files_data_put(struct nss_files_per_file_data* data)",
    "void __nss_setent(const char* func_name, db_lookup_function lookup_fct, nss_action_list* nip, nss_action_list* startp, nss_action_list* last_nip, int stayon, int* stayon_tmp, int res)",
    "void __nss_endent(const char* func_name, db_lookup_function lookup_fct, nss_action_list* nip, nss_action_list* startp, nss_action_list* last_nip, int res)",
    "int __nss_getent_r(const char* getent_func_name, const char* setent_func_name, db_lookup_function lookup_fct, nss_action_list* nip, nss_action_list* startp, nss_action_list* last_nip, int* stayopen_tmp, int res, void* resbuf, char* buffer, size_t buflen, void** result, int* h_errnop)",
    "void* __nss_getent(getent_r_function func, void** resbuf, char** buffer, size_t buflen, size_t* buffer_size, int* h_errnop)",
    "bool __nss_valid_field(const char* value)",
    "bool_t xdr_opaque_auth(XDR* xdrs, struct opaque_auth* ap)",
    "bool_t xdr_replymsg(XDR* xdrs, struct rpc_msg* rmsg)",
    "bool_t xdr_opaque(XDR* xdrs, caddr_t cp, u_int cnt)",
    "void _pthread_cleanup_push(struct _pthread_cleanup_buffer* buffer, void* routine, void* arg)",
    "void _pthread_cleanup_pop(struct _pthread_cleanup_buffer* buffer, int execute)",
    "int __gconv_close_transform(struct __gconv_step* steps, size_t nsteps)",
    "void __set_vma_name(void* start, size_t len, const char* name)",
    "const char* __correctly_grouped_prefixmb(const char* begin, const char* end, const char* thousands, const char* grouping)",
    "const wchar_t* __correctly_grouped_prefixwc(const wchar_t* begin, const wchar_t* end, wchar_t thousands, const char* grouping)",
    "int _IO_do_write(FILE* fp, const char* data, size_t to_do)",
    "int _IO_wdo_write(FILE* fp, const wchar_t* data, size_t to_do)",
    "void _IO_free_wbackup_area(FILE* fp)",
    "void _IO_str_init_static_internal(_IO_strfile* sf, char* ptr, size_t size, char* pstart)",
    "int __pthread_tpp_change_priority(int prev_prio, int new_prio)",
    "void* _int_malloc(mstate av, size_t bytes)",
    "int __fxprintf_nocancel(FILE* fp, const char* fmt, ...)",
    "int __res_context_query(struct resolv_context* ctx, const char* name, int class, int type, unsigned char* answer, int anslen, unsigned char** answerp, unsigned char** answerp2, int* nanswerp2, int* resplen2, int* answerp2_malloced)",
    "int ns_name_unpack(const unsigned char* msg, const unsigned char* eom, const unsigned char* src, unsigned char* dst, size_t dstsiz)",
    "void __gettext_free_exp(struct expression* exp)",
    "unsigned long plural_eval(const struct expression* pexp, unsigned long n)",
    "mp_limb_t __mpn_submul_1(mp_ptr res_ptr, mp_srcptr s1_ptr, mp_size_t s1_size, mp_limb_t s2_limb)",
    "mp_limb_t __mpn_addmul_1(mp_ptr res_ptr, mp_srcptr s1_ptr, mp_size_t s1_size, mp_limb_t s2_limb)",
    "void __mpn_impn_mul_n(mp_ptr prodp, mp_srcptr up, mp_srcptr vp, mp_size_t size, mp_ptr tspace)",
    "int __printf_buffer_done(struct __printf_buffer* buf)",
    "void __printf_fp_l_buffer(struct __printf_buffer* buf, locale_t loc, const struct printf_info* info, const void* const* args)",
    "void char_buffer_add_slow(struct char_buffer* buffer, char ch)",
    "void __pthread_unwind(__pthread_unwind_buf_t* buf)",
    "void __libc_dynarray_at_failure(size_t size, size_t index)",
    "void __libc_alloc_buffer_create_failure(void* start, size_t size)",
    "int __nptl_setxid(struct xid_command* cmdp)",
    "void __resolv_conf_put(struct resolv_conf* conf)",
    "bool __grouping_iterator_init(struct grouping_iterator* it, int category, locale_t loc, unsigned int digits)",
    "void* __default_morecore(ptrdiff_t increment)",
    "void* __argp_input(const struct argp* argp, const struct argp_state* state)",
    "int key_call_socket(u_long proc, xdrproc_t xdr_arg, char* arg, xdrproc_t xdr_rslt, char* rslt)",
    "void __sfp_handle_exceptions(int _fex)",
    "struct unwind_link* __libc_unwind_link_get()",
    // the long tail of the GNU C library (2): the public functions it calls 4 times or more without a line (readdir64, strncasecmp, getpwnam_r,
    // regexec, the signals, the timers), the regular expressions, the conversions of the numbers, the streams, the condition variables,
    // spawn, NSS, the resolver (their calls checked: the argument registers they set)
    "struct dirent64* readdir64(DIR* dirp)",
    "int strncasecmp(const char* s1, const char* s2, size_t n)",
    "int getpwnam_r(const char* name, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result)",
    "int getpwuid_r(uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result)",
    "int chdir(const char* path)",
    "ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)",
    "int fstatfs64(int fd, struct statfs64* buf)",
    "void tdestroy(void* root, void* free_node)",
    "int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock)",
    "int pthread_sigmask(int how, const sigset_t* set, sigset_t* oldset)",
    "size_t wcsrtombs(char* dest, const wchar_t** src, size_t len, mbstate_t* ps)",
    "wint_t btowc(int c)",
    "wchar_t* wmempcpy(wchar_t* dest, const wchar_t* src, size_t n)",
    "int iswspace_l(wint_t wc, locale_t locale)",
    "int ttyname_r(int fd, char* buf, size_t buflen)",
    "char* hasmntopt(const struct mntent* mnt, const char* opt)",
    "int setitimer(int which, const struct itimerval* new_value, struct itimerval* old_value)",
    "unsigned int alarm(unsigned int seconds)",
    "void freeifaddrs(struct ifaddrs* ifa)",
    "int regexec(const regex_t* preg, const char* string, size_t nmatch, regmatch_t* pmatch, int eflags)",
    "int sched_getscheduler(pid_t pid)",
    "int __isoc23_sscanf(const char* str, const char* format, ...)",
    "int ns_name_ntop(const unsigned char* src, char* dst, size_t dstsiz)",
    "bool_t xdr_string(XDR* xdrs, char** sp, u_int maxsize)",
    "bool_t xdr_u_int(XDR* xdrs, u_int* up)",
    "bool_t xdr_authunix_parms(XDR* xdrs, struct authunix_parms* p)",
    "bool_t xdrrec_endofrecord(XDR* xdrs, bool_t sendnow)",
    "int __libc_current_sigrtmin()",
    "int __libc_current_sigrtmax()",
    "struct link_map* _dl_find_dso_for_object(uintptr_t addr)",
    "int _dl_addr(const void* address, Dl_info* info, struct link_map** mapp, const void** symbolp)",
    "Idx re_node_set_contains(const re_node_set* set, Idx elem)",
    "unsigned int re_string_context_at(const re_string_t* input, Idx idx, int eflags)",
    "re_dfastate_t* re_acquire_state_context(reg_errcode_t* err, const re_dfa_t* dfa, const re_node_set* nodes, unsigned int context)",
    "re_dfastate_t* re_acquire_state(reg_errcode_t* err, const re_dfa_t* dfa, const re_node_set* nodes)",
    "bool re_node_set_insert(re_node_set* set, Idx elem)",
    "reg_errcode_t re_node_set_init_copy(re_node_set* dest, const re_node_set* src)",
    "reg_errcode_t re_node_set_merge(re_node_set* dest, const re_node_set* src)",
    "int peek_token_bracket(re_token_t* token, re_string_t* input, reg_syntax_t syntax)",
    "unsigned long ____strtoul_l_internal(const char* nptr, char** endptr, int base, int group, bool bin_cst, locale_t loc)",
    "long long ____strtoll_l_internal(const char* nptr, char** endptr, int base, int group, bool bin_cst, locale_t loc)",
    "unsigned long long ____wcstoull_l_internal(const wchar_t* nptr, wchar_t** endptr, int base, int group, bool bin_cst, locale_t loc)",
    "int __gen_tempname(char* tmpl, int suffixlen, int flags, int kind)",
    "int __vfprintf_internal(FILE* s, const char* format, va_list ap, unsigned int mode_flags)",
    "int __vfwprintf_internal(FILE* s, const wchar_t* format, va_list ap, unsigned int mode_flags)",
    "int __vasprintf_internal(char** result_ptr, const char* format, va_list ap, unsigned int mode_flags)",
    "int __vsnprintf_internal(char* string, size_t maxlen, const char* format, va_list ap, unsigned int mode_flags)",
    "int _IO_file_close_it(FILE* fp)",
    "off64_t _IO_seekoff_unlocked(FILE* fp, off64_t offset, int dir, int mode)",
    "void _IO_wstr_init_static(FILE* fp, wchar_t* ptr, size_t size, wchar_t* pstart)",
    "void _IO_doallocbuf(FILE* fp)",
    "void _IO_setb(FILE* f, char* b, char* eb, int a)",
    "void _IO_wsetb(FILE* f, wchar_t* b, wchar_t* eb, int a)",
    "void _IO_un_link(struct _IO_FILE_plus* fp)",
    "void _IO_free_backup_area(FILE* fp)",
    "size_t _IO_getline(FILE* fp, char* buf, size_t n, int delim, int extract_delim)",
    "int _IO_switch_to_get_mode(FILE* fp)",
    "int __underflow(FILE* fp)",
    "void _IO_new_file_init_internal(struct _IO_FILE_plus* fp)",
    "void __condvar_cancel_waiting(pthread_cond_t* cond, uint64_t seq, unsigned int g, int private)",
    "void __condvar_confirm_wakeup(pthread_cond_t* cond, int private)",
    "int __posix_spawn_file_actions_realloc(posix_spawn_file_actions_t* file_actions)",
    "void* __libc_allocate_once_slow(void** place, void* allocate, void* deallocate, void* closure)",
    "int __inet_aton_exact(const char* cp, struct in_addr* inp)",
    "void* __nss_module_get_function(struct nss_module* module, const char* name)",
    "void __free_in6ai(struct in6addrinfo* ai)",
    "void __nss_files_data_setent(enum nss_files_file file, const char* path)",
    "void __nss_files_data_endent(enum nss_files_file file)",
    "void _dl_signal_error(int errcode, const char* object, const char* occasion, const char* errstring)",
    "void __libc_message_impl(const char* fmt, ...)",
    "int __gconv_find_transform(const char* toset, const char* fromset, struct __gconv_step** handle, size_t* nsteps, int flags)",
    "bool __printf_buffer_flush(struct __printf_buffer* buf)",
    "bool __wprintf_buffer_flush(struct __wprintf_buffer* buf)",
    "void __printf_fphex_l_buffer(struct __printf_buffer* buf, locale_t loc, const struct printf_info* info, const void* const* args)",
    "bool __grouping_iterator_next(struct grouping_iterator* it)",
    "void __grouping_iterator_init_none(struct grouping_iterator* it, unsigned int digits)",
    "int __translated_number_width(locale_t loc, const char* first, const char* last)",
    "int __libio_codecvt_encoding(struct _IO_codecvt* codecvt)",
    "int _dlerror_run(void* operate, void* args)",
    "struct era_entry* _nl_select_era_entry(int cnt, locale_t loc)",
    "struct era_entry* _nl_get_era_entry(const struct tm* tp, struct __locale_data* current)",
    "int __spawni(pid_t* pid, const char* path, const posix_spawn_file_actions_t* acts, const posix_spawnattr_t* attrp, char* const* argv, char* const* envp, int xflags)",
    "bool __spawn_valid_fd(int fd)",
    "int __utimensat64_helper(int fd, const char* file, const struct __timespec64* tsp, int flags)",
    "void __netlink_assert_response(int fd, ssize_t result)",
    "int __res_context_search(struct resolv_context* ctx, const char* name, int class, int type, unsigned char* answer, int anslen, unsigned char** answerp, unsigned char** answerp2, int* nanswerp2, int* resplen2, int* answerp2_malloced)",
    "void __libc_setutent()",
    "const char* __get_errname(int errnum)",
    "char* __fd_to_filename(int descriptor, struct fd_to_filename* storage)",
    "int __pthread_clockjoin_ex(pthread_t threadid, void** thread_return, clockid_t clockid, const struct __timespec64* abstime, bool block)",
    "int __gconv(__gconv_t cd, const unsigned char** inbuf, const unsigned char* inbufend, unsigned char** outbuf, unsigned char* outbufend, size_t* irreversible)",
    "void _int_free_chunk(mstate av, mchunkptr p, size_t size, int have_lock)",
    // the long tail of the GNU C library (3): the public functions it calls 3 times or more without a line (getdents64, statfs64,
    // ftruncate, the streams, the users, the terminals, the networks, Sun RPC), the internals of the threads, aio, the locales, malloc,
    // getopt, the streams, printf, mpn, the regular expressions, wordexp, glob, the resolver, NSS (their calls checked: the argument
    // registers they set)
    "ssize_t getdents64(int fd, void* buffer, size_t length)",
    "int statfs64(const char* file, struct statfs64* buf)",
    "int iswalnum(wint_t wc)",
    "gid_t getegid()",
    "gid_t getgid()",
    "int ftruncate(int fd, off_t length)",
    "void rewind(FILE* stream)",
    "int fgetpos(FILE* stream, fpos_t* pos)",
    "int fsetpos64(FILE* stream, const fpos64_t* pos)",
    "int fseeko64(FILE* stream, off64_t offset, int whence)",
    "FILE* fdopen(int fd, const char* mode)",
    "int getnameinfo(const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags)",
    "pthread_t pthread_self()",
    "int random_r(struct random_data* buf, int32_t* result)",
    "int srandom_r(unsigned int seed, struct random_data* buf)",
    "wctrans_t wctrans(const char* property)",
    "wctype_t wctype(const char* property)",
    "int sched_get_priority_min(int policy)",
    "int sched_get_priority_max(int policy)",
    "int sched_getparam(pid_t pid, struct sched_param* param)",
    "int sched_setscheduler(pid_t pid, int policy, const struct sched_param* param)",
    "int pthread_attr_setstacksize(pthread_attr_t* attr, size_t stacksize)",
    "void pthread_testcancel()",
    "char* envz_entry(const char* envz, size_t envz_len, const char* name)",
    "int iswalpha_l(wint_t wc, locale_t locale)",
    "int glob64(const char* pattern, int flags, void* errfunc, glob64_t* pglob)",
    "FILE* setmntent(const char* filename, const char* type)",
    "struct mntent* getmntent_r(FILE* fp, struct mntent* mntbuf, char* buf, int buflen)",
    "int nanosleep(const struct timespec* req, struct timespec* rem)",
    "int gethostbyname_r(const char* name, struct hostent* ret, char* buf, size_t buflen, struct hostent** result, int* h_errnop)",
    "int gethostbyname2_r(const char* name, int af, struct hostent* ret, char* buf, size_t buflen, struct hostent** result, int* h_errnop)",
    "int gethostbyaddr_r(const void* addr, socklen_t len, int type, struct hostent* ret, char* buf, size_t buflen, struct hostent** result, int* h_errnop)",
    "char* strsep(char** stringp, const char* delim)",
    "void flockfile(FILE* stream)",
    "void funlockfile(FILE* stream)",
    "void argp_state_help(const struct argp_state* state, FILE* stream, unsigned int flags)",
    "void argp_error(const struct argp_state* state, const char* fmt, ...)",
    "ssize_t writev(int fd, const struct iovec* iov, int iovcnt)",
    "ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags)",
    "int innetgr(const char* netgroup, const char* host, const char* user, const char* domain)",
    "int res_hnok(const char* dn)",
    "in_addr_t inet_network(const char* cp)",
    "const char* inet_ntop(int af, const void* src, char* dst, socklen_t size)",
    "int getifaddrs(struct ifaddrs** ifap)",
    "int bindresvport(int sd, struct sockaddr_in* sin)",
    "int gsignal(int sig)",
    "int dup(int oldfd)",
    "int sigsuspend(const sigset_t* mask)",
    "int sigfillset(sigset_t* set)",
    "int posix_spawn(pid_t* pid, const char* path, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const* argv, char* const* envp)",
    "int posix_spawn_file_actions_init(posix_spawn_file_actions_t* file_actions)",
    "int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t* file_actions, int fildes, int newfildes)",
    "char* secure_getenv(const char* name)",
    "wchar_t* wcschrnul(const wchar_t* s, wchar_t c)",
    "wint_t putwc_unlocked(wchar_t wc, FILE* stream)",
    "ssize_t pread64(int fd, void* buf, size_t count, off64_t offset)",
    "ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset)",
    "int clock_adjtime(clockid_t clk_id, struct timex* buf)",
    "int fstatvfs(int fd, struct statvfs* buf)",
    "int statvfs64(const char* path, struct statvfs64* buf)",
    "int getgroups(int size, gid_t* list)",
    "pid_t setsid()",
    "int tcgetattr(int fd, struct termios* termios_p)",
    "int tcsetattr(int fd, int optional_actions, const struct termios* termios_p)",
    "int uname(struct utsname* buf)",
    "int sysinfo(struct sysinfo* info)",
    "int brk(void* addr)",
    "int profil(unsigned short* buf, size_t bufsiz, size_t offset, unsigned int scale)",
    "int __profile_frequency()",
    "void warnx(const char* fmt, ...)",
    "int ns_name_pton(const char* src, unsigned char* dst, size_t dstsiz)",
    "int ns_name_skip(const unsigned char** ptrptr, const unsigned char* eom)",
    "int dn_skipname(const unsigned char* comp_dn, const unsigned char* eom)",
    "int dn_expand(const unsigned char* msg, const unsigned char* eomorig, const unsigned char* comp_dn, char* exp_dn, int length)",
    "void setutent()",
    "void endutent()",
    "int getutline_r(const struct utmp* line, struct utmp* buffer, struct utmp** result)",
    "void __libc_endutent()",
    "uintptr_t _Unwind_GetCFA(struct _Unwind_Context* context)",
    "bool_t xdr_callmsg(XDR* xdrs, struct rpc_msg* cmsg)",
    "bool_t xdr_callhdr(XDR* xdrs, struct rpc_msg* cmsg)",
    "bool_t xdr_reference(XDR* xdrs, caddr_t* pp, u_int size, xdrproc_t proc)",
    "bool_t xdr_des_block(XDR* xdrs, des_block* blkp)",
    "bool_t xdrrec_skiprecord(XDR* xdrs)",
    "void xdrrec_create(XDR* xdrs, u_int sendsize, u_int recvsize, caddr_t tcp_handle, void* readit, void* writeit)",
    "int _rpc_dtablesize()",
    "void xprt_register(SVCXPRT* xprt)",
    "void xprt_unregister(SVCXPRT* xprt)",
    "int* __rpc_thread_svc_max_pollfd()",
    "struct pollfd** __rpc_thread_svc_pollfd()",
    "void _seterr_reply(struct rpc_msg* msg, struct rpc_err* error)",
    "AUTH* authnone_create()",
    "AUTH* authunix_create(char* machname, uid_t uid, gid_t gid, int len, gid_t* aup_gids)",
    "char* clnt_sperrno(enum clnt_stat stat)",
    "CLIENT* clnttcp_create(struct sockaddr_in* raddr, u_long prog, u_long vers, int* sockp, u_int sendsz, u_int recvsz)",
    "u_short pmap_getport(struct sockaddr_in* address, u_long program, u_long version, u_int protocol)",
    "int ecb_crypt(char* key, char* buf, unsigned int len, unsigned int mode)",
    "int cbc_crypt(char* key, char* buf, unsigned int len, unsigned int mode, char* ivec)",
    "u_long _create_xid()",
    "int __libc_rpc_gethostbyname(const char* host, struct sockaddr_in* addr)",
    "void __svc_accept_failed()",
    "bool_t flush_out(RECSTREAM* rstrm, bool_t eor)",
    "bool_t get_input_bytes(RECSTREAM* rstrm, caddr_t addr, int len)",
    "void* __libc_alloc_buffer_alloc_array(struct alloc_buffer* buf, size_t size, size_t align, size_t count)",
    "void* __libc_dlopen_mode(const char* name, int mode)",
    "int dlerror_run(void* operate, void* args)",
    "void _dl_deallocate_tls(void* tcb, bool dealloc_tcb)",
    "long __internal_syscall_cancel(long a1, long a2, long a3, long a4, long a5, long a6, long nr)",
    "int __openat64_nocancel(int fd, const char* file, int oflag, ...)",
    "void __abort_lock_rdlock(internal_sigset_t* set)",
    "void __abort_lock_wrlock(internal_sigset_t* set)",
    "void __abort_lock_unlock(const internal_sigset_t* set)",
    "void __run_exit_handlers(int status, struct exit_function_list** listp, bool run_list_atexit, bool run_dtors)",
    "int __drand48_iterate(unsigned short* xsubi, struct drand48_data* buffer)",
    "void _longjmp_unwind(void* env, int val)",
    "int __futex_lock_pi64(int* futex_word, clockid_t clockid, const struct __timespec64* abstime, int private)",
    "int __pthread_current_priority()",
    "void __init_sched_fifo_prio()",
    "int __pthread_attr_setsigmask_internal(pthread_attr_t* attr, const sigset_t* sigmask)",
    "int __pthread_mutex_unlock_usercnt(pthread_mutex_t* mutex, int decr)",
    "int __pthread_mutex_cond_lock(pthread_mutex_t* mutex)",
    "int __pthread_attr_copy(pthread_attr_t* target, const pthread_attr_t* source)",
    "size_t __pthread_get_minstack(const pthread_attr_t* attr)",
    "int __shm_get_name(struct shmdir_name* result, const char* name, bool sem_prefix)",
    "void __aio_remove_request(struct requestlist* last, struct requestlist* req, int all)",
    "struct requestlist* __aio_enqueue_request(aiocb_union* aiocbp, int operation)",
    "int __aio_notify_only(struct sigevent* sigev)",
    "void _nl_load_domain(struct loaded_l10nfile* domain_file, struct binding* domainbinding)",
    "char* _nl_find_msg(struct loaded_l10nfile* domain_file, struct binding* domainbinding, const char* msgid, int convert, size_t* lengthp)",
    "const char* _nl_expand_alias(const char* name)",
    "void _nl_remove_locale(int locale, struct __locale_data* data)",
    "struct __locale_data* _nl_intern_locale_data(int category, const void* data, size_t datasize)",
    "struct __locale_data* _nl_find_locale(const char* locale_path, size_t locale_path_len, int category, const char** name)",
    "void __gconv_release_step(struct __gconv_step* step)",
    "void __gconv_get_builtin_trans(const char* name, struct __gconv_step* step)",
    "struct __gconv_loaded_object* __gconv_find_shlib(const char* name)",
    "void free_modules_db(struct gconv_module* node)",
    "int find_module_idx(const char* str, size_t* idxp)",
    "unsigned long __hash_string(const char* str_param)",
    "void _int_free_merge_chunk(mstate av, mchunkptr p, size_t size)",
    "void* _int_memalign(mstate av, size_t alignment, size_t bytes)",
    "heap_info* new_heap(size_t size, size_t top_pad)",
    "void* sysmalloc_mmap(size_t nb, size_t pagesize, int extra_flags, mstate av)",
    "mstate arena_get2(size_t size, mstate avoid_arena)",
    "mstate arena_get_retry(mstate ar_ptr, size_t bytes)",
    "int _getopt_internal(int argc, char** argv, const char* optstring, const struct option* longopts, int* longind, int long_only, int posixly_correct)",
    "int _getopt_internal_r(int argc, char** argv, const char* optstring, const struct option* longopts, int* longind, int long_only, struct _getopt_data* d, int posixly_correct)",
    "void __tzfile_read(const char* file, size_t extra, char** extrap)",
    "int __offtime(__time64_t t, long offset, struct tm* tp)",
    "long ydhms_diff(long year1, long yday1, int hour1, int min1, int sec1, int year0, int yday0, int hour0, int min0, int sec0)",
    "void day_of_the_week(struct tm* tm)",
    "size_t _IO_sgetn(FILE* fp, void* data, size_t n)",
    "size_t _IO_getwline(FILE* fp, wchar_t* buf, size_t n, wint_t delim, int extract_delim)",
    "int _IO_switch_to_wget_mode(FILE* fp)",
    "ssize_t _IO_padn(FILE* fp, int pad, ssize_t count)",
    "ssize_t _IO_wpadn(FILE* fp, wint_t pad, ssize_t count)",
    "FILE* _IO_file_fopen(FILE* fp, const char* filename, const char* mode, int is32not64)",
    "void _IO_init_internal(FILE* fp, int flags)",
    "int save_for_backup(FILE* fp, char* end_p)",
    "int save_for_wbackup(FILE* fp, wchar_t* end_p)",
    "void _IO_wdoallocbuf(FILE* fp)",
    "void _IO_unsave_markers(FILE* fp)",
    "void _IO_link_in(struct _IO_FILE_plus* fp)",
    "int __libio_codecvt_length(struct _IO_codecvt* codecvt, __mbstate_t* statep, const char* from_start, const char* from_end, size_t max)",
    "enum __codecvt_result __libio_codecvt_in(struct _IO_codecvt* codecvt, __mbstate_t* statep, const char* from_start, const char* from_end, const char** from_stop, wchar_t* to_start, wchar_t* to_end, wchar_t** to_stop)",
    "void _obstack_newchunk(struct obstack* h, size_t length)",
    "int __vfxprintf(FILE* fp, const char* format, va_list ap, unsigned int mode_flags)",
    "void __wprintf_buffer(struct __wprintf_buffer* buf, const wchar_t* format, va_list ap, unsigned int mode_flags)",
    "void __printf_buffer_snprintf_init(struct __printf_buffer_snprintf* buf, char* buffer, size_t length)",
    "int __printf_buffer_snprintf_done(struct __printf_buffer_snprintf* buf)",
    "void __printf_buffer_to_file_init(struct __printf_buffer_to_file* buf, FILE* fp)",
    "int __printf_buffer_to_file_done(struct __printf_buffer_to_file* buf)",
    "void __wprintf_buffer_to_file_init(struct __wprintf_buffer_to_file* buf, FILE* fp)",
    "int __wprintf_buffer_to_file_done(struct __wprintf_buffer_to_file* buf)",
    "bool __printf_buffer_as_file_commit(struct __printf_buffer_as_file* file)",
    "bool __wprintf_buffer_as_file_commit(struct __wprintf_buffer_as_file* file)",
    "int __wprintf_buffer_done(struct __wprintf_buffer* buf)",
    "void __wprintf_fp_l_buffer(struct __wprintf_buffer* buf, locale_t loc, const struct printf_info* info, const void* const* args)",
    "int __path_search(char* tmpl, size_t tmpl_len, const char* dir, const char* pfx, int try_tmpdir)",
    "int __readonly_area(const void* ptr, size_t size)",
    "void __mpn_impn_mul_n_basecase(mp_ptr prodp, mp_srcptr up, mp_srcptr vp, mp_size_t size)",
    "void __mpn_impn_sqr_n(mp_ptr prodp, mp_srcptr up, mp_size_t size, mp_ptr tspace)",
    "void __mpn_impn_sqr_n_basecase(mp_ptr prodp, mp_srcptr up, mp_size_t size)",
    "Idx search_cur_bkref_entry(const re_match_context_t* mctx, Idx str_idx)",
    "Idx check_halt_state_context(const re_match_context_t* mctx, const re_dfastate_t* state, Idx idx)",
    "reg_errcode_t re_node_set_init_union(re_node_set* dest, const re_node_set* src1, const re_node_set* src2)",
    "int check_node_accept_bytes(const re_dfa_t* dfa, Idx node_idx, const re_string_t* input, Idx str_idx)",
    "reg_errcode_t re_string_realloc_buffers(re_string_t* pstr, Idx new_buf_len)",
    "Idx duplicate_node(re_dfa_t* dfa, Idx org_idx, unsigned int constraint)",
    "void free_dfa_content(re_dfa_t* dfa)",
    "void re_compile_fastmap_iter(regex_t* bufp, const re_dfastate_t* init_state, char* fastmap)",
    "void build_wcs_buffer(re_string_t* pstr)",
    "reg_errcode_t build_wcs_upper_buffer(re_string_t* pstr)",
    "void build_upper_buffer(re_string_t* pstr)",
    "void free_state(re_dfastate_t* state)",
    "reg_errcode_t check_arrival_expand_ecl(const re_dfa_t* dfa, re_node_set* cur_nodes, Idx ex_subexp, int type)",
    "bool check_node_accept(const re_match_context_t* mctx, const re_token_t* node, Idx idx)",
    "reg_errcode_t sift_states_backward(const re_match_context_t* mctx, re_sift_context_t* sctx)",
    "reg_errcode_t extend_buffers(re_match_context_t* mctx, int min_len)",
    "reg_errcode_t check_subexp_matching_top(re_match_context_t* mctx, re_node_set* cur_nodes, Idx str_idx)",
    "reg_errcode_t transit_state_bkref(re_match_context_t* mctx, const re_node_set* nodes)",
    "bin_tree_t* duplicate_tree(const bin_tree_t* root, re_dfa_t* dfa)",
    "reg_errcode_t re_compile_internal(regex_t* preg, const char* pattern, size_t length, reg_syntax_t syntax)",
    "regoff_t re_search_stub(struct re_pattern_buffer* bufp, const char* string, Idx length, Idx start, regoff_t range, Idx stop, struct re_registers* regs, bool ret_len)",
    "int check_dst_limits_calc_pos_1(const re_match_context_t* mctx, int boundaries, Idx subexp_idx, Idx from_node, Idx bkref_idx)",
    "int parse_dollars(char** word, size_t* word_length, size_t* max_length, const char* words, size_t* offset, int flags, wordexp_t* pwordexp, const char* ifs, const char* ifs_white, int quoted)",
    "int parse_backtick(char** word, size_t* word_length, size_t* max_length, const char* words, size_t* offset, int flags, wordexp_t* pwordexp, const char* ifs, const char* ifs_white)",
    "int parse_qtd_backslash(char** word, size_t* word_length, size_t* max_length, const char* words, size_t* offset)",
    "int eval_expr(char* expr, long* result)",
    "int eval_expr_val(char** expr, long* result)",
    "int eval_expr_multdiv(char** expr, long* result)",
    "const char* next_brace_sub(const char* cp, int flags)",
    "int glob_in_dir(const char* pattern, const char* directory, int flags, void* errfunc, glob_t* pglob, size_t alloca_used)",
    "bool is_dir(const char* filename, int flags, const glob_t* pglob)",
    "int get_scope(const struct sockaddr_in6* in6)",
    "int match_prefix(const struct sockaddr_in6* in6, const struct prefixentry* list, int default_val)",
    "void search_list_add__(struct search_list* list, const char* item)",
    "bool try_file_lock(int fd, int type)",
    "ssize_t read_last_entry()",
    "bool matches_last_entry(const struct utmp* data)",
    "void do_swap(void* a, void* b, size_t size, enum swap_type_t swap_type)",
    "int round_away(bool negative, bool last_digit_odd, bool half_bit, bool more_bits, int mode)",
    "struct fstab_state* fstab_init(int opt_rewind)",
    "void openlog_internal(const char* ident, int logstat, int logfac)",
    "int canon_doc_option(const char** name)",
    "const char* arg_bool(const char* fname, int line_num, const char* args, unsigned int flag)",
    "const char* arg_trimdomain_list(const char* fname, int line_num, const char* args)",
    "void _res_hconf_reorder_addrs(struct hostent* hp)",
    "int inet_aton_end(const char* cp, struct in_addr* addr, const char** endp)",
    "bool __ns_rr_cursor_init(struct ns_rr_cursor* c, const unsigned char* buf, size_t len)",
    "bool __ns_rr_cursor_next(struct ns_rr_cursor* c, struct ns_rr_wire* rr)",
    "bool __ns_samebinaryname(const unsigned char* a, const unsigned char* b)",
    "enum nss_status gethostbyname3_context(struct resolv_context* ctx, const char* name, int af, struct hostent* result, char* buffer, size_t buflen, int* errnop, int* h_errnop, int32_t* ttlp, char** canonp)",
    "int __opensock()",
    "int __netlink_request(struct netlink_handle* h, int type)",
    "int __res_context_mkquery(struct resolv_context* ctx, int op, const char* dname, int class, int type, const unsigned char* data, unsigned char* buf, int buflen)",
    "int __res_context_send(struct resolv_context* ctx, const unsigned char* buf, int buflen, const unsigned char* buf2, int buflen2, unsigned char* ans, int anssiz, unsigned char** ansp, unsigned char** ansp2, int* nansp2, int* resplen2, int* ansp2_malloced)",
    "int __res_context_querydomain(struct resolv_context* ctx, const char* name, const char* domain, int class, int type, unsigned char* answer, int anslen, unsigned char** answerp, unsigned char** answerp2, int* nanswerp2, int* resplen2, int* answerp2_malloced)",
    "const char* __res_context_hostalias(struct resolv_context* ctx, const char* name, char* dst, size_t siz)",
    "unsigned int __res_randomid()",
    "int __res_nopt(struct resolv_context* ctx, int n0, unsigned char* buf, int buflen, int anslen)",
    "int __libc_res_queriesmatch(const unsigned char* buf1, const unsigned char* eom1, const unsigned char* buf2, const unsigned char* eom2)",
    "bool __res_binary_hnok(const unsigned char* dn)",
    "bool binary_hnok(const unsigned char* dn)",
    "struct resolv_conf* __resolv_conf_get(struct __res_state* resp)",
    "struct resolv_conf* __resolv_conf_get_current()",
    "bool __resolv_conf_attach(struct __res_state* resp, struct resolv_conf* conf)",
    "struct resolv_context* __resolv_context_get_override(struct __res_state* resp)",
    "int __nss_hostname_digits_dots_context(struct resolv_context* ctx, const char* name, struct hostent* resbuf, char** buffer, size_t* buffer_size, size_t buflen, struct hostent** result, enum nss_status* status, int af, int* h_errnop)",
    "bool __nss_valid_list_field(char** list)",
    "int __nss_hosts_lookup2(nss_action_list* ni, const char* fct_name, const char* fct2_name, void** fctp)",
    "int __nss_publickey_lookup2(nss_action_list* ni, const char* fct_name, const char* fct2_name, void** fctp)",
    "nss_action_list __nss_action_parse(const char* line)",
    "int __nss_fgetent_r(FILE* fp, void* result, char* buffer, size_t buffer_length, void* parser)",
    "bool __file_is_unchanged(const struct file_change_detection* left, const struct file_change_detection* right)",
    "void gaih_result_reset(struct gaih_result* res)",
    // the run-time of C++ of GCC / Clang (the Itanium ABI: the exceptions, the guards of the static locals, dynamic_cast), the locales and the
    // wide characters libstdc++ calls
    "void* __cxa_allocate_exception(size_t thrown_size)",
    "void __cxa_free_exception(void* thrown_exception)",
    "void __cxa_throw(void* thrown_exception, std::type_info* tinfo, void* dest)",
    "void* __cxa_begin_catch(void* exceptionObject)",
    "void* __cxa_get_exception_ptr(void* exceptionObject)",
    "void __cxa_call_unexpected(void* exceptionObject)",
    "void __cxa_call_terminate(void* exceptionObject)",
    "void _Unwind_DeleteException(struct _Unwind_Exception* exception_object)",
    "int __cxa_guard_acquire(__guard* guard_object)",
    "void __cxa_guard_release(__guard* guard_object)",
    "void __cxa_guard_abort(__guard* guard_object)",
    "int __cxa_atexit(void* func, void* arg, void* dso_handle)",
    "void* __dynamic_cast(const void* sub, const __class_type_info* src, const __class_type_info* dst, ptrdiff_t src2dst_offset)",
    "char* __cxa_demangle(const char* mangled_name, char* output_buffer, size_t* length, int* status)",
    "void __cxa_vec_cleanup(void* array_address, size_t element_count, size_t element_size, void* destructor)",
    "char* __nl_langinfo_l(nl_item item, locale_t locale)",
    "locale_t __uselocale(locale_t newloc)",
    "wchar_t* wmemchr(const wchar_t* s, wchar_t c, size_t n)",
    "int wmemcmp(const wchar_t* s1, const wchar_t* s2, size_t n)",
    "wchar_t* wmemset(wchar_t* wcs, wchar_t wc, size_t n)",
    "wchar_t* wmemmove(wchar_t* dest, const wchar_t* src, size_t n)",
    // the operators new and delete of C++ (by their kind and the kinds of their parameters, OperatorKey: operator delete(void*, unsigned long)
    // of libstdc++, void __cdecl operator delete(void *) of the CRT of MSVC)
    "void* operator new(size_t size)",
    "void* operator new[](size_t size)",
    "void* operator new(size_t size, const std::nothrow_t& tag)",
    "void* operator new[](size_t size, const std::nothrow_t& tag)",
    "void* operator new(size_t size, std::align_val_t alignment)",
    "void* operator new[](size_t size, std::align_val_t alignment)",
    "void operator delete(void* ptr)",
    "void operator delete[](void* ptr)",
    "void operator delete(void* ptr, size_t size)",
    "void operator delete[](void* ptr, size_t size)",
    "void operator delete(void* ptr, std::align_val_t alignment)",
    "void operator delete[](void* ptr, std::align_val_t alignment)",
    "void operator delete(void* ptr, size_t size, std::align_val_t alignment)",
    "void operator delete[](void* ptr, size_t size, std::align_val_t alignment)",
    // the long tail of the SDK the samples call (each 3 times or more): the base API, security, the registry, the services, RPC, ETW, DbgHelp
    "int LCMapStringW(LCID Locale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest)",
    "void DebugBreak()",
    "BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount)",
    "BOOL FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData)",
    "LANGID GetUserDefaultUILanguage()",
    "BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)",
    "DWORD TlsAlloc()",
    "int I_RpcExceptionFilter(unsigned long ExceptionCode)",
    "BOOL IsValidSid(PSID pSid)",
    "BOOL ActivateActCtx(HANDLE hActCtx, ULONG_PTR* lpCookie)",
    "int CompareStringEx(LPCWSTR lpLocaleName, DWORD dwCmpFlags, LPCWCH lpString1, int cchCount1, LPCWCH lpString2, int cchCount2, LPNLSVERSIONINFO lpVersionInformation, LPVOID lpReserved, LPARAM lParam)",
    "BOOL CopySid(DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid)",
    "ATOM GlobalAddAtomW(LPCWSTR lpString)",
    "HANDLE OpenEventW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)",
    "BOOL ConvertStringSidToSidW(LPCWSTR StringSid, PSID* Sid)",
    "BOOL DbgHelpCreateUserDump(LPCSTR FileName, PDBGHELP_CREATE_USER_DUMP_CALLBACK Callback, PVOID UserData)",
    "ULONG EventActivityIdControl(ULONG ControlCode, LPGUID ActivityId)",
    "PVOID FlsGetValue(DWORD dwFlsIndex)",
    "BOOL GetFileSecurityW(LPCWSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, LPDWORD lpnLengthNeeded)",
    "BOOL HeapDestroy(HANDLE hHeap)",
    "BOOL CheckTokenMembership(HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember)",
    "ULONG EventRegister(LPCGUID ProviderId, PENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle)",
    "ULONG EventUnregister(REGHANDLE RegHandle)",
    "BOOL GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation)",
    "DWORD GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer)",
    "PDWORD GetSidSubAuthority(PSID pSid, DWORD nSubAuthority)",
    "DECLSPEC_ALLOCATOR HGLOBAL GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags)",
    "NTSTATUS LsaFreeMemory(PVOID Buffer)",
    "LPVOID MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress)",
    "LSTATUS RegOpenCurrentUser(REGSAM samDesired, PHKEY phkResult)",
    "BOOL CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID pSid, DWORD* cbSid)",
    "ULONG EventSetInformation(REGHANDLE RegHandle, EVENT_INFO_CLASS InformationClass, PVOID EventInformation, ULONG InformationLength)",
    "LCID GetThreadLocale()",
    "BOOL InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents)",
    "NTSTATUS LsaClose(LSA_HANDLE ObjectHandle)",
    "CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall3(MIDL_STUBLESS_PROXY_INFO* pProxyInfo, unsigned long nProcNum, void* pReturnValue, ...)",
    "LSTATUS RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)",
    "UINT RegisterWindowMessageA(LPCSTR lpString)",
    "PWSTR SymSetHomeDirectoryW(HANDLE hProcess, PCWSTR dir)",
    "DWORD SymSetOptions(DWORD SymOptions)",
    "RPC_STATUS UuidCreate(UUID* Uuid)",
    "HRESULT CfGetSyncRootInfoByPath(LPCWSTR FilePath, CF_SYNC_ROOT_INFO_CLASS InfoClass, PVOID InfoBuffer, DWORD InfoBufferLength, DWORD* ReturnedLength)",
    "void CloseThreadpoolWait(PTP_WAIT pwa)",
    "HRESULT CreateXmlReader(REFIID riid, void** ppvObject, IMalloc* pMalloc)",
    "HRESULT DllRegisterServer()",
    "BOOL DuplicateToken(HANDLE ExistingTokenHandle, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, PHANDLE DuplicateTokenHandle)",
    "BOOL EnumSystemLocalesW(LOCALE_ENUMPROCW lpLocaleEnumProc, DWORD dwFlags)",
    "ATOM FindAtomW(LPCWSTR lpString)",
    "int FoldStringW(DWORD dwMapFlags, LPCWCH lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest)",
    "BOOL FreeEnvironmentStringsW(LPWCH penv)",
    "BOOL GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode)",
    "DWORD GetFinalPathNameByHandleW(HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags)",
    "DWORD GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR* lpFilePart)",
    "DWORD GetLongPathNameW(LPCWSTR lpszShortPath, LPWSTR lpszLongPath, DWORD cchBuffer)",
    "DWORD GetProcessId(HANDLE Process)",
    "BOOL GetStringTypeW(DWORD dwInfoType, LPCWCH lpSrcStr, int cchSrc, LPWORD lpCharType)",
    "DWORD GetVirtualDiskPhysicalPath(HANDLE VirtualDiskHandle, PULONG DiskPathSizeInBytes, PWSTR DiskPath)",
    "UINT GlobalGetAtomNameW(ATOM nAtom, LPWSTR lpBuffer, int nSize)",
    "BOOL InitializeAcl(PACL pAcl, DWORD nAclLength, DWORD dwAclRevision)",
    "BOOL InternetCreateUrlW(LPURL_COMPONENTSW lpUrlComponents, DWORD dwFlags, LPWSTR lpszUrl, LPDWORD lpdwUrlLength)",
    "BOOL IsWellKnownSid(PSID pSid, WELL_KNOWN_SID_TYPE WellKnownSidType)",
    "int LCMapStringEx(LPCWSTR lpLocaleName, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest, LPNLSVERSIONINFO lpVersionInformation, LPVOID lpReserved, LPARAM sortHandle)",
    "BOOL LocalFileTimeToFileTime(const FILETIME* lpLocalFileTime, LPFILETIME lpFileTime)",
    "LCID LocaleNameToLCID(LPCWSTR lpName, DWORD dwFlags)",
    "NTSTATUS LsaOpenPolicy(PLSA_UNICODE_STRING SystemName, PLSA_OBJECT_ATTRIBUTES ObjectAttributes, ACCESS_MASK DesiredAccess, PLSA_HANDLE PolicyHandle)",
    "DWORD OpenVirtualDisk(PVIRTUAL_STORAGE_TYPE VirtualStorageType, PCWSTR Path, VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask, OPEN_VIRTUAL_DISK_FLAG Flags, POPEN_VIRTUAL_DISK_PARAMETERS Parameters, PHANDLE Handle)",
    "LSTATUS RegSetKeyValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData)",
    "void RemoveInvalidModuleList(HANDLE hProcess)",
    "BOOLEAN TryAcquireSRWLockShared(PSRWLOCK SRWLock)",
    "BOOL TrySubmitThreadpoolCallback(PTP_SIMPLE_CALLBACK pfns, PVOID pv, PTP_CALLBACK_ENVIRON pcbe)",
    "ULONGLONG VerSetConditionMask(ULONGLONG ConditionMask, ULONG TypeMask, UCHAR Condition)",
    "DWORD WNetGetConnectionW(LPCWSTR lpLocalName, LPWSTR lpRemoteName, LPDWORD lpnLength)",
    "BOOL Wow64DisableWow64FsRedirection(PVOID* OldValue)",
    "BOOL Wow64RevertWow64FsRedirection(PVOID OlValue)",
    "BOOL AccessCheck(PSECURITY_DESCRIPTOR pSecurityDescriptor, HANDLE ClientToken, DWORD DesiredAccess, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, LPDWORD PrivilegeSetLength, LPDWORD GrantedAccess, LPBOOL AccessStatus)",
    "BOOL AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID* pSid)",
    "NTSTATUS BCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags)",
    "PCCTL_CONTEXT CertCreateCTLContext(DWORD dwMsgAndCertEncodingType, const BYTE* pbCtlEncoded, DWORD cbCtlEncoded)",
    "PCCRL_CONTEXT CertDuplicateCRLContext(PCCRL_CONTEXT pCrlContext)",
    "DWORD CertGetPublicKeyLength(DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pPublicKey)",
    "BOOL CertStrToNameW(DWORD dwCertEncodingType, LPCWSTR pszX500, DWORD dwStrType, void* pvReserved, BYTE* pbEncoded, DWORD* pcbEncoded, LPCWSTR* ppszError)",
    "PTP_WAIT CreateThreadpoolWait(PTP_WAIT_CALLBACK pfnwa, PVOID pv, PTP_CALLBACK_ENVIRON pcbe)",
    "BOOL CryptMsgControl(HCRYPTMSG hCryptMsg, DWORD dwFlags, DWORD dwCtrlType, void const* pvCtrlPara)",
    "BOOL CryptMsgUpdate(HCRYPTMSG hCryptMsg, const BYTE* pbData, DWORD cbData, BOOL fFinal)",
    "BOOL CryptSignHashW(HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR szDescription, DWORD dwFlags, BYTE* pbSignature, DWORD* pdwSigLen)",
    "BOOL CryptVerifyCertificateSignatureEx(HCRYPTPROV_LEGACY hCryptProv, DWORD dwCertEncodingType, DWORD dwSubjectType, void* pvSubject, DWORD dwIssuerType, void* pvIssuer, DWORD dwFlags, void* pvExtra)",
    "BOOL CryptVerifySignatureW(HCRYPTHASH hHash, const BYTE* pbSignature, DWORD dwSigLen, HCRYPTKEY hPubKey, LPCWSTR szDescription, DWORD dwFlags)",
    "BOOL DecryptFileW(LPCWSTR lpFileName, DWORD dwReserved)",
    "DWORD DetachVirtualDisk(HANDLE VirtualDiskHandle, DETACH_VIRTUAL_DISK_FLAG Flags, ULONG ProviderSpecificFlags)",
    "BOOL DisableThreadLibraryCalls(HMODULE hLibModule)",
    "DWORD DsBindW(LPCWSTR DomainControllerName, LPCWSTR DnsDomainName, HANDLE* phDS)",
    "void DsFreeNameResultW(DS_NAME_RESULTW* pResult)",
    "DWORD DsGetSiteNameW(LPCWSTR ComputerName, LPWSTR* SiteName)",
    "BOOL EnumResourceNamesExW(HMODULE hModule, LPCWSTR lpType, ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam, DWORD dwFlags, LANGID LangId)",
    "BOOL GetBinaryTypeW(LPCWSTR lpApplicationName, LPDWORD lpBinaryType)",
    "BOOL GetDiskFreeSpaceW(LPCWSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector, LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters)",
    "LPWCH GetEnvironmentStringsW()",
    "DWORD GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)",
    "BOOL GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)",
    "BOOL GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL* pDacl, LPBOOL lpbDaclDefaulted)",
    "PUCHAR GetSidSubAuthorityCount(PSID pSid)",
    "void GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime)",
    "UINT GetSystemWow64DirectoryW(LPWSTR lpBuffer, UINT uSize)",
    "LANGID GetThreadUILanguage()",
    "LCID GetUserDefaultLCID()",
    "BOOL HeapSetInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation, SIZE_T HeapInformationLength)",
    "BOOL IsValidCodePage(UINT CodePage)",
    "int LCIDToLocaleName(LCID Locale, LPWSTR lpName, int cchName, DWORD dwFlags)",
    "int LoadStringA(HINSTANCE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax)",
    "SIZE_T LocalSize(HLOCAL hMem)",
    "BOOL MakeSelfRelativeSD(PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor, PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor, LPDWORD lpdwBufferLength)",
    "HRESULT MappingFreePropertyBag(PMAPPING_PROPERTY_BAG pBag)",
    "HRESULT MappingRecognizeText(PMAPPING_SERVICE_INFO pServiceInfo, LPCWSTR pszText, DWORD dwLength, DWORD dwIndex, PMAPPING_OPTIONS pOptions, PMAPPING_PROPERTY_BAG pbag)",
    "__kernel_entry NTSTATUS NtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)",
    "HANDLE OpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)",
    "DWORD QueryDosDeviceW(LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax)",
    "BOOL QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize)",
    "BOOL QueueUserWorkItem(LPTHREAD_START_ROUTINE Function, PVOID Context, ULONG Flags)",
    "LSTATUS RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree, DWORD dwNotifyFilter, HANDLE hEvent, BOOL fAsynchronous)",
    "LSTATUS RegQueryValueW(HKEY hKey, LPCWSTR lpSubKey, LPWSTR lpData, PLONG lpcbData)",
    "RPC_STATUS RpcBindingUnbind(RPC_BINDING_HANDLE Binding)",
    "USHORT RtlCaptureStackBackTrace(ULONG FramesToSkip, ULONG FramesToCapture, PVOID* BackTrace, PULONG BackTraceHash)",
    "BOOL SymGetSourceFileFromTokenByTokenNameW(HANDLE hProcess, PVOID Token, PCWSTR TokenName, PCWSTR Params, PWSTR FilePath, DWORD Size)",
    "BOOL SymGetSourceFileTokenByTokenNameW(HANDLE hProcess, ULONG64 Base, PCWSTR FileSpec, PCWSTR TokenName, PCWSTR TokenParameters, PVOID* Token, DWORD* Size)",
    "BOOL SymSrvGetFileIndexesW(PCWSTR File, GUID* Id, PDWORD Val1, PDWORD Val2, DWORD Flags)",
    "PCWSTR SymSrvStoreFileW(HANDLE hProcess, PCWSTR SrvPath, PCWSTR File, DWORD Flags)",
    "HRESULT UiaRaiseAutomationEvent(IRawElementProviderSimple* pProvider, EVENTID id)",
    "BOOL VerifyVersionInfoW(LPOSVERSIONINFOEXW lpVersionInformation, DWORD dwTypeMask, DWORDLONG dwlConditionMask)",
    "BOOL WTSRegisterSessionNotification(HWND hWnd, DWORD dwFlags)",
    "HRESULT WsReadValue(WS_XML_READER* reader, WS_VALUE_TYPE valueType, void* value, ULONG valueSize, WS_ERROR* error)",
    // the shell, the property system, COM, WinRT
    "PIDLIST_ABSOLUTE ILCreateFromPathW(PCWSTR pszPath)",
    "HRESULT ILLoadFromStreamEx(IStream* pstm, PIDLIST_RELATIVE* pidl)",
    "HRESULT PSPropertyBag_ReadBSTR(IPropertyBag* propBag, LPCWSTR propName, BSTR* value)",
    "PIDLIST_ABSOLUTE SHCloneSpecialIDList(HWND hwnd, int csidl, BOOL fCreate)",
    "HRESULT SHGetTemporaryPropertyForItem(IShellItem* psi, REFPROPERTYKEY propkey, PROPVARIANT* ppropvar)",
    "LRESULT SHSendMessageBroadcastW(UINT uMsg, WPARAM wParam, LPARAM lParam)",
    "PCWSTR StrStrW(PCWSTR pszFirst, PCWSTR pszSrch)",
    "HRESULT CreateClassMoniker(REFCLSID rclsid, LPMONIKER* ppmk)",
    "HRESULT CreateUri(LPCWSTR pwzURI, DWORD dwFlags, DWORD_PTR dwReserved, IUri** ppURI)",
    "HRESULT GetRunningObjectTable(DWORD reserved, LPRUNNINGOBJECTTABLE* pprot)",
    "HRESULT ILSaveToStream(IStream* pstm, PCUIDLIST_RELATIVE pidl)",
    "HRESULT IStream_Size(IStream* pstm, ULARGE_INTEGER* pui)",
    "HRESULT PSFormatForDisplay(REFPROPERTYKEY propkey, REFPROPVARIANT propvar, PROPDESC_FORMAT_FLAGS pdfFlags, LPWSTR pwszText, DWORD cchText)",
    "HRESULT PSGetNameFromPropertyKey(REFPROPERTYKEY propkey, PWSTR* ppszCanonicalName)",
    "BOOL PathMatchSpecW(LPCWSTR pszFile, LPCWSTR pszSpec)",
    "BOOL PathStripToRootW(LPWSTR pszPath)",
    "HRESULT SHCreateDefaultExtractIcon(REFIID riid, void** ppv)",
    "HRESULT SHEvaluateSystemCommandTemplate(PCWSTR pszCmdTemplate, PWSTR* ppszApplication, PWSTR* ppszCommandLine, PWSTR* ppszParameters)",
    "PIDLIST_ABSOLUTE SHSimpleIDListFromPath(PCWSTR pszPath)",
    "HRESULT SHStrDupA(LPCSTR psz, LPWSTR* ppwsz)",
    "int StrCmpNA(PCSTR psz1, PCSTR psz2, int nChar)",
    "PCWSTR StrRStrIW(PCWSTR pszSource, PCWSTR pszLast, PCWSTR pszSrch)",
    "HRESULT PSPropertyBag_ReadStream(IPropertyBag* propBag, LPCWSTR propName, IStream** value)",
    "HRESULT PathCchStripToRoot(PWSTR pszPath, size_t cchPath)",
    "int PathCleanupSpec(PCWSTR pszDir, PWSTR pszSpec)",
    "int PathCommonPrefixW(LPCWSTR pszFile1, LPCWSTR pszFile2, LPWSTR achPath)",
    "BOOL PathIsDirectoryW(LPCWSTR pszPath)",
    "BOOL PathIsRelativeW(LPCWSTR pszPath)",
    "BOOL PathYetAnotherMakeUniqueName(PWSTR pszUniqueName, PCWSTR pszPath, PCWSTR pszShort, PCWSTR pszFileSpec)",
    "or 1 otherwise ULONG PropVariantGetElementCount(REFPROPVARIANT propvar)",
    "HRESULT PropVariantToVariant(const PROPVARIANT* pPropVar, VARIANT* pVar)",
    "HRESULT SHCreateStreamOnFileW(LPCWSTR pszFile, DWORD grfMode, IStream** ppstm)",
    "BOOL SHGetDiskFreeSpaceExW(LPCWSTR pszDirectoryName, ULARGE_INTEGER* pulFreeBytesAvailableToCaller, ULARGE_INTEGER* pulTotalNumberOfBytes, ULARGE_INTEGER* pulTotalNumberOfFreeBytes)",
    "BOOL SHGetSpecialFolderPathW(HWND hwnd, LPWSTR pszPath, int csidl, BOOL fCreate)",
    "LSTATUS SHRegCloseUSKey(HUSKEY hUSKey)",
    "HRESULT SHSetTemporaryPropertyForItem(IShellItem* psi, REFPROPERTYKEY propkey, REFPROPVARIANT propvar)",
    "int UrlCompareW(PCWSTR psz1, PCWSTR psz2, BOOL fIgnoreSlash)",
    "HRESULT VariantToStringAlloc(REFVARIANT varIn, PWSTR* ppszBuf)",
    "HRESULT AssocCreateForClasses(const ASSOCIATIONELEMENT* rgClasses, ULONG cClasses, REFIID riid, void** ppv)",
    "HRESULT CoRegisterClassObject(REFCLSID rclsid, LPUNKNOWN pUnk, DWORD dwClsContext, DWORD flags, LPDWORD lpdwRegister)",
    "HRESULT CoRevokeClassObject(DWORD dwRegister)",
    "void ColorRGBToHLS(COLORREF clrRGB, WORD* pwHue, WORD* pwLuminance, WORD* pwSaturation)",
    "PUIDLIST_RELATIVE ILGetNext(PCUIDLIST_RELATIVE pidl)",
    "BOOL IsCharSpaceW(WCHAR wch)",
    "HRESULT PSCreateMultiplexPropertyStore(IUnknown** prgpunkStores, DWORD cStores, REFIID riid, void** ppv)",
    "HRESULT PSCreatePropertyChangeArray(const PROPERTYKEY* rgpropkey, const PKA_FLAGS* rgflags, const PROPVARIANT* rgpropvar, UINT cChanges, REFIID riid, void** ppv)",
    "HRESULT PSCreateSimplePropertyChange(PKA_FLAGS flags, REFPROPERTYKEY key, REFPROPVARIANT propvar, REFIID riid, void** ppv)",
    "HRESULT PSGetPropertyKeyFromName(PCWSTR pszName, PROPERTYKEY* ppropkey)",
    "HRESULT PSPropertyBag_ReadLONG(IPropertyBag* propBag, LPCWSTR propName, LONG* value)",
    "HRESULT PathCchRemoveFileSpec(PWSTR pszPath, size_t cchPath)",
    "BOOL PathIsExe(PCWSTR pszPath)",
    "int PathResolve(PWSTR pszPath, PZPCWSTR dirs, UINT fFlags)",
    "BOOL PropVariantToBooleanWithDefault(REFPROPVARIANT propvarIn, BOOL fDefault)",
    "HRESULT PropVariantToGUID(REFPROPVARIANT propvar, GUID* pguid)",
    "HRESULT PropVariantToString(REFPROPVARIANT propvar, PWSTR psz, UINT cch)",
    "void* SHAlloc(SIZE_T cb)",
    "HRESULT SHAssocEnumHandlers(PCWSTR pszExtra, ASSOC_FILTER afFilter, IEnumAssocHandlers** ppEnumHandler)",
    "HRESULT SHAutoComplete(HWND hwndEdit, DWORD dwFlags)",
    "HRESULT SHBindToFolderIDListParentEx(IShellFolder* psfRoot, PCUIDLIST_RELATIVE pidl, IBindCtx* ppbc, REFIID riid, void** ppv, PCUITEMID_CHILD* ppidlLast)",
    "HANDLE SHChangeNotification_Lock(HANDLE hChange, DWORD dwProcId, PIDLIST_ABSOLUTE** pppidl, LONG* plEvent)",
    "BOOL SHChangeNotification_Unlock(HANDLE hLock)",
    "HRESULT SHCreateItemFromRelativeName(IShellItem* psiParent, PCWSTR pszName, IBindCtx* pbc, REFIID riid, void** ppv)",
    "HRESULT SHDefExtractIconW(LPCWSTR pszIconFile, int iIndex, UINT uFlags, HICON* phiconLarge, HICON* phiconSmall, UINT nIconSize)",
    "LSTATUS SHEnumValueW(HKEY hkey, DWORD dwIndex, PWSTR pszValueName, LPDWORD pcchValueName, LPDWORD pdwType, void* pvData, LPDWORD pcbData)",
    "BOOL SHFindFiles(PCIDLIST_ABSOLUTE pidlFolder, PCIDLIST_ABSOLUTE pidlSaveFile)",
    "PCWSTR StrChrIW(PCWSTR pszStart, WCHAR wMatch)",
    "PCWSTR StrRChrW(PCWSTR pszStart, PCWSTR pszEnd, WCHAR wMatch)",
    "HRESULT VariantToPropVariant(const VARIANT* pVar, PROPVARIANT* pPropVar)",
    "HRESULT CLSIDFromProgID(LPCOLESTR lpszProgID, LPCLSID lpclsid)",
    "HRESULT CoGetMalloc(DWORD dwMemContext, LPMALLOC* ppMalloc)",
    "HRESULT CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities)",
    "COLORREF ColorHLSToRGB(WORD wHue, WORD wLuminance, WORD wSaturation)",
    "BOOL DAD_DragLeave()",
    "HRESULT InitVariantFromBuffer(const void* pv, UINT cb, VARIANT* pvar)",
    "BOOL IsLFNDriveW(LPCWSTR pszPath)",
    "HRESULT LoadRegTypeLib(REFGUID rguid, WORD wVerMajor, WORD wVerMinor, LCID lcid, ITypeLib** pptlib)",
    "IStream* OpenRegStream(HKEY hkey, PCWSTR pszSubkey, PCWSTR pszValue, DWORD grfMode)",
    "HRESULT PSFormatForDisplayAlloc(REFPROPERTYKEY key, REFPROPVARIANT propvar, PROPDESC_FORMAT_FLAGS pdff, PWSTR* ppszDisplay)",
    "HRESULT PSPropertyBag_ReadUnknown(IPropertyBag* propBag, LPCWSTR propName, REFIID riid, void** ppv)",
    "HRESULT PSPropertyBag_WriteStream(IPropertyBag* propBag, LPCWSTR propName, IStream* value)",
    "BOOL PathAppendW(LPWSTR pszPath, LPCWSTR pszMore)",
    "int PickIconDlg(HWND hwnd, PWSTR pszIconPath, UINT cchIconPath, int* piIconIndex)",
    "ULONG PropVariantToUInt32WithDefault(REFPROPVARIANT propvarIn, ULONG ulDefault)",
    "HRESULT RegisterDragDrop(HWND hwnd, LPDROPTARGET pDropTarget)",
    "HRESULT SHDoDragDrop(HWND hwnd, IDataObject* pdata, IDropSource* pdsrc, DWORD dwEffect, DWORD* pdwEffect)",
    "BOOL SHGetPathFromIDListEx(PCIDLIST_ABSOLUTE pidl, PWSTR pszPath, DWORD cchPath, GPFIDL_FLAGS uOpts)",
    "BOOL SHInvokePrinterCommandW(HWND hwnd, UINT uAction, LPCWSTR lpBuf1, LPCWSTR lpBuf2, BOOL fModal)",
    "LSTATUS SHRegOpenUSKeyW(LPCWSTR pwzPath, REGSAM samDesired, HUSKEY hRelativeUSKey, PHUSKEY phNewUSKey, BOOL fIgnoreHKCU)",
    "HRESULT SHRemoveLocalizedName(PCWSTR pszPath)",
    "UINT SafeArrayGetDim(SAFEARRAY* psa)",
    "HRESULT StgMakeUniqueName(IStorage* pstgParent, PCWSTR pszFileSpec, DWORD grfMode, REFIID riid, void** ppv)",
    "PCWSTR StrPBrkW(PCWSTR psz, PCWSTR pszSet)",
    "HRESULT UrlCanonicalizeW(PCWSTR pszUrl, PWSTR pszCanonicalized, DWORD* pcchCanonicalized, DWORD dwFlags)",
    "HRESULT UrlEscapeW(PCWSTR pszUrl, PWSTR pszEscaped, DWORD* pcchEscaped, DWORD dwFlags)",
    "HRESULT VariantToGUID(REFVARIANT varIn, GUID* pguid)",
    "HRESULT CDefFolderMenu_Create2(PCIDLIST_ABSOLUTE pidlFolder, HWND hwnd, UINT cidl, PCUITEMID_CHILD_ARRAY apidl, IShellFolder* psf, LPFNDFMCALLBACK pfn, UINT nKeys, const HKEY* ahkeys, IContextMenu** ppcm)",
    "HRESULT CoGetCallContext(REFIID riid, void** ppInterface)",
    "LPWSTR* CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs)",
    "HRESULT DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)",
    "HRESULT GetHGlobalFromStream(LPSTREAM pstm, HGLOBAL* phglobal)",
    "HRESULT HashData(BYTE* pbData, DWORD cbData, BYTE* pbHash, DWORD cbHash)",
    "HRESULT OleSetClipboard(LPDATAOBJECT pDataObj)",
    "HRESULT PSPropertyKeyFromString(LPCWSTR pszString, PROPERTYKEY* pkey)",
    "HRESULT PSStringFromPropertyKey(REFPROPERTYKEY pkey, LPWSTR psz, UINT cch)",
    "HRESULT PathCchRemoveBackslash(PWSTR pszPath, size_t cchPath)",
    "BOOL PathCompactPathW(HDC hDC, LPWSTR pszPath, UINT dx)",
    "LPCWSTR PathFindNextComponentW(LPCWSTR pszPath)",
    "void PathGetShortPath(PWSTR pszLongPath)",
    "BOOL PathIsUNCServerShareW(LPCWSTR pszPath)",
    "void PathQualify(PWSTR psz)",
    "BOOL PathUnExpandEnvStringsW(LPCWSTR pszPath, LPWSTR pszBuf, UINT cchBuf)",
    "HRESULT PropVariantToFileTime(REFPROPVARIANT propvar, PSTIME_FLAGS pstfOut, FILETIME* pftOut)",
    "HRESULT PropVariantToInt32(REFPROPVARIANT propvarIn, LONG* plRet)",
    "HRESULT PropVariantToWinRTPropertyValue(REFPROPVARIANT propvar, REFIID riid, void** ppv)",
    "BOOL ReadCabinetState(CABINETSTATE* pcs, int cLength)",
    "HRESULT RevokeDragDrop(HWND hwnd)",
    "BOOL SHCreateThreadWithHandle(LPTHREAD_START_ROUTINE pfnThreadProc, void* pData, SHCT_FLAGS flags, LPTHREAD_START_ROUTINE pfnCallback, HANDLE* pHandle)",
    "HRESULT SHEmptyRecycleBinW(HWND hwnd, LPCWSTR pszRootPath, DWORD dwFlags)",
    "LSTATUS SHEnumKeyExW(HKEY hkey, DWORD dwIndex, LPWSTR pszName, LPDWORD pcchName)",
    "HRESULT SHGetDataFromIDListW(IShellFolder* psf, PCUITEMID_CHILD pidl, int nFormat, void* pv, int cb)",
    "HRESULT SHGetFolderLocation(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, PIDLIST_ABSOLUTE* ppidl)",
    "HRESULT SHGetFolderPathAndSubDirW(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPCWSTR pszSubDir, LPWSTR pszPath)",
    "int SHGetIconOverlayIndexW(LPCWSTR pszIconPath, int iIconIndex)",
    "int SHHandleUpdateImage(PCIDLIST_ABSOLUTE pidlExtra)",
    "HRESULT SHQueryRecycleBinW(LPCWSTR pszRootPath, LPSHQUERYRBINFO pSHQueryRBInfo)",
    "LSTATUS SHRegEnumUSKeyW(HUSKEY hUSKey, DWORD dwIndex, LPWSTR pwzName, LPDWORD pcchName, SHREGENUM_FLAGS enumRegFlags)",
    "HRESULT SHSetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PCWSTR pszPath)",
    "HRESULT SHSetLocalizedName(PCWSTR pszPath, PCWSTR pszResModule, int idsRes)",
    "int StrCSpnW(PCWSTR pszStr, PCWSTR pszSet)",
    "int StrToIntA(PCSTR pszSrc)",
    "BOOL StrToIntExW(PCWSTR pszString, STIF_FLAGS dwFlags, int* piRet)",
    "HRESULT UrlFixupW(PCWSTR pcszUrl, PWSTR pszTranslatedUrl, DWORD cchMax)",
    "BOOL UrlIsW(PCWSTR pszUrl, URLIS UrlIs)",
    "int VariantCompare(REFVARIANT var1, REFVARIANT var2)",
    "LONG VariantToInt32WithDefault(REFVARIANT varIn, LONG lDefault)",
    "PCWSTR VariantToStringWithDefault(REFVARIANT varIn, LPCWSTR pszDefault)",
    "BOOL Win32DeleteFile(PCWSTR pszPath)",
    "BOOL WriteCabinetState(CABINETSTATE* pcs)",
    // the windows, GDI / GDI+, the themes, DDE, accessibility
    "GpStatus GdipDeleteGraphics(GpGraphics* graphics)",
    "BOOL SetWindowOrgEx(HDC hdc, int x, int y, LPPOINT lppt)",
    "LPSTR CharNextA(LPCSTR lpsz)",
    "HPEN CreatePen(int iStyle, int cWidth, COLORREF color)",
    "HSZ DdeCreateStringHandleW(DWORD idInst, LPCWSTR psz, int iCodePage)",
    "BOOL DdeFreeStringHandle(DWORD idInst, HSZ hsz)",
    "GpStatus GdipDeleteBrush(GpBrush* brush)",
    "BOOL GetClassInfoExW(HINSTANCE hInstance, LPCWSTR lpszClass, LPWNDCLASSEXW lpwcx)",
    "BOOL GetIconInfo(HICON hIcon, PICONINFO piconinfo)",
    "HRESULT GetThemeTextExtent(HTHEME hTheme, HDC hdc, int iPartId, int iStateId, LPCWSTR pszText, int cchCharCount, DWORD dwTextFlags, LPCRECT pBoundingRect, LPRECT pExtentRect)",
    "BOOL IsAppThemed()",
    "BOOL IsWindowEnabled(HWND hWnd)",
    "BOOL LockSetForegroundWindow(UINT uLockCode)",
    "BOOL RemoveMenu(HMENU hMenu, UINT uPosition, UINT uFlags)",
    "LRESULT SendMessageTimeoutW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, UINT fuFlags, UINT uTimeout, PDWORD_PTR lpdwResult)",
    "HRESULT AccessibleObjectFromWindow(HWND hwnd, DWORD dwId, REFIID riid, void** ppvObject)",
    "BOOL AllowSetForegroundWindow(DWORD dwProcessId)",
    "BOOL CheckMenuRadioItem(HMENU hmenu, UINT first, UINT last, UINT check, UINT flags)",
    "HANDLE CopyImage(HANDLE h, UINT type, int cx, int cy, UINT flags)",
    "HDDEDATA DdeNameService(DWORD idInst, HSZ hsz1, HSZ hsz2, UINT afCmd)",
    "BOOL DestroyAcceleratorTable(HACCEL hAccel)",
    "BOOL EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)",
    "void* GdipAlloc(size_t size)",
    "HRESULT GetDpiForMonitor(HMONITOR hmonitor, MONITOR_DPI_TYPE dpiType, UINT* dpiX, UINT* dpiY)",
    "int GetMenuStringW(HMENU hMenu, UINT uIDItem, LPWSTR lpString, int cchMax, UINT flags)",
    "BOOL GetPointerDevices(UINT32* deviceCount, POINTER_DEVICE_INFO* pointerDevices)",
    "COLORREF GetTextColor(HDC hdc)",
    "HRESULT GetThemeFont(HTHEME hTheme, HDC hdc, int iPartId, int iStateId, int iPropId, LOGFONTW* pFont)",
    "BOOL SetMenuInfo(HMENU hmenu, LPCMENUINFO lpmi)",
    "BOOL AdjustWindowRectEx(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle)",
    "DWORD CharUpperBuffW(LPWSTR lpsz, DWORD cchLength)",
    "BOOL CheckRadioButton(HWND hDlg, int nIDFirstButton, int nIDLastButton, int nIDCheckButton)",
    "BOOL ClientToScreen(HWND hWnd, LPPOINT lpPoint)",
    "HRESULT CreateStdAccessibleObject(HWND hwnd, LONG idObject, REFIID riid, void** ppvObject)",
    "HDWP DeferWindowPos(HDWP hWinPosInfo, HWND hWnd, HWND hWndInsertAfter, int x, int y, int cx, int cy, UINT uFlags)",
    "INT_PTR DialogBoxParamW(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam)",
    "BOOL EnumDisplayMonitors(HDC hdc, LPCRECT lprcClip, MONITORENUMPROC lpfnEnum, LPARAM dwData)",
    "BOOL ExitWindowsEx(UINT uFlags, DWORD dwReason)",
    "BOOL GetTextExtentPointW(HDC hdc, LPCWSTR lpString, int c, LPSIZE lpsz)",
    "HDC GetWindowDC(HWND hWnd)",
    "BOOL IsRectEmpty(const RECT* lprc)",
    "BOOL LPtoDP(HDC hdc, LPPOINT lppt, int c)",
    "BOOL SetViewportExtEx(HDC hdc, int x, int y, LPSIZE lpsz)",
    "BOOL TrackPopupMenu(HMENU hMenu, UINT uFlags, int x, int y, int nReserved, HWND hWnd, const RECT* prcRect)",
    "BOOL TrackPopupMenuEx(HMENU hMenu, UINT uFlags, int x, int y, HWND hwnd, LPTPMPARAMS lptpm)",
    "HWND WindowFromPoint(POINT Point)",
    "BOOL AttachThreadInput(DWORD idAttach, DWORD idAttachTo, BOOL fAttach)",
    "BOOL ChangeWindowMessageFilterEx(HWND hwnd, UINT message, DWORD action, PCHANGEFILTERSTRUCT pChangeFilterStruct)",
    "GpStatus GdipDisposeImage(GpImage* image)",
    "int GetDlgCtrlID(HWND hWnd)",
    "UINT GetMenuState(HMENU hMenu, UINT uId, UINT uFlags)",
    "BOOL IsClipboardFormatAvailable(UINT format)",
    "HMENU LoadMenuW(HINSTANCE hInstance, LPCWSTR lpMenuName)",
    "BOOL MapDialogRect(HWND hDlg, LPRECT lpRect)",
    "BOOL PostThreadMessageW(DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam)",
    "BOOL ReleaseCapture()",
    "HANDLE SetClipboardData(UINT uFormat, HANDLE hMem)",
    "COLORREF SetDCBrushColor(HDC hdc, COLORREF color)",
    "BOOL SetLayeredWindowAttributes(HWND hwnd, COLORREF crKey, BYTE bAlpha, DWORD dwFlags)",
    "LPARAM SetMessageExtraInfo(LPARAM lParam)",
    "BOOL SetProcessDPIAware()",
    "BOOL TrackMouseEvent(LPTRACKMOUSEEVENT lpEventTrack)",
    "BOOL UnionRect(LPRECT lprcDst, const RECT* lprcSrc1, const RECT* lprcSrc2)",
    "int CopyAcceleratorTableW(HACCEL hAccelSrc, LPACCEL lpAccelDst, int cAccelEntries)",
    "HICON CopyIcon(HICON hIcon)",
    "HMENU CreateMenu()",
    "HRGN CreateRectRgnIndirect(const RECT* lprect)",
    "HDDEDATA DdeCreateDataHandle(DWORD idInst, LPBYTE pSrc, DWORD cb, DWORD cbOff, HSZ hszItem, UINT wFmt, UINT afCmd)",
    "LONG DisplayConfigGetDeviceInfo(DISPLAYCONFIG_DEVICE_INFO_HEADER* requestPacket)",
    "BOOL DrawFocusRect(HDC hDC, const RECT* lprc)",
    "HRESULT DwmGetWindowAttribute(HWND hwnd, DWORD dwAttribute, PVOID pvAttribute, DWORD cbAttribute)",
    "BOOL EnumDisplayDevicesW(LPCWSTR lpDevice, DWORD iDevNum, PDISPLAY_DEVICEW lpDisplayDevice, DWORD dwFlags)",
    "GpStatus GdipFillRectangleI(GpGraphics* graphics, GpBrush* brush, INT x, INT y, INT width, INT height)",
    "void GdipFree(void* ptr)",
    "HGDIOBJ GetCurrentObject(HDC hdc, UINT type)",
    "UINT GetDpiForSystem()",
    "LPARAM GetMessageExtraInfo()",
    "DWORD GetMessagePos()",
    "BOOL GetScrollInfo(HWND hwnd, int nBar, LPSCROLLINFO lpsi)",
    "BOOL ModifyMenuW(HMENU hMnu, UINT uPosition, UINT uFlags, UINT_PTR uIDNewItem, LPCWSTR lpNewItem)",
    "HMONITOR MonitorFromRect(LPCRECT lprc, DWORD dwFlags)",
    "DWORD MsgWaitForMultipleObjects(DWORD nCount, const HANDLE* pHandles, BOOL fWaitAll, DWORD dwMilliseconds, DWORD dwWakeMask)",
    "BOOL OffsetWindowOrgEx(HDC hdc, int x, int y, LPPOINT lppt)",
    "HWND SetActiveWindow(HWND hWnd)",
    "HWND SetCapture(HWND hWnd)",
    "BOOL SetGestureConfig(HWND hwnd, DWORD dwReserved, UINT cIDs, PGESTURECONFIG pGestureConfig, UINT cbSize)",
    "int SetStretchBltMode(HDC hdc, int mode)",
    "BOOL SetWindowExtEx(HDC hdc, int x, int y, LPSIZE lpsz)",
    "int SetWindowRgn(HWND hWnd, HRGN hRgn, BOOL bRedraw)",
    "BOOL SystemParametersInfoA(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)",
    "BOOL SystemParametersInfoForDpi(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni, UINT dpi)",
    "BOOL UnregisterPowerSettingNotification(HPOWERNOTIFY Handle)",
    // the kernel (ntifs.h, wdm.h, clfs.h: ntfs.sys)
    "UINT ExtractIconExW(LPCWSTR lpszFile, int nIconIndex, HICON* phiconLarge, HICON* phiconSmall, UINT nIcons)",
    "NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation)",
    "void SetThreadpoolWait(PTP_WAIT pwa, HANDLE h, PFILETIME pftTimeout)",
    "HICON ExtractIconW(HINSTANCE hInst, LPCWSTR pszExeFileName, UINT nIconIndex)",
    "__kernel_entry NTSTATUS NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)",
    "__kernel_entry NTSTATUS NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle)",
    "__kernel_entry NTSTATUS NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)",
    "NTSTATUS RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PCWSTR SourceString)",
    "void RtlMapGenericMask(PACCESS_MASK AccessMask, const GENERIC_MAPPING* GenericMapping)",
    "NTSTATUS CcErrorCallbackRoutine(PCC_ERROR_CALLBACK_CONTEXT Context)",
    "void CcSetParallelFlushFile(PFILE_OBJECT FileObject, BOOLEAN EnableParallelFlush)",
    "PVOID ExEnterCriticalRegionAndAcquireResourceExclusive(PERESOURCE Resource)",
    "ULONG ExGetSharedWaiterCount(PERESOURCE Resource)",
    "void ExReInitializeRundownProtection(PEX_RUNDOWN_REF RunRef)",
    "void ExReleaseResourceAndLeaveCriticalRegion(PERESOURCE Resource)",
    "void ExReleaseRundownProtection(PEX_RUNDOWN_REF RunRef)",
    "BOOLEAN ExSetTimer(PEX_TIMER Timer, LONGLONG DueTime, LONGLONG Period, PEXT_SET_PARAMETERS Parameters)",
    "BOOLEAN ExTryAcquirePushLockExclusiveEx(PEX_PUSH_LOCK PushLock, ULONG Flags)",
    "BOOL ExpandEnvironmentStringsForUserW(HANDLE hToken, LPCWSTR lpSrc, LPWSTR lpDest, DWORD dwSize)",
    "void FsRtlDeleteTunnelCache(TUNNEL* Cache)",
    "BOOLEAN FsRtlDoesNameContainWildCards(PUNICODE_STRING Name)",
    "BOOLEAN FsRtlFastCheckLockForWrite(PFILE_LOCK FileLock, PLARGE_INTEGER StartingByte, PLARGE_INTEGER Length, ULONG Key, PVOID FileObject, PVOID ProcessId)",
    "BOOLEAN FsRtlFindInTunnelCacheEx(TUNNEL* Cache, ULONGLONG DirectoryKey, UNICODE_STRING* Name, UNICODE_STRING* ShortName, UNICODE_STRING* LongName, ULONG Flags, ULONG* DataLength, VOID* Data)",
    "NTSTATUS FsRtlGetVirtualDiskNestingLevel(PDEVICE_OBJECT DeviceObject, PULONG NestingLevel, PULONG NestingFlags)",
    "NTSTATUS FsRtlOplockBreakH2(POPLOCK Oplock, PIRP Irp, ULONG Flags, PVOID Context, POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine, POPLOCK_FS_PREPOST_IRP PostIrpRoutine, PACCESS_MASK GrantedAccess, PUSHORT ShareAccess)",
    "BOOLEAN FsRtlOplockIsSharedRequest(PIRP Irp)",
    "void IoAcquireCancelSpinLock(PKIRQL Irql)",
    "void IoAcquireVpbSpinLock(PKIRQL Irql)",
    "void IoCancelFileOpen(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject)",
    "NTSTATUS IoCheckEaBufferValidity(PFILE_FULL_EA_INFORMATION EaBuffer, ULONG EaLength, PULONG ErrorOffset)",
    "PIRP IoMakeAssociatedIrpEx(PIRP Irp, PDEVICE_OBJECT DeviceObject, CCHAR StackSize)",
    "void IoReleaseVpbSpinLock(KIRQL Irql)",
    "void IoSetDeviceToVerify(PETHREAD Thread, PDEVICE_OBJECT DeviceObject)",
    "void IoTransferActivityId(LPCGUID ActivityId, LPCGUID RelatedActivityId)",
    "ULONG KeQueryTimeIncrement()",
    "BOOLEAN KeSetCoalescableTimer(PKTIMER Timer, LARGE_INTEGER DueTime, ULONG Period, ULONG TolerableDelay, PKDPC Dpc)",
    "PVOID MmAllocateMappingAddress(SIZE_T NumberOfBytes, ULONG PoolTag)",
    "PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect)",
    "__kernel_entry NTSTATUS NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)",
    "NTSTATUS ObQueryNameString(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length, PULONG ReturnLength)",
    "NTSTATUS PcwAddInstance(PPCW_BUFFER Buffer, PCUNICODE_STRING Name, ULONG Id, ULONG Count, PPCW_DATA Data)",
    "BOOLEAN RtlAreBitsClear(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG Length)",
    "ULONG RtlFindSetBits(PRTL_BITMAP BitMapHeader, ULONG NumberToFind, ULONG HintIndex)",
    "LOGICAL RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress)",
    "NTSTATUS RtlGetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, PBOOLEAN DaclPresent, PACL* Dacl, PBOOLEAN DaclDefaulted)",
    "PCWSTR RtlGetNtSystemRoot()",
    "NTSTATUS RtlGetOwnerSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID* Owner, PBOOLEAN OwnerDefaulted)",
    "BOOLEAN RtlIsNonEmptyDirectoryReparsePointAllowed(ULONG ReparseTag)",
    "BOOLEAN RtlIsStateSeparationEnabled()",
    "ULONG RtlNtStatusToDosErrorNoTeb(NTSTATUS Status)",
    "NTSTATUS RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN DaclPresent, PACL Dacl, BOOLEAN DaclDefaulted)",
    "WCHAR RtlUpcaseUnicodeChar(WCHAR SourceCharacter)",
    "void RtlUpperString(PSTRING DestinationString, const STRING* SourceString)",
    "void SeAuditTransactionStateChange(GUID* TransactionId, GUID* ResourceManagerId, ULONG NewTransactionState)",
    "BOOLEAN SePrivilegeCheck(PPRIVILEGE_SET RequiredPrivileges, PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext, KPROCESSOR_MODE AccessMode)",
    "DWORD SetSecurityInfo(HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)",
    "BOOL SetThreadPriority(HANDLE hThread, int nPriority)",
    "BOOL SetupFindFirstLineW(HINF InfHandle, PCWSTR Section, PCWSTR Key, PINFCONTEXT Context)",
    "NTSTATUS TmDereferenceEnlistmentKey(PKENLISTMENT Enlistment, PBOOLEAN LastReference)",
    "NTSTATUS TmRollbackComplete(PKENLISTMENT Enlistment, PLARGE_INTEGER TmVirtualClock)",
    "NTSTATUS ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)",
    "NTSTATUS ZwPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)",
    "NTSTATUS ZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)",
    "NTSTATUS ZwQueryInformationTransactionManager(HANDLE TransactionManagerHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass, PVOID TransactionManagerInformation, ULONG TransactionManagerInformationLength, PULONG ReturnLength)",
    // functions without a declaration in the SDK (DirectUI: shell32's views), their shapes from the calls; the auto-expand push locks
    // and the AVL trees of the kernel
    "ATOM StrToID(LPCWSTR psz)",
    "ULONG EtwTraceMessage(TRACEHANDLE LoggerHandle, ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, ...)",
    "ULONG RtlComputeCrc32(ULONG PartialCrc, PUCHAR Buffer, ULONG Length)",
    "void ExAcquireAutoExpandPushLockExclusive(PEX_PUSH_LOCK_AUTO_EXPAND PushLock, ULONG Flags)",
    "void ExReleaseAutoExpandPushLockExclusive(PEX_PUSH_LOCK_AUTO_EXPAND PushLock, ULONG Flags)",
    "void ExAcquireAutoExpandPushLockShared(PEX_PUSH_LOCK_AUTO_EXPAND PushLock, ULONG Flags)",
    "void ExReleaseAutoExpandPushLockShared(PEX_PUSH_LOCK_AUTO_EXPAND PushLock, ULONG Flags)",
    "PRTL_BALANCED_NODE RtlAvlRemoveNode(PRTL_AVL_TREE Tree, PRTL_BALANCED_NODE Node)",
    "void KeFreeCalloutStack(PVOID Context)",
};

struct PrototypeTable {
    std::deque<std::string> strings; // the names, the types and the texts of the prototypes (stable addresses)
    std::deque<AsmFunctionDetails> functions;
    std::unordered_map<std::string_view, const AsmFunctionDetails*> byName;
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

bool IsIdentifier(std::string_view text)
{
    if (text.empty() || !(std::isalpha(static_cast<unsigned char>(text.front())) || text.front() == '_'))
        return false;
    return std::all_of(text.begin(), text.end(), [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; });
}

// an operator new / delete of C++ (a line of the table, a demangled name: operator new(unsigned long), void * __ptr64 __cdecl operator
// new(unsigned __int64)): the operator and the kinds of its parameters (p: a pointer, n: a size, a: std::align_val_t, t: std::nothrow_t):
// "operator delete(p,n)"; empty for another name
std::string OperatorKey(std::string_view text)
{
    size_t start = std::string_view::npos;
    for (const std::string_view op : { std::string_view("operator new"), std::string_view("operator delete") })
        if (const auto found = text.find(op); found != std::string_view::npos)
            start = found;
    if (start == std::string_view::npos)
        return {};
    const auto open  = text.find('(', start);
    const auto close = text.rfind(')');
    if (open == std::string_view::npos || close == std::string_view::npos || close < open)
        return {};
    std::string key(Trim(text.substr(start, open - start)));
    if (key != "operator new" && key != "operator new[]" && key != "operator delete" && key != "operator delete[]")
        return {};
    key += '(';
    std::string_view parameters = text.substr(open + 1, close - open - 1);
    bool first                  = true;
    while (!parameters.empty()) {
        const auto comma                 = parameters.find(',');
        const std::string_view parameter = Trim(parameters.substr(0, comma));
        parameters                       = comma == std::string_view::npos ? std::string_view() : parameters.substr(comma + 1);
        if (parameter.empty() || parameter == "void")
            continue;
        if (!first)
            key += ',';
        first = false;
        key += parameter.find("align_val_t") != std::string_view::npos ? 'a'
               : parameter.find("nothrow") != std::string_view::npos   ? 't'
               : parameter.find('*') != std::string_view::npos         ? 'p'
                                                                       : 'n';
    }
    return key + ')';
}

std::vector<std::string_view> SplitDemangledParameters(std::string_view parameters);

// a qualified C++ name in a prototype of the user (std::locale::~locale, std::basic_ios<char, std::char_traits<char> >::clear): identifiers
// joined by ::, the ~ of a destructor, template arguments
bool IsQualifiedName(std::string_view name)
{
    if (name.empty() || !(std::isalpha(static_cast<unsigned char>(name.front())) || name.front() == '_' || name.front() == '~') || name.back() == ':')
        return false;
    int32 depth = 0;
    for (const char c : name) {
        if (c == '<')
            depth++;
        else if (c == '>') {
            if (--depth < 0)
                return false;
        } else if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == ':' || c == '~' ||
                     (depth > 0 && (c == ',' || c == ' ' || c == '*' || c == '&'))))
            return false;
    }
    return depth == 0;
}

// the last space or * of a text outside of its template arguments (the name after it: std::basic_ios<char, std::char_traits<char> >* this)
size_t LastSeparatorOutsideTemplates(std::string_view text)
{
    size_t last  = std::string_view::npos;
    uint32 depth = 0;
    for (size_t index = 0; index < text.size(); index++) {
        if (text[index] == '<')
            depth++;
        else if (text[index] == '>' && depth > 0)
            depth--;
        else if ((text[index] == ' ' || text[index] == '*') && depth == 0)
            last = index;
    }
    return last;
}

// "HANDLE CreateFileW(LPCWSTR lpFileName, ...)": the function, its parameters (the name after the last space or * outside of the template
// arguments, the type before it); the texts are kept in `strings` (stable addresses). `strict` (a prototype of the user): every name an
// identifier (the function: a qualified C++ name too), every parameter named, the parameters split at the commas outside of <>
bool ParsePrototypeText(std::deque<std::string>& strings, const std::string& line, AsmFunctionDetails& details, bool strict)
{
    const auto open  = line.find('(');
    const auto close = line.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close < open || (strict && Trim(std::string_view(line).substr(close + 1)) != ""))
        return false;
    const auto& text = strings.emplace_back(line);
    const std::string_view head = Trim(std::string_view(text).substr(0, open));
    const auto operatorStart    = head.find("operator "); // void* operator new[](size_t size): its name with the space
    const auto nameStart        = operatorStart != std::string_view::npos && operatorStart > 0 ? operatorStart - 1 : LastSeparatorOutsideTemplates(head);
    const std::string_view name = nameStart == std::string_view::npos ? head : head.substr(nameStart + 1);
    if (name.empty() || (strict && !IsIdentifier(name) && !IsQualifiedName(name)))
        return false;
    details.functionName = name;
    details.prototype    = text;
    if (const std::string_view returnType = Trim(head.substr(0, nameStart == std::string_view::npos ? 0 : nameStart + 1));
        returnType != "void" && returnType != "VOID")
        details.returnType = returnType;
    std::string_view parameters = std::string_view(text).substr(open + 1, close - open - 1);
    if (strict && (parameters.find('(') != std::string_view::npos || parameters.find(')') != std::string_view::npos))
        return false; // a pointer to a function as a parameter: not split by the commas
    const auto strictParameters = strict ? SplitDemangledParameters(parameters) : std::vector<std::string_view>();
    for (size_t next = 0; strict ? next < strictParameters.size() : !parameters.empty(); next++) {
        std::string_view parameter;
        if (strict) {
            parameter = strictParameters[next];
        } else {
            const auto comma = parameters.find(',');
            parameter        = Trim(parameters.substr(0, comma));
            parameters       = comma == std::string_view::npos ? std::string_view() : parameters.substr(comma + 1);
        }
        if (parameter.empty() || parameter == "void" || parameter == "...")
            continue;
        const auto split = strict ? LastSeparatorOutsideTemplates(parameter) : parameter.find_last_of(" *");
        if (split == std::string_view::npos || (strict && (!IsIdentifier(parameter.substr(split + 1)) || Trim(parameter.substr(0, split + 1)).empty()))) {
            if (strict)
                return false;
            continue;
        }
        const auto& parameterName = strings.emplace_back(parameter.substr(split + 1));
        const auto& parameterType = strings.emplace_back(Trim(parameter.substr(0, split + 1)));
        details.params.push_back({ parameterName.c_str(), parameterType.c_str() });
    }
    return true;
}

void AddPrototype(PrototypeTable& table, const std::string& line)
{
    AsmFunctionDetails details;
    if (!ParsePrototypeText(table.strings, line, details, false) || table.byName.contains(details.functionName))
        return;
    const auto& added = table.functions.emplace_back(std::move(details));
    if (added.functionName.starts_with("operator ")) // the operators by their parameters (OperatorKey): operator delete(p,n)
        table.byName.emplace(table.strings.emplace_back(OperatorKey(added.prototype)), &added);
    else
        table.byName.emplace(added.functionName, &added);
}

const PrototypeTable& GetPrototypeTable()
{
    static const PrototypeTable table = [] {
        PrototypeTable result;
        for (const std::string_view line : PROTOTYPES) {
            if (line.find('%') == std::string_view::npos) {
                AddPrototype(result, std::string(line));
                continue;
            }
            // the A and the W functions
            const std::string text(line);
            AddPrototype(result, ReplaceAll(ReplaceAll(ReplaceAll(text, "%", "A"), "LPCTSTR", "LPCSTR"), "LPTSTR", "LPSTR"));
            AddPrototype(result, ReplaceAll(ReplaceAll(ReplaceAll(text, "%", "W"), "LPCTSTR", "LPCWSTR"), "LPTSTR", "LPWSTR"));
        }
        return result;
    }();
    return table;
}

// the parenthesis that opens the parameters of a demangled name, the one at `close` closes them (operator(), a pointer to a function among
// them); npos when they do not match
size_t FindParametersOpen(std::string_view text, size_t close)
{
    uint32 depth = 0;
    for (size_t index = close + 1; index-- > 0;) {
        if (text[index] == ')')
            depth++;
        else if (text[index] == '(' && --depth == 0)
            return index;
    }
    return std::string_view::npos;
}

// the parameters of a demangled name split at the commas outside of <>, () and [] (std::map<int, char>, void (*)(int, int)); none for (void)
std::vector<std::string_view> SplitDemangledParameters(std::string_view parameters)
{
    std::vector<std::string_view> result;
    uint32 depth = 0;
    size_t start = 0;
    for (size_t index = 0; index <= parameters.size(); index++) {
        const char c = index < parameters.size() ? parameters[index] : ',';
        if (c == '<' || c == '(' || c == '[')
            depth++;
        else if ((c == '>' || c == ')' || c == ']') && depth > 0)
            depth--;
        else if (c == ',' && (depth == 0 || index == parameters.size())) {
            result.push_back(Trim(parameters.substr(start, index - start)));
            start = index + 1;
        }
    }
    if (result.size() == 1 && (result[0].empty() || result[0] == "void"))
        result.clear();
    return result;
}

// the scope of a qualified name (std::locale::~locale: std::locale), before its last :: outside of the template arguments; empty for none
std::string_view ScopeOfName(std::string_view name)
{
    if (const auto op = name.find("::operator"); op != std::string_view::npos)
        return name.substr(0, op); // operator< / operator>>: not template arguments
    size_t last  = std::string_view::npos;
    uint32 depth = 0;
    for (size_t index = 0; index + 1 < name.size(); index++) {
        if (name[index] == '<')
            depth++;
        else if (name[index] == '>' && depth > 0)
            depth--;
        else if (depth == 0 && name[index] == ':' && name[index + 1] == ':')
            last = index++;
    }
    return last == std::string_view::npos ? std::string_view() : name.substr(0, last);
}

std::string_view WithoutTemplateArguments(std::string_view name)
{
    return name.substr(0, std::min(name.find('<'), name.size()));
}

// GCC: a constructor / destructor (std::locale::~locale: the last scope is its class, without the template arguments)
bool IsConstructorOrDestructor(std::string_view functionName, std::string_view scope)
{
    const std::string_view outer     = ScopeOfName(scope);
    const std::string_view className = WithoutTemplateArguments(outer.empty() ? scope : scope.substr(outer.size() + 2));
    const std::string_view own       = WithoutTemplateArguments(functionName.substr(scope.size() + 2));
    return !className.empty() && (own == className || (own.size() == className.size() + 1 && own.front() == '~' && own.substr(1) == className));
}

// GCC: a scope that is a namespace, never a class (the demangled names do not tell them apart): its functions take no this
bool IsGccNamespace(std::string_view scope)
{
    static constexpr std::string_view NAMESPACES[] = {
        "std",      "std::_V2",         "std::__cxx11", "std::__detail", "std::__exception_ptr", "std::chrono", "std::filesystem", "std::filesystem::__cxx11",
        "std::pmr", "std::this_thread", "__gnu_cxx",    "__cxxabiv1"
    };
    return std::find(std::begin(NAMESPACES), std::end(NAMESPACES), scope) != std::end(NAMESPACES);
}

// a pointer to a function (void (*)(void*), struct DirectUI::PropertyInfo const * (__cdecl *)(void)): one pointer; not a pointer to a member
// function (void (__cdecl A::*)(void): its size depends on the class)
bool IsPointerToFunction(std::string_view type)
{
    return type.ends_with(')') && type.find("*)(") != std::string_view::npos && type.find("::*") == std::string_view::npos;
}

// MSVC: a class / struct / union passed or returned by value (not a pointer or a reference to it, nor a pointer to a function returning one)
bool IsClassByValue(std::string_view type)
{
    return (type.starts_with("class ") || type.starts_with("struct ") || type.starts_with("union ")) && !type.ends_with('*') && !type.ends_with('&') &&
           !IsPointerToFunction(type);
}

// GCC: the integer registers of System V a parameter takes: 1 for a pointer, a reference, an integer, an enum of the standard library
// (std::_Ios_Iostate, std::align_val_t, std::filesystem::perms) or a class of one eightbyte of integers (__gnu_cxx::__normal_iterator,
// std::chrono::time_point of a long); 2 for a class of two (std::error_code, std::istreambuf_iterator, std::basic_string_view); 0 for a
// float (an xmm register) or a long double (the stack); -1 when not known (another class by value, an empty tag class, variadic)
int32 SystemVIntegerRegisters(std::string_view type)
{
    static constexpr std::string_view INTEGERS[] = { "bool",     "char",          "signed char", "unsigned char",     "wchar_t", "char8_t",
                                                     "char16_t", "char32_t",      "short",       "unsigned short",    "int",     "unsigned int",
                                                     "long",     "unsigned long", "long long",   "unsigned long long" };
    static constexpr std::string_view ENUMS[]    = { "std::_Ios_Iostate",
                                                     "std::_Ios_Openmode",
                                                     "std::_Ios_Seekdir",
                                                     "std::_Ios_Fmtflags",
                                                     "std::align_val_t",
                                                     "std::ios_base::event",
                                                     "std::memory_order",
                                                     "std::float_round_style",
                                                     "std::regex_constants::error_type",
                                                     "std::regex_constants::syntax_option_type",
                                                     "std::regex_constants::match_flag_type",
                                                     "std::filesystem::directory_options",
                                                     "std::filesystem::copy_options",
                                                     "std::filesystem::perms",
                                                     "std::filesystem::perm_options",
                                                     "std::filesystem::file_type",
                                                     "std::launch",
                                                     "std::future_status",
                                                     "std::errc",
                                                     "std::io_errc",
                                                     "std::future_errc",
                                                     "std::byte",
                                                     "__mbstate_t" };
    if (type.ends_with('*') || type.ends_with('&') || IsPointerToFunction(type) || std::find(std::begin(INTEGERS), std::end(INTEGERS), type) != std::end(INTEGERS) ||
        std::find(std::begin(ENUMS), std::end(ENUMS), type) != std::end(ENUMS) || type.starts_with("__gnu_cxx::__normal_iterator<") ||
        (type.starts_with("std::chrono::time_point<") && type.find("std::chrono::duration<long,") != std::string_view::npos))
        return 1;
    if (type == "std::error_code" || type == "std::error_condition" || type.starts_with("std::istreambuf_iterator<") ||
        type.starts_with("std::ostreambuf_iterator<") || type.starts_with("std::basic_string_view<"))
        return 2;
    if (type == "float" || type == "double" || type == "long double" || type == "__float128")
        return 0;
    return -1;
}

// GCC: the integer registers and the stack slots of System V the parameters take after `hidden` registers (this, the address of a result),
// their types (an empty one for the second eightbyte of a class of two): a class that does not fit in the registers left goes whole to the
// stack, the integers after it still in registers. The parameters up to the first one not known (`complete` false), the stack slots up to
// a long double (in the stack, aligned)
struct SystemVSlots {
    std::vector<std::string_view> registers;
    std::vector<std::string_view> stack;
    bool complete = true;
};

SystemVSlots AssignSystemVSlots(const std::vector<std::string_view>& parameters, uint32 hidden)
{
    SystemVSlots slots;
    bool stackKnown = true;
    for (const auto parameter : parameters) {
        const int32 taken = parameter == "..." ? -1 : SystemVIntegerRegisters(parameter);
        if (taken < 0) {
            slots.complete = false;
            break;
        }
        stackKnown = stackKnown && parameter != "long double";
        auto& to   = hidden + slots.registers.size() + static_cast<uint32>(taken) <= 6 ? slots.registers : slots.stack;
        for (int32 half = 0; half < taken && (&to == &slots.registers || stackKnown); half++)
            to.push_back(half == 0 ? parameter : std::string_view());
        if (&to == &slots.stack && !stackKnown) {
            slots.complete = false;
            break;
        }
    }
    return slots;
}

// the prototype a demangled C++ name tells, its parameters named by their types (IDA: ; unsigned int), null when it does not tell its
// arguments surely:
// - MSVC (public: long __cdecl DirectUI::Element::SetLayoutPos(int)): a method (an access, not static) takes this first (__thiscall of 32
//   bit x86: in ecx, no pushed argument), then the address of what it returns when that is a class / struct / union (result); none for a
//   function or a static method returning one by value (in rax or not: its size), the other conventions, a class passed by value (several
//   pushes on 32 bit x86), a pointer to a function returned
// - GCC (std::locale::~locale(), std::runtime_error::runtime_error(char const*)): the constructors and the destructors only (the name of
//   Itanium tells neither a static method nor what a method returns through a hidden pointer before this); its parameters up to the first
//   one that takes no integer register of System V (a float, a class by value), none of a stream (a virtual base: the VTT after this)
std::unique_ptr<DissasmUserPrototype> MakeDemangledPrototype(std::string_view name)
{
    // the number of a name given twice (std::ios_base::~ios_base()_1), the qualifiers after the parameters (const, &, __ptr64)
    size_t end = name.size();
    while (end > 0 && name[end - 1] >= '0' && name[end - 1] <= '9')
        end--;
    if (end < name.size() && end > 1 && name[end - 1] == '_' && name[end - 2] == ')')
        name = name.substr(0, end - 1);
    const auto close = name.rfind(')');
    if (close == std::string_view::npos || std::any_of(name.begin() + close + 1, name.end(), [](char c) {
            return !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == ' ' || c == '&');
        }))
        return nullptr;
    const auto open = FindParametersOpen(name, close);
    if (open == std::string_view::npos || open == 0)
        return nullptr;
    const std::string_view head = Trim(name.substr(0, open));
    if (head.empty() || head.front() == '[' || (head.find('(') != std::string_view::npos && !head.ends_with("operator()")))
        return nullptr; // [thunk]:, a pointer to a function returned
    const auto parameters = SplitDemangledParameters(name.substr(open + 1, close - open - 1));

    // MSVC: the access, static / virtual, the return type, the convention before the name
    std::string_view rest = head;
    bool member = false, isStatic = false;
    for (const std::string_view access : { std::string_view("public: "), std::string_view("protected: "), std::string_view("private: ") })
        if (rest.starts_with(access)) {
            member = true;
            rest.remove_prefix(access.size());
        }
    if (rest.starts_with("static "))
        isStatic = true;
    if (rest.starts_with("static ") || rest.starts_with("virtual "))
        rest.remove_prefix(rest.find(' ') + 1);
    std::string_view convention;
    size_t conventionStart = std::string_view::npos;
    for (const std::string_view candidate : { std::string_view("__cdecl"),
                                              std::string_view("__thiscall"),
                                              std::string_view("__stdcall"),
                                              std::string_view("__fastcall"),
                                              std::string_view("__vectorcall"),
                                              std::string_view("__clrcall") })
        for (size_t found = rest.find(candidate); found != std::string_view::npos; found = rest.find(candidate, found + 1))
            if ((found == 0 || rest[found - 1] == ' ') && found + candidate.size() < rest.size() && rest[found + candidate.size()] == ' ' &&
                (conventionStart == std::string_view::npos || found > conventionStart)) {
                conventionStart = found;
                convention      = candidate;
            }

    auto prototype      = std::make_unique<DissasmUserPrototype>();
    auto& details       = prototype->details;
    details.demangled   = true;
    const auto& unnamed = prototype->strings.emplace_back();
    std::string text;
    std::string_view functionName;
    std::vector<std::string_view> kept; // the parameters with their argument known
    bool variadic = false;
    if (!convention.empty()) {
        if (convention != "__cdecl" && convention != "__thiscall" && convention != "__stdcall")
            return nullptr;
        const std::string_view returnType = Trim(rest.substr(0, conventionStart));
        functionName                      = Trim(rest.substr(conventionStart + convention.size()));
        const bool hasThis                = member && !isStatic;
        const std::string_view scope      = ScopeOfName(functionName);
        if (functionName.empty() || (hasThis && scope.empty()) || (IsClassByValue(returnType) && !hasThis))
            return nullptr;
        details.callerCleansStack = convention == "__cdecl";
        text = (returnType.empty() ? std::string() : std::string(returnType) + " ") + std::string(convention) + " " + std::string(functionName) + "(";
        if (hasThis) {
            const auto& thisType = prototype->strings.emplace_back(std::string(scope) + "*");
            text += thisType + " this";
            if (convention != "__thiscall") // __thiscall: this in ecx
                details.params.push_back({ "this", thisType.c_str() });
        }
        if (IsClassByValue(returnType)) { // the address of what a method returns (after this)
            const auto& resultType = prototype->strings.emplace_back(std::string(returnType) + "*");
            text += ", " + resultType + " result";
            details.params.push_back({ "result", resultType.c_str() });
        } else if (returnType != "void") {
            details.returnType = prototype->strings.emplace_back(returnType);
        }
        for (const auto parameter : parameters) {
            if (IsClassByValue(parameter))
                return nullptr;
            if (parameter == "...") {
                variadic = true;
                break;
            }
            kept.push_back(parameter);
        }
        for (const auto parameter : parameters)
            text += (text.ends_with('(') ? "" : ", ") + std::string(parameter);
    } else {
        // GCC: a constructor / destructor, no return type (a space outside of the template arguments)
        uint32 depth = 0;
        for (const char c : head) {
            if (c == '<')
                depth++;
            else if (c == '>' && depth > 0)
                depth--;
            else if (c == ' ' && depth == 0)
                return nullptr;
        }
        if (member || isStatic)
            return nullptr;
        functionName                 = head;
        const std::string_view scope = ScopeOfName(functionName);
        if (scope.empty())
            return nullptr;
        if (scope == "std" && functionName.substr(scope.size() + 2).starts_with("__throw_")) {
            // std::__throw_logic_error(char const*), std::__throw_out_of_range_fmt(char const*, ...): a function of the namespace std that never
            // returns (no address of a result before its parameters, whatever the code of another file reads; no this): its parameters in the
            // registers of System V; the string before the variadic arguments of a function named *_fmt is its format
            details.callerCleansStack = true;
            text                      = std::string(functionName) + "(";
            for (const auto parameter : parameters) {
                text += (text.ends_with('(') ? "" : ", ") + std::string(parameter);
                variadic = variadic || parameter == "...";
            }
            const auto slots = AssignSystemVSlots(parameters, 0);
            kept             = slots.registers;
            if (!slots.stack.empty())
                kept.resize(6);
            kept.insert(kept.end(), slots.stack.begin(), slots.stack.end());
            const bool format = variadic && functionName.ends_with("_fmt") && !kept.empty() && kept.size() + 1 == parameters.size() &&
                                (kept.back() == "char const*" || kept.back() == "wchar_t const*");
            for (size_t index = 0; index < kept.size(); index++)
                details.params.push_back({ format && index + 1 == kept.size() ? prototype->strings.emplace_back("format").c_str() : unnamed.c_str(),
                                           prototype->strings.emplace_back(kept[index]).c_str() });
            details.prototype    = prototype->strings.emplace_back(text + ")");
            details.functionName = prototype->strings.emplace_back(functionName);
            return prototype;
        }
        if (!IsConstructorOrDestructor(functionName, scope))
            return nullptr;
        const std::string_view outer     = ScopeOfName(scope);
        const std::string_view className = WithoutTemplateArguments(outer.empty() ? scope : scope.substr(outer.size() + 2));
        details.callerCleansStack        = true;
        const auto& thisType             = prototype->strings.emplace_back(std::string(scope) + "*");
        text                             = std::string(functionName) + "(" + thisType + " this";
        details.params.push_back({ "this", thisType.c_str() });
        for (const auto parameter : parameters) {
            text += ", " + std::string(parameter);
            variadic = variadic || parameter == "...";
        }
        if (!className.ends_with("stream")) { // a stream: the VTT of its virtual base after this
            // the registers after this, the stack slots after the sixth (a class of two eightbytes: its second without a type)
            const auto slots = AssignSystemVSlots(parameters, 1);
            kept             = slots.registers;
            if (!slots.stack.empty())
                kept.resize(5);
            kept.insert(kept.end(), slots.stack.begin(), slots.stack.end());
        }
    }
    for (const auto parameter : kept)
        details.params.push_back({ unnamed.c_str(), prototype->strings.emplace_back(parameter).c_str() });
    if (variadic && !text.ends_with("..."))
        text += text.ends_with('(') ? "..." : ", ...";
    details.prototype    = prototype->strings.emplace_back(text + ")");
    details.functionName = prototype->strings.emplace_back(functionName);
    return prototype;
}

// the prototypes of the demangled names met (MakeDemangledPrototype), the names without one too (null); not past 0x10000 names (a hostile
// file: then none)
const AsmFunctionDetails* FindDemangledPrototype(std::string_view name)
{
    constexpr size_t MAX_NAMES     = 0x10000;
    constexpr size_t MAX_NAME_SIZE = 0x1000;
    static std::mutex lock;
    static std::map<std::string, std::unique_ptr<DissasmUserPrototype>, std::less<>> known;
    if (name.size() > MAX_NAME_SIZE)
        return nullptr;
    const std::lock_guard<std::mutex> guard(lock);
    if (const auto found = known.find(name); found != known.end())
        return found->second ? &found->second->details : nullptr;
    if (known.size() >= MAX_NAMES)
        return nullptr;
    const auto& added = known.emplace(std::string(name), MakeDemangledPrototype(name)).first->second;
    return added ? &added->details : nullptr;
}

// GCC: a demangled name that is no constructor / destructor, operator new / delete or name of MSVC (GetGccMethodParameters): the function,
// the return type of a template before it (std::basic_istream<char, ...>& std::ws<char, ...>(...)), the qualifiers after its parameters, the
// parameters (each of a known class of System V: AssignSystemVSlots)
struct GccMethodName {
    std::string_view functionName;
    std::string_view returnType;
    std::string_view qualifiers;
    std::vector<std::string_view> parameters;
};

std::optional<GccMethodName> ParseGccMethodName(std::string_view name)
{
    size_t end = name.size();
    while (end > 0 && name[end - 1] >= '0' && name[end - 1] <= '9')
        end--;
    if (end < name.size() && end > 1 && name[end - 1] == '_' && name[end - 2] == ')')
        name = name.substr(0, end - 1);
    const auto close = name.rfind(')');
    if (close == std::string_view::npos || !OperatorKey(name).empty() ||
        std::any_of(name.begin() + close + 1, name.end(), [](char c) { return !((c >= 'a' && c <= 'z') || c == ' ' || c == '&'); }))
        return std::nullopt;
    const auto open = FindParametersOpen(name, close);
    if (open == std::string_view::npos || open == 0)
        return std::nullopt;
    const std::string_view head = Trim(name.substr(0, open));
    if (head.empty() || head.front() == '[' || (head.find('(') != std::string_view::npos && !head.ends_with("operator()")) || head.starts_with("public: ") ||
        head.starts_with("protected: ") || head.starts_with("private: "))
        return std::nullopt;
    for (const std::string_view convention : { std::string_view("__cdecl "),
                                               std::string_view("__thiscall "),
                                               std::string_view("__stdcall "),
                                               std::string_view("__fastcall "),
                                               std::string_view("__vectorcall "),
                                               std::string_view("__clrcall ") })
        if (const auto found = head.find(convention); found != std::string_view::npos && (found == 0 || head[found - 1] == ' '))
            return std::nullopt;
    // the return type of a template: before the last space outside of the template arguments (not after operator: operator bool)
    size_t nameStart = 0;
    uint32 depth     = 0;
    for (size_t index = 0; index < std::min(head.find("operator"), head.size()); index++) {
        if (head[index] == '<')
            depth++;
        else if (head[index] == '>' && depth > 0)
            depth--;
        else if (head[index] == ' ' && depth == 0)
            nameStart = index + 1;
    }
    GccMethodName parsed{
        head.substr(nameStart), Trim(head.substr(0, nameStart)), name.substr(close + 1), SplitDemangledParameters(name.substr(open + 1, close - open - 1))
    };
    if (const auto scope = ScopeOfName(parsed.functionName); !scope.empty() && IsConstructorOrDestructor(parsed.functionName, scope))
        return std::nullopt; // MakeDemangledPrototype
    if (parsed.functionName.empty() || !AssignSystemVSlots(parsed.parameters, 0).complete)
        return std::nullopt; // a class by value, variadic, ...: the registers after it not known
    return parsed;
}
} // namespace

const AsmFunctionDetails* GView::View::DissasmViewer::FindApiPrototype(std::string_view name)
{
    // the import / thunk prefixes (the forwarders of the UCRT: _o__wcsicmp is _wcsicmp; the hidden aliases of glibc: __GI___fcntl64_nocancel),
    // the version / PLT / stdcall suffixes (as
    // IsNoReturnFunctionName)
    for (bool stripped = true; stripped;) {
        stripped = false;
        for (const std::string_view prefix :
             { std::string_view("__imp_"), std::string_view("_imp__"), std::string_view("j_"), std::string_view("_o_"), std::string_view("__GI_") })
            if (name.size() > prefix.size() && name.starts_with(prefix)) {
                name.remove_prefix(prefix.size());
                stripped = true;
            }
    }
    if (const auto at = name.find('@'); at != std::string_view::npos && at > 0)
        name = name.substr(0, at);
    const auto& byName = GetPrototypeTable().byName;
    if (const auto key = OperatorKey(name); !key.empty()) { // a demangled operator new / delete (its parameters choose the line)
        const auto found = byName.find(key);
        return found != byName.end() ? found->second : nullptr;
    }
    if (name.find('(') != std::string_view::npos) // another demangled C++ name: what its form tells (MakeDemangledPrototype)
        return FindDemangledPrototype(name);
    if (const auto found = byName.find(name); found != byName.end())
        return found->second;
    if (name.size() > 2 && name.starts_with("Zw")) { // the Zw functions are the Nt ones
        const std::string nt = "Nt" + std::string(name.substr(2));
        if (const auto found = byName.find(nt); found != byName.end())
            return found->second;
    }
    if (name.size() > 1 && name.front() == '_') // Mach-O / 32 bit Windows: _connect, _CreateFileA
        if (const auto found = byName.find(name.substr(1)); found != byName.end())
            return found->second;
    return nullptr;
}

size_t GView::View::DissasmViewer::GetApiPrototypesCount()
{
    return GetPrototypeTable().functions.size();
}

void GView::View::DissasmViewer::ForEachApiPrototype(const std::function<void(const AsmFunctionDetails&)>& callback)
{
    for (const auto& details : GetPrototypeTable().functions)
        callback(details);
}

bool GView::View::DissasmViewer::IsWideX86Type(std::string_view type)
{
    static constexpr std::string_view WIDE_TYPES[] = {
        "__int64",       "long long",      "unsigned long long", "LONGLONG",   "ULONGLONG", "DWORD64", "QWORD",     "int64_t",     "uint64_t",        "double",
        "LARGE_INTEGER", "ULARGE_INTEGER", "REGHANDLE",          "POOL_FLAGS", "ULONG64",   "POINT",   "DWORDLONG", "TRACEHANDLE", "unsigned __int64"
    };
    return std::find(std::begin(WIDE_TYPES), std::end(WIDE_TYPES), Trim(type)) != std::end(WIDE_TYPES);
}

std::optional<uint32> GView::View::DissasmViewer::GetX86StdcallPushes(const AsmFunctionDetails& prototype)
{
    const std::string_view name = prototype.functionName;
    const bool lowercase        = std::all_of(name.begin(), name.end(), [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; });
    if (prototype.prototype.find("...") != std::string_view::npos || (lowercase && (GetApiCategories(name) & API_NETWORK) == 0) ||
        name.starts_with("operator ") || prototype.callerCleansStack)
        return std::nullopt; // cdecl: the C run-time, the variadic APIs, the operators of C++, the __cdecl functions of C++
    uint32 pushes = 0;
    for (const auto& parameter : prototype.params)
        pushes += IsWideX86Type(parameter.type) ? 2u : 1u;
    return pushes;
}

std::shared_ptr<const DissasmUserPrototype> GView::View::DissasmViewer::ParseApiPrototype(std::string_view text)
{
    auto prototype = std::make_shared<DissasmUserPrototype>();
    if (!ParsePrototypeText(prototype->strings, std::string(Trim(text)), prototype->details, false))
        return nullptr;
    return prototype;
}

bool GView::View::DissasmViewer::IsCxxConstructorOrDestructor(std::string_view functionName)
{
    const auto scope = ScopeOfName(functionName);
    return !scope.empty() && IsConstructorOrDestructor(functionName, scope);
}

std::optional<uint32> GView::View::DissasmViewer::GetGccMethodParameters(std::string_view name)
{
    const auto parsed = name.find('(') != std::string_view::npos ? ParseGccMethodName(name) : std::nullopt;
    if (!parsed.has_value())
        return std::nullopt;
    const auto slots = AssignSystemVSlots(parsed->parameters, 0);
    return static_cast<uint32>(slots.registers.size() + slots.stack.size());
}

std::shared_ptr<const DissasmUserPrototype> GView::View::DissasmViewer::MakeGccMethodPrototype(
      std::string_view name, int32 highestRead, bool readsFirstArgument, bool staticMethod)
{
    const auto parsed = ParseGccMethodName(name);
    if (!parsed.has_value())
        return nullptr;
    // the arguments before its parameters: 1 is this for a const method, the address of what it returns for a function without a scope,
    // else either (a static method / a function of a namespace returning a class); 2 are that address, then this. The highest register read
    // is the last of the arguments for the one count that fits; with the six registers read two may fit: the return type of a template
    // in a register (or none) leaves no address of a result (a const method of it: this alone, whatever it reads)
    const std::string_view scope = ScopeOfName(parsed->functionName);
    const bool isConst           = parsed->qualifiers.find("const") != std::string_view::npos;
    const bool returnInRegisters = !parsed->returnType.empty() && (parsed->returnType == "void" || SystemVIntegerRegisters(parsed->returnType) >= 0);
    // a function of a namespace (std::filesystem::status, std::_Hash_bytes): no this; none or the address of what it returns before its
    // parameters (std::filesystem::space returns a space_info)
    const bool inNamespace = IsGccNamespace(scope);
    if ((scope.empty() || inNamespace || staticMethod) && isConst)
        return nullptr;
    // a static method (std::locale::facet::_S_destroy_c_locale(__locale_struct*&)): no this, nothing before its parameters
    const bool noThis = inNamespace || (staticMethod && !scope.empty());
    int32 hidden      = -1;
    SystemVSlots slots;
    for (int32 candidate = noThis ? 0 : 1; candidate <= (staticMethod ? 0 : 2); candidate++) {
        if ((candidate == 2 && (scope.empty() || inNamespace || returnInRegisters)) || (candidate == 1 && (scope.empty() || inNamespace) && returnInRegisters))
            continue;
        auto assigned    = AssignSystemVSlots(parsed->parameters, static_cast<uint32>(candidate));
        const int32 last = candidate + static_cast<int32>(assigned.registers.size()) - 1;
        if (highestRead == last || (candidate == 1 && isConst && returnInRegisters && highestRead < last)) {
            if (hidden >= 0 && !slots.stack.empty())
                return nullptr; // both fit
            if (hidden >= 0)
                break; // both fit, this alone with every parameter in a register (as 9v: far more common than a result in memory)
            hidden = candidate;
            slots  = std::move(assigned);
        }
    }
    if (hidden < 0)
        return nullptr;
    auto prototype            = std::make_shared<DissasmUserPrototype>();
    auto& details             = prototype->details;
    details.demangled         = true;
    details.callerCleansStack = true;
    const auto& unnamed       = prototype->strings.emplace_back();
    const auto& thisType      = prototype->strings.emplace_back(std::string(scope) + "*");
    std::string text          = std::string(parsed->functionName) + "(";
    if (hidden == 2 || ((scope.empty() || inNamespace) && hidden == 1)) { // the address of what it returns (a function: no this)
        details.params.push_back({ "result", unnamed.c_str() });
        text += hidden == 2 ? "void* result, " : "void* result";
    }
    if (noThis) {
        // no this
    } else if (hidden == 2 || isConst || (!scope.empty() && (returnInRegisters || readsFirstArgument))) { // the object read: no result written first
        details.params.push_back({ "this", thisType.c_str() });
        text += thisType + " this";
    } else if (!scope.empty()) { // this, or the address of what a static method / a function of a namespace returns
        details.params.push_back({ unnamed.c_str(), unnamed.c_str() });
        text += "a1";
    }
    for (const auto type : slots.registers) // a float takes none, a class of two eightbytes two (the second without a type)
        details.params.push_back({ unnamed.c_str(), prototype->strings.emplace_back(type).c_str() });
    for (size_t index = 0; index < slots.stack.size(); index++) { // the stack slots after the sixth (pushed: 9y)
        while (index == 0 && details.params.size() < 6)
            details.params.push_back({ unnamed.c_str(), unnamed.c_str() });
        details.params.push_back({ unnamed.c_str(), prototype->strings.emplace_back(slots.stack[index]).c_str() });
    }
    for (const auto parameter : parsed->parameters)
        text += (text.ends_with('(') ? "" : ", ") + std::string(parameter);
    details.prototype    = prototype->strings.emplace_back(text + ")" + std::string(parsed->qualifiers));
    details.functionName = prototype->strings.emplace_back(parsed->functionName);
    return prototype;
}

std::string GView::View::DissasmViewer::EditablePrototypeName(std::string_view name)
{
    // a demangled name: without its parameters and qualifiers (and the number of a name given twice), without the return type of a template
    const auto close = name.rfind(')');
    if (close == std::string_view::npos)
        return std::string(name);
    const auto open = FindParametersOpen(name, close);
    if (open == std::string_view::npos || open == 0)
        return std::string(name);
    std::string_view head  = Trim(name.substr(0, open));
    const auto operatorAt  = head.find("operator");
    const auto returnTypes = LastSeparatorOutsideTemplates(head.substr(0, std::min(operatorAt, head.size())));
    if (returnTypes != std::string_view::npos && head[returnTypes] == ' ')
        head.remove_prefix(returnTypes + 1);
    return std::string(head);
}

std::string GView::View::DissasmViewer::FormatEditablePrototype(const AsmFunctionDetails& details)
{
    std::string text =
          (details.returnType.empty() ? std::string("void") : std::string(details.returnType)) + " " + EditablePrototypeName(details.functionName) + "(";
    for (size_t index = 0; index < details.params.size(); index++) {
        const std::string_view name = details.params[index].name ? details.params[index].name : "";
        const std::string_view type = details.params[index].type ? details.params[index].type : "";
        text += (index > 0 ? ", " : "") + (type.empty() ? std::string("void*") : std::string(type)) + " " +
                (name.empty() ? "a" + std::to_string(index + 1) : std::string(name));
    }
    return text + ")";
}

std::shared_ptr<const DissasmUserPrototype> GView::View::DissasmViewer::ParseUserPrototype(std::string_view text)
{
    const std::string_view trimmed = Trim(text);
    if (trimmed.empty() || trimmed.size() > DISSASM_MAX_USER_PROTOTYPE_SIZE)
        return nullptr;
    auto prototype = std::make_shared<DissasmUserPrototype>();
    if (!ParsePrototypeText(prototype->strings, std::string(trimmed), prototype->details, true))
        return nullptr;
    return prototype;
}

std::string GView::View::DissasmViewer::GetPointedType(std::string_view type)
{
    // the P / LP types of the table that are not pointers
    static constexpr std::string_view NOT_POINTERS[] = { "LPARAM", "POOL_TYPE", "PROCESSINFOCLASS" };
    type = Trim(type);
    std::string_view pointed;
    if (!type.empty() && type.back() == '*') { // char* / HMODULE* / char* const*: the const of the pointer dropped
        pointed = Trim(type.substr(0, type.size() - 1));
        if (pointed.ends_with(" const"))
            pointed = Trim(pointed.substr(0, pointed.size() - 6));
    } else if (std::find(std::begin(NOT_POINTERS), std::end(NOT_POINTERS), type) != std::end(NOT_POINTERS)) {
        return {};
    } else {
        // the Windows pointer types: REFIID, LPCWSTR, LPDWORD, PHKEY (a prefix, then the upper case name of the pointed type)
        for (const std::string_view prefix : { std::string_view("REF"), std::string_view("LPC"), std::string_view("LP"), std::string_view("P") })
            if (type.size() > prefix.size() && type.starts_with(prefix) && type[prefix.size()] >= 'A' && type[prefix.size()] <= 'Z') {
                pointed = type.substr(prefix.size());
                break;
            }
        if (pointed.empty() || std::any_of(type.begin(), type.end(), [](char c) { return c >= 'a' && c <= 'z'; }))
            return {};
        // the strings: their characters
        if (pointed == "STR" || pointed == "CSTR" || pointed == "CH" || pointed == "CCH")
            return "CHAR";
        if (pointed == "WSTR" || pointed == "CWSTR" || pointed == "WCH" || pointed == "CWCH")
            return "WCHAR";
        if (pointed == "TSTR" || pointed == "CTSTR")
            return "TCHAR";
    }
    if (pointed.starts_with("const "))
        pointed.remove_prefix(6);
    if (pointed.empty() || pointed == "void" || pointed == "VOID" || pointed == "CVOID")
        return {};
    return std::string(pointed);
}

std::string GView::View::DissasmViewer::GetReturnValueName(const AsmFunctionDetails& function)
{
    if (!function.returnName.empty())
        return std::string(function.returnName);
    std::string_view name = function.functionName;
    if (name.starts_with("operator new")) // what the operator gives: new_result, new_array_result
        return name.ends_with("[]") ? "new_array_result" : "new_result";
    // the A and the W functions of a line: the ending dropped (CreateFileW -> CreateFile)
    if (name.size() > 1 && (name.back() == 'A' || name.back() == 'W')) {
        std::string other(name);
        other.back() = name.back() == 'A' ? 'W' : 'A';
        if (GetPrototypeTable().byName.contains(other))
            name.remove_suffix(1);
    }
    // a status is not the object of the verb (CreateProcessW returns a BOOL, NtCreateFile an NTSTATUS): no name of an object
    static constexpr std::string_view STATUS_TYPES[] = { "BOOL", "BOOLEAN", "NTSTATUS", "LSTATUS", "HRESULT" };
    if (std::find(std::begin(STATUS_TYPES), std::end(STATUS_TYPES), function.returnType) != std::end(STATUS_TYPES))
        return std::string(name) + "_result";
    const auto startsWithWord = [](std::string_view text, std::string_view word) {
        return text.size() > word.size() && text.starts_with(word) && text[word.size()] >= 'A' && text[word.size()] <= 'Z';
    };
    // the verb after the prefix of a kernel / native component: ExAllocatePoolWithTag -> PoolWithTag, MmGetSystemRoutineAddress
    std::string_view verbs = name;
    for (const std::string_view component : { "Ex", "Io", "Ke", "Mm", "Ob", "Ps", "Rtl", "Nt", "Zw" })
        if (startsWithWord(name, component)) {
            verbs = name.substr(component.size());
            break;
        }
    for (const std::string_view verb : { "Get", "Create", "Open", "Load", "Find", "Allocate" })
        if (startsWithWord(verbs, verb))
            return std::string(verbs.substr(verb.size()));
    return std::string(name) + "_result";
}

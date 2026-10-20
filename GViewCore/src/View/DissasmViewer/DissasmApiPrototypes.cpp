#include "DissasmViewer.hpp"

#include <algorithm>
#include <deque>
#include <memory>

using namespace GView::View::DissasmViewer;

namespace
{
// The prototypes of the common APIs: the Windows API (kernel32, advapi32, user32, gdi32, shell32, ws2_32, wininet, winhttp, crypt32,
// bcrypt, ntdll, the kernel) and the C run-time / POSIX (a literal each: MSVC limits a literal to 16 KB). A % in the name is the A and the W function (LPCTSTR / LPTSTR become
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
    "HANDLE FindFirstFile%(LPCTSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData)",
    "BOOL FindNextFile%(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData)",
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
    "BOOL CreateProcess%(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)",
    "BOOL CreateProcessAsUser%(HANDLE hToken, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)",
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
    "BOOL ShellExecuteEx%(LPSHELLEXECUTEINFO pExecInfo)",
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
    "void qsort(void* base, size_t num, size_t width, void* compare)",
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

// "HANDLE CreateFileW(LPCWSTR lpFileName, ...)": the function, its parameters (the name after the last space or *, the type before it)
void AddPrototype(PrototypeTable& table, const std::string& line)
{
    const auto open  = line.find('(');
    const auto close = line.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close < open)
        return;
    const auto& text = table.strings.emplace_back(line);
    const std::string_view head = Trim(std::string_view(text).substr(0, open));
    const auto nameStart        = head.find_last_of(" *");
    const std::string_view name = nameStart == std::string_view::npos ? head : head.substr(nameStart + 1);
    if (name.empty() || table.byName.contains(name))
        return;
    auto& details        = table.functions.emplace_back();
    details.functionName = name;
    details.prototype    = text;
    if (const std::string_view returnType = Trim(head.substr(0, nameStart == std::string_view::npos ? 0 : nameStart + 1));
        returnType != "void" && returnType != "VOID")
        details.returnType = returnType;
    std::string_view parameters = std::string_view(text).substr(open + 1, close - open - 1);
    while (!parameters.empty()) {
        const auto comma          = parameters.find(',');
        const std::string_view parameter = Trim(parameters.substr(0, comma));
        parameters                = comma == std::string_view::npos ? std::string_view() : parameters.substr(comma + 1);
        if (parameter.empty() || parameter == "void" || parameter == "...")
            continue;
        const auto split = parameter.find_last_of(" *");
        if (split == std::string_view::npos)
            continue;
        const auto& parameterName = table.strings.emplace_back(parameter.substr(split + 1));
        const auto& parameterType = table.strings.emplace_back(Trim(parameter.substr(0, split + 1)));
        details.params.push_back({ parameterName.c_str(), parameterType.c_str() });
    }
    table.byName.emplace(name, &details);
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
} // namespace

const AsmFunctionDetails* GView::View::DissasmViewer::FindApiPrototype(std::string_view name)
{
    // the import / thunk prefixes, the version / PLT / stdcall suffixes (as IsNoReturnFunctionName)
    for (bool stripped = true; stripped;) {
        stripped = false;
        for (const std::string_view prefix : { std::string_view("__imp_"), std::string_view("_imp__"), std::string_view("j_") })
            if (name.size() > prefix.size() && name.starts_with(prefix)) {
                name.remove_prefix(prefix.size());
                stripped = true;
            }
    }
    if (const auto at = name.find('@'); at != std::string_view::npos && at > 0)
        name = name.substr(0, at);
    const auto& byName = GetPrototypeTable().byName;
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
    std::string_view name = function.functionName;
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

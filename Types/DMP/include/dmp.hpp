#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace DMP
    {
        //littel / big endian
        const uint32 MAGIC_1 = 0x4D444D50;
        #pragma pack(push, 4)
        //file header structure
        struct Header {
            uint32_t Signature;
            uint32_t Version;
            uint32_t NumberOfStreams;
            uint32_t StreamDirectoryRva;
            uint32_t CheckSum;
            uint32_t TimeDateStamp;
            uint64_t Flags;
        };
        //this is the basic structure of a minidump location component having 2 fields
        //the amount of data in the component and the starting location in the file
        struct MINIDUMP_LOCATION_DESCRIPTOR {
            uint32_t DataSize;
            uint32_t Rva;
        };
        // stream type - information type available defined in this structure "MINIDUMP_STREAM_TYPE"
        struct MINIDUMP_DIRECTORY {
            uint32_t StreamType;
            MINIDUMP_LOCATION_DESCRIPTOR Location;
        };
        //
        struct MINIDUMP_STRING {
            uint32_t Length;
            wchar_t Buffer[1];
        };
        //custom structure for the system_info partition
        //aka MINIDUMP_STREAM_TYPE = 7
        struct MINIDUMP_SYSTEM_INFO {
            uint16_t ProcessorArchitecture;
            uint16_t ProcessorLevel;
            uint16_t ProcessorRevision;
            uint8_t NumberOfProcessors;
            uint8_t ProductType;
            uint32_t MajorVersion;
            uint32_t MinorVersion;
            uint32_t BuildNumber;
            uint32_t PlatformId;
            uint32_t CSDVersionRva;
            uint16_t SuiteMask;
            uint16_t Reserved2;
        };
        // custom structure for the exception details partition
        // aka MINIDUMP_STREAM_TYPE = 6
        struct MINIDUMP_EXCEPTION {
            uint32_t ExceptionCode;
            uint32_t ExceptionFlags;
            uint64_t ExceptionRecord;
            uint64_t ExceptionAddress;
            uint32_t NumberParameters;
            uint32_t __unusedAlignment;
            uint64_t ExceptionInformation[15];
        };
        // custom structure for the exception stream
        struct MINIDUMP_EXCEPTION_STREAM {
            uint32_t ThreadId;
            uint32_t __alignment;
            MINIDUMP_EXCEPTION ExceptionRecord;
            MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
        };

        struct MINIDUMP_THREAD {
            uint32_t ThreadId;
            uint32_t SuspendCount;
            uint32_t PriorityClass;
            uint32_t Priority;
            uint64_t Teb;
            MINIDUMP_LOCATION_DESCRIPTOR Stack;
            MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
        };

        struct MINIDUMP_THREAD_LIST {
            uint32_t NumberOfThreads;
            MINIDUMP_THREAD Threads[1];
        };
        //information about a specific module
        struct MINIDUMP_MODULE {
            uint64_t BaseOfImage;
            uint32_t SizeOfImage;
            uint32_t CheckSum;
            uint32_t TimeDateStamp;
            uint32_t ModuleNameRva;
            uint8_t VersionInfo[52];
            MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
            MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
            uint64_t Reserved0;
            uint64_t Reserved1;
        };

        struct MINIDUMP_MODULE_LIST {
            uint32_t NumberOfModules;
            MINIDUMP_MODULE Modules[1];
        };

        struct MINIDUMP_MEMORY_DESCRIPTOR {
            uint64_t StartOfMemoryRange;
            MINIDUMP_LOCATION_DESCRIPTOR Memory;
        };

        struct MINIDUMP_MEMORY_LIST {
            uint32_t NumberOfMemoryRanges;
            MINIDUMP_MEMORY_DESCRIPTOR MemoryRanges[1];
        };

        struct MINIDUMP_MEMORY_DESCRIPTOR64 {
            uint64_t StartOfMemoryRange;
            uint64_t DataSize;
        };

        struct MINIDUMP_MEMORY64_LIST {
            uint64_t NumberOfMemoryRanges;
            uint64_t BaseRva;
            MINIDUMP_MEMORY_DESCRIPTOR64 MemoryRanges[1];
        };

        struct CONTEXT_X86 {
            uint32_t ContextFlags;
            uint32_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            uint32_t SegGs, SegFs, SegEs, SegDs;
            uint32_t Edi, Esi, Ebx, Edx, Ecx, Eax;
            uint32_t Ebp, Eip, SegCs, EFlags, Esp, SegSs;
        };

        struct CONTEXT_AMD64 {
            uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            uint32_t ContextFlags;
            uint32_t MxCsr;
            uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            uint32_t EFlags;
            uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
        };
        struct MINIDUMP_THREAD_NAME {
            uint32_t ThreadId;
            uint64_t StackNameRva;
        };

        struct MINIDUMP_THREAD_NAME_LIST {
            uint32_t NumberOfThreadNames;
            MINIDUMP_THREAD_NAME ThreadNames[1];
        };


        #pragma pack(pop)
        //the list of all available module types
        enum MINIDUMP_STREAM_TYPE {
            UnusedStream                = 0,
            ReservedStream0             = 1,
            ReservedStream1             = 2,
            ThreadListStream            = 3,
            ModuleListStream            = 4,
            MemoryListStream            = 5,
            ExceptionStream             = 6,
            SystemInfoStream            = 7,
            ThreadExListStream          = 8,
            Memory64ListStream          = 9,
            CommentStreamA              = 10,
            CommentStreamW              = 11,
            HandleDataStream            = 12,
            FunctionTableStream         = 13,
            UnloadedModuleListStream    = 14,
            MiscInfoStream              = 15,
            MemoryInfoListStream        = 16,
            ThreadInfoListStream        = 17,
            HandleOperationListStream   = 18,
            TokenStream                 = 19,
            JavaScriptDataStream        = 20,
            SystemMemoryInfoStream      = 21,
            ProcessVmCountersStream     = 22,
            IptTraceStream              = 23,
            ThreadNamesStream           = 24,
            ceStreamNull                = 0x8000,
            ceStreamSystemInfo          = 0x8001,
            ceStreamException           = 0x8002,
            ceStreamModuleList          = 0x8003,
            ceStreamProcessList         = 0x8004,
            ceStreamThreadList          = 0x8005,
            ceStreamThreadContextList   = 0x8006,
            ceStreamThreadCallStackList = 0x8007,
            ceStreamMemoryVirtualList   = 0x8008,
            ceStreamMemoryPhysicalList  = 0x8009,
            ceStreamBucketParameters    = 0x800A,
            ceStreamProcessModuleMap    = 0x800B,
            ceStreamDiagnosisList       = 0x800C,
            LastReservedStream          = 0xffff
        };



        class DMPFile : public TypeInterface
        {
          public:
            DMP::Header header;
            std::vector<MINIDUMP_DIRECTORY> directories;
            DMP::MINIDUMP_SYSTEM_INFO systemInfo;
            DMP::MINIDUMP_EXCEPTION_STREAM exception;
            DMP::MINIDUMP_THREAD_LIST threadList;
            std::vector<MINIDUMP_THREAD> threads;
            DMP::MINIDUMP_MODULE_LIST moduleList;
            std::vector<MINIDUMP_MODULE> modules;

            uint32_t threadNamesCount;
            std::map<uint32_t, std::string> threadNamesMap;
            uint32_t functionTablesCount;
            struct FunctionTableEntry {
                uint64_t minAddr;
                uint64_t maxAddr;
                uint32_t entryCount;
            };
            std::vector<FunctionTableEntry> functionTables;

            bool Update();
            std::vector<String> GetThreadInfo();
            std::vector<String> GetModuleInfo();
            String GetModuleName(const MINIDUMP_MODULE& m);
            std::vector<String> GetCallStack(uint32_t threadIndex);

            std::vector<String> GetHighlightedInfoLeft();
            std::vector<String> GetHighlightedInfoRight();
            DMP::MINIDUMP_MEMORY_LIST memoryList;
            std::vector<MINIDUMP_MEMORY_DESCRIPTOR> memoryRanges;
            DMP::MINIDUMP_MEMORY64_LIST memory64List;
            std::vector<MINIDUMP_MEMORY_DESCRIPTOR64> memory64Ranges;
            
            int memoryRangesFound;
            int memory64RangesFound;
            int threadsFound;
            int modulesFound;
            int threadNamesFound;
            int functionTablesFound; 

            //std::vector<String> GetMemoryInfo();
            //std::vector<String> GetMemory64Info();
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;
            std::string_view GetTypeName() override
            {
                return "DMP";
            };
            void RunCommand(std::string_view) override
            {
            }
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }

            GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt);
            const char*  getArchitecture();
            const char* getStreamTypeName(uint32_t type);
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::DMP::DMPFile> dmp;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> streams;
                Reference<AppCUI::Controls::ListView> system;
                Reference<AppCUI::Controls::ListView> exception;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::DMP::DMPFile> dmp);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
         

        }; // namespace Panels
    }      // namespace ICO
} // namespace Type
} // namespace GView

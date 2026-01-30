#include "dmp.hpp"

using namespace GView::Type::DMP;
 
//reading and parsing a dmp file
bool DMPFile::Update()
{
    CHECK(obj->GetData().Copy<Header>(0, header), false, "Failed to read header");
    size_t offset = sizeof(Header);
    directories.clear();
    for (uint32_t i = 0; i < header.NumberOfStreams; i++) {
        //search for all directory entries
        uint32_t offset = header.StreamDirectoryRva + i * sizeof(MINIDUMP_DIRECTORY);
        DMP::MINIDUMP_DIRECTORY q;

        CHECK(obj->GetData().Copy<MINIDUMP_DIRECTORY>(offset, q), false, "Failed to read directories");
        if (q.Location.DataSize == 0)
            break;
        directories.push_back(q);
    }
    //feeling cute today :>
    uint32_t threadsRva;
    for (auto& dir : directories) {
    
        switch (dir.StreamType) {
        case SystemInfoStream:
            CHECK(obj->GetData().Copy<MINIDUMP_SYSTEM_INFO>(dir.Location.Rva, systemInfo), false, "Failed to read \"System Info\" steam");
            break;
        case ExceptionStream:
            CHECK(obj->GetData().Copy<MINIDUMP_EXCEPTION_STREAM>(dir.Location.Rva, exception), false, "Failed to read \"Exception Stream\" steam")
            break;
        case ThreadListStream:
            CHECK(obj->GetData().Copy<uint32_t>(dir.Location.Rva, threadList.NumberOfThreads), false, "Failed to read \"Thread list\" steam");
            if (threadList.NumberOfThreads > 10000)
                return false;
            threadsRva = dir.Location.Rva + sizeof(uint32_t);
            for (uint32_t i = 0; i < threadList.NumberOfThreads; i++) {
                MINIDUMP_THREAD thread{};
                CHECK(obj->GetData().Copy<MINIDUMP_THREAD>(threadsRva + i * sizeof(MINIDUMP_THREAD), thread), false, "Failed to read thread");
                threads.push_back(thread);
            }
            break;
        case ModuleListStream:
            CHECK(obj->GetData().Copy<uint32_t>(dir.Location.Rva, moduleList.NumberOfModules), false, "Failed to read NumberOfThreads");
            threadsRva = dir.Location.Rva + sizeof(uint32_t);
            for (uint32_t i = 0; i < moduleList.NumberOfModules; i++) {
                MINIDUMP_MODULE module{};
                CHECK(obj->GetData().Copy<MINIDUMP_MODULE>(threadsRva + i * sizeof(MINIDUMP_MODULE), module), false, "Failed to read module");
                modules.push_back(module);
            }
            break;
        case MemoryListStream:
            CHECK(obj->GetData().Copy<uint32_t>(dir.Location.Rva, memoryList.NumberOfMemoryRanges), 
                  false, "Failed to read NumberOfMemoryRanges");
            
            if (memoryList.NumberOfMemoryRanges > 100000)
                return false;
            
            threadsRva = dir.Location.Rva + sizeof(uint32_t);
            
            for (uint32_t i = 0; i < memoryList.NumberOfMemoryRanges; i++) {
                MINIDUMP_MEMORY_DESCRIPTOR memDesc{};
                CHECK(obj->GetData().Copy<MINIDUMP_MEMORY_DESCRIPTOR>(
                          threadsRva + i * sizeof(MINIDUMP_MEMORY_DESCRIPTOR), memDesc),
                      false, "Failed to read memory descriptor");
                memoryRanges.push_back(memDesc);
            }
            memoryRangesFound = memoryList.NumberOfMemoryRanges;
            break;

        case Memory64ListStream:
            CHECK(obj->GetData().Copy<uint64_t>(dir.Location.Rva, memory64List.NumberOfMemoryRanges),
                  false, "Failed to read NumberOfMemoryRanges (64)");
            CHECK(obj->GetData().Copy<uint64_t>(dir.Location.Rva + sizeof(uint64_t), memory64List.BaseRva),
                  false, "Failed to read BaseRva");
            
            if (memory64List.NumberOfMemoryRanges > 100000)
                return false;
            
            threadsRva = dir.Location.Rva + 2 * sizeof(uint64_t);
            
            for (uint64_t i = 0; i < memory64List.NumberOfMemoryRanges; i++) {
                MINIDUMP_MEMORY_DESCRIPTOR64 memDesc64{};
                CHECK(obj->GetData().Copy<MINIDUMP_MEMORY_DESCRIPTOR64>(
                          threadsRva + i * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64), memDesc64),
                      false, "Failed to read memory64 descriptor");
                memory64Ranges.push_back(memDesc64);
            }
            memory64RangesFound = memory64List.NumberOfMemoryRanges;
            break;
        case ThreadNamesStream: 
            uint32_t numThreadNames = 0;
            CHECK(obj->GetData().Copy<uint32_t>(dir.Location.Rva, numThreadNames), false, "Failed to read ThreadNames count");

            threadNamesFound     = numThreadNames;
            uint32_t entryOffset = dir.Location.Rva + sizeof(uint32_t);

            for (uint32_t i = 0; i < numThreadNames; i++) {
                struct {
                    uint32_t ThreadId;
                    uint64_t NameRva;
                } entry;

                if (obj->GetData().Copy(entryOffset + i * sizeof(entry), entry)) {

                    uint32_t strLen = 0;
                    if (obj->GetData().Copy<uint32_t>(entry.NameRva, strLen)) {
                        Buffer nameBuf = obj->GetData().CopyToBuffer(entry.NameRva + sizeof(uint32_t), strLen, false);
                        if (nameBuf.IsValid()) {
                            const wchar_t* wName = reinterpret_cast<const wchar_t*>(nameBuf.GetData());
                            std::string name;
                            for (uint32_t j = 0; j < strLen / 2; j++) {
                                name.push_back(wName[j] < 128 ? static_cast<char>(wName[j]) : '?');
                            }
                            threadNamesMap[entry.ThreadId] = name;
                        }
                    }
                }
            }
            break;
        
        }
    }
    
    return true;
}
std::vector<String> DMPFile::GetThreadInfo()
{
    std::vector<String> result;
    String line;

    for (size_t i = 0; i < threads.size(); i++) {
        const MINIDUMP_THREAD& t = threads[i];

        bool isFaultingThread = (t.ThreadId == exception.ThreadId);

        if (isFaultingThread) {
            result.push_back((String)"***************************************************");
            result.push_back((String) " FAULTING THREAD ");
        }

        // Basic Thread Information
        line.Format("Thread %zu | ID= %u", i, t.ThreadId);
        result.push_back(line);
        line.Format("  SuspendCount: %u", t.SuspendCount);
        result.push_back(line);
        line.Format("  Priority: %u (Class=%u)", t.Priority, t.PriorityClass);
        result.push_back(line);
        //line.Format("  TEB: 0x%016llX", static_cast<unsigned long long>(t.Teb));
        //result.push_back(line);
        line.Format("  Stack: RVA=0x%08X Size=%u", t.Stack.Rva, t.Stack.DataSize);
        result.push_back(line);
        line.Format("  Context: RVA=0x%08X Size=%u", t.ThreadContext.Rva, t.ThreadContext.DataSize);
        result.push_back(line);

        if (isFaultingThread) {
            result.emplace_back("");

            std::vector<String> callStack = GetCallStack(static_cast<uint32_t>(i));

            if (callStack.empty()) {
                result.push_back((String) "  [No Call Stack available or Stack empty]");
            } else {
                for (const auto& entry : callStack) {
                    String indentedLine;
                    indentedLine.Format("  %s", entry.GetText());
                    result.push_back(indentedLine);
                }
            }

            result.push_back((String)"***************************************************");
        }

    }

    return result;
}

std::vector<String> DMPFile::GetHighlightedInfoLeft()
{
    std::vector<String> result;
    String line;
    uint64_t errorAdress = exception.ExceptionRecord.ExceptionAddress;
    for (size_t i = 0; i < modules.size(); i++) {
        const MINIDUMP_MODULE& m = modules[i];

        DMP::MINIDUMP_STRING moduleString{};
        obj->GetData().Copy<MINIDUMP_STRING>(m.ModuleNameRva, moduleString);

        uint32_t len              = moduleString.Length / 2; 
        uint64_t stringDataOffset = m.ModuleNameRva + sizeof(uint32_t);

      
        Buffer b            = obj->GetData().CopyToBuffer(stringDataOffset, len * sizeof(wchar_t), false);
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(b.GetData());

     
        std::string moduleName;
        moduleName.reserve(len);
        for (uint32_t j = 0; j < len && j < 256; j++) {
            wchar_t wc = wstr[j];
            if (wc == 0)
                break;
            moduleName.push_back(wc < 128 ? static_cast<char>(wc) : '?');
        }
        
        if (errorAdress >= m.BaseOfImage && errorAdress < m.BaseOfImage + m.SizeOfImage) {
            line.Format("Module %i", i);
            result.push_back(line);

            line.Format("  Module Name: %s", moduleName.c_str());
            result.push_back(line);

            line.Format("  BaseOfImage: 0x%08X", m.BaseOfImage);
            result.push_back(line);

            line.Format("  SizeOfImage: 0x%08X", m.SizeOfImage);
            result.push_back(line);
        }

    }

    return result;
}



std::vector<String> DMPFile::GetHighlightedInfoRight()
{
    std::vector<String> result;
    String line;
    uint64_t errorAdress = exception.ExceptionRecord.ExceptionAddress;
    for (size_t i = 0; i < modules.size(); i++) {
        const MINIDUMP_MODULE& m = modules[i];

        DMP::MINIDUMP_STRING moduleString{};
        obj->GetData().Copy<MINIDUMP_STRING>(m.ModuleNameRva, moduleString);

        uint32_t len              = moduleString.Length / 2;
        uint64_t stringDataOffset = m.ModuleNameRva + sizeof(uint32_t);

        Buffer b            = obj->GetData().CopyToBuffer(stringDataOffset, len * sizeof(wchar_t), false);
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(b.GetData());

        std::string moduleName;
        moduleName.reserve(len);
        for (uint32_t j = 0; j < len && j < 256; j++) {
            wchar_t wc = wstr[j];
            if (wc == 0)
                break; // Null terminator
            moduleName.push_back(wc < 128 ? static_cast<char>(wc) : '?');
        }

        if (errorAdress >= m.BaseOfImage && errorAdress < m.BaseOfImage + m.SizeOfImage) {
            line.Format("Module %i", i);
            result.push_back(line);

            line.Format("  Module Name: %s", moduleName.c_str());
            result.push_back(line);

            line.Format("  BaseOfImage: 0x%08X", m.BaseOfImage);
            result.push_back(line);

            line.Format("  SizeOfImage: 0x%08X", m.SizeOfImage);
            result.push_back(line);

            if (sizeof(m.VersionInfo) >= 16) {
                const uint8_t* v = m.VersionInfo;
                line.Format(
                      "  VersionInfo: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                      v[0],
                      v[1],
                      v[2],
                      v[3],
                      v[4],
                      v[5],
                      v[6],
                      v[7],
                      v[8],
                      v[9],
                      v[10],
                      v[11],
                      v[12],
                      v[13],
                      v[14],
                      v[15]);
                result.push_back(line);
            }
        }
    }

    return result;
}



std::vector<String> DMPFile::GetModuleInfo()
{
    std::vector<String> result;
    String line;

    for (size_t i = 0; i < modules.size(); i++) {
        const MINIDUMP_MODULE& m = modules[i];

        DMP::MINIDUMP_STRING moduleString{};
        obj->GetData().Copy<MINIDUMP_STRING>(m.ModuleNameRva, moduleString);

        uint32_t len              = moduleString.Length / 2;
        uint64_t stringDataOffset = m.ModuleNameRva + sizeof(uint32_t);


        Buffer b            = obj->GetData().CopyToBuffer(stringDataOffset, len * sizeof(wchar_t), false);
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(b.GetData());

        std::string moduleName;
        moduleName.reserve(len);
        for (uint32_t j = 0; j < len && j < 256; j++) {
            wchar_t wc = wstr[j];
            if (wc == 0)
                break; 
            moduleName.push_back(wc < 128 ? static_cast<char>(wc) : '?');
        }
        uint64_t errorAdress = exception.ExceptionRecord.ExceptionAddress;
        bool isTHEProblem     = false;
        if (errorAdress >= m.BaseOfImage && errorAdress < m.BaseOfImage + m.SizeOfImage)
            isTHEProblem = true;
        if (isTHEProblem) 
        {
            result.push_back((String)"***************************************");
        }
        //line.Format("Module %i | Address=0x%08X | Name=%s", i, m.BaseOfImage, moduleName.c_str());
        line.Format("Module %i", i);
        result.push_back(line);

        line.Format("  Module Name: %s", moduleName.c_str());
        result.push_back(line);

        line.Format("  BaseOfImage: 0x%08X", m.BaseOfImage);
        result.push_back(line);

        line.Format("  SizeOfImage: 0x%08X", m.SizeOfImage);
        result.push_back(line);

      /*  line.Format("  CheckSum: 0x%08X", m.CheckSum);
        result.push_back(line);

        line.Format("  TimeDateStamp: 0x%08X", m.TimeDateStamp);
        result.push_back(line);

        line.Format("  CV Record: RVA=0x%08X Size=%u", m.CvRecord.Rva, m.CvRecord.DataSize);
        result.push_back(line);

        line.Format("  Misc Record: RVA=0x%08X Size=%u", m.MiscRecord.Rva, m.MiscRecord.DataSize);
        result.push_back(line);*/

        // Optional: first 16 bytes of VersionInfo as GUID-style
        if (sizeof(m.VersionInfo) >= 16) {
            const uint8_t* v = m.VersionInfo;
            line.Format(
                  "  VersionInfo: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  v[0],v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],
                  v[9],v[10],v[11],v[12],v[13],v[14],v[15]);
            result.push_back(line);
        }
        if (isTHEProblem) {
            vector<String> d2 = GetCallStack(i);
            result.push_back((String) "***************************************");
        }
        result.emplace_back(""); 
    }

    return result;
}


const char* DMPFile::getArchitecture()
{
    switch (systemInfo.ProcessorArchitecture) {
    case 0:
        return "x86";
    case 5:
        return "ARM";
    case 6:
        return "IA64";
    case 9:
        return "x64";
    case 12:
        return "ARM64";
    default:
        return "Unknown";
    }
}

const char* DMPFile::getStreamTypeName(uint32_t type)
{
    static char buffer[64];
    const char* name = nullptr;

    switch (type) {
    case ThreadListStream:
        name = "ThreadList";
        break;
    case ModuleListStream:
        name = "ModuleList";
        break;
    case MemoryListStream:
        name = "MemoryList";
        break;
    case ExceptionStream:
        name = "Exception";
        break;
    case SystemInfoStream:
        name = "SystemInfo";
        break;
    case Memory64ListStream:
        name = "Memory64List";
        break;
    case MiscInfoStream:
        name = "MiscInfo";
        break;
    case ThreadNamesStream:
        name = "ThreadNames";
        break;
    case UnloadedModuleListStream:
        name = "UnloadedModuleList";
        break;
    default:
        name = "Unknown";
        break;
    }
    snprintf(buffer, sizeof(buffer), "%s (%u)", name, type);

    return buffer;
}

GView::Utils::JsonBuilderInterface* DMPFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    return builder;
}

std::vector<String> DMPFile::GetCallStack(uint32_t threadIndex)
{
    std::vector<String> result;
    if (threadIndex >= threads.size())
        return {};

    const auto& thread = threads[threadIndex];
    String line;

    Buffer stackData = obj->GetData().CopyToBuffer(thread.Stack.Rva, thread.Stack.DataSize, false);
    if (!stackData.IsValid())
        return {};

    const uint8_t* rawStack = stackData.GetData();
    size_t stackSize        = stackData.GetLength();

    const char* arch = getArchitecture();
    bool is64Bit     = (strcmp(arch, "x64") == 0 || strcmp(arch, "ARM64") == 0);
    size_t ptrSize   = is64Bit ? 8 : 4;

    result.push_back((String)"  FRAME | STACK OFFSET | INSTRUCTION ADDR   | MODULE + OFFSET");
    result.push_back((String)"  ------|--------------|--------------------|--------------------------");

    uint32_t frameCount = 0;

    for (size_t offset = 0; offset <= stackSize - ptrSize; offset += ptrSize) {
        uint64_t potentialAddr = 0;
        if (is64Bit) {
            potentialAddr = *reinterpret_cast<const uint64_t*>(rawStack + offset);
        } else {
            potentialAddr = *reinterpret_cast<const uint32_t*>(rawStack + offset);
        }

        for (size_t mIdx = 0; mIdx < modules.size(); mIdx++) {
            const auto& mod = modules[mIdx];
            if (potentialAddr >= mod.BaseOfImage && potentialAddr < (mod.BaseOfImage + mod.SizeOfImage)) {
                uint64_t offsetInModule = potentialAddr - mod.BaseOfImage;

                std::string modName = "Module_" + std::to_string(mIdx);


                line.Format("   #%02u  |  +0x%04zX     | 0x%016llX | %s + 0x%llX", frameCount++, offset, potentialAddr, modName.c_str(), offsetInModule);

                result.push_back(line);
                break;
            }
        }
    }

    return result;
}

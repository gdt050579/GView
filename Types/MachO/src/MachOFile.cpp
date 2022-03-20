#include "MachO.hpp"

namespace GView::Type::MachO
{
MachOFile::MachOFile(Reference<GView::Utils::FileCache> file) : header({}), is64(false), shouldSwapEndianess(false), panelsMask(0)
{
    this->file = file;
}

bool MachOFile::Update()
{
    uint64_t offset = 0;

    SetArchitectureAndEndianess(offset);
    SetHeader(offset);
    const auto commandsStartOffset = offset;
    SetLoadCommands(offset);
    SetSegments(offset);

    offset = commandsStartOffset;
    SetSections(offset);

    offset = commandsStartOffset;
    SetDyldInfo(offset);

    offset = commandsStartOffset;
    SetIdDylibs(offset);

    offset = commandsStartOffset;
    SetMain(offset);

    offset = commandsStartOffset;
    SetSymbols(offset);

    offset = commandsStartOffset;
    SetSourceVersion(offset);

    offset = commandsStartOffset;
    SetUUID(offset);

    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8_t) Panels::IDs::LoadCommands);

    if (segments.empty() == false)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Segments);
    }

    if (sections.empty() == false)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Sections);
    }

    if (dyldInfo.isSet)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::DyldInfo);
    }

    if (dylibs.empty() == false)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Dylib);
    }

    if (dySymTab.isSet)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::DySymTab);
    }

    return true;
}

bool MachOFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << ((uint8_t) id))) != 0;
}

uint64_t MachOFile::TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex)
{
    return value;
}

uint64_t MachOFile::TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex)
{
    return value;
}

bool MachOFile::SetArchitectureAndEndianess(uint64_t& offset)
{
    uint32_t magic = 0;
    CHECK(file->Copy<uint32_t>(offset, magic), false, "");

    is64                = magic == MAC::MH_MAGIC_64 || magic == MAC::MH_CIGAM_64;
    shouldSwapEndianess = magic == MAC::MH_CIGAM || magic == MAC::MH_CIGAM_64;

    return true;
}

bool MachOFile::SetHeader(uint64_t& offset)
{
    CHECK(file->Copy<MachO::MAC::mach_header>(offset, header), false, "");
    offset += sizeof(header);
    if (is64 == false)
    {
        offset -= sizeof(MachO::MAC::mach_header::reserved);
    }

    if (shouldSwapEndianess)
    {
        header.magic      = Utils::SwapEndian(header.magic);
        header.cputype    = Utils::SwapEndian(header.cputype);
        header.cpusubtype = Utils::SwapEndian(header.cpusubtype);
        header.filetype   = Utils::SwapEndian(header.filetype);
        header.ncmds      = Utils::SwapEndian(header.ncmds);
        header.sizeofcmds = Utils::SwapEndian(header.sizeofcmds);
        header.flags      = Utils::SwapEndian(header.flags);
    }

    return true;
}

bool MachOFile::SetLoadCommands(uint64_t& offset)
{
    loadCommands.reserve(header.ncmds);

    for (decltype(header.ncmds) i = 0; i < header.ncmds; i++)
    {
        MAC::load_command lc{};
        CHECK(file->Copy<MAC::load_command>(offset, lc), false, "");
        if (shouldSwapEndianess)
        {
            lc.cmd     = Utils::SwapEndian(lc.cmd);
            lc.cmdsize = Utils::SwapEndian(lc.cmdsize);
        }
        loadCommands.push_back({ lc, offset });
        offset += lc.cmdsize;
    }

    return true;
}

bool MachOFile::SetSegments(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::SEGMENT)
        {
            Segment s{};
            CHECK(file->Copy<MAC::segment_command>(lc.offset, s.x86), false, "");
            if (shouldSwapEndianess)
            {
                s.x86.cmd     = Utils::SwapEndian(s.x86.cmd);
                s.x86.cmdsize = Utils::SwapEndian(s.x86.cmdsize);
                for (auto i = 0U; i < sizeof(s.x86.segname) / sizeof(s.x86.segname[0]); i++)
                {
                    s.x86.segname[i] = Utils::SwapEndian(s.x86.segname[i]);
                }
                s.x86.vmaddr   = Utils::SwapEndian(s.x86.vmaddr);
                s.x86.vmsize   = Utils::SwapEndian(s.x86.vmsize);
                s.x86.fileoff  = Utils::SwapEndian(s.x86.fileoff);
                s.x86.filesize = Utils::SwapEndian(s.x86.filesize);
                s.x86.maxprot  = Utils::SwapEndian(s.x86.maxprot);
                s.x86.initprot = Utils::SwapEndian(s.x86.initprot);
                s.x86.nsects   = Utils::SwapEndian(s.x86.nsects);
                s.x86.flags    = Utils::SwapEndian(s.x86.flags);
            }
            segments.emplace_back(s);
        }
        else if (lc.value.cmd == MAC::LoadCommandType::SEGMENT_64)
        {
            Segment s{};
            CHECK(file->Copy<MAC::segment_command_64>(lc.offset, s.x64), false, "");
            if (shouldSwapEndianess)
            {
                s.x64.cmd     = Utils::SwapEndian(s.x64.cmd);
                s.x64.cmdsize = Utils::SwapEndian(s.x64.cmdsize);
                for (auto i = 0U; i < sizeof(s.x64.segname) / sizeof(s.x64.segname[0]); i++)
                {
                    s.x64.segname[i] = Utils::SwapEndian(s.x64.segname[i]);
                }
                s.x64.vmaddr   = Utils::SwapEndian(s.x64.vmaddr);
                s.x64.vmsize   = Utils::SwapEndian(s.x64.vmsize);
                s.x64.fileoff  = Utils::SwapEndian(s.x64.fileoff);
                s.x64.filesize = Utils::SwapEndian(s.x64.filesize);
                s.x64.maxprot  = Utils::SwapEndian(s.x64.maxprot);
                s.x64.initprot = Utils::SwapEndian(s.x64.initprot);
                s.x64.nsects   = Utils::SwapEndian(s.x64.nsects);
                s.x64.flags    = Utils::SwapEndian(s.x64.flags);
            }
            segments.emplace_back(s);
        }
    }

    return true;
}

bool MachOFile::SetSections(uint64_t& offset)
{
    for (const auto& segment : segments)
    {
        if (is64)
        {
            offset += sizeof(MAC::segment_command_64);
            for (auto i = 0U; i < segment.x64.nsects; i++)
            {
                Section s{};
                CHECK(file->Copy<MAC::section_64>(offset, s.x64), false, "");
                if (shouldSwapEndianess)
                {
                    for (auto i = 0U; i < sizeof(s.x64.sectname) / sizeof(s.x64.sectname[0]); i++)
                    {
                        s.x64.sectname[i] = Utils::SwapEndian(s.x64.sectname[i]);
                    }
                    for (auto i = 0U; i < sizeof(s.x64.segname) / sizeof(s.x64.segname[0]); i++)
                    {
                        s.x64.segname[i] = Utils::SwapEndian(s.x64.segname[i]);
                    }
                    s.x64.addr      = Utils::SwapEndian(s.x64.addr);
                    s.x64.size      = Utils::SwapEndian(s.x64.size);
                    s.x64.offset    = Utils::SwapEndian(s.x64.offset);
                    s.x64.align     = Utils::SwapEndian(s.x64.align);
                    s.x64.reloff    = Utils::SwapEndian(s.x64.reloff);
                    s.x64.nreloc    = Utils::SwapEndian(s.x64.nreloc);
                    s.x64.flags     = Utils::SwapEndian(s.x64.flags);
                    s.x64.reserved1 = Utils::SwapEndian(s.x64.reserved1);
                    s.x64.reserved2 = Utils::SwapEndian(s.x64.reserved2);
                    s.x64.reserved3 = Utils::SwapEndian(s.x64.reserved3);
                }
                sections.emplace_back(s);
                offset += sizeof(MAC::section_64);
            }
        }
        else
        {
            offset += sizeof(MAC::segment_command);
            for (auto i = 0U; i < segment.x86.nsects; i++)
            {
                Section s{};
                CHECK(file->Copy<MAC::section>(offset, s.x86), false, "");
                if (shouldSwapEndianess)
                {
                    for (auto i = 0U; i < sizeof(s.x86.sectname) / sizeof(s.x86.sectname[0]); i++)
                    {
                        s.x86.sectname[i] = Utils::SwapEndian(s.x86.sectname[i]);
                    }
                    for (auto i = 0U; i < sizeof(s.x86.segname) / sizeof(s.x86.segname[0]); i++)
                    {
                        s.x86.segname[i] = Utils::SwapEndian(s.x86.segname[i]);
                    }
                    s.x86.addr      = Utils::SwapEndian(s.x86.addr);
                    s.x86.size      = Utils::SwapEndian(s.x86.size);
                    s.x86.offset    = Utils::SwapEndian(s.x86.offset);
                    s.x86.align     = Utils::SwapEndian(s.x86.align);
                    s.x86.reloff    = Utils::SwapEndian(s.x86.reloff);
                    s.x86.nreloc    = Utils::SwapEndian(s.x86.nreloc);
                    s.x86.flags     = Utils::SwapEndian(s.x86.flags);
                    s.x86.reserved1 = Utils::SwapEndian(s.x86.reserved1);
                    s.x86.reserved2 = Utils::SwapEndian(s.x86.reserved2);
                }
                sections.emplace_back(s);
                offset += sizeof(MAC::section);
            }
        }
    }

    return true;
}

bool MachOFile::SetDyldInfo(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::DYLD_INFO || lc.value.cmd == MAC::LoadCommandType::DYLD_INFO_ONLY)
        {
            if (dyldInfo.isSet == false)
            {
                CHECK(file->Copy<MAC::dyld_info_command>(offset, dyldInfo.value), false, "");
                dyldInfo.isSet = true;
            }
            else
            {
                throw "Multiple LoadCommandType::DYLD_INFO or MAC::LoadCommandType::DYLD_INFO_ONLY found! Reimplement this!";
            }
        }

        offset += lc.value.cmdsize;
    }

    return true;
}

bool MachOFile::SetIdDylibs(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::ID_DYLIB || lc.value.cmd == MAC::LoadCommandType::LOAD_DYLIB ||
            lc.value.cmd == MAC::LoadCommandType::LOAD_WEAK_DYLIB || lc.value.cmd == MAC::LoadCommandType::REEXPORT_DYLIB ||
            lc.value.cmd == MAC::LoadCommandType::LAZY_LOAD_DYLIB || lc.value.cmd == MAC::LoadCommandType::LOAD_UPWARD_DYLIB)
        {
            uint32_t cmdSize = 0;
            CHECK(file->Copy<uint32_t>(offset + 4, cmdSize), false, "");
            if (shouldSwapEndianess)
            {
                cmdSize = Utils::SwapEndian(cmdSize);
            }

            auto buffer = file->CopyToBuffer(offset, cmdSize);
            auto ptr    = buffer.GetData();

            Dylib d{};
            d.offset = lc.offset;

            d.value.cmd = *(MAC::LoadCommandType*) buffer.GetData();

            ptr += sizeof(MAC::LoadCommandType);
            d.value.cmdsize = *(uint32_t*) (ptr);

            ptr += sizeof(d.value.cmdsize);
            // if (is64)
            //{
            //     d.value.dylib.name.ptr = *(uint64_t*) (ptr);
            //     ptr += sizeof(d.value.dylib.name.ptr);
            // }
            // else
            {
                d.value.dylib.name.offset = *(uint32_t*) (ptr);
                ptr += sizeof(d.value.dylib.name.offset);
            }

            d.value.dylib.timestamp = *(uint32_t*) (ptr);
            ptr += sizeof(d.value.dylib.timestamp);

            d.value.dylib.current_version = *(uint32_t*) (ptr);
            ptr += sizeof(d.value.dylib.current_version);

            d.value.dylib.compatibility_version = *(uint32_t*) (ptr);
            ptr += sizeof(d.value.dylib.compatibility_version);

            if (shouldSwapEndianess)
            {
                d.value.cmd     = Utils::SwapEndian(d.value.cmd);
                d.value.cmdsize = Utils::SwapEndian(d.value.cmdsize);

                if (is64)
                {
                    d.value.dylib.name.ptr = Utils::SwapEndian(d.value.dylib.name.ptr);
                }
                else
                {
                    d.value.dylib.name.offset = Utils::SwapEndian(d.value.dylib.name.offset);
                }
                d.value.dylib.timestamp             = Utils::SwapEndian(d.value.dylib.timestamp);
                d.value.dylib.current_version       = Utils::SwapEndian(d.value.dylib.current_version);
                d.value.dylib.compatibility_version = Utils::SwapEndian(d.value.dylib.compatibility_version);
            }

            d.name = reinterpret_cast<char*>(ptr);

            dylibs.emplace_back(d);
        }

        offset += lc.value.cmdsize;
    }

    return true;
}

bool MachOFile::SetMain(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::MAIN)
        {
            if (main.isSet == false)
            {
                CHECK(file->Copy<MAC::entry_point_command>(offset, main.ep), false, "");

                if (shouldSwapEndianess)
                {
                    main.ep.cmd       = Utils::SwapEndian(main.ep.cmd);
                    main.ep.cmdsize   = Utils::SwapEndian(main.ep.cmdsize);
                    main.ep.entryoff  = Utils::SwapEndian(main.ep.entryoff);
                    main.ep.stacksize = Utils::SwapEndian(main.ep.stacksize);
                }

                main.isSet = true;
            }
            else
            {
                throw "Multiple LoadCommandType::MAIN found! Reimplement this!";
            }
        }
        else if (lc.value.cmd == MAC::LoadCommandType::UNIXTHREAD)
        {
            main.ep.cmd     = lc.value.cmd;
            main.ep.cmdsize = lc.value.cmdsize;
            auto cmd        = file->CopyToBuffer(offset, main.ep.cmdsize);

            if (header.cputype == MAC::CPU_TYPE_I386)
            {
                typedef struct
                {
                    uint32_t eax;
                    uint32_t ebx;
                    uint32_t ecx;
                    uint32_t edx;
                    uint32_t edi;
                    uint32_t esi;
                    uint32_t ebp;
                    uint32_t esp;
                    uint32_t ss;
                    uint32_t eflags;
                    uint32_t eip;
                    uint32_t cs;
                    uint32_t ds;
                    uint32_t es;
                    uint32_t fs;
                    uint32_t gs;
                } i386_thread_state_t;

                const auto registers = (i386_thread_state_t*) (((char*) cmd.GetData()) + 16);

                main.isSet       = true;
                main.ep.entryoff = registers->eip;
            }
            else if (header.cputype == MAC::CPU_TYPE_X86_64)
            {
                struct x86_thread_state64_t
                {
                    uint64_t rax;
                    uint64_t rbx;
                    uint64_t rcx;
                    uint64_t rdx;
                    uint64_t rdi;
                    uint64_t rsi;
                    uint64_t rbp;
                    uint64_t rsp;
                    uint64_t r8;
                    uint64_t r9;
                    uint64_t r10;
                    uint64_t r11;
                    uint64_t r12;
                    uint64_t r13;
                    uint64_t r14;
                    uint64_t r15;
                    uint64_t rip;
                    uint64_t rflags;
                    uint64_t cs;
                    uint64_t fs;
                    uint64_t gs;
                };

                const x86_thread_state64_t* registers = (x86_thread_state64_t*) (((char*) cmd.GetData()) + 16);
                main.isSet                            = true;
                main.ep.entryoff                      = registers->rip;
            }
            else if (header.cputype == MAC::CPU_TYPE_POWERPC)
            {
                typedef struct
                {
                    uint32_t srr0; /* Instruction address register (PC) */
                    uint32_t srr1; /* Machine state register (supervisor) */
                    uint32_t r[32];

                    uint32_t cr;  /* Condition register */
                    uint32_t xer; /* User's integer exception register */
                    uint32_t lr;  /* Link register */
                    uint32_t ctr; /* Count register */
                    uint32_t mq;  /* MQ register (601 only) */

                    uint32_t vrsave; /* Vector Save Register */
                } ppc_thread_state_t;

                const auto registers = (ppc_thread_state_t*) (((char*) cmd.GetData()) + 16);
                main.isSet           = true;
                main.ep.entryoff     = registers->srr0;
            }
            else if (header.cputype == MAC::CPU_TYPE_POWERPC64)
            {
                typedef struct
                {
                    uint64_t srr0, srr1;
                    uint64_t r[32];
                    uint32_t cr;
                    uint64_t xer, lr, ctr;
                    uint32_t vrsave;
                } ppc_thread_state64_t;

                const auto registers = (ppc_thread_state64_t*) (((char*) cmd.GetData()) + 16);
                main.isSet           = true;
                main.ep.entryoff     = registers->srr0;
            }
            else
            {
                throw "EP not handled for CPU from LoadCommandType::UNIXTHREAD!";
            }
        }

        offset += lc.value.cmdsize;
    }

    return true;
}

bool MachOFile::SetSymbols(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::SYMTAB)
        {
            if (dySymTab.isSet)
            {
                throw "Got a second LoadCommandType::SYMTAB command!";
            }

            CHECK(file->Copy<MAC::symtab_command>(offset, dySymTab.sc), false, "");

            if (shouldSwapEndianess)
            {
                dySymTab.sc.cmd     = Utils::SwapEndian(dySymTab.sc.cmd);
                dySymTab.sc.cmdsize = Utils::SwapEndian(dySymTab.sc.cmdsize);
                dySymTab.sc.symoff  = Utils::SwapEndian(dySymTab.sc.symoff);
                dySymTab.sc.nsyms   = Utils::SwapEndian(dySymTab.sc.nsyms);
                dySymTab.sc.stroff  = Utils::SwapEndian(dySymTab.sc.stroff);
                dySymTab.sc.strsize = Utils::SwapEndian(dySymTab.sc.strsize);
            }

            {
                const auto buffer = file->CopyToBuffer(dySymTab.sc.stroff, dySymTab.sc.strsize);
                dySymTab.stringTable.reset(new char[dySymTab.sc.strsize]);
                memcpy(dySymTab.stringTable.get(), (char*) buffer.GetData(), dySymTab.sc.strsize);
            }

            if (is64)
            {
                const auto buffer = file->CopyToBuffer(dySymTab.sc.symoff, dySymTab.sc.nsyms * sizeof(MAC::nlist_64));
                dySymTab.symbolTable.reset(new char[dySymTab.sc.nsyms * sizeof(MAC::nlist_64)]);
                memcpy(dySymTab.symbolTable.get(), (char*) buffer.GetData(), dySymTab.sc.nsyms * sizeof(MAC::nlist_64));
            }
            else
            {
                const auto buffer = file->CopyToBuffer(dySymTab.sc.symoff, dySymTab.sc.nsyms * sizeof(MAC::nlist));
                dySymTab.symbolTable.reset(new char[dySymTab.sc.nsyms * sizeof(MAC::nlist)]);
                memcpy(dySymTab.symbolTable.get(), (char*) buffer.GetData(), dySymTab.sc.nsyms * sizeof(MAC::nlist));
            }

            dySymTab.isSet = true;
        }
        offset += lc.value.cmdsize;
    }
    return true;
}

bool MachOFile::SetSourceVersion(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::SOURCE_VERSION)
        {
            if (sourceVersion.isSet == false)
            {
                sourceVersion.svc.cmd     = lc.value.cmd;
                sourceVersion.svc.cmdsize = lc.value.cmdsize;

                CHECK(file->Copy<uint64_t>(offset + 8, sourceVersion.svc.version), false, "");
                if (shouldSwapEndianess)
                {
                    sourceVersion.svc.version = Utils::SwapEndian(sourceVersion.svc.version);
                }

                sourceVersion.isSet = true;
            }
            else
            {
                throw "Multiple LoadCommandType::MAIN found! Reimplement this!";
            }
        }
    }

    return true;
}

bool MachOFile::SetUUID(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::UUID)
        {
            if (uuid.isSet == false)
            {
                uuid.value.cmd     = lc.value.cmd;
                uuid.value.cmdsize = lc.value.cmdsize;

                CHECK(file->Copy<decltype(uuid.value.uuid)>(offset + 8, uuid.value.uuid), false, "");
                if (shouldSwapEndianess)
                {
                    for (auto i = 0U; i < sizeof(uuid.value.uuid) / sizeof(uuid.value.uuid[0]); i++)
                    {
                        uuid.value.uuid[i] = Utils::SwapEndian(uuid.value.uuid[i]);
                    }
                }

                uuid.isSet = true;
            }
            else
            {
                throw "Multiple LoadCommandType::UUID found! Reimplement this!";
            }
        }
    }

    return true;
}
} // namespace GView::Type::MachO

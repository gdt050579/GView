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

    SetSegmentsAndTheirSections();

    SetDyldInfo();

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

    offset = commandsStartOffset;
    SetLinkEditData(offset);

    SetCodeSignature();

    SetVersionMin();

    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8_t) Panels::IDs::LoadCommands);

    if (segments.empty() == false)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Segments);
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Sections);
    }

    if (dyldInfo.has_value())
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::DyldInfo);
    }

    if (dylibs.empty() == false)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::Dylib);
    }

    if (dySymTab.has_value())
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::DySymTab);
    }

    if (codeSignature.isSet)
    {
        panelsMask |= (1ULL << (uint8_t) Panels::IDs::CodeSign);
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
    CHECK(file->Copy<MAC::mach_header>(offset, header), false, "");
    offset += sizeof(header);
    if (is64 == false)
    {
        offset -= sizeof(MAC::mach_header::reserved);
    }

    if (shouldSwapEndianess)
    {
        Swap(header);
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
            Swap(lc);
        }
        loadCommands.push_back({ lc, offset });
        offset += lc.cmdsize;
    }

    return true;
}

bool MachOFile::SetSegmentsAndTheirSections()
{
    for (const auto& lc : loadCommands)
    {
        Segment segment;

        if (lc.value.cmd == MAC::LoadCommandType::SEGMENT)
        {
            MAC::segment_command sc{};
            CHECK(file->Copy<decltype(sc)>(lc.offset, sc), false, "");
            if (shouldSwapEndianess)
            {
                Swap(sc);
            }

            segment.cmd     = sc.cmd;
            segment.cmdsize = sc.cmdsize;
            memcpy(segment.segname, sc.segname, 16);
            segment.vmaddr   = sc.vmaddr;
            segment.vmsize   = sc.vmsize;
            segment.fileoff  = sc.fileoff;
            segment.filesize = sc.filesize;
            segment.maxprot  = sc.maxprot;
            segment.initprot = sc.initprot;
            segment.nsects   = sc.nsects;
            segment.flags    = sc.flags;

            auto offset = lc.offset + sizeof(decltype(sc));
            for (auto i = 0U; i < sc.nsects; i++)
            {
                MAC::section section{};
                CHECK(file->Copy<decltype(section)>(offset, section), false, "");
                if (shouldSwapEndianess)
                {
                    Swap(section);
                }

                Section s{};
                memcpy(s.sectname, section.sectname, 16);
                memcpy(s.segname, section.segname, 16);
                s.addr      = section.addr;
                s.size      = section.size;
                s.offset    = section.offset;
                s.align     = section.align;
                s.reloff    = section.reloff;
                s.nreloc    = section.nreloc;
                s.flags     = section.flags;
                s.reserved1 = section.reserved1;
                s.reserved2 = section.reserved2;
                s.reserved3 = 0ULL /* section.reserved3 */;

                segment.sections.emplace_back(s);
                offset += sizeof(decltype(section));
            }
        }
        else if (lc.value.cmd == MAC::LoadCommandType::SEGMENT_64)
        {
            MAC::segment_command_64 sc{};
            CHECK(file->Copy<MAC::segment_command_64>(lc.offset, sc), false, "");
            if (shouldSwapEndianess)
            {
                Swap(sc);
            }

            segment.cmd     = sc.cmd;
            segment.cmdsize = sc.cmdsize;
            memcpy(segment.segname, sc.segname, 16);
            segment.vmaddr   = sc.vmaddr;
            segment.vmsize   = sc.vmsize;
            segment.fileoff  = sc.fileoff;
            segment.filesize = sc.filesize;
            segment.maxprot  = sc.maxprot;
            segment.initprot = sc.initprot;
            segment.nsects   = sc.nsects;
            segment.flags    = sc.flags;

            auto offset = lc.offset + sizeof(decltype(sc));
            for (auto i = 0U; i < sc.nsects; i++)
            {
                MAC::section_64 section{};
                CHECK(file->Copy<decltype(section)>(offset, section), false, "");
                if (shouldSwapEndianess)
                {
                    Swap(section);
                }

                Section s{};
                memcpy(s.sectname, section.sectname, 16);
                memcpy(s.segname, section.segname, 16);
                s.addr      = section.addr;
                s.size      = section.size;
                s.offset    = section.offset;
                s.align     = section.align;
                s.reloff    = section.reloff;
                s.nreloc    = section.nreloc;
                s.flags     = section.flags;
                s.reserved1 = section.reserved1;
                s.reserved2 = section.reserved2;
                s.reserved3 = section.reserved3;

                segment.sections.emplace_back(s);
                offset += sizeof(decltype(section));
            }
        }

        if (lc.value.cmd == MAC::LoadCommandType::SEGMENT || lc.value.cmd == MAC::LoadCommandType::SEGMENT_64)
        {
            segments.emplace_back(segment);
        }
    }

    return true;
}

bool MachOFile::SetDyldInfo()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::DYLD_INFO || lc.value.cmd == MAC::LoadCommandType::DYLD_INFO_ONLY)
        {
            if (dyldInfo.has_value())
            {
                throw "Multiple LoadCommandType::DYLD_INFO or MAC::LoadCommandType::DYLD_INFO_ONLY found! Reimplement this!";
            }

            dyldInfo.emplace(MAC::dyld_info_command{});
            CHECK(file->Copy<MAC::dyld_info_command>(lc.offset, *dyldInfo), false, "");

            if (shouldSwapEndianess)
            {
                Swap(*dyldInfo);
            }
        }
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
            auto buffer = file->CopyToBuffer(lc.offset, lc.value.cmdsize);
            auto ptr    = buffer.GetData();
            auto ptr2   = buffer.GetData();

            Dylib d{};
            d.offset = lc.offset;

            d.value.cmd = *(MAC::LoadCommandType*) buffer.GetData();

            ptr += sizeof(MAC::LoadCommandType);
            d.value.cmdsize = *(uint32_t*) (ptr);

            ptr += sizeof(d.value.cmdsize);

            d.value.dylib.name.ptr = *(uint64_t*) (ptr);
            ptr += sizeof(d.value.dylib.name.offset);

            d.value.dylib.timestamp = *(uint32_t*) (ptr);
            ptr += sizeof(d.value.dylib.timestamp);

            d.value.dylib.current_version = *(uint32_t*) (ptr);
            ptr += sizeof(d.value.dylib.current_version);

            d.value.dylib.compatibility_version = *(uint32_t*) (ptr);
            ptr += sizeof(d.value.dylib.compatibility_version);

            if (shouldSwapEndianess)
            {
                Swap(d.value);
            }

            d.name = reinterpret_cast<char*>(ptr);

            const auto a = ptr - ptr2;

            dylibs.emplace_back(d);
        }
    }

    return true;
}

bool MachOFile::SetMain(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::MAIN)
        {
            if (main.has_value())
            {
                throw "Multiple LoadCommandType::MAIN found! Reimplement this!";
            }

            main.emplace(MAC::entry_point_command{});
            CHECK(file->Copy<MAC::entry_point_command>(offset, *main), false, "");
            if (shouldSwapEndianess)
            {
                Swap(*main);
            }
        }
        else if (lc.value.cmd == MAC::LoadCommandType::UNIXTHREAD)
        {
            main.emplace(MAC::entry_point_command{});

            main->cmd     = lc.value.cmd;
            main->cmdsize = lc.value.cmdsize;
            auto cmd      = file->CopyToBuffer(offset, main->cmdsize);

            if (header.cputype == MAC::CPU_TYPE_I386)
            {
                const auto registers = reinterpret_cast<MAC::i386_thread_state_t*>((((char*) cmd.GetData()) + 16));
                main->entryoff       = registers->eip;
            }
            else if (header.cputype == MAC::CPU_TYPE_X86_64)
            {
                const auto registers = reinterpret_cast<MAC::x86_thread_state64_t*>((((char*) cmd.GetData()) + 16));
                main->entryoff       = registers->rip;
            }
            else if (header.cputype == MAC::CPU_TYPE_POWERPC)
            {
                const auto registers = reinterpret_cast<MAC::ppc_thread_state_t*>((((char*) cmd.GetData()) + 16));
                main->entryoff       = registers->srr0;
            }
            else if (header.cputype == MAC::CPU_TYPE_POWERPC64)
            {
                const auto registers = reinterpret_cast<MAC::ppc_thread_state64_t*>((((char*) cmd.GetData()) + 16));
                main->entryoff       = registers->srr0;
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
            if (dySymTab.has_value())
            {
                throw "Got a second LoadCommandType::SYMTAB command!";
            }

            dySymTab.emplace(DySymTab{});
            CHECK(file->Copy<MAC::symtab_command>(offset, dySymTab->sc), false, "");

            if (shouldSwapEndianess)
            {
                Swap(dySymTab->sc);
            }

            const auto stringTable       = file->CopyToBuffer(dySymTab->sc.stroff, dySymTab->sc.strsize);
            const auto symbolTableOffset = dySymTab->sc.nsyms * (is64 ? sizeof(MAC::nlist_64) : sizeof(MAC::nlist));
            const auto symbolTable       = file->CopyToBuffer(dySymTab->sc.symoff, static_cast<uint32>(symbolTableOffset));

            for (auto i = 0U; i < dySymTab->sc.nsyms; i++)
            {
                MyNList nlist{};

                if (is64)
                {
                    auto nl = reinterpret_cast<MAC::nlist_64*>(symbolTable.GetData())[i];
                    if (shouldSwapEndianess)
                    {
                        Swap(nl);
                    }

                    nlist.n_strx  = nl.n_un.n_strx;
                    nlist.n_type  = nl.n_type;
                    nlist.n_sect  = nl.n_sect;
                    nlist.n_desc  = nl.n_desc;
                    nlist.n_value = nl.n_value;
                }
                else
                {
                    auto nl = reinterpret_cast<MAC::nlist*>(symbolTable.GetData())[i];
                    if (shouldSwapEndianess)
                    {
                        Swap(nl);
                    }

                    nlist.n_strx  = nl.n_un.n_strx;
                    nlist.n_type  = nl.n_type;
                    nlist.n_sect  = nl.n_sect;
                    nlist.n_desc  = nl.n_desc;
                    nlist.n_value = nl.n_value;
                }

                String demangled;
                const auto str = reinterpret_cast<char*>(stringTable.GetData() + nlist.n_strx);
                if (GView::Utils::Demangle(str, demangled) == false)
                {
                    demangled = str;
                }

                nlist.symbolNameDemangled = demangled;
                dySymTab->objects.emplace_back(nlist);
            }
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
                CHECK(file->Copy<MAC::source_version_command>(offset, sourceVersion.svc), false, "");

                if (shouldSwapEndianess)
                {
                    Swap(sourceVersion.svc);
                }

                sourceVersion.isSet = true;
            }
            else
            {
                throw "Multiple LoadCommandType::MAIN found! Reimplement this!";
            }
        }

        offset += lc.value.cmdsize;
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
                CHECK(file->Copy<MAC::uuid_command>(offset, uuid.value), false, "");

                if (shouldSwapEndianess)
                {
                    Swap(uuid.value);
                }

                uuid.isSet = true;
            }
            else
            {
                throw "Multiple LoadCommandType::UUID found! Reimplement this!";
            }
        }

        offset += lc.value.cmdsize;
    }

    return true;
}

bool MachOFile::SetLinkEditData(uint64_t& offset)
{
    for (const auto& lc : loadCommands)
    {
        switch (lc.value.cmd)
        {
        case MAC::LoadCommandType::CODE_SIGNATURE:
        case MAC::LoadCommandType::SEGMENT_SPLIT_INFO:
        case MAC::LoadCommandType::FUNCTION_STARTS:
        case MAC::LoadCommandType::DATA_IN_CODE:
        case MAC::LoadCommandType::DYLIB_CODE_SIGN_DRS:
        case MAC::LoadCommandType::LINKER_OPTIMIZATION_HINT:
        case MAC::LoadCommandType::DYLD_EXPORTS_TRIE:
        case MAC::LoadCommandType::DYLD_CHAINED_FIXUPS:
        {
            MAC::linkedit_data_command ledc{};
            CHECK(file->Copy<MAC::linkedit_data_command>(offset, ledc), false, "");

            if (shouldSwapEndianess)
            {
                Swap(ledc);
            }

            linkEditDatas.emplace_back(ledc);
        }
        break;
        default:
            break;
        }

        offset += lc.value.cmdsize;
    }

    return true;
}

bool MachOFile::SetCodeSignature()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::CODE_SIGNATURE)
        {
            codeSignature.isSet = true;

            CHECK(file->Copy<MAC::linkedit_data_command>(lc.offset, codeSignature.ledc), false, "");

            if (shouldSwapEndianess)
            {
                Swap(codeSignature.ledc);
            }

            CHECK(file->Copy<MAC::CS_SuperBlob>(codeSignature.ledc.dataoff, codeSignature.superBlob), false, "");

            // All fields are big endian (in case PPC ever makes a comeback)
            Swap(codeSignature.superBlob);

            const auto startBlobOffset = codeSignature.ledc.dataoff + sizeof(MAC::CS_SuperBlob);
            auto currentBlobOffset     = startBlobOffset;
            for (auto i = 0U; i < codeSignature.superBlob.count; i++)
            {
                MAC::CS_BlobIndex blob{};

                CHECK(file->Copy<MAC::CS_BlobIndex>(currentBlobOffset, blob), false, "");
                Swap(blob);

                codeSignature.blobs.emplace_back(blob);

                currentBlobOffset += sizeof(MAC::CS_BlobIndex);
            }

            for (const auto& blob : codeSignature.blobs)
            {
                const auto csOffset = codeSignature.ledc.dataoff + blob.offset;

                switch (blob.type)
                {
                case MAC::CodeSignMagic::CSSLOT_CODEDIRECTORY:
                {
                    CHECK(file->Copy<MAC::CS_CodeDirectory>(csOffset, codeSignature.codeDirectory), false, "");
                    Swap(codeSignature.codeDirectory);
                }
                break;
                case MAC::CodeSignMagic::CSSLOT_INFOSLOT:
                    break;
                case MAC::CodeSignMagic::CSSLOT_REQUIREMENTS:
                {
                    CHECK(file->Copy<MAC::CS_RequirementsBlob>(csOffset, codeSignature.requirements.blob), false, "");
                    Swap(codeSignature.requirements.blob);

                    codeSignature.requirements.data = file->CopyToBuffer(
                          csOffset + sizeof(MAC::CS_RequirementsBlob),
                          codeSignature.requirements.blob.length - sizeof(MAC::CS_RequirementsBlob));

                    // TODO: needs to parse requirements and translate them to human readable text...
                    // MAC::CS_Requirement* r = (MAC::CS_Requirement*) codeSignature.requirements.data.GetData();
                    // r->type                = Utils::SwapEndian(r->type);
                    // r->offset              = Utils::SwapEndian(r->offset);
                    // const auto c           = codeSignature.requirements.data.GetData() + sizeof(MAC::CS_Requirement) + r->offset + 4;
                }
                break;
                case MAC::CodeSignMagic::CSSLOT_RESOURCEDIR:
                    break;
                case MAC::CodeSignMagic::CSSLOT_APPLICATION:
                    break;
                case MAC::CodeSignMagic::CSSLOT_ENTITLEMENTS:
                {
                    CHECK(file->Copy<MAC::CS_GenericBlob>(csOffset, codeSignature.entitlements.blob), false, "");
                    Swap(codeSignature.entitlements.blob);
                    codeSignature.entitlements.data =
                          file->CopyToBuffer(csOffset + sizeof(blob), codeSignature.entitlements.blob.length - sizeof(blob));
                }
                break;

                case MAC::CodeSignMagic::CS_SUPPL_SIGNER_TYPE_TRUSTCACHE:
                    break;

                case MAC::CodeSignMagic::CSSLOT_SIGNATURESLOT:
                    break;

                case MAC::CodeSignMagic::CSSLOT_ALTERNATE_CODEDIRECTORIES:
                {
                    MAC::CS_CodeDirectory cd{};
                    CHECK(file->Copy<MAC::CS_CodeDirectory>(csOffset, cd), false, "")
                    Swap(cd);
                    codeSignature.alternateDirectories.emplace_back(cd);
                }
                break;
                default:
                    throw "Slot type not supported!";
                }
            }

            // auto pageSize  = codeDirectory->pageSize ? (1U << codeDirectory->pageSize) : 0U;
            // auto remaining = codeDirectory->codeLimit;
            // auto processed = 0ULL;
            // for (auto slot = 0U; slot < codeDirectory->nCodeSlots; slot++)
            // {
            //     const auto size = std::min<>(remaining, pageSize);
            //     CHECK(ValidateSlot(b.GetData() + processed, size, slot, codeDirectory), false, "Failed validating slot [%u]!", slot);
            //
            //     processed += size;
            //     remaining -= size;
            // }
        }
    }

    return true;
}

bool MachOFile::SetVersionMin()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::VERSION_MIN_IPHONEOS || lc.value.cmd == MAC::LoadCommandType::VERSION_MIN_MACOSX ||
            lc.value.cmd == MAC::LoadCommandType::VERSION_MIN_TVOS || lc.value.cmd == MAC::LoadCommandType::VERSION_MIN_WATCHOS)
        {
            if (versionMinCommand.isSet)
            {
                throw "Version min command already set!";
            }

            versionMinCommand.isSet = true;

            CHECK(file->Copy<MAC::version_min_command>(lc.offset, versionMinCommand.vmc), false, "");

            if (shouldSwapEndianess)
            {
                Swap(versionMinCommand.vmc);
            }
        }
    }

    return true;
}
} // namespace GView::Type::MachO

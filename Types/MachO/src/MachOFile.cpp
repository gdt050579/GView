#include "MachO.hpp"

namespace GView::Type::MachO
{
MachOFile::MachOFile(Reference<GView::Utils::DataCache> file)
    : header({}), fatHeader({}), isFat(false), isMacho(false), is64(false), shouldSwapEndianess(false), panelsMask(0)
{
}

bool MachOFile::Update()
{
    uint64 offset = 0;

    SetHeaderInfo(offset);

    panelsMask |= (1ULL << (uint8_t) Panels::IDs::Information);

    if (isMacho)
    {
        SetHeader(offset);
        SetLoadCommands(offset);
        SetSegmentsAndTheirSections();
        SetDyldInfo();
        SetIdDylibs();
        SetMain();
        SetSymbols();
        SetSourceVersion();
        SetUUID();
        SetLinkEditData();
        SetCodeSignature();
        SetVersionMin();

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

        if (codeSignature.has_value())
        {
            panelsMask |= (1ULL << (uint8_t) Panels::IDs::CodeSign);
        }
    }
    else if (isFat)
    {
        uint64 offset = 0;

        CHECK(obj->GetData().Copy<MAC::fat_header>(offset, fatHeader), false, "");
        offset += sizeof(MAC::fat_header);

        if (shouldSwapEndianess)
        {
            Swap(fatHeader);
        }

        archs.clear();
        archs.reserve(fatHeader.nfat_arch);

        for (decltype(fatHeader.nfat_arch) i = 0; i < fatHeader.nfat_arch; i++)
        {
            MAC::Arch arch{};
            if (is64)
            {
                MAC::fat_arch64 fa64;
                CHECK(obj->GetData().Copy<MAC::fat_arch64>(offset, fa64), false, "");
                if (shouldSwapEndianess)
                {
                    Swap(fa64);
                }
                offset += sizeof(MAC::fat_arch64);

                arch.cputype    = fa64.cputype;
                arch.cpusubtype = fa64.cpusubtype;
                arch.offset     = fa64.offset;
                arch.size       = fa64.size;
                arch.align      = fa64.align;
                arch.reserved   = fa64.reserved;
            }
            else
            {
                MAC::fat_arch fa;
                CHECK(obj->GetData().Copy<MAC::fat_arch>(offset, fa), false, "");
                if (shouldSwapEndianess)
                {
                    Swap(fa);
                }
                offset += sizeof(MAC::fat_arch);

                arch.cputype    = fa.cputype;
                arch.cpusubtype = fa.cpusubtype;
                arch.offset     = fa.offset;
                arch.size       = fa.size;
                arch.align      = fa.align;
            }

            MAC::mach_header mh{};
            CHECK(obj->GetData().Copy<MAC::mach_header>(arch.offset, mh), false, "");
            if (mh.magic == MAC::MH_CIGAM || mh.magic == MAC::MH_CIGAM_64)
            {
                Swap(mh);
            }

            arch.filetype = mh.filetype;

            arch.info = MAC::GetArchInfoFromCPUTypeAndSubtype(arch.cputype, arch.cpusubtype);
            archs.emplace_back(arch);
        }
    }

    return true;
}

bool MachOFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << ((uint8_t) id))) != 0;
}

uint64_t MachOFile::TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex)
{
    return value;
}

uint64_t MachOFile::TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex)
{
    return value;
}

bool MachOFile::SetHeaderInfo(uint64& offset)
{
    uint32 magic = 0;
    CHECK(obj->GetData().Copy<uint32>(offset, magic), false, "");

    isMacho = magic == MAC::MH_MAGIC || magic == MAC::MH_CIGAM || magic == MAC::MH_MAGIC_64 || magic == MAC::MH_CIGAM_64;
    isFat   = magic == MAC::FAT_MAGIC || magic == MAC::FAT_CIGAM || magic == MAC::FAT_MAGIC_64 || magic == MAC::FAT_CIGAM_64;

    is64 = magic == MAC::MH_MAGIC_64 || magic == MAC::MH_CIGAM_64 || magic == MAC::FAT_MAGIC_64 || magic == MAC::FAT_CIGAM_64;
    shouldSwapEndianess = magic == MAC::MH_CIGAM || magic == MAC::MH_CIGAM_64 || magic == MAC::FAT_CIGAM || magic == MAC::FAT_CIGAM_64;

    return true;
}

bool MachOFile::SetHeader(uint64& offset)
{
    CHECK(obj->GetData().Copy<MAC::mach_header>(offset, header), false, "");
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

bool MachOFile::SetLoadCommands(uint64& offset)
{
    loadCommands.reserve(header.ncmds);

    for (decltype(header.ncmds) i = 0; i < header.ncmds; i++)
    {
        MAC::load_command lc{};
        CHECK(obj->GetData().Copy<MAC::load_command>(offset, lc), false, "");
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
            CHECK(obj->GetData().Copy<decltype(sc)>(lc.offset, sc), false, "");
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
                CHECK(obj->GetData().Copy<decltype(section)>(offset, section), false, "");
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
            CHECK(obj->GetData().Copy<MAC::segment_command_64>(lc.offset, sc), false, "");
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
                CHECK(obj->GetData().Copy<decltype(section)>(offset, section), false, "");
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
            CHECK(obj->GetData().Copy<MAC::dyld_info_command>(lc.offset, *dyldInfo), false, "");

            if (shouldSwapEndianess)
            {
                Swap(*dyldInfo);
            }
        }
    }

    return true;
}

bool MachOFile::SetIdDylibs()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::ID_DYLIB || lc.value.cmd == MAC::LoadCommandType::LOAD_DYLIB ||
            lc.value.cmd == MAC::LoadCommandType::LOAD_WEAK_DYLIB || lc.value.cmd == MAC::LoadCommandType::REEXPORT_DYLIB ||
            lc.value.cmd == MAC::LoadCommandType::LAZY_LOAD_DYLIB || lc.value.cmd == MAC::LoadCommandType::LOAD_UPWARD_DYLIB)
        {
            auto buffer = obj->GetData().CopyToBuffer(lc.offset, lc.value.cmdsize);
            auto ptr    = buffer.GetData();

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

            dylibs.emplace_back(d);
        }
    }

    return true;
}

bool MachOFile::SetMain()
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
            CHECK(obj->GetData().Copy<MAC::entry_point_command>(lc.offset, *main), false, "");
            if (shouldSwapEndianess)
            {
                Swap(*main);
            }
        }
        else if (lc.value.cmd == MAC::LoadCommandType::UNIXTHREAD)
        {
            if (main.has_value())
            {
                throw "Multiple LoadCommandType::MAIN found! Reimplement this!";
            }

            main.emplace(MAC::entry_point_command{});

            main->cmd     = lc.value.cmd;
            main->cmdsize = lc.value.cmdsize;
            auto cmd      = obj->GetData().CopyToBuffer(lc.offset, main->cmdsize);

            if (header.cputype == MAC::CPU_TYPE_I386)
            {
                const auto registers = reinterpret_cast<MAC::i386_thread_state_t*>(cmd.GetData() + 16);
                if (shouldSwapEndianess)
                {
                    Swap(*registers);
                }
                main->entryoff = registers->eip;
            }
            else if (header.cputype == MAC::CPU_TYPE_X86_64)
            {
                const auto registers = reinterpret_cast<MAC::x86_thread_state64_t*>(cmd.GetData() + 16);
                if (shouldSwapEndianess)
                {
                    Swap(*registers);
                }
                main->entryoff = registers->rip;
            }
            else if (header.cputype == MAC::CPU_TYPE_POWERPC)
            {
                const auto registers = reinterpret_cast<MAC::ppc_thread_state_t*>(cmd.GetData() + 16);
                if (shouldSwapEndianess)
                {
                    Swap(*registers);
                }
                main->entryoff = registers->srr0;
            }
            else if (header.cputype == MAC::CPU_TYPE_POWERPC64)
            {
                const auto registers = reinterpret_cast<MAC::ppc_thread_state64_t*>(cmd.GetData() + 16);
                if (shouldSwapEndianess)
                {
                    Swap(*registers);
                }
                main->entryoff = registers->srr0;
            }
            else
            {
                throw "EP not handled for CPU from LoadCommandType::UNIXTHREAD!";
            }
        }
    }

    return true;
}

bool MachOFile::SetSymbols()
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
            CHECK(obj->GetData().Copy<MAC::symtab_command>(lc.offset, dySymTab->sc), false, "");

            if (shouldSwapEndianess)
            {
                Swap(dySymTab->sc);
            }

            const auto stringTable       = obj->GetData().CopyToBuffer(dySymTab->sc.stroff, dySymTab->sc.strsize);
            const auto symbolTableOffset = dySymTab->sc.nsyms * (is64 ? sizeof(MAC::nlist_64) : sizeof(MAC::nlist));
            const auto symbolTable       = obj->GetData().CopyToBuffer(dySymTab->sc.symoff, static_cast<uint32>(symbolTableOffset));

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
    }

    return true;
}

bool MachOFile::SetSourceVersion()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::SOURCE_VERSION)
        {
            if (sourceVersion.has_value())
            {
                throw "Multiple LoadCommandType::MAIN found! Reimplement this!";
            }

            sourceVersion.emplace(MAC::source_version_command{});
            CHECK(obj->GetData().Copy<MAC::source_version_command>(lc.offset, *sourceVersion), false, "");
            if (shouldSwapEndianess)
            {
                Swap(*sourceVersion);
            }
        }
    }

    return true;
}

bool MachOFile::SetUUID()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::UUID)
        {
            if (uuid.has_value())
            {
                throw "Multiple LoadCommandType::UUID found! Reimplement this!";
            }

            uuid.emplace(MAC::uuid_command{});
            CHECK(obj->GetData().Copy<MAC::uuid_command>(lc.offset, *uuid), false, "");
            if (shouldSwapEndianess)
            {
                Swap(*uuid);
            }
        }
    }

    return true;
}

bool MachOFile::SetLinkEditData()
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
            CHECK(obj->GetData().Copy<MAC::linkedit_data_command>(lc.offset, ledc), false, "");

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
    }

    return true;
}

bool MachOFile::SetCodeSignature()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::CODE_SIGNATURE)
        {
            codeSignature.emplace(CodeSignature{});

            CHECK(obj->GetData().Copy<MAC::linkedit_data_command>(lc.offset, codeSignature->ledc), false, "");
            if (shouldSwapEndianess)
            {
                Swap(codeSignature->ledc);
            }

            CHECK(obj->GetData().Copy<MAC::CS_SuperBlob>(codeSignature->ledc.dataoff, codeSignature->superBlob), false, "");

            // All fields are big endian (in case PPC ever makes a comeback)
            Swap(codeSignature->superBlob);

            const auto startBlobOffset = codeSignature->ledc.dataoff + sizeof(MAC::CS_SuperBlob);
            auto currentBlobOffset     = startBlobOffset;
            for (auto i = 0U; i < codeSignature->superBlob.count; i++)
            {
                MAC::CS_BlobIndex blob{};

                CHECK(obj->GetData().Copy<MAC::CS_BlobIndex>(currentBlobOffset, blob), false, "");
                Swap(blob);

                codeSignature->blobs.emplace_back(blob);

                currentBlobOffset += sizeof(MAC::CS_BlobIndex);
            }

            for (const auto& blob : codeSignature->blobs)
            {
                const auto csOffset = static_cast<uint64>(codeSignature->ledc.dataoff) + blob.offset;
                switch (blob.type)
                {
                case MAC::CodeSignMagic::CSSLOT_CODEDIRECTORY:
                {
                    CHECK(obj->GetData().Copy<MAC::CS_CodeDirectory>(csOffset, codeSignature->codeDirectory), false, "");
                    Swap(codeSignature->codeDirectory);

                    const auto blobBuffer                  = obj->GetData().CopyToBuffer(csOffset, codeSignature->codeDirectory.length);
                    codeSignature->codeDirectoryIdentifier = (char*) blobBuffer.GetData() + codeSignature->codeDirectory.identOffset;

                    const auto hashType = codeSignature->codeDirectory.hashType;
                    {
                        if (ComputeHash(blobBuffer, hashType, codeSignature->cdHash) == false)
                        {
                            throw "Unable to validate!";
                        }
                    }

                    auto pageSize  = codeSignature->codeDirectory.pageSize ? (1U << codeSignature->codeDirectory.pageSize) : 0U;
                    auto remaining = codeSignature->codeDirectory.codeLimit;
                    auto processed = 0ULL;
                    for (auto slot = 0U; slot < codeSignature->codeDirectory.nCodeSlots; slot++)
                    {
                        const auto size       = std::min<>(remaining, pageSize);
                        const auto hashOffset = codeSignature->codeDirectory.hashOffset + codeSignature->codeDirectory.hashSize * slot;
                        const auto bufferToValidate = obj->GetData().CopyToBuffer(processed, size);

                        std::string hashComputed;
                        if (ComputeHash(bufferToValidate, hashType, hashComputed) == false)
                        {
                            throw "Unable to validate!";
                        }

                        const auto hash = ((unsigned char*) blobBuffer.GetData() + hashOffset);
                        LocalString<128> ls;
                        for (auto i = 0U; i < codeSignature->codeDirectory.hashSize; i++)
                        {
                            ls.AddFormat("%.2X", hash[i]);
                        }
                        std::string hashFound{ ls };

                        codeSignature->cdSlotsHashes.emplace_back(std::pair<std::string, std::string>{ hashFound, hashComputed });

                        processed += size;
                        remaining -= size;
                    }
                }
                break;
                case MAC::CodeSignMagic::CSSLOT_INFOSLOT:
                    break;
                case MAC::CodeSignMagic::CSSLOT_REQUIREMENTS:
                {
                    CHECK(obj->GetData().Copy<MAC::CS_RequirementsBlob>(csOffset, codeSignature->requirements.blob), false, "");
                    Swap(codeSignature->requirements.blob);

                    codeSignature->requirements.data = obj->GetData().CopyToBuffer(
                          csOffset + sizeof(MAC::CS_RequirementsBlob),
                          codeSignature->requirements.blob.length - sizeof(MAC::CS_RequirementsBlob));

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
                    CHECK(obj->GetData().Copy<MAC::CS_GenericBlob>(csOffset, codeSignature->entitlements.blob), false, "");
                    Swap(codeSignature->entitlements.blob);
                    codeSignature->entitlements.data =
                          obj->GetData().CopyToBuffer(csOffset + sizeof(blob), codeSignature->entitlements.blob.length - sizeof(blob));
                }
                break;
                case MAC::CodeSignMagic::CS_SUPPL_SIGNER_TYPE_TRUSTCACHE:
                    break;
                case MAC::CodeSignMagic::CSSLOT_SIGNATURESLOT:
                {
                    MAC::CS_GenericBlob gblob{};
                    CHECK(obj->GetData().Copy<MAC::CS_GenericBlob>(csOffset, gblob), false, "");
                    Swap(gblob);

                    codeSignature->signature.offset = csOffset + sizeof(gblob);
                    codeSignature->signature.size   = gblob.length - sizeof(gblob);

                    const auto blobBuffer = obj->GetData().CopyToBuffer(
                          codeSignature->signature.offset, static_cast<uint32>(codeSignature->signature.size), false);
                    codeSignature->signature.errorHumanReadable =
                          !GView::DigitalSignature::CMSToHumanReadable(blobBuffer, codeSignature->signature.humanReadable);
                    codeSignature->signature.errorPEMs = !GView::DigitalSignature::CMSToPEMCerts(
                          blobBuffer, codeSignature->signature.PEMs, codeSignature->signature.PEMsCount);
                    codeSignature->signature.errorSig = !GView::DigitalSignature::CMSToStructure(blobBuffer, codeSignature->signature.sig);
                }
                break;
                case MAC::CodeSignMagic::CSSLOT_ALTERNATE_CODEDIRECTORIES:
                {
                    MAC::CS_CodeDirectory cd{};
                    CHECK(obj->GetData().Copy<MAC::CS_CodeDirectory>(csOffset, cd), false, "")
                    Swap(cd);
                    codeSignature->alternateDirectories.emplace_back(cd);

                    const auto blobBuffer = obj->GetData().CopyToBuffer(csOffset, cd.length);
                    codeSignature->alternateDirectoriesIdentifiers.emplace_back((char*) blobBuffer.GetData() + cd.identOffset);

                    const auto hashType = cd.hashType;
                    {
                        std::string cdHash;
                        if (ComputeHash(blobBuffer, hashType, cdHash) == false)
                        {
                            throw "Unable to validate!";
                        }
                        codeSignature->acdHashes.emplace_back(cdHash);
                    }

                    std::vector<std::pair<std::string, std::string>> cdSlotsHashes;

                    auto pageSize  = cd.pageSize ? (1U << cd.pageSize) : 0U;
                    auto remaining = cd.codeLimit;
                    auto processed = 0ULL;
                    for (auto slot = 0U; slot < cd.nCodeSlots; slot++)
                    {
                        const auto size             = std::min<>(remaining, pageSize);
                        const auto hashOffset       = cd.hashOffset + cd.hashSize * slot;
                        const auto bufferToValidate = obj->GetData().CopyToBuffer(processed, size);

                        std::string hashComputed;
                        if (ComputeHash(bufferToValidate, hashType, hashComputed) == false)
                        {
                            throw "Unable to validate!";
                        }

                        const auto hash = ((unsigned char*) blobBuffer.GetData() + hashOffset);
                        LocalString<128> ls;
                        for (auto i = 0U; i < cd.hashSize; i++)
                        {
                            ls.AddFormat("%.2X", hash[i]);
                        }
                        std::string hashFound{ ls };

                        cdSlotsHashes.emplace_back(std::pair<std::string, std::string>{ hashFound, hashComputed });

                        processed += size;
                        remaining -= size;
                    }

                    codeSignature->acdSlotsHashes.emplace_back(cdSlotsHashes);
                }
                break;
                default:
                    throw "Slot type not supported!";
                }
            }
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
            if (versionMin.has_value())
            {
                throw "Version min command already set!";
            }

            versionMin.emplace(MAC::version_min_command{});
            CHECK(obj->GetData().Copy<MAC::version_min_command>(lc.offset, *versionMin), false, "");
            if (shouldSwapEndianess)
            {
                Swap(*versionMin);
            }
        }
    }

    return true;
}

bool MachOFile::ComputeHash(const Buffer& buffer, uint8 hashType, std::string& output) const
{
    switch (static_cast<MAC::CodeSignMagic>(hashType))
    {
    case MAC::CodeSignMagic::CS_HASHTYPE_NO_HASH:
        throw "What to do?";
    case MAC::CodeSignMagic::CS_HASHTYPE_SHA1:
    {
        GView::Hashes::OpenSSLHash sha1(GView::Hashes::OpenSSLHashKind::Sha1);
        CHECK(sha1.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        CHECK(sha1.Final(), false, "");
        output = sha1.GetHexValue();
        output.resize(static_cast<uint64>(MAC::CodeSignMagic::CS_CDHASH_LEN) * 2ULL);
        return true;
    }
    case MAC::CodeSignMagic::CS_HASHTYPE_SHA256:
    {
        GView::Hashes::OpenSSLHash sha256(GView::Hashes::OpenSSLHashKind::Sha256);
        CHECK(sha256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        CHECK(sha256.Final(), false, "");
        output = sha256.GetHexValue();
        output.resize(static_cast<uint64>(MAC::CodeSignMagic::CS_SHA256_LEN) * 2ULL);
        return true;
    }
    case MAC::CodeSignMagic::CS_HASHTYPE_SHA256_TRUNCATED:
    {
        GView::Hashes::OpenSSLHash sha256(GView::Hashes::OpenSSLHashKind::Sha256);
        CHECK(sha256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        CHECK(sha256.Final(), false, "");
        output = sha256.GetHexValue();
        output.resize(static_cast<uint64>(MAC::CodeSignMagic::CS_SHA256_TRUNCATED_LEN) * 2ULL);
        return true;
    }
    case MAC::CodeSignMagic::CS_HASHTYPE_SHA384:
    {
        GView::Hashes::OpenSSLHash sha384(GView::Hashes::OpenSSLHashKind::Sha384);
        CHECK(sha384.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        CHECK(sha384.Final(), false, "");
        output = sha384.GetHexValue();
        output.resize(static_cast<uint64>(MAC::CodeSignMagic::CS_CDHASH_LEN) * 2ULL);
        return true;
    }
    case MAC::CodeSignMagic::CS_HASHTYPE_SHA512:
    {
        GView::Hashes::OpenSSLHash sha512(GView::Hashes::OpenSSLHashKind::Sha512);
        CHECK(sha512.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        CHECK(sha512.Final(), false, "");
        output = sha512.GetHexValue();
        output.resize(static_cast<uint64>(MAC::CodeSignMagic::CS_CDHASH_LEN) * 2ULL);
        return true;
    }
    default:
        throw "What to do?";
    }

    return false;
}

bool MachOFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    currentItemIndex = 0;
    return archs.size() > 0;
}
bool MachOFile::PopulateItem(TreeViewItem item)
{
    LocalString<128> tmp;
    NumericFormatter nf;
    const static auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, '.' };
    const static auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    const auto& arch = archs.at(currentItemIndex);
    const auto& info = arch.info;
    item.SetText(tmp.Format("%s (%s)", info.name.c_str(), nf.ToString(arch.cputype, hex).data()));
    item.SetText(1, tmp.Format("%s (%s)", info.description.c_str(), nf.ToString(arch.cpusubtype, hex).data()));

    const auto fileType             = arch.filetype;
    const auto& fileTypeName        = MAC::FileTypeNames.at(fileType);
    const auto& fileTypeDescription = MAC::FileTypeDescriptions.at(fileType);
    item.SetText(2, tmp.Format("%s (0x%X) %s", fileTypeName.data(), fileType, fileTypeDescription.data()));
    item.SetText(3, nf.ToString(arch.offset, hex));
    item.SetText(4, nf.ToString(arch.size, hex));
    item.SetText(5, nf.ToString(arch.align, hex));
    item.SetText(6, nf.ToString(1ULL << arch.align, hex));

    item.SetData<MAC::Arch>(&archs.at(currentItemIndex));

    currentItemIndex++;

    return currentItemIndex != archs.size();
}
void MachOFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    CHECKRET(item.GetParent().GetHandle() != InvalidItemHandle, "");

    auto data         = item.GetData<MAC::Arch>();
    const auto offset = data->offset;
    const auto length = (uint32) data->size;

    const auto buffer = obj->GetData().CopyToBuffer(offset, length);
    GView::App::OpenBuffer(buffer, data->info.name);
}
} // namespace GView::Type::MachO

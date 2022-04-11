#include "MachO.hpp"

//#include <time.h>
//#include <openssl/pem.h>
//#include <openssl/cms.h>
//#include <openssl/err.h>
//#include <openssl/pkcs12.h>
//#include <openssl/conf.h>
//#include <openssl/asn1.h>

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

    if (codeSignature.has_value())
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

bool MachOFile::SetIdDylibs()
{
    for (const auto& lc : loadCommands)
    {
        if (lc.value.cmd == MAC::LoadCommandType::ID_DYLIB || lc.value.cmd == MAC::LoadCommandType::LOAD_DYLIB ||
            lc.value.cmd == MAC::LoadCommandType::LOAD_WEAK_DYLIB || lc.value.cmd == MAC::LoadCommandType::REEXPORT_DYLIB ||
            lc.value.cmd == MAC::LoadCommandType::LAZY_LOAD_DYLIB || lc.value.cmd == MAC::LoadCommandType::LOAD_UPWARD_DYLIB)
        {
            auto buffer = file->CopyToBuffer(lc.offset, lc.value.cmdsize);
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
            CHECK(file->Copy<MAC::entry_point_command>(lc.offset, *main), false, "");
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
            auto cmd      = file->CopyToBuffer(lc.offset, main->cmdsize);

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
            CHECK(file->Copy<MAC::symtab_command>(lc.offset, dySymTab->sc), false, "");

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
            CHECK(file->Copy<MAC::source_version_command>(lc.offset, *sourceVersion), false, "");
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
            CHECK(file->Copy<MAC::uuid_command>(lc.offset, *uuid), false, "");
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
            CHECK(file->Copy<MAC::linkedit_data_command>(lc.offset, ledc), false, "");

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

            CHECK(file->Copy<MAC::linkedit_data_command>(lc.offset, codeSignature->ledc), false, "");
            if (shouldSwapEndianess)
            {
                Swap(codeSignature->ledc);
            }

            CHECK(file->Copy<MAC::CS_SuperBlob>(codeSignature->ledc.dataoff, codeSignature->superBlob), false, "");

            // All fields are big endian (in case PPC ever makes a comeback)
            Swap(codeSignature->superBlob);

            const auto startBlobOffset = codeSignature->ledc.dataoff + sizeof(MAC::CS_SuperBlob);
            auto currentBlobOffset     = startBlobOffset;
            for (auto i = 0U; i < codeSignature->superBlob.count; i++)
            {
                MAC::CS_BlobIndex blob{};

                CHECK(file->Copy<MAC::CS_BlobIndex>(currentBlobOffset, blob), false, "");
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
                    CHECK(file->Copy<MAC::CS_CodeDirectory>(csOffset, codeSignature->codeDirectory), false, "");
                    Swap(codeSignature->codeDirectory);

                    const auto blobBuffer                  = file->CopyToBuffer(csOffset, codeSignature->codeDirectory.length);
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
                        const auto bufferToValidate = file->CopyToBuffer(processed, size);

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
                    CHECK(file->Copy<MAC::CS_RequirementsBlob>(csOffset, codeSignature->requirements.blob), false, "");
                    Swap(codeSignature->requirements.blob);

                    codeSignature->requirements.data = file->CopyToBuffer(
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
                    CHECK(file->Copy<MAC::CS_GenericBlob>(csOffset, codeSignature->entitlements.blob), false, "");
                    Swap(codeSignature->entitlements.blob);
                    codeSignature->entitlements.data =
                          file->CopyToBuffer(csOffset + sizeof(blob), codeSignature->entitlements.blob.length - sizeof(blob));
                }
                break;
                case MAC::CodeSignMagic::CS_SUPPL_SIGNER_TYPE_TRUSTCACHE:
                    break;
                case MAC::CodeSignMagic::CSSLOT_SIGNATURESLOT:
                {
                    MAC::CS_GenericBlob gblob{};
                    CHECK(file->Copy<MAC::CS_GenericBlob>(csOffset, gblob), false, "");
                    Swap(gblob);

                    codeSignature->signature.offset = csOffset + sizeof(gblob);
                    codeSignature->signature.size   = gblob.length - sizeof(gblob);

                    const auto blobBuffer =
                          file->CopyToBuffer(codeSignature->signature.offset, static_cast<uint32>(codeSignature->signature.size), false);
                    codeSignature->signature.errorHumanReadable =
                          !GView::DigitalSignature::BufferToHumanReadable(blobBuffer, codeSignature->signature.humanReadable);
                    codeSignature->signature.errorPEMs =
                          !GView::DigitalSignature::BufferToPEMCerts(blobBuffer, codeSignature->signature.PEMs);

                    // BIO* in = BIO_new(BIO_s_mem());
                    // OPENSSL_assert((size_t) BIO_write(in, blobBuffer.GetData(), blobBuffer.GetLength()) == blobBuffer.GetLength());
                    // CMS_ContentInfo* cms = d2i_CMS_bio(in, NULL);
                    // const auto a         = ERR_get_error();
                    // char ubf[1000]{ 0 };
                    // ERR_error_string_n(a, ubf, 1000);
                    // if (!cms)
                    // {
                    //     throw "Failed parsing CMS!";
                    // }
                    // int detached           = CMS_is_detached(cms);
                    // const ASN1_OBJECT* obj = CMS_get0_type(cms);
                    // const char* sn         = OBJ_nid2ln(OBJ_obj2nid(obj));
                    //
                    // ASN1_OCTET_STRING** pos = CMS_get0_content(cms);
                    // if (pos)
                    // {
                    //     if ((*pos))
                    //     {
                    //         const auto data = (const char*) (*pos)->data;
                    //         const auto l    = (*pos)->length;
                    //     }
                    // }
                    //
                    // STACK_OF(X509)* certs = CMS_get1_certs(cms);
                    // for (int i = 0; i < sk_X509_num(certs); i++)
                    // {
                    //     const auto cert    = sk_X509_value(certs, i);
                    //     const auto version = (int) X509_get_version(cert);
                    //
                    //     std::string strIssuer  = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
                    //     std::string strSubject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
                    //
                    //     auto a = ERR_get_error();
                    //     char ubf[1000]{ 0 };
                    //     ERR_error_string_n(a, ubf, 1000);
                    //
                    //     EVP_PKEY* pkey = X509_get_pubkey(cert);
                    //     int r          = X509_verify(cert, pkey);
                    //     if (r != 1)
                    //     {
                    //         a = ERR_get_error();
                    //         ERR_error_string_n(a, ubf, 1000);
                    //     }
                    //     EVP_PKEY_free(pkey);
                    // }

                    /*
                    BIO* in = BIO_new(BIO_s_mem());
                    OPENSSL_assert((size_t) BIO_write(in, blobBuffer.GetData(), blobBuffer.GetLength()) == blobBuffer.GetLength());
                    CMS_ContentInfo* cms = d2i_CMS_bio(in, NULL);
                    const auto a         = ERR_get_error();
                    char ubf[1000]{ 0 };
                    ERR_error_string_n(a, ubf, 1000);
                    if (!cms)
                    {
                        throw "Failed parsing CMS!";
                    }
                    int detached           = CMS_is_detached(cms);
                    const ASN1_OBJECT* obj = CMS_get0_type(cms);
                    const char* sn         = OBJ_nid2ln(OBJ_obj2nid(obj));

                    ASN1_OCTET_STRING** pos = CMS_get0_content(cms);
                    if (pos)
                    {
                        if ((*pos))
                        {
                            const auto data = (const char*) (*pos)->data;
                            const auto l    = (*pos)->length;
                        }
                    }

                    STACK_OF(X509)* certs = CMS_get1_certs(cms);
                    for (int i = 0; i < sk_X509_num(certs); i++)
                    {
                        const auto cert      = sk_X509_value(certs, i);
                        const auto version   = (int) X509_get_version(cert);
                        ASN1_INTEGER* asn1_i = X509_get_serialNumber(cert);
                        if (asn1_i)
                        {
                            BIGNUM* bignum          = ASN1_INTEGER_to_BN(asn1_i, NULL);
                            const auto serialNumber = BN_bn2hex(bignum);
                        }

                        const auto SignatureAlgorithm = OBJ_nid2ln(X509_get_signature_nid(cert));

                        EVP_PKEY* pubkey               = X509_get_pubkey(cert);
                        int type                       = EVP_PKEY_id(pubkey);
                        const auto PublicKey_Algorithm = OBJ_nid2ln(type);

                        const auto ASN1_TIMEtoString = [](const ASN1_TIME* time) -> std::string
                        {
                            BIO* out = BIO_new(BIO_s_mem());
                            if (!out)
                            {
                                // CMSError();
                                return "";
                            }

                            ASN1_TIME_print(out, time);
                            BUF_MEM* bptr = NULL;
                            BIO_get_mem_ptr(out, &bptr);
                            if (!bptr)
                            {
                                // CMSError();
                                return "";
                            }
                            std::string strTime;
                            strTime.append(bptr->data, bptr->length);
                            return strTime;
                        };

                        const auto Validity_NotBefore = ASN1_TIMEtoString(X509_get0_notBefore(cert));
                        const auto Validity_NotAfter  = ASN1_TIMEtoString(X509_get0_notAfter(cert));

                        std::string strIssuer  = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
                        std::string strSubject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

                        const auto ParseCertSubject = [](const std::string& strSubject)
                        {
                            const auto split = [](const std::string& s, char seperator) -> std::vector<std::string>
                            {
                                std::vector<std::string> output;

                                std::string::size_type prev_pos = 0, pos = 0;

                                while ((pos = s.find(seperator, pos)) != std::string::npos)
                                {
                                    std::string substring(s.substr(prev_pos, pos - prev_pos));

                                    output.push_back(substring);

                                    prev_pos = ++pos;
                                }

                                output.push_back(s.substr(prev_pos, pos - prev_pos)); // Last word

                                return output;
                            };

                            vector<std::string> arrNodes = split(strSubject, '/');
                            for (size_t i = 0; i < arrNodes.size(); i++)
                            {
                                std::vector<std::string> arrLines = split(arrNodes[i], '=');
                                if (2 == arrLines.size())
                                {
                                    return arrLines[1];
                                }
                            }
                        };

                        ParseCertSubject(strIssuer);
                        ParseCertSubject(strSubject);
                    }

                    STACK_OF(CMS_SignerInfo)* sis = CMS_get0_SignerInfos(cms);
                    for (int i = 0; i < sk_CMS_SignerInfo_num(sis); i++)
                    {
                        CMS_SignerInfo* si = sk_CMS_SignerInfo_value(sis, i);
                        // int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si, ASN1_OCTET_STRING **keyid, X509_NAME **issuer, ASN1_INTEGER
                        // **sno);

                        int nSignedAttsCount = CMS_signed_get_attr_count(si);
                        for (int j = 0; j < nSignedAttsCount; j++)
                        {
                            X509_ATTRIBUTE* attr = CMS_signed_get_attr(si, j);
                            if (!attr)
                            {
                                continue;
                            }
                            int nCount = X509_ATTRIBUTE_count(attr);
                            if (nCount <= 0)
                            {
                                continue;
                            }

                            ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
                            if (!obj)
                            {
                                continue;
                            }

                            char txtobj[128] = { 0 };
                            OBJ_obj2txt(txtobj, 128, obj, 1);

                            if (0 == strcmp("1.2.840.113549.1.9.3", txtobj))
                            { // V_ASN1_OBJECT
                                ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
                                if (NULL != av)
                                {
                                    const auto attrs_ContentType_obj  = txtobj;
                                    const auto attrs_ContentType_data = OBJ_nid2ln(OBJ_obj2nid(av->value.object));
                                }
                            }
                            else if (0 == strcmp("1.2.840.113549.1.9.4", txtobj))
                            { // V_ASN1_OCTET_STRING
                                ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
                                if (NULL != av)
                                {
                                    std::string strSHASum;
                                    char buf[16] = { 0 };
                                    for (int m = 0; m < av->value.octet_string->length; m++)
                                    {
                                        sprintf(buf, "%02x", (uint8_t) av->value.octet_string->data[m]);
                                        strSHASum += buf;
                                    }
                                    const auto attrs_MessageDigest_obj  = txtobj;
                                    const auto attrs_MessageDigest_data = strSHASum;
                                }
                            }
                            else if (0 == strcmp("1.2.840.113549.1.9.5", txtobj))
                            { // V_ASN1_UTCTIME
                                ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
                                if (NULL != av)
                                {
                                    BIO* mem = BIO_new(BIO_s_mem());
                                    ASN1_UTCTIME_print(mem, av->value.utctime);
                                    BUF_MEM* bptr = NULL;
                                    BIO_get_mem_ptr(mem, &bptr);
                                    BIO_set_close(mem, BIO_NOCLOSE);
                                    std::string strTime;
                                    strTime.append(bptr->data, bptr->length);
                                    BIO_free_all(mem);

                                    const auto attrs_SigningTime_obj  = txtobj;
                                    const auto attrs_SigningTime_data = strTime;
                                }
                            }
                            else if (0 == strcmp("1.2.840.113635.100.9.2", txtobj))
                            { // V_ASN1_SEQUENCE
                                const auto attrs_CDHashes2_obj = txtobj;
                                for (int m = 0; m < nCount; m++)
                                {
                                    ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, m);
                                    if (NULL != av)
                                    {
                                        ASN1_STRING* s = av->value.sequence;

                                        BIO* mem = BIO_new(BIO_s_mem());

                                        ASN1_parse_dump(mem, s->data, s->length, 2, 0);
                                        BUF_MEM* bptr = NULL;
                                        BIO_get_mem_ptr(mem, &bptr);
                                        BIO_set_close(mem, BIO_NOCLOSE);
                                        std::string strData;
                                        strData.append(bptr->data, bptr->length);
                                        BIO_free_all(mem);

                                        std::string strSHASum;
                                        size_t pos1 = strData.find("[HEX DUMP]:");
                                        if (std::string::npos != pos1)
                                        {
                                            size_t pos2 = strData.find("\n", pos1);
                                            if (std::string::npos != pos2)
                                            {
                                                strSHASum = strData.substr(pos1 + 11, pos2 - pos1 - 11);
                                            }
                                        }
                                        transform(strSHASum.begin(), strSHASum.end(), strSHASum.begin(), ::tolower);
                                        const auto attrs_CDHashes2_data = strSHASum; //.push_back(strSHASum);
                                    }
                                }
                            }
                            else if (0 == strcmp("1.2.840.113635.100.9.1", txtobj))
                            { // V_ASN1_OCTET_STRING
                                ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
                                if (NULL != av)
                                {
                                    std::string strPList;
                                    strPList.append((const char*) av->value.octet_string->data, av->value.octet_string->length);
                                    const auto attrs_CDHashes_obj  = txtobj;
                                    const auto attrs_CDHashes_data = strPList;
                                }
                            }
                            else
                            {
                                ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
                                if (NULL != av)
                                {
                                    const auto obj_   = txtobj;
                                    const auto name  = OBJ_nid2ln(OBJ_obj2nid(obj));
                                    const auto type  = av->type;
                                    const auto count = nCount;
                                    //const auto attrs_unknown = //.push_back(jvAttr);
                                }
                            }
                        }
                    }
                */
                }
                break;
                case MAC::CodeSignMagic::CSSLOT_ALTERNATE_CODEDIRECTORIES:
                {
                    MAC::CS_CodeDirectory cd{};
                    CHECK(file->Copy<MAC::CS_CodeDirectory>(csOffset, cd), false, "")
                    Swap(cd);
                    codeSignature->alternateDirectories.emplace_back(cd);

                    const auto blobBuffer = file->CopyToBuffer(csOffset, cd.length);
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
                        const auto bufferToValidate = file->CopyToBuffer(processed, size);

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
            CHECK(file->Copy<MAC::version_min_command>(lc.offset, *versionMin), false, "");
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
} // namespace GView::Type::MachO

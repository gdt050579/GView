#pragma once

#include "Mac.hpp"
#include "Utils.hpp"

namespace MAC
{
inline void Swap(fat_header& obj)
{
    SwapEndianInplace(obj.magic);
    SwapEndianInplace(obj.nfat_arch);
}

inline void Swap(fat_arch64& obj)
{
    SwapEndianInplace(obj.cputype);
    SwapEndianInplace(obj.cpusubtype);
    SwapEndianInplace(obj.offset);
    SwapEndianInplace(obj.size);
    SwapEndianInplace(obj.align);
    SwapEndianInplace(obj.reserved);
}

inline void Swap(fat_arch& obj)
{
    SwapEndianInplace(obj.cputype);
    SwapEndianInplace(obj.cpusubtype);
    SwapEndianInplace(obj.offset);
    SwapEndianInplace(obj.size);
    SwapEndianInplace(obj.align);
}

inline void Swap(mach_header& obj)
{
    SwapEndianInplace(obj.magic);
    SwapEndianInplace(obj.cputype);
    SwapEndianInplace(obj.cpusubtype);
    SwapEndianInplace(obj.filetype);
    SwapEndianInplace(obj.ncmds);
    SwapEndianInplace(obj.sizeofcmds);
    SwapEndianInplace(obj.flags);
}

inline void Swap(load_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
}

inline void Swap(segment_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.segname);
    SwapEndianInplace(obj.vmaddr);
    SwapEndianInplace(obj.vmsize);
    SwapEndianInplace(obj.fileoff);
    SwapEndianInplace(obj.filesize);
    SwapEndianInplace(obj.maxprot);
    SwapEndianInplace(obj.initprot);
    SwapEndianInplace(obj.nsects);
    SwapEndianInplace(obj.flags);
}

inline void Swap(segment_command_64& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.segname);
    SwapEndianInplace(obj.vmaddr);
    SwapEndianInplace(obj.vmsize);
    SwapEndianInplace(obj.fileoff);
    SwapEndianInplace(obj.filesize);
    SwapEndianInplace(obj.maxprot);
    SwapEndianInplace(obj.initprot);
    SwapEndianInplace(obj.nsects);
    SwapEndianInplace(obj.flags);
}

inline void Swap(section_64& obj)
{
    SwapEndianInplace(obj.sectname);
    SwapEndianInplace(obj.segname);
    SwapEndianInplace(obj.addr);
    SwapEndianInplace(obj.size);
    SwapEndianInplace(obj.offset);
    SwapEndianInplace(obj.align);
    SwapEndianInplace(obj.reloff);
    SwapEndianInplace(obj.nreloc);
    SwapEndianInplace(obj.flags);
    SwapEndianInplace(obj.reserved1);
    SwapEndianInplace(obj.reserved2);
    SwapEndianInplace(obj.reserved3);
}

inline void Swap(section& obj)
{
    SwapEndianInplace(obj.sectname);
    SwapEndianInplace(obj.segname);
    SwapEndianInplace(obj.addr);
    SwapEndianInplace(obj.size);
    SwapEndianInplace(obj.offset);
    SwapEndianInplace(obj.align);
    SwapEndianInplace(obj.reloff);
    SwapEndianInplace(obj.nreloc);
    SwapEndianInplace(obj.flags);
    SwapEndianInplace(obj.reserved1);
    SwapEndianInplace(obj.reserved2);
}

inline void Swap(dylib_mac& obj)
{
    SwapEndianInplace(obj.name.ptr);
    SwapEndianInplace(obj.name.offset);
    SwapEndianInplace(obj.timestamp);
    SwapEndianInplace(obj.current_version);
    SwapEndianInplace(obj.compatibility_version);
}

inline void Swap(dylib_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    Swap(obj.dylib);
}

inline void Swap(entry_point_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.entryoff);
    SwapEndianInplace(obj.stacksize);
}

inline void Swap(symtab_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.symoff);
    SwapEndianInplace(obj.nsyms);
    SwapEndianInplace(obj.stroff);
    SwapEndianInplace(obj.strsize);
}

inline void Swap(nlist_64& obj)
{
    SwapEndianInplace(obj.n_un.n_strx);
    SwapEndianInplace(obj.n_desc);
    SwapEndianInplace(obj.n_sect);
    SwapEndianInplace(obj.n_type);
    SwapEndianInplace(obj.n_value);
}

inline void Swap(nlist& obj)
{
    SwapEndianInplace(obj.n_un.n_strx);
    SwapEndianInplace(obj.n_desc);
    SwapEndianInplace(obj.n_sect);
    SwapEndianInplace(obj.n_type);
    SwapEndianInplace(obj.n_value);
}

inline void Swap(source_version_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.version);
}

inline void Swap(uuid_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.uuid);
}

inline void Swap(linkedit_data_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.dataoff);
    SwapEndianInplace(obj.datasize);
}

inline void Swap(CS_SuperBlob& obj)
{
    SwapEndianInplace(obj.magic);
    SwapEndianInplace(obj.length);
    SwapEndianInplace(obj.count);
}

inline void Swap(CS_BlobIndex& obj)
{
    SwapEndianInplace(obj.type);
    SwapEndianInplace(obj.offset);
}

inline void Swap(CS_CodeDirectory& obj)
{
    SwapEndianInplace(obj.magic);
    SwapEndianInplace(obj.length);
    SwapEndianInplace(obj.version);
    SwapEndianInplace(obj.flags);
    SwapEndianInplace(obj.hashOffset);
    SwapEndianInplace(obj.identOffset);
    SwapEndianInplace(obj.nSpecialSlots);
    SwapEndianInplace(obj.nCodeSlots);
    SwapEndianInplace(obj.codeLimit);
    SwapEndianInplace(obj.hashSize);
    SwapEndianInplace(obj.hashType);
    SwapEndianInplace(obj.platform);
    SwapEndianInplace(obj.pageSize);
    SwapEndianInplace(obj.spare2);

    if (obj.version >= static_cast<uint32>(CodeSignMagic::CS_SUPPORTSSCATTER))
    {
        SwapEndianInplace(obj.scatterOffset);
    }
    if (obj.version >= static_cast<uint32>(CodeSignMagic::CS_SUPPORTSTEAMID))
    {
        SwapEndianInplace(obj.teamOffset);
    }
    if (obj.version >= static_cast<uint32>(CodeSignMagic::CS_SUPPORTSCODELIMIT64))
    {
        SwapEndianInplace(obj.spare3);
        SwapEndianInplace(obj.codeLimit64);
    }
    if (obj.version >= static_cast<uint32>(CodeSignMagic::CS_SUPPORTSEXECSEG))
    {
        SwapEndianInplace(obj.execSegBase);
        SwapEndianInplace(obj.execSegLimit);
        SwapEndianInplace(obj.execSegFlags);
    }
}

inline void Swap(CS_RequirementsBlob& obj)
{
    SwapEndianInplace(obj.magic);
    SwapEndianInplace(obj.length);
    SwapEndianInplace(obj.data);
}

inline void Swap(CS_GenericBlob& obj)
{
    SwapEndianInplace(obj.magic);
    SwapEndianInplace(obj.length);
}

inline void Swap(version_min_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.version);
    SwapEndianInplace(obj.sdk);
}

inline void Swap(dyld_info_command& obj)
{
    SwapEndianInplace(obj.cmd);
    SwapEndianInplace(obj.cmdsize);
    SwapEndianInplace(obj.rebase_off);
    SwapEndianInplace(obj.rebase_size);
    SwapEndianInplace(obj.bind_off);
    SwapEndianInplace(obj.bind_size);
    SwapEndianInplace(obj.weak_bind_off);
    SwapEndianInplace(obj.weak_bind_size);
    SwapEndianInplace(obj.lazy_bind_off);
    SwapEndianInplace(obj.lazy_bind_size);
    SwapEndianInplace(obj.export_off);
    SwapEndianInplace(obj.export_size);
}

inline void Swap(i386_thread_state_t& obj)
{
    SwapEndianInplace(obj.eax);
    SwapEndianInplace(obj.ebx);
    SwapEndianInplace(obj.ecx);
    SwapEndianInplace(obj.edx);
    SwapEndianInplace(obj.edi);
    SwapEndianInplace(obj.esi);
    SwapEndianInplace(obj.ebp);
    SwapEndianInplace(obj.esp);
    SwapEndianInplace(obj.ss);
    SwapEndianInplace(obj.eflags);
    SwapEndianInplace(obj.eip);
    SwapEndianInplace(obj.cs);
    SwapEndianInplace(obj.ds);
    SwapEndianInplace(obj.es);
    SwapEndianInplace(obj.fs);
    SwapEndianInplace(obj.gs);
}

inline void Swap(x86_thread_state64_t& obj)
{
    SwapEndianInplace(obj.rax);
    SwapEndianInplace(obj.rbx);
    SwapEndianInplace(obj.rcx);
    SwapEndianInplace(obj.rdx);
    SwapEndianInplace(obj.rdi);
    SwapEndianInplace(obj.rsi);
    SwapEndianInplace(obj.rbp);
    SwapEndianInplace(obj.rsp);
    SwapEndianInplace(obj.r8);
    SwapEndianInplace(obj.r9);
    SwapEndianInplace(obj.r10);
    SwapEndianInplace(obj.r11);
    SwapEndianInplace(obj.r12);
    SwapEndianInplace(obj.r13);
    SwapEndianInplace(obj.r14);
    SwapEndianInplace(obj.r15);
    SwapEndianInplace(obj.rip);
    SwapEndianInplace(obj.rflags);
    SwapEndianInplace(obj.cs);
    SwapEndianInplace(obj.fs);
    SwapEndianInplace(obj.gs);
}

inline void Swap(ppc_thread_state_t& obj)
{
    SwapEndianInplace(obj.srr0);
    SwapEndianInplace(obj.srr1);
    SwapEndianInplace(obj.r);
    SwapEndianInplace(obj.cr);
    SwapEndianInplace(obj.xer);
    SwapEndianInplace(obj.lr);
    SwapEndianInplace(obj.ctr);
    SwapEndianInplace(obj.mq);
    SwapEndianInplace(obj.vrsave);
}

inline void Swap(ppc_thread_state64_t& obj)
{
    SwapEndianInplace(obj.srr0);
    SwapEndianInplace(obj.srr1);
    SwapEndianInplace(obj.r);
    SwapEndianInplace(obj.cr);
    SwapEndianInplace(obj.xer);
    SwapEndianInplace(obj.lr);
    SwapEndianInplace(obj.ctr);
    /*SwapEndianInplace(obj.mq); // only on 601 */
    SwapEndianInplace(obj.vrsave);
}
} // namespace MAC

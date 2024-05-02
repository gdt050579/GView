#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Executables
{
enum class Types { MZPE, MachO, MachOFat, COFF, ELF };

static const std::map<Types, Metadata> TYPES_MAP{
    { Types::MZPE,
      { "MZPE",
        "Portable Executable (PE) format is a file format for executables, object code, DLLs and others used in 32-bit and 64-bit versions of Windows "
        "operating systems, and in UEFI environments.",
        true } },
    { Types::MachO,
      { "Mach-O",
        "Mach-O, short for Mach object file format, is a file format for executables, object code, shared libraries, dynamically loaded code, and core dumps. "
        "It was developed to replace the a.out format. Mach-O is used by some systems based on the Mach kernel.NeXTSTEP, macOS, and iOS.",
        false } },
    { Types::MachOFat,
      { "Mach-O Fat", "A fat binary is an uncompressed archive format to embed more than one standalone Mach-O object in a single file.", false } },
    { Types::COFF,
      { "COFF",
        "The Common Object File Format (COFF) is a format for executable, object code, and shared library computer files used on Unix systems. It was "
        "introduced in Unix System V, replaced the previously used a.out format, and formed the basis for extended specifications such as XCOFF and ECOFF, "
        "before being largely replaced by ELF, introduced with SVR4. COFF and its variants continue to be used on some Unix-like systems, on Microsoft Windows "
        "(Portable Executable), in UEFI environments and in some embedded development systems.",
        false } },
    { Types::ELF,
      { "ELF",
        "ELF is short for Executable and Linkable Format. It's a format used for storing binaries, libraries, and core dumps on disks in Linux and Unix-based "
        "systems.",
        false } },
};

class MZPE : public IDrop
{
  private:
  public:
    MZPE() = default;

    virtual const std::string_view GetName() const override;
    virtual ObjectCategory GetGroup() const override;
    virtual uint32 GetSubGroup() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::Executables

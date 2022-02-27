#include "machofb.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

template <typename T>
constexpr std::string BinaryToHexString(const T number, const size_t length)
{
    constexpr const char digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(length * 3);

    const auto input = reinterpret_cast<const uint8_t*>(&number);
    std::for_each(
          input,
          input + length,
          [&output](uint8_t byte)
          {
              output.push_back(digits[byte >> 4]);
              output.push_back(digits[byte & 0x0F]);
              output.push_back(' ');
          });

    if (output.empty() == false)
    {
        output.resize(output.size() - 1);
    }

    return output;
}

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        auto header = buf.GetObject<MachOFB::fat_header>();
        CHECK(header != nullptr, false, "");
        CHECK(header->magic == MachOFB::FAT_MAGIC || header->magic == MachOFB::FAT_CIGAM || header->magic == MachOFB::FAT_MAGIC_64 ||
                    header->magic == MachOFB::FAT_CIGAM_64,
              false,
              "Magic is [%u]!",
              header->magic);
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new MachOFB::MachOFBFile(file);
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MachOFB::MachOFBFile> macho)
    {
        BufferViewer::Settings settings;
        uint64_t offset = 0;

        const auto a = sizeof(macho->header);
        settings.AddZone(offset, sizeof(macho->header), macho->colors.header, "Header");
        offset += sizeof(macho->header);

        uint32_t objectCount = 0;
        LocalString<128> temp;
        if (macho->is64)
        {
            for (const auto& arch : macho->archs64)
            {
                temp.Format("Arch #%u", objectCount);
                settings.AddZone(offset, sizeof(arch), macho->colors.archs, temp);

                temp.Format("Obj #%u", objectCount);
                settings.AddZone(arch.offset, arch.size, macho->colors.object, temp);

                objectCount++;
            }
        }
        else
        {
            for (const auto& arch : macho->archs)
            {

                const auto a = sizeof(arch);
                temp.Format("Arch #%u", objectCount);
                settings.AddZone(offset, sizeof(arch), macho->colors.archs, temp);

                temp.Format("Obj #%u", objectCount);
                settings.AddZone(arch.offset, arch.size, macho->colors.object, temp);

                objectCount++;
            }
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto mach = reinterpret_cast<MachOFB::MachOFBFile*>(win->GetObject()->type);
        mach->Update();

        CreateBufferView(win, mach);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> patterns = {
            "hex:'" + BinaryToHexString(MachOFB::FAT_MAGIC, sizeof(MachOFB::FAT_MAGIC)) + "'",
            "hex:'" + BinaryToHexString(MachOFB::FAT_CIGAM, sizeof(MachOFB::FAT_CIGAM)) + "'",
            "hex:'" + BinaryToHexString(MachOFB::FAT_MAGIC_64, sizeof(MachOFB::FAT_MAGIC_64)) + "'",
            "hex:'" + BinaryToHexString(MachOFB::FAT_CIGAM_64, sizeof(MachOFB::FAT_CIGAM_64)) + "'"
        };

        sect["Pattern"]  = patterns;
        sect["Priority"] = 1;
    }
}

int main()
{
    return 0;
}

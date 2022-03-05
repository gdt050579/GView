#include "MachO.hpp"

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
        auto dword = buf.GetObject<uint32_t>();
        CHECK(dword != nullptr, false, "");
        const uint32_t magic = dword;
        CHECK(magic == MachO::MAC::MH_MAGIC || magic == MachO::MAC::MH_CIGAM || magic == MachO::MAC::MH_MAGIC_64 ||
                    magic == MachO::MAC::MH_CIGAM_64,
              false,
              "Magic is [%u]!",
              magic);
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new MachO::MachOFile(file);
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MachO::MachOFile> machO)
    {
        BufferViewer::Settings settings;
        uint64_t offset = 0;

        const auto headerSize =
              machO->is64 ? sizeof(MachO::MAC::mach_header) + sizeof(MachO::MAC::mach_header::reserved) : sizeof(MachO::MAC::mach_header);
        settings.AddZone(offset, headerSize, machO->colors.header, "Header");
        offset += headerSize;

        uint32_t objectCount = 0;
        LocalString<128> temp;

        //

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto mach = reinterpret_cast<MachO::MachOFile*>(win->GetObject()->type);
        mach->Update();

        CreateBufferView(win, mach);

        if (mach->HasPanel(MachO::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::Information(mach)), true);
        }

        if (mach->HasPanel(MachO::Panels::IDs::Objects))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::Objects(mach, win)), false);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> patterns = {
            "hex:'" + BinaryToHexString(MachO::MAC::MH_MAGIC, sizeof(MachO::MAC::MH_MAGIC)) + "'",
            "hex:'" + BinaryToHexString(MachO::MAC::MH_CIGAM, sizeof(MachO::MAC::MH_CIGAM)) + "'",
            "hex:'" + BinaryToHexString(MachO::MAC::MH_MAGIC_64, sizeof(MachO::MAC::MH_MAGIC_64)) + "'",
            "hex:'" + BinaryToHexString(MachO::MAC::MH_CIGAM_64, sizeof(MachO::MAC::MH_CIGAM_64)) + "'"
        };

        sect["Pattern"]  = patterns;
        sect["Priority"] = 1;
    }
}

int main()
{
    return 0;
}

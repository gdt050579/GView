#pragma once

#include "NameMapping.hpp"
#include "Swap.hpp"

namespace GView::Type::UniversalMachO
{
namespace Panels
{
    enum class IDs : uint8_t
    {
        Information = 0,
        Objects     = 1
    };
};

class UniversalMachOFile : public TypeInterface, public GView::View::BufferViewer::OffsetTranslateInterface
{
  public:
    const struct Colors
    {
        const ColorPair header{ Color::Olive, Color::Transparent };
        const ColorPair arch{ Color::Magenta, Color::Transparent };
        const ColorPair objectName{ Color::DarkRed, Color::Transparent };
        const ColorPair object{ Color::Silver, Color::Transparent };
    } colors;

  public:
    MAC::fat_header header;
    std::vector<MAC::Arch> archs;
    bool shouldSwapEndianess;
    bool is64;

    uint64_t panelsMask;

  public:
    // OffsetTranslateInterface
    uint64_t TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex) override;
    uint64_t TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex) override;

    // TypeInterface
    std::string_view GetTypeName() override
    {
        return "Universal Mach-O";
    }

  public:
    UniversalMachOFile();
    virtual ~UniversalMachOFile(){};

    bool Update();

    bool HasPanel(Panels::IDs id);
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<UniversalMachOFile> machO;
        Reference<AppCUI::Controls::ListView> general;

        void UpdateGeneralInformation();
        void RecomputePanelsPositions();

      public:
        Information(Reference<UniversalMachOFile> machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class Objects : public AppCUI::Controls::TabPage
    {
        Reference<UniversalMachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Objects(Reference<UniversalMachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
} // namespace Panels
} // namespace GView::Type::UniversalMachO

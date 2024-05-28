#pragma once

#include "Internal.hpp"

#include <array>

namespace GView::Type::Prefetch
{

template <typename T>
static const std::string BinaryToHexString(const T number, const size_t length)
{
    std::string output;
    output.reserve(length * 3);

    const auto input = reinterpret_cast<const uint8_t*>(&number);
    std::for_each(
          input,
          input + length,
          [&output](uint8_t byte)
          {
              constexpr const char digits[] = "0123456789ABCDEF";
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

class PrefetchFile : public TypeInterface
{
  public:
    Header header{};
    SectionArea area{};
    std::variant<FileInformation_17, FileInformation_23, FileInformation_30v1, FileInformation_30v2> fileInformation{};
    Buffer bufferSectionA;
    Buffer bufferSectionB;
    Buffer bufferSectionC;
    Buffer executablePath; // Windows 10 V2
    Buffer bufferSectionD;

    struct VolumeEntry
    {
        std::string name;
        Buffer files;
        Buffer directories;
    };

    std::map<uint32, VolumeEntry> volumeEntries;

    int64 xpHash    = 0;
    int64 vistaHash = 0;
    int64 hash2008  = 0;
    std::string filename;
    std::string exePath;
    Win10Version win10Version = Win10Version::None;

  public:
    PrefetchFile();
    virtual ~PrefetchFile()
    {
    }

    bool Update();
    bool UpdateSectionArea();
    bool Update_17();
    bool Update_23();
    bool Update_26();
    bool Update_30();

    std::string_view GetTypeName() override
    {
        return "Prefetch";
    }
    void RunCommand(std::string_view) override
    {
    }

  private:
    bool SetFilename();
    bool ComputeHashForMainExecutable(std::u16string_view path);
    bool AddVolumeEntry(
          uint32 devicePathOffset,
          uint32 devicePathLength,
          uint32 fileReferencesOffset,
          uint32 fileReferencesSize,
          uint32 directoryStringsOffset,
          uint32 i);
    bool SetEntries(uint32 sectionASize, uint32 sectionBSize, uint32 sectionCSize);

  public:
    Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

    uint32 GetSelectionZonesCount() override
    {
        CHECK(selectionZoneInterface.IsValid(), 0, "");
        return selectionZoneInterface->GetSelectionZonesCount();
    }

    TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
    {
        static auto d = TypeInterface::SelectionZone{ 0, 0 };
        CHECK(selectionZoneInterface.IsValid(), d, "");
        CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

        return selectionZoneInterface->GetSelectionZone(index);
    }
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::Prefetch::PrefetchFile> prefetch;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateHeader();
        void UpdateSectionArea();
        void UpdateFileInformation();
        void UpdateFileInformation_17();
        void UpdateFileInformation_23();
        void UpdateFileInformation_26();
        void UpdateFileInformation_30v1();
        void UpdateFileInformation_30v2();
        void UpdateIssues();
        void RecomputePanelsPositions();

      public:
        Information(Reference<Object> _object, Reference<GView::Type::Prefetch::PrefetchFile> _prefetch);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class FileInformationEntry : public AppCUI::Controls::TabPage
    {
        Reference<PrefetchFile> prefetch;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        FileInformationEntry(Reference<PrefetchFile> prefetch, Reference<GView::View::WindowInterface> win);

        void Update();
        void Update_17();
        void Update_23_26_30();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class TraceChains : public AppCUI::Controls::TabPage
    {
        Reference<PrefetchFile> prefetch;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        TraceChains(Reference<PrefetchFile> prefetch, Reference<GView::View::WindowInterface> win);

        void Update();
        void Update_17_23_26();
        void Update_30();
        void AddItem_17_23_26(const TraceChainEntry_17_23_26& tc, uint32 i);
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class VolumeInformation : public AppCUI::Controls::TabPage
    {
        Reference<PrefetchFile> prefetch;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 base;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        VolumeInformation(Reference<PrefetchFile> prefetch, Reference<GView::View::WindowInterface> win);

        void Update();
        void Update_17();
        void Update_23_26();
        void Update_30();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class VolumeDirectories : public AppCUI::Controls::TabPage
    {
        Reference<PrefetchFile> prefetch;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 base;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        VolumeDirectories(Reference<PrefetchFile> prefetch, Reference<GView::View::WindowInterface> win);

        void Update();
        void Update_17();
        void Update_23_26();
        void Update_30();
        void AddItem(uint32 index, uint32 directoryStringsEntries);
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class VolumeFiles : public AppCUI::Controls::TabPage
    {
        Reference<PrefetchFile> prefetch;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 base;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        VolumeFiles(Reference<PrefetchFile> prefetch, Reference<GView::View::WindowInterface> win);

        void Update();
        void Update_17();
        void Update_23_26_30();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::Prefetch

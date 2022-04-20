#pragma once

#include <GView.hpp>

namespace GView::Type::Prefetch
{
enum class Magic : uint32
{
    WIN_XP_2003 = 0x00000011,
    WIN_VISTA_7 = 0x00000017,
    WIN_8       = 0x0000001A,
    WIN_10      = 0x0000001E,
    WIN_10_MAM  = 0x044D414D // Windows 10 compressed
};

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
  public:
    PrefetchFile();
    virtual ~PrefetchFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "Prefetch";
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
        void UpdateIssues();
        void RecomputePanelsPositions();

        template <typename T>
        void AddDecAndHexElement(std::string_view name, std::string_view format, T value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            NumericFormatter nf2;

            const auto v    = nf.ToString(value, dec);
            const auto hexV = nf2.ToString(value, hex);
            general->AddItem({ name, ls.Format(format.data(), v.data(), hexV.data()) });
        }

        template <typename T>
        void AddNameAndHexElement(std::string_view name, std::string_view format, const T& value)
        {
            LocalString<1024> ls;
            LocalString<1024> ls2;

            constexpr auto size = sizeof(value) / sizeof(value[0]);
            ls2.Format("0x");
            for (auto i = 0ULL; i < size; i++)
            {
                ls2.AddFormat("%.2x", value[i]);
            }
            const auto vHex = ls2.GetText();
            general->AddItem({ name, ls.Format(format.data(), std::string{ value, sizeof(value) }.c_str(), vHex) });
        }

      public:
        Information(Reference<Object> _object, Reference<GView::Type::Prefetch::PrefetchFile> _prefetch);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class Objects : public AppCUI::Controls::TabPage
    {
        Reference<PrefetchFile> prefetch;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Objects(Reference<PrefetchFile> prefetch, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::Prefetch

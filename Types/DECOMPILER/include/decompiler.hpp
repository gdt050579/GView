#pragma once

#include "GView.hpp"

#define DECOMPILER_RZA_MAGIC        "##RZABINARY"
#define DECOMPILER_RZA_MAGIC_LENGTH 11

namespace GView
{
namespace Type
{
    namespace DECOMPILER
    {
        class DecompilerFile : public TypeInterface
        {
            Reference<GView::Utils::FileCache> file;

          public:
            void StartDecompiling();
            DecompilerFile(Reference<GView::Utils::FileCache> file);

            void UpdateBufferViewZones(Reference<GView::View::BufferViewerInterface> bufferView);

            // Inherited via TypeInterface
            virtual std::string_view GetTypeName() override;
            Reference<GView::View::WindowInterface> win_interface;
        };

        namespace Panels
        {
            class Sections : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::DECOMPILER::DecompilerFile> decompiler;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;
                int Base;

                std::string_view GetValue(NumericFormatter& n, unsigned int value);
                void GoToSelectedSection();
                void SelectCurrentSection();

              public:
                Sections(Reference<GView::Type::DECOMPILER::DecompilerFile> decompiler, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
        } // namespace Panel

    } // namespace DECOMPILER
} // namespace Type
} // namespace GView

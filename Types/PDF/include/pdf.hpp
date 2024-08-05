#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace PDF
    {
#pragma pack(push, 2)

        namespace WSC // white space characters
        {
            constexpr uint8 HORIZONAL_TAB = 0x09;
            constexpr uint8 LINE_FEED = 0x0A;
            constexpr uint8 FORM_FEED = 0x0C;
            constexpr uint8 CARRIAGE_RETURN = 0x0D;
            constexpr uint8 SPACE = 0x20;
        }

        namespace DC
        {
            constexpr uint8 LEFT_PARETHESIS = 0x28; // (
            constexpr uint8 RIGHT_PARETHESIS = 0x29; // )
            constexpr uint8 LESS_THAN = 0x3C; // <
            constexpr uint8 GREATER_THAN = 0x3E; // >
            constexpr uint16 END_TAG              = 0x3E3E; // >>
            constexpr uint8 LEFT_SQUARE_BRACKET = 0x5B; // [
            constexpr uint8 RIGHT_SQUARE_BRACKET = 0x5D; // ]
            constexpr uint8 LEFT_CURLY_BRACKET   = 0x7B; // {
            constexpr uint8 RIGHT_CURLY_BRACKET   = 0x7D; // }
            constexpr uint8 SOLIUDS = 0x2F; // / 
            constexpr uint8 PERCENT = 0x25;// %
        }

        namespace FILTER
        {
            constexpr uint8_t ASCIIHEX[] = "/ASCIIHexDecode";
            constexpr uint8_t ASCII85[] = "/ASCII85Decode";
            constexpr uint8_t LZW[] = "/LZWDecode";
            constexpr uint8_t FLATE[] = "/FlateDecode";
            constexpr uint8_t RUNLENGTH[] = "/RunLengthDecode";
            constexpr uint8_t CCITTFAX[] = "/CCITTFaxDecode";
            constexpr uint8_t JBIG2[] = "/JBIG2Decode";
            constexpr uint8_t DCT[] = "/DCTDecode";
            constexpr uint8_t JPX[] = "/JPXDecode";
            constexpr uint8_t CRYPT[] = "/Crypt";
        }

        constexpr uint8_t PDF_MAGIC[] = "%PDF-";
        constexpr uint8_t PDF_EOF[]   = "%%EOF";
        constexpr uint8_t PDF_EOF_SIZE  = 5;
        constexpr uint8_t PDF_XREF[]  = "xref";
        constexpr uint8_t PDF_TRAILER[] = "trailer";
        constexpr uint8_t PDF_TRAILER_SIZE   = 7;
        constexpr uint8_t PDF_STREAM[]           = "stream";
        constexpr uint8_t PDF_STREAM_SIZE    = 6;
        constexpr uint8_t PDF_ENDSTREAM[]           = "endstream";
        constexpr uint8_t PDF_ENDSTREAM_SIZE = 9;
        constexpr uint8_t PDF_PREV[]       = "/Prev";
        constexpr uint8_t PDF_PREV_SIZE      = 5;
        constexpr uint8_t PDF_STREAM_LENGTH[]    = "/Length";
        constexpr uint8_t PDF_STREAM_LENGTH_SIZE = 7;
        constexpr uint8_t PDF_FILTER[]           = "/Filter";
        constexpr uint8_t PDF_FILTER_SIZE = 7;

        struct Header {
            char identifier[5]; // %PDF-
            uint8 version_1; // 1
            uint8 point; // . 
            uint8 version_N; // N = [0,7]
        };

#pragma pack(pop) // Back to default packing

        class PDFFile : public TypeInterface //, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
        {
          public:
            Header header{};
            bool version_under_5;
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

          public:
            PDFFile();
            virtual ~PDFFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "PDF";
            }
            void RunCommand(std::string_view) override
            {
            }

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
                Reference<GView::Type::PDF::PDFFile> pdf;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::PDF::PDFFile> pdf);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        } // namespace Panels
    }     // namespace PDF
} // namespace Type
} // namespace GView
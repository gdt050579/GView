#pragma once

/*https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
 * https://datatracker.ietf.org/doc/html/rfc2083
 * https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art019
 * https://stackoverflow.com/questions/56791861/trying-to-understand-data-in-cross-reference-xref-stream-in-pdf
 */

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
            constexpr uint8 HORIZONAL_TAB   = 0x09;
            constexpr uint8 LINE_FEED       = 0x0A;
            constexpr uint8 FORM_FEED       = 0x0C;
            constexpr uint8 CARRIAGE_RETURN = 0x0D;
            constexpr uint8 SPACE           = 0x20;
        } // namespace WSC

        namespace DC
        {
            constexpr uint8 LEFT_PARETHESIS      = 0x28;   // (
            constexpr uint8 RIGHT_PARETHESIS     = 0x29;   // )
            constexpr uint8 LESS_THAN            = 0x3C;   // <
            constexpr uint8 GREATER_THAN         = 0x3E;   // >
            constexpr uint16 END_TAG             = 0x3E3E; // >>
            constexpr uint8 LEFT_SQUARE_BRACKET  = 0x5B;   // [
            constexpr uint8 RIGHT_SQUARE_BRACKET = 0x5D;   // ]
            constexpr uint8 LEFT_CURLY_BRACKET   = 0x7B;   // {
            constexpr uint8 RIGHT_CURLY_BRACKET  = 0x7D;   // }
            constexpr uint8 SOLIUDS              = 0x2F;   // /
            constexpr uint8 PERCENT              = 0x25;   // %
            constexpr uint8 REVERSE_SOLIDUS      = 0x5C;   // '\'
        }                                                  // namespace DC

        namespace FILTER
        {
            constexpr const char ASCIIHEX[]  = "/ASCIIHexDecode";
            constexpr const char ASCII85[]   = "/ASCII85Decode";
            constexpr const char LZW[]       = "/LZWDecode";
            constexpr const char FLATE[]     = "/FlateDecode";
            constexpr const char RUNLENGTH[] = "/RunLengthDecode";
            constexpr const char CCITTFAX[]  = "/CCITTFaxDecode";
            constexpr const char JBIG2[]     = "/JBIG2Decode";
            constexpr const char DCT[]       = "/DCTDecode";
            constexpr const char JPX[]       = "/JPXDecode";
            constexpr const char CRYPT[]     = "/Crypt";
        } // namespace FILTER

        namespace KEY
        {
            constexpr uint8_t PDF_MAGIC[] = "%PDF-";

            constexpr uint8_t PDF_ROOT[]             = "/Root";
            constexpr uint8_t PDF_ROOT_SIZE          = 5;
            constexpr uint8_t PDF_PREV[]             = "/Prev";
            constexpr uint8_t PDF_PREV_SIZE          = 5;
            constexpr uint8_t PDF_STREAM_LENGTH[]    = "/Length";
            constexpr uint8_t PDF_STREAM_LENGTH_SIZE = 7;
            constexpr uint8_t PDF_FILTER[]           = "/Filter";
            constexpr uint8_t PDF_FILTER_SIZE        = 7;
            constexpr uint8_t PDF_DECODEPARMS[]      = "/DecodeParms";
            constexpr uint8_t PDF_DECODEPARMS_SIZE   = 12;

            constexpr uint8_t PDF_COLUMNS[]      = "/Columns";
            constexpr uint8_t PDF_COLUMNS_SIZE   = 8;
            constexpr uint8_t PDF_PREDICTOR[]    = "/Predictor";
            constexpr uint8_t PDF_PREDICTOR_SIZE = 10;
            constexpr uint8_t PDF_BPC[]          = "/BitsPerComponent";
            constexpr uint8_t PDF_BPC_SIZE       = 17;

            constexpr uint8_t PDF_W[]    = "/W";
            constexpr uint8_t PDF_W_SIZE = 2;

            constexpr uint8_t PDF_DIC_START[] = "<<";
            constexpr uint8_t PDF_DIC_END[]   = ">>";
            constexpr uint8_t PDF_DIC_SIZE    = 2;

            constexpr uint8_t PDF_TRUE[]     = "true";
            constexpr uint8_t PDF_TRUE_SIZE  = 4;
            constexpr uint8_t PDF_FALSE[]    = "false";
            constexpr uint8_t PDF_FALSE_SIZE = 5;
            constexpr uint8_t PDF_NULL[]     = "null";
            constexpr uint8_t PDF_NULL_SIZE  = 4;

            constexpr uint8_t PDF_XREF[]       = "xref";
            constexpr uint8_t PDF_XREF_SIZE    = 4;
            constexpr uint8_t PDF_TRAILER[]    = "trailer";
            constexpr uint8_t PDF_TRAILER_SIZE = 7;

            constexpr uint8_t PDF_STREAM[]       = "stream";
            constexpr uint8_t PDF_STREAM_SIZE    = 6;
            constexpr uint8_t PDF_ENDSTREAM[]    = "endstream";
            constexpr uint8_t PDF_ENDSTREAM_SIZE = 9;

            constexpr uint8_t PDF_OBJ[]    = "obj";
            constexpr uint8_t PDF_OBJ_SIZE = 3;
            constexpr uint8_t PDF_ENDOBJ[]    = "endobj";
            constexpr uint8_t PDF_ENDOBJ_SIZE = 6;

            constexpr uint8_t PDF_STARTXREF[]    = "startxref";
            constexpr uint8_t PDF_STARTXREF_SIZE = 9;

            constexpr uint8_t PDF_EOF[]    = "%%EOF";
            constexpr uint8_t PDF_EOF_SIZE = 5;

            constexpr uint8_t PDF_XREF_ENTRY  = 20;
            constexpr uint8_t PDF_FREE_ENTRY  = 'f';
            constexpr uint8_t ZERO            = 0;
            constexpr uint8_t PDF_INDIRECTOBJ = 'R';
        } // namespace KEY

        namespace PREDICTOR
        {
            constexpr uint8_t NONE    = 10;
            constexpr uint8_t SUB     = 11;
            constexpr uint8_t UP      = 12;
            constexpr uint8_t AVERAGE = 13;
            constexpr uint8_t PAETH   = 14;
            constexpr uint8_t OPTIMUM = 15;
        } // namespace PREDICTOR

        struct Header {
            char identifier[5]; // %PDF-
            uint8 version;     // 1 or 2
            uint8 point;        // .
            uint8 subVersion;     // for version = 1 -> [0,7], for version = 2 -> 0
        };

        struct TableEntry {
            uint8_t objectOffset[10];
            uint8_t space1;
            uint8_t generationNumber[5];
            uint8_t space2;
            uint8_t flag;
            uint8_t eofSequence[2];
        };

        struct TypeFlags {
            bool hasLength;
            bool hasFilter;
            bool hasPrev;
            bool hasDecodeParms;
            bool hasW;

            TypeFlags() : hasLength(false), hasFilter(false), hasPrev(false), hasDecodeParms(false), hasW(false)
            {
            }
        };

        struct WValues { // W[x y z]
            uint8 x;
            uint8 y;
            uint8 z;
        };

        struct DecodeParms {
            uint8 predictor;
            uint16 column;
            uint8 bitsPerComponent;
        };

        enum class SectionPDFObjectType : uint8 {
            Object         = 1,
            CrossRefTable  = 2,
            CrossRefStream = 3,
            Trailer        = 4,
        };

        struct PDFObject {
            uint64 startBuffer;
            uint64 endBuffer;
            SectionPDFObjectType type;
            uint32 number;
        };

        enum class PDFObjectType : uint8 {
            Unknown = 0,
            Object  = 1,
            Boolean = 2,
            Numeric = 3,
            Literal_String = 4,
            Hex_String = 5,
            Name = 6, 
            Array = 7, 
            Dictionary = 8,
            Null = 9,
            Indirect = 10,
            Trailer = 11,
        };

        struct ObjectKeyVal {
            Buffer key;
            PDFObjectType keyType;
            uint64 offset;
            Buffer value;
        };

        struct ObjectNode {
            PDFObjectType type;
            uint64 offset;
            uint64 size;
            uint32 objectNr = 0;
            std::vector<ObjectKeyVal> keyValues;
            std::vector<ObjectNode> children;   
        };

#pragma pack(pop) // Back to default packing

        class PDFFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
        {
          public:
            Header header{};
            bool hasXrefTable; // Cross-reference table or Cross-reference Stream
            bool trailer_processed;
            uint64 index         = 0;
            ObjectNode objectNodeRoot;
            std::vector<uint32> curentChildIndexes{};
            vector<PDFObject> pdfObjects;
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

          public:
            PDFFile();
            virtual ~PDFFile()
            {
            }

            bool Update();
            void AddPDFObject(Reference<GView::Type::PDF::PDFFile> pdf, const PDF::PDFObject& obj);

            std::string_view GetTypeName() override
            {
                return "PDF";
            }
            void RunCommand(std::string_view) override
            {
            }

            // View::ContainerViewer::EnumerateInterface
            virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
            virtual bool PopulateItem(TreeViewItem item) override;

            // View::ContainerViewer::OpenItemInterface
            virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;

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
            bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }
        };
        namespace Panels
        {
            class Sections : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::PDF::PDFFile> pdf;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;
                int Base;

                std::string_view GetValue(NumericFormatter& n, uint32 value);
                void GoToSelectedSection();
                void SelectCurrentSection();

              public:
                Sections(Reference<GView::Type::PDF::PDFFile> pdf, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
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
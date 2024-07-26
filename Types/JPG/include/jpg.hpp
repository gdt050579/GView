#pragma once 

#include "GView.hpp"

namespace GView
{
namespace Type
{
	namespace JPG
	{
#pragma pack(push, 2)
		
		constexpr uint16 JPG_SOI_MARKER  = 0xD8FF; 
		constexpr uint16 JPG_EOI_MARKER  = 0xD9FF; 
        constexpr uint16 JPG_APP0_MARKER = 0xE0FF;
        constexpr uint16 JPG_SOF0_MARKER = 0xC0FF;
        constexpr uint16 JPG_SOF1_MARKER = 0xC1FF;
        constexpr uint16 JPG_SOF2_MARKER = 0xC2FF;
        constexpr uint16 JPG_SOF3_MARKER = 0xC3FF;
        constexpr uint8 JPG_START_MAKER_BYTE = 0xFF;
        constexpr uint8 JPG_SOS_BYTE = 0xDA;
        constexpr uint8 JPG_EOI_BYTE = 0xD9;


		struct Header {
            uint16 soi;  // Start of Image marker
            uint16 app0; // APP0 marker
        };

        struct App0MarkerSegment {
            uint16 length;
            char identifier[5]; // "JFIF" null-terminated
            uint8 version[2];
            uint8 densityUnits;
            uint16 xDensity;
            uint16 yDensity;
            uint8 xThumbnail;
            uint8 yThumbnail;
        };

        struct SOF0MarkerSegment {
            uint16 height;
            uint16 width;
        };

#pragma pack(pop) // Back to default packing

		class JPGFile : public TypeInterface, public View::ImageViewer::LoadImageInterface
		{
          public:
            Header header{};
            App0MarkerSegment app0MarkerSegment{};
            SOF0MarkerSegment sof0MarkerSegment{};

			Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

		  public:
            JPGFile();
            virtual ~JPGFile()
            {
            }

			bool Update();

			std::string_view GetTypeName() override
			{
                return "JPG";
			}
			void RunCommand(std::string_view) override
			{
			}

			bool LoadImageToObject(Image& img, uint32 index) override;

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
                Reference<GView::Type::JPG::JPGFile> jpg;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::JPG::JPGFile> jpg);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
	}      // namespace JPG
} // namespace Type
} // namespace GView
#pragma once

#include "Internal.hpp"
#include <array>

namespace GView
{
namespace View
{
    namespace ImageViewer
    {
        using namespace AppCUI;

        namespace Commands
        {
            using namespace AppCUI::Input;
            constexpr int32 CMD_ID_ZOOMIN     = 0xBF00;
            constexpr int32 CMD_ID_ZOOMOUT    = 0xBF01;
            constexpr int32 CMD_ID_NEXT_IMAGE = 0xBF02;
            constexpr int32 CMD_ID_PREV_IMAGE = 0xBF03;

            static KeyboardControl ZoomIn    = { Key::F3, "ZoomIn", "Zoom in the picture", CMD_ID_ZOOMIN };
            static KeyboardControl ZoomOut   = { Key::F2, "ZoomOut", "Zoom out the picture", CMD_ID_ZOOMOUT };
            static KeyboardControl NextImage = { Key::PageUp, "PrevImage", "Go to the previous image", CMD_ID_NEXT_IMAGE };
            static KeyboardControl PrevImage = { Key::PageDown, "NextImage", "Go to the next image", CMD_ID_PREV_IMAGE };

            static std::array ImageViewCommands = { &ZoomIn, &ZoomOut, &NextImage, &PrevImage };
        }

        struct ImageInfo
        {
            uint64 start, end;
        };
        struct SettingsData
        {
            String name;
            vector<ImageInfo> imgList;            
            Reference<LoadImageInterface> loadImageCallback;
            SettingsData();
        };

        struct Config
        {
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };

        class Instance : public View::ViewControl
        {
            Image img;
            Pointer<SettingsData> settings;
            Reference<AppCUI::Controls::ImageView> imgView;
            Reference<GView::Object> obj;
            uint32 currentImageIndex;
            ImageScaleMethod scale;

            static Config config;

            void LoadImage();
            void RedrawImage();
            ImageScaleMethod NextPreviousScale(bool next);
          public:
            Instance(Reference<GView::Object> obj, Settings* settings);

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual bool ShowGoToDialog() override;
            virtual bool ShowFindDialog() override;
            virtual bool ShowCopyDialog() override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;


            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
            std::string_view GetCategoryNameForSerialization() const override
            {
                return "View.Image";
            }
            bool AddCategoryBeforePropertyNameWhenSerializing() const override
            {
                return true;
            }
            bool UpdateKeys(KeyboardControlsInterface* interface) override;
        };
        class GoToDialog : public Window
        {
            Reference<RadioBox> rbImageIndex;
            Reference<ComboBox> cbImageList;
            Reference<RadioBox> rbFileOffset;
            Reference<TextField> txFileOffset;
            uint64 maxSize;
            uint64 resultedPos;
            bool gotoImageIndex;

            void UpdateEnableStatus();
            void Validate();


        public:
            GoToDialog(Reference<SettingsData> settings, uint32 currentImageIndex, uint64 size);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            bool ShouldGoToImage() const
            {
                return gotoImageIndex;
            }
            uint32 GetSelectedImageIndex() const
            {
                return static_cast<uint32>(resultedPos);                
            }
            uint64 GetFileOffset() const
            {
                return resultedPos;
            }
        };
    } // namespace ImageViewer
} // namespace View

}; // namespace GView
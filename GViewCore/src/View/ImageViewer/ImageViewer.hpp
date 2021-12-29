#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace ImageViewer
    {
        using namespace AppCUI;

        struct SettingsData
        {
            uint32 imagesCount;
            Reference<LoadImageInterface> loadImageCallback;
            SettingsData();
        };

        struct Config
        {
            struct
            {
                ColorPair Inactive;
                ColorPair Normal;
                ColorPair Line;
            } Colors;
            struct
            {
                AppCUI::Input::Key ZoomIn;
                AppCUI::Input::Key ZoomOut;
                AppCUI::Input::Key ChangeImageRenderMethod;
            } Keys;
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };

        class Instance : public View::ViewControl
        {
            Image img;
            Pointer<SettingsData> settings;
            Reference<AppCUI::Controls::ImageViewer> imgView;
            Reference<GView::Object> obj;
            FixSizeString<29> name;
            uint32 currentImageIndex;

            static Config config;

            void LoadImage();
          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual std::string_view GetName() override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;


            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropetyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
        };

    } // namespace ImageViewer
} // namespace View

}; // namespace GView
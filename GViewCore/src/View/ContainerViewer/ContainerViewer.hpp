#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace ContainerViewer
    {
        using namespace AppCUI;

        struct SettingsData
        {          
            static constexpr uint32 MAX_COLUMNS = 32;
            struct Column
            {
                FixSizeString<29> Name;
                TextAlignament Align;
                uint32 Width;
            } columns[MAX_COLUMNS];
            AppCUI::Graphics::Image icon;
            uint32 columnsCount;
            Reference<ListItemsInterface> listItemsInterface; 
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
            Pointer<SettingsData> settings;
            Reference<AppCUI::Controls::ImageView> imgView;
            Reference<AppCUI::Controls::ListView> propList;
            Reference<AppCUI::Controls::Tree> items;
            Reference<GView::Object> obj;
            FixSizeString<29> name;

            static Config config;


          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual std::string_view GetName() override;
            virtual bool ExtractTo(Reference<AppCUI::OS::IFile> output, ExtractItem item, uint64 size) override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;


            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
        };

    } // namespace ImageViewer
} // namespace View

}; // namespace GView
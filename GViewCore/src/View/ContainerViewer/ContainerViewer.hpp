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
                FixSizeUnicode<29> Name;
                TextAlignament Align;
                uint32 Width;
            } columns[MAX_COLUMNS];
            AppCUI::Graphics::Image icon;
            uint32 columnsCount;
            Reference<EnumerateInterface> enumInterface; 
            char16 pathSeparator;
            SettingsData();
        };

        struct Config
        {
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };

        class Instance : public View::ViewControl, public Controls::Handlers::OnTreeItemToggleInterface
        {
            Pointer<SettingsData> settings;
            Reference<AppCUI::Controls::ImageView> imgView;
            Reference<AppCUI::Controls::ListView> propList;
            Reference<AppCUI::Controls::TreeView> items;
            Reference<GView::Object> obj;
            FixSizeString<29> name;
            TreeViewItem root;
            UnicodeStringBuilder currentPath;

            static Config config;
            void BuildPath(TreeViewItem item);
            void UpdatePathForItem(TreeViewItem item);
            void PopulateItem(TreeViewItem item);
          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual std::string_view GetName() override;
            virtual bool ExtractTo(Reference<AppCUI::OS::DataObject> output, ExtractItem item, uint64 size) override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

            // tree item toggle
            virtual void OnTreeItemToggle(TreeViewItem& item) override;

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
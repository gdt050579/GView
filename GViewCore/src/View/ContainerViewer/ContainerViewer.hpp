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
            static constexpr uint32 MAX_COLUMNS    = 32;
            static constexpr uint32 MAX_PROPERTIES = 32;
            struct
            {
                LocalUnicodeStringBuilder<256> layout;
            } columns[MAX_COLUMNS];
            uint32 columnsCount;
            struct
            {
                AppCUI::Utils::String key;
                AppCUI::Utils::UnicodeStringBuilder value;
                ListViewItem::Type itemType;
            } properties[MAX_PROPERTIES];
            uint32 propertiesCount;
            AppCUI::Graphics::Image icon;
            Reference<EnumerateInterface> enumInterface;
            Reference<OpenItemInterface> openItemInterface;
            char16 pathSeparator{ (char16_t) std::filesystem::path::preferred_separator };
            SettingsData();
        };

        struct Config
        {
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };

        class Instance : public View::ViewControl,
                         public Controls::Handlers::OnTreeViewItemToggleInterface,
                         public Controls::Handlers::OnTreeViewCurrentItemChangedInterface,
                         public Controls::Handlers::OnTreeViewItemPressedInterface
        {
            Pointer<SettingsData> settings;
            Reference<AppCUI::Controls::ImageView> imgView;
            Reference<AppCUI::Controls::ListView> propList;
            Reference<AppCUI::Controls::TreeView> items;
            Reference<GView::Object> obj;
            FixSizeString<29> name;
            TreeViewItem root;
            UnicodeStringBuilder currentPath;
            uint32 tempCountRecursiveItems;

            static Config config;
            void BuildPath(TreeViewItem item);
            void UpdatePathForItem(TreeViewItem item);
            bool PopulateItem(TreeViewItem item);

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual bool ShowGoToDialog() override;
            virtual bool ShowFindDialog() override;
            virtual bool ShowCopyDialog() override;
            virtual std::string_view GetName() override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

            // tree item toggle
            virtual bool OnTreeViewItemToggle(Reference<TreeView>, TreeViewItem& item, bool recursiveCall) override;
            virtual void OnTreeViewItemPressed(Reference<TreeView>, TreeViewItem& item) override;
            virtual void OnTreeViewCurrentItemChanged(Reference<TreeView>, TreeViewItem& item) override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
        };

    } // namespace ContainerViewer
} // namespace View

}; // namespace GView
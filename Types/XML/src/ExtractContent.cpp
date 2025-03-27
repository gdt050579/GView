#include "xml.hpp"
#include <string>
#include <set>

// Extract from key:
//     w:name sau w:var
//   Optiuni de merge: linie dupa linie, una dupa alta

using std::string;
using std::u16string;
struct AttributeData {
    u16string attName, attNamespace;
};

namespace GView::Type::XML::Plugins
{

using namespace GView::View::LexicalViewer;

constexpr int32 BTN_ID_EXTRACT     = 1;
constexpr int32 BTN_ID_CANCEL = 2;
class XMLExtractContentWindow : public Window
{
    u16string result;
    const std::vector<AttributeData>& attributes;
    Reference<ComboBox> comboAttributes, appendMethodology;
    Reference<CheckBox> includeNamespaces;

    void Validate()
    {
        LocalString<128> tmp;
        if (comboAttributes->GetCurrentItemIndex() == ComboBox::NO_ITEM_SELECTED || appendMethodology->GetCurrentItemIndex() == ComboBox::NO_ITEM_SELECTED) {
            Dialogs::MessageBox::ShowError("Error", "Please enter a value to extract!");
            return;
        }
        result = comboAttributes->GetText();
        Exit(Dialogs::Result::Ok);
    }

    void PopulateAttributes()
    {
        comboAttributes->DeleteAllItems();
        const bool isIncludeNamespacesChecked = includeNamespaces->IsChecked();

        LocalUnicodeStringBuilder<128> sb;
        for (const auto& att : attributes) {
            if (isIncludeNamespacesChecked) {
                if (att.attNamespace.empty())
                    continue;
                sb.Add(att.attNamespace);
                sb.AddChar(':');
            } else if (!att.attNamespace.empty())
                continue;
            sb.Add(att.attName);
            comboAttributes->AddItem(u16string_view{ sb.GetString(), sb.Len() });
            sb.Clear();
        }
    }

  public:
    XMLExtractContentWindow(const std::vector<AttributeData>& availableAttributes, const char* title)
        : Window(title, "d:c,w:60,h:13", WindowFlags::ProcessReturn), attributes(availableAttributes)
    {
        Factory::Label::Create(this, "&Attributes", "x:1,y:1,w:14");
        comboAttributes = Factory::ComboBox::Create(this, "x:15,y:1,w:41", "Select tag");
        comboAttributes->SetHotKey('A');

        includeNamespaces = Factory::CheckBox::Create(this, "Include namespaces", "x:1,y:3,w:40");
        includeNamespaces->SetChecked(false);

        Factory::Label::Create(this, "&Append method", "x:1,y:5,w:16");
        appendMethodology = Factory::ComboBox::Create(this, "x:17,y:5,w:35", "After each other");
        appendMethodology->AddItem("On new line");

        Factory::Button::Create(this, "&Extract", "l:16,b:0,w:13", BTN_ID_EXTRACT);
        Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);

        // textField->SetFocus();

        PopulateAttributes();
    }
    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override
    {
        switch (eventType) {
        case Event::CheckedStatusChanged: {
            PopulateAttributes();
            return true;
        }
        case Event::ButtonClicked: {
            switch (ID) {
            case BTN_ID_CANCEL:
                Exit(Dialogs::Result::Cancel);
                return true;
            case BTN_ID_EXTRACT:
                Validate();
                return true;
            default:
                break;
            }
            break;
        }
        case Event::WindowAccept:
            Validate();
            return true;
        case Event::WindowClose:
            Exit(Dialogs::Result::Cancel);
            return true;
        default:
            return false;
        }

        return false;
    }
    inline std::u16string GetResult() const
    {
        return result;
    }
};

vector<string> split(const string& str, char delimiter)
{
    vector<string> tokens;
    size_t start = 0, end;
    while ((end = str.find(delimiter, start)) != string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    tokens.push_back(str.substr(start));
    return tokens;
}

std::string_view ExtractContent::GetName()
{
    return "Extract content";
}

std::string_view ExtractContent::GetDescription()
{
    return "Extract tag attributes or tag text from the XML file";
}

bool ExtractContent::CanBeAppliedOn(const PluginData& data)
{
    return true;
}

PluginAfterActionRequest ExtractContent::Execute(PluginData& data)
{
    std::vector<AttributeData> attributes;
    AttributeData att;
    std::set<u16string> untaggedAttributes, taggedAttributes;

    for (auto token : data.tokens) {
        const auto tokenType = token.GetTypeID(TokenType::None);
        if (tokenType == TokenType::AttributeNamespace) {
            att.attNamespace = token.GetText();
        } else if (tokenType == TokenType::AttributeName) {
            att.attName = token.GetText();
            if (att.attNamespace.empty()) {
                if (untaggedAttributes.contains(att.attName))
                    continue;
                untaggedAttributes.insert(att.attName);
            } else {
                LocalUnicodeStringBuilder<128> sb;
                sb.Add(att.attNamespace);
                sb.AddChar(':');
                sb.Add(att.attName);
                if (taggedAttributes.contains(sb.GetString()))
                    continue;
                taggedAttributes.insert(sb.GetString());
            }
            attributes.push_back(att);
            att.attNamespace.clear();
        }
    }

    XMLExtractContentWindow win(attributes, "Extract content");
    const auto result = win.Show();
    if (result != Dialogs::Result::Ok) {
        return PluginAfterActionRequest::None;
    }

    return PluginAfterActionRequest::None;
}

} // namespace GView::Type::XML::Plugins
#include "xml.hpp"
#include <string>
#include <set>
#include <codecvt>

// Extract from key:
//     w:name sau w:var
//   Optiuni de merge: linie dupa linie, una dupa alta

using std::string;
using std::u16string;
struct AttributeData {
    u16string attName, attNamespace;
};

enum class ExtractMethodology { AfterEachOther, OnNewLine };

namespace GView::Type::XML::Plugins
{

using namespace GView::View::LexicalViewer;

constexpr int32 BTN_ID_EXTRACT = 1;
constexpr int32 BTN_ID_CANCEL  = 2;
class XMLExtractContentWindow : public Window
{
    u16string result;
    const std::vector<AttributeData>& attributes;
    Reference<ComboBox> comboAttributes, appendMethodology;
    Reference<CheckBox> includeNamespaces;
    Reference<Button> extractButton;

    void Validate()
    {
        LocalString<128> tmp;
        if (comboAttributes->GetCurrentItemIndex() == ComboBox::NO_ITEM_SELECTED || appendMethodology->GetCurrentItemIndex() == ComboBox::NO_ITEM_SELECTED) {
            Dialogs::MessageBox::ShowError("Error", "Please enter a value to extract!");
            return;
        }
        result = comboAttributes->GetCurrentItemText();
        Exit(Dialogs::Result::Ok);
    }

    void PopulateAttributes()
    {
        comboAttributes->DeleteAllItems();
        const bool isIncludeNamespacesChecked = includeNamespaces->IsChecked();
        extractButton->SetEnabled(true);

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

        if (!comboAttributes->GetItemsCount()) {
            comboAttributes->AddItem("No result, try (un)checking");
            extractButton->SetEnabled(false);
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

        extractButton = Factory::Button::Create(this, "&Extract", "l:16,b:0,w:13", BTN_ID_EXTRACT);
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

    inline ExtractMethodology GetMethodology()
    {
        return appendMethodology->GetCurrentItemIndex() == 0 ? ExtractMethodology::AfterEachOther : ExtractMethodology::OnNewLine;
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

std::string u16stringToString(const std::u16string& u16str)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    return converter.to_bytes(u16str);
}

PluginAfterActionRequest ExtractContent::Execute(PluginData& data, Reference<Window> parent)
{
    std::vector<AttributeData> attributes;
    AttributeData att;
    std::set<u16string> untaggedAttributes, taggedAttributes;

    for (uint32 i = data.startIndex; i < data.endIndex; i++) {
        auto token           = data.tokens[i];
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

    UnicodeStringBuilder dataFound;
    const auto methodology = win.GetMethodology();

    bool foundSearchedTag  = false;
    const auto tagToSearch = win.GetResult();
    if (tagToSearch.find(':') != u16string::npos) {
        for (uint32 i = data.startIndex; i < data.endIndex; i++) {
            auto token           = data.tokens[i];
            const auto tokenType = token.GetTypeID(TokenType::None);
            if (foundSearchedTag && tokenType == TokenType::AttributeValue) {
                foundSearchedTag = false;
                auto tokenText   = token.GetText();
                dataFound.Add(tokenText.substr(1, tokenText.length() - 2));
                if (methodology == ExtractMethodology::OnNewLine)
                    dataFound.AddChar('\n');
                continue;
            }

            if (tokenType == TokenType::AttributeNamespace) {
                if (token.GetText().empty())
                    continue;
                att.attNamespace = token.GetText();
            } else if (tokenType == TokenType::AttributeName) {
                if (att.attNamespace.empty()) {
                    continue;
                }
                att.attName = token.GetText();
                LocalUnicodeStringBuilder<128> sb;
                sb.Add(att.attNamespace);
                sb.AddChar(':');
                sb.Add(att.attName);
                if (tagToSearch == (u16string_view) sb) {
                    foundSearchedTag = true;
                }
            }
        }
    } else {
        for (uint32 i = data.startIndex; i < data.endIndex; i++) {
            auto token           = data.tokens[i];
            const auto tokenType = token.GetTypeID(TokenType::None);
            if (foundSearchedTag && tokenType == TokenType::AttributeValue) {
                foundSearchedTag = false;
                auto tokenText   = token.GetText();
                dataFound.Add(tokenText.substr(1, tokenText.length() - 2));
                if (methodology == ExtractMethodology::OnNewLine)
                    dataFound.AddChar('\n');
                continue;
            }
            if (tokenType == TokenType::AttributeNamespace) {
                if (token.GetText().empty())
                    continue;
                att.attNamespace = token.GetText();
            } else if (tokenType == TokenType::AttributeName) {
                if (!att.attNamespace.empty()) {
                    continue;
                }
                att.attName = token.GetText();
                if (att.attName == (u16string_view) tagToSearch) {
                    foundSearchedTag = true;
                }
            }
        }
    }

    auto asciiCode = u16stringToString({ dataFound.GetString(), dataFound.Len() });

    LocalUnicodeStringBuilder<512> fullPath;
    fullPath.Add(".");
    fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
    fullPath.Add(tagToSearch);

    LocalString<64> indexToAdd;
    indexToAdd.SetFormat(" %u", data.startIndex);

    UnicodeStringBuilder sb;
    sb.Add("Attribute ");
    sb.Add(tagToSearch);
    sb.Add(indexToAdd.GetText());

    std::u16string_view bufferName = { sb.GetString(), sb.Len() };

    BufferView buffer = { asciiCode.data(), asciiCode.length() };
    GView::App::OpenBuffer(buffer, bufferName, fullPath, GView::App::OpenMethod::BestMatch, "", parent,"attribute extraction");

    return PluginAfterActionRequest::None;
}

} // namespace GView::Type::XML::Plugins
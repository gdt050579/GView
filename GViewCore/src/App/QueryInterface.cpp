#include <cassert>

#include "Internal.hpp"

using namespace GView::App;
using namespace GView::App::InstanceCommands;
using namespace GView::View;
using namespace AppCUI::Input;

#define SMART_ASSISTANTS_CONFIGURATION_NAME "SmartAssistants"
#define BUTTON_1_ID                         1

GView::CommonInterfaces::QueryInterface* FileWindow::GetQueryInterface()
{
    return &queryInterface;
}

using GView::CommonInterfaces::SmartAssistants::SmartAssistantRegisterInterface;
#pragma region SmartAssistantUI
class SmartAssistantEntryTab : public AppCUI::Controls::TabPage
{
    SmartAssistantRegisterInterface* smartAssistant;
    Reference<AppCUI::Controls::Label> value;
    Reference<AppCUI::Controls::Panel> chatHistory;
    Reference<AppCUI::Controls::TextField> prompt;
    Reference<AppCUI::Controls::Button> sendButton;
    uint32 newY;

    LocalString<128> gemini;

  public:
    SmartAssistantEntryTab(std::string_view caption, SmartAssistantRegisterInterface* smartAssistant) : TabPage(caption), smartAssistant(smartAssistant)
    {
        value       = Factory::Label::Create(this, smartAssistant->GetSmartAssistantName(), "x:1,y:1,w:60");
        chatHistory = Factory::Panel::Create(this, "ChatHistory", "x:1,y:2,h:20,w:60");
        newY        = 0;

        prompt     = Factory::TextField::Create(this, "", "x:1,y:23,h:4,w:53");
        sendButton = Factory::Button::Create(this, "Send", "x:54,y:25,h:4,w:6", BUTTON_1_ID);
    }

    bool OnEvent(Reference<Control>, Event evnt, int controlID) override
    {
        if (evnt == Event::ButtonClicked) {
            if (controlID == BUTTON_1_ID) {
                std::string text = prompt->GetText();
                if (text.empty()) {
                    text = "Give me a prime number";
                    // return true;
                }

                LocalString<32> newLabelLocation;
                newLabelLocation.SetFormat("x:1,y:%d,w:4,h:5", newY);
                Factory::Label::Create(chatHistory, "You: ", newLabelLocation.GetText());
                newLabelLocation.SetFormat("x:5,y:%d,w:53,h:5", newY);
                Factory::Button::Create(chatHistory, text, newLabelLocation.GetText());
                newY += 2;

                bool success = false;
                auto result  = smartAssistant->AskSmartAssistant(text, success);

                newLabelLocation.SetFormat("x:1,y:%d,w:11,h:1", newY);
                const char* assistantLabel = success ? "Assistant: " : "Error:";
                Factory::Label::Create(chatHistory, assistantLabel, newLabelLocation.GetText());

                newLabelLocation.SetFormat("x:11,y:%d,w:47,h:1", newY);
                Factory::Button::Create(chatHistory, result, newLabelLocation.GetText());
                newY += 2;
                prompt->SetText("");
                return true;
            }
            return true;
        }
        return false;
    }

    void MarkNoConfig()
    {
        prompt->SetEnabled(false);

        LocalString<128> textData;
        textData.SetFormat(
              "Error: No config token found!\nPlease add \"%s\" to \"%s\" section in GView.ini",
              smartAssistant->GetSmartAssistantName().data(),
              SMART_ASSISTANTS_CONFIGURATION_NAME);

        prompt->SetText(textData);
        sendButton->SetEnabled(false);
    }
};

class SmartAssistantsTab : public AppCUI::Controls::TabPage
{
    Reference<Tab> tabs;
    uint32 tabsCount;

  public:
    SmartAssistantsTab() : TabPage("Smart &Assistants"), tabsCount(0)
    {
        tabs = Factory::Tab::Create(this, "l:1,t:1,r:1,b:1", TabFlags::TopTabs | TabFlags::TransparentBackground);
    }

    void AddSmartAssistant(SmartAssistantRegisterInterface* registerInterface)
    {
        tabs->AddControl(Pointer(new SmartAssistantEntryTab(registerInterface->GetSmartAssistantName(), registerInterface)));
        ++tabsCount;
    }

    void MarkLastAssistantNoConfig()
    {
        if (!tabs->SetCurrentTabPageByIndex(tabsCount - 1, false))
            return;
        tabs->GetCurrentTab().ToObjectRef<SmartAssistantEntryTab>()->MarkNoConfig();
        tabs->SetCurrentTabPageByIndex(0, false);
    }
};
#pragma endregion

#pragma region SmartAssistantPickPrefferedAssistant

struct PickPreferredSmartAssistant : public Window, public Handlers::OnButtonPressedInterface {
    uint16 preferredIndex;
    uint32 newY;
    PickPreferredSmartAssistant(const std::vector<Pointer<SmartAssistantRegisterInterface>>& smartAssistants, std::vector<bool>& validSmartAssistants)
        : Window("Pick preferred Smart Assistant", "d:c,w:60,h:30", WindowFlags::Sizeable), preferredIndex(UINT16_MAX), newY(0)
    {
        for (uint32 i = 0; i < smartAssistants.size(); ++i) {
            if (validSmartAssistants[i]) {
                AddSmartAssistantOption(smartAssistants[i]->GetSmartAssistantName(), i);
            }
        }
    }

    void AddSmartAssistantOption(std::string_view name, uint32 index)
    {
        LocalString<32> newLabelLocation;
        newLabelLocation.SetFormat("x:1,y:%d,w:50,h:1", newY);
        Factory::Label::Create(this, name, newLabelLocation);

        newLabelLocation.SetFormat("x:1,y:51,w:7,h:1", newY);
        Factory::Button::Create(this, "Pick", newLabelLocation, (int32) index);
        newY+= 2;
    }

    void OnButtonPressed(Reference<Controls::Button> r) override
    {
        const auto id = r->GetControlID();
        if (id < 0) {
            Dialogs::MessageBox::ShowError("Smart Assistants", "Invalid ID button!");
            return;
        }
        preferredIndex = static_cast<uint16>(id);
        Exit(Dialogs::Result::Ok);
    }
};
#pragma endregion

namespace GView::App::QueryInterfaceImpl
{

bool GViewQueryInterface::RegisterSmartAssistantInterface(Pointer<SmartAssistantRegisterInterface> registerInterface)
{
    const auto newAssistantName = registerInterface->GetSmartAssistantName();
    if (newAssistantName.empty()) {
        LocalString<128> data;
        data.SetFormat("Assistant \"%s\" has empty name!");
        Dialogs::MessageBox::ShowError("Smart Assistant Error", data);
        return false;
    }
    for (const auto& smartAssistant : smartAssistants) {
        if (smartAssistant->GetSmartAssistantName().compare(newAssistantName) == 0) {
            LocalString<128> data;
            data.SetFormat("Assistant with name: \"%s\" already exists!");
            Dialogs::MessageBox::ShowError("Smart Assistant Error", data);
            return false;
        }
    }
    smartAssistants.push_back(std::move(registerInterface));
    return true;
}
SmartAssistantPromptInterface* GViewQueryInterface::GetSmartAssistantInterface()
{
    if (validAssistants == 0) {
        if (!smartAssistants.empty())
            Dialogs::MessageBox::ShowError(
                  "Smart Assistant", "Please configure the SmartAssistants in the vertical Panel for SmartAssistants before using them!");
        else
            Dialogs::MessageBox::ShowError("Smart Assistant", "No SmartAssistants available!");
        return nullptr;
    }
    if (validAssistants == 1) {
        if (prefferedIndex == UINT16_MAX) {
            for (uint32 i = 0; i < validSmartAssistants.size(); ++i) {
                if (validSmartAssistants[i]) {
                    prefferedIndex = static_cast<uint16>(i);
                    break;
                }
            }
        }
        return smartAssistants[prefferedIndex].get();
    }
    PickPreferredSmartAssistant pickPreferred(smartAssistants, validSmartAssistants);
    pickPreferred.Show();
    this->prefferedIndex = pickPreferred.preferredIndex;
    if (prefferedIndex == UINT16_MAX) {
        Dialogs::MessageBox::ShowError("Smart Assistant", "Failed to pick a Smart Assistant!");
        return nullptr;
    }
    return smartAssistants[prefferedIndex].get();
}

void GViewQueryInterface::Start()
{
    if (smartAssistants.empty()) {
        return;
    }

    bool hasSmartAssistantConfigDat = false;
    auto SmartAssistants            = IniSection();
    const auto settings             = Application::GetAppSettings();
    if (settings->HasSection(SMART_ASSISTANTS_CONFIGURATION_NAME)) {
        SmartAssistants            = settings->GetSection(SMART_ASSISTANTS_CONFIGURATION_NAME);
        hasSmartAssistantConfigDat = true;
    }

    auto ptrSmartAssistantsTab = Pointer<TabPage>(new SmartAssistantsTab());
    const auto convertedPtr    = static_cast<SmartAssistantsTab*>(ptrSmartAssistantsTab.get());

    validSmartAssistants.resize(smartAssistants.size(), false);

    uint32 index = 0;
    for (auto& smartAssistant : smartAssistants) {
        convertedPtr->AddSmartAssistant(smartAssistant.get());
        bool hasConfig = false;
        if (hasSmartAssistantConfigDat) {
            auto currentData = SmartAssistants[smartAssistant->GetSmartAssistantName()];
            if (currentData.HasValue()) {
                auto dataValue = currentData.AsString();
                if (dataValue.has_value()) {
                    hasConfig = true;
                    smartAssistant->ReceiveConfigToken(dataValue.value());
                    ++validAssistants;
                    validSmartAssistants[index] = true;
                }
            }
        }
        if (!hasConfig) {
            convertedPtr->MarkLastAssistantNoConfig();
        }
        ++index;
    }
    fileWindow->AddPanel(std::move(ptrSmartAssistantsTab), true);
}

} // namespace GView::App::QueryInterfaceImpl

#include <cassert>

#include "Internal.hpp"

using namespace GView::App;
using namespace GView::App::InstanceCommands;
using namespace GView::View;
using namespace AppCUI::Input;

constexpr ColorPair PROMPT_YOU_AND_ASSISTANT_COLOR = ColorPair{ Color::Aqua, Color::Black };

const char* SMART_ASSISTANTS_CONFIGURATION_NAME = "SmartAssistants";
constexpr int32 PROMPT_BUTTON_ID = 1;
constexpr int32 SHOW_LAST_PROMPT = 2;

GView::CommonInterfaces::QueryInterface* FileWindow::GetQueryInterface()
{
    return &queryInterface;
}

using GView::CommonInterfaces::SmartAssistants::SmartAssistantRegisterInterface;
using QueryInterfaceImpl::SmartAssistantPromptInterfaceProxy;
#pragma region SmartAssistantUI
class SmartAssistantEntryTab : public AppCUI::Controls::TabPage
{
    SmartAssistantRegisterInterface* smartAssistant;
    SmartAssistantPromptInterfaceProxy* proxyInterface;
    Reference<AppCUI::Controls::TextArea> chatHistory;
    Reference<AppCUI::Controls::TextField> prompt;
    Reference<AppCUI::Controls::Button> sendButton, lastPromptButton;
    std::string lastPromptData;
    uint32 assistantIndex;

    LocalString<128> gemini;

  public:
    SmartAssistantEntryTab(std::string_view caption, SmartAssistantPromptInterfaceProxy* proxyInterface, uint32 assistantIndex)
        : TabPage(caption), proxyInterface(proxyInterface), assistantIndex(assistantIndex)
    {
        lastPromptData = "There is no prompt given!";
        smartAssistant = proxyInterface->smartAssistants[assistantIndex].get();
        Factory::Label::Create(this, smartAssistant->GetSmartAssistantName(), "x:1,y:1,w:39");
        lastPromptButton = Factory::Button::Create(this, "Show last prompt", "x:40,y:1,w:19", SHOW_LAST_PROMPT);
        chatHistory =
              Factory::TextArea::Create(this, "", "l:1,t:2,r:1,b:12", TextAreaFlags::Readonly | TextAreaFlags::SyntaxHighlighting | TextAreaFlags::ScrollBars);

        Factory::Label::Create(this, "Prompt", "l:1,r:1,b:9,h:1");

        prompt     = Factory::TextField::Create(this, "", "l:1,r:1,b:4,h:5");
        sendButton = Factory::Button::Create(this, "Send", "l:45%,b:1,h:4,w:10", PROMPT_BUTTON_ID);
    }

    bool OnEvent(Reference<Control>, Event evnt, int controlID) override
    {
        if (evnt == Event::ButtonClicked) {
            if (controlID == PROMPT_BUTTON_ID) {
                const std::string text = prompt->GetText();
                AskSmartAssistant(text, text);
                return true;
            } else if (controlID == SHOW_LAST_PROMPT) {
                Dialogs::MessageBox::ShowNotification("Last Prompt", lastPromptData.data());
                return true;
            }
            return true;
        }
        return false;
    }

    void AskSmartAssistant(std::string_view promptText, std::string_view displayPrompt, const std::string* hasAnswer = nullptr, const bool* isSuccess = nullptr)
    {
        if (promptText.empty()) {
            // text = "Give me a prime number";
            Dialogs::MessageBox::ShowError("Smart Assistant Error", "Empty prompt");
            return;
        }
        auto currentText = chatHistory->GetText();
        currentText.Add("You: ", PROMPT_YOU_AND_ASSISTANT_COLOR);
        currentText.Add(displayPrompt);
        currentText.Add("\n");
        lastPromptData = promptText;

        bool success = false;
        if (isSuccess)
            success = *isSuccess;
        std::string result;
        if (hasAnswer)
            result = *hasAnswer;
        else {
            proxyInterface->prefferedChatIndex = static_cast<uint16>(assistantIndex);
            const auto chatContext             = proxyInterface->BuildChatContext(promptText, displayPrompt, assistantIndex);
            result                             = proxyInterface->AskSmartAssistant(chatContext, promptText, success);
        }

        const char* assistantLabel = success ? "Assistant: " : "Error:";
        currentText.Add(assistantLabel, PROMPT_YOU_AND_ASSISTANT_COLOR);
        currentText.Add(result);
        currentText.Add("\n");
        chatHistory->SetText(currentText);
        prompt->SetText("");
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
        lastPromptButton->SetEnabled(false);
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

    void* AddSmartAssistant(SmartAssistantPromptInterfaceProxy* proxyInterface, uint32 assistantIndex)
    {
        auto ptr =
              Pointer(new SmartAssistantEntryTab(proxyInterface->smartAssistants[assistantIndex]->GetSmartAssistantName(), proxyInterface, assistantIndex));
        void* ptrVoid = ptr.get();
        tabs->AddControl(std::move(ptr));
        ++tabsCount;
        return ptrVoid;
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

struct PickPreferredSmartAssistant : public Window {
    uint16 preferredIndex;
    uint32 newY;
    PickPreferredSmartAssistant(const std::vector<Pointer<SmartAssistantRegisterInterface>>& smartAssistants, std::vector<bool>& validSmartAssistants)
        : Window("Pick preferred Smart Assistant", "d:c,w:60,h:30", WindowFlags::Sizeable), preferredIndex(UINT16_MAX), newY(1)
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

        newLabelLocation.SetFormat("x:51,y:%d,w:7,h:1", newY);
        Factory::Button::Create(this, "Pick", newLabelLocation, (int32) index);
        newY += 2;
    }

    bool OnEvent(Reference<Control>, Event eventType, int ID) override
    {
        if (eventType == Event::ButtonClicked) {
            if (ID < 0) {
                Dialogs::MessageBox::ShowError("Smart Assistants", "Invalid ID button!");
                return false;
            }
            preferredIndex = static_cast<uint16>(ID);
            Exit(Dialogs::Result::Ok);
        }
        return false;
    }
};
#pragma endregion

namespace GView::App::QueryInterfaceImpl
{

std::string SmartAssistantPromptInterfaceProxy::AskSmartAssistant(std::string_view prompt, std::string_view displayPrompt, bool& isSuccess)
{
    uint16 indexToUse = prefferedChatIndex;
    if (prefferedChatIndex == UINT16_MAX) {
        indexToUse = prefferedIndex;
    }else {
        prefferedChatIndex = UINT16_MAX;
    }
    assert(indexToUse < smartAssistants.size());
    auto result = smartAssistants[indexToUse].get()->AskSmartAssistant(prompt, displayPrompt, isSuccess);
    if (!result.empty()) {
        if (result[result.size() - 1] == '\n')
            result.pop_back();
    }
    const auto ptrUI = static_cast<SmartAssistantEntryTab*>(smartAssistantEntryTabUIPointers[indexToUse]);
    ptrUI->AskSmartAssistant(prompt, displayPrompt, &result, &isSuccess);
    return result;
}

bool SmartAssistantPromptInterfaceProxy::RegisterSmartAssistantInterface(Pointer<SmartAssistantRegisterInterface> registerInterface)
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
SmartAssistantPromptInterface* SmartAssistantPromptInterfaceProxy::GetSmartAssistantInterface()
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
        return this;
    }
    if (prefferedIndex == UINT16_MAX) {
        PickPreferredSmartAssistant pickPreferred(smartAssistants, validSmartAssistants);
        pickPreferred.Show();
        this->prefferedIndex = pickPreferred.preferredIndex;
        if (prefferedIndex == UINT16_MAX) {
            Dialogs::MessageBox::ShowError("Smart Assistant", "Failed to pick a Smart Assistant!");
            return nullptr;
        }
    }
    return this;
}

std::string SmartAssistantPromptInterfaceProxy::BuildChatContext(std::string_view prompt, std::string_view displayPrompt, uint32 assistantIndex)
{
    std::string chatContext = std::string(prompt.data(), prompt.size());
    auto n                  = typePlugin->GetSmartAssistantContext(prompt, displayPrompt);
    return chatContext;
}

void SmartAssistantPromptInterfaceProxy::Start(Reference<FileWindow> fileWindow)
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
    smartAssistantEntryTabUIPointers.resize(smartAssistants.size(), nullptr);

    uint32 index = 0;
    for (const auto& smartAssistant : smartAssistants) {
        const auto ptrUI                        = convertedPtr->AddSmartAssistant(this, index);
        smartAssistantEntryTabUIPointers[index] = ptrUI;
        bool hasConfig                          = false;
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
    this->typePlugin = fileWindow->GetObject()->GetContentType();
}

bool GViewQueryInterface::RegisterSmartAssistantInterface(Pointer<SmartAssistantRegisterInterface> registerInterface)
{
    return smartAssistantProxy.RegisterSmartAssistantInterface(std::move(registerInterface));
}

SmartAssistantPromptInterface* GViewQueryInterface::GetSmartAssistantInterface()
{
    return smartAssistantProxy.GetSmartAssistantInterface();
}

void GViewQueryInterface::Start()
{
    smartAssistantProxy.Start(fileWindow);
}

} // namespace GView::App::QueryInterfaceImpl

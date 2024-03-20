#include "Config.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;
using namespace AppCUI::Graphics;
using namespace AppCUI::Controls;
using AppCUI::Graphics::Color;

void Config::Update(AppCUI::Utils::IniSection sect)
{
    for (const auto& cmd : AllKeyboardCommands) {
        sect.UpdateValue(cmd.get().Caption, cmd.get().Key, true);
    }

    sect.UpdateValue("ShowFileContent", true, true);
    sect.UpdateValue("ShowOnlyDissasm", false, true);
    sect.UpdateValue("DeepScanDissasmOnStart", false, true);
}
void Config::Initialize()
{
    this->Colors.Inactive                      = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Cursor                        = ColorPair{ Color::Black, Color::Yellow };
    this->Colors.Line                          = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.Normal                        = ColorPair{ Color::Silver, Color::DarkBlue };
    this->Colors.Highlight                     = ColorPair{ Color::Yellow, Color::DarkBlue };
    this->Colors.HighlightCursorLine           = ColorPair{ Color::Teal, Color::Gray };
    this->Colors.Selection                     = ColorPair{ Color::Black, Color::White };
    this->Colors.OutsideZone                   = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.StructureColor                = ColorPair{ Color::Magenta, Color::DarkBlue };
    this->Colors.DataTypeColor                 = ColorPair{ Color::Green, Color::DarkBlue };
    this->Colors.AsmOffsetColor                = ColorPair{ Color::White, Color::DarkBlue };
    this->Colors.AsmIrrelevantInstructionColor = ColorPair{ Color::Gray, Color::DarkBlue };
    this->Colors.AsmWorkRegisterColor          = ColorPair{ Color::Aqua, Color::DarkBlue };
    this->Colors.AsmStackRegisterColor         = ColorPair{ Color::Magenta, Color::DarkBlue };
    this->Colors.AsmCompareInstructionColor    = ColorPair{ Color::Olive, Color::DarkBlue };
    this->Colors.AsmFunctionColor              = ColorPair{ Color::Pink, Color::DarkBlue };
    this->Colors.AsmLocationInstruction        = ColorPair{ Color::Teal, Color::DarkBlue };
    this->Colors.AsmJumpInstruction            = ColorPair{ Color::Silver, Color::DarkBlue };
    this->Colors.AsmComment                    = ColorPair{ Color::Silver, Color::DarkBlue };
    this->Colors.AsmDefaultColor               = ColorPair{ Color::Green, Color::DarkBlue };
    this->Colors.AsmTitleColor                 = ColorPair{ Color::Silver, Color::Magenta };
    this->Colors.AsmTitleColumnColor           = ColorPair{ Color::Yellow, Color::DarkBlue };

    bool foundSettings = false;
    auto ini           = AppCUI::Application::GetAppSettings();
    if (ini) {
        auto sect = ini->GetSection("DissasmView");
        if (sect.Exists()) {
            for (auto& cmd : AllKeyboardCommands) {
                cmd.get().Key = sect.GetValue(cmd.get().Caption).ToKey(cmd.get().Key);
            }

            this->ShowFileContent              = sect.GetValue("ShowFileContent").ToBool(true);
            this->ShowOnlyDissasm              = sect.GetValue("ShowOnlyDissasm").ToBool(false);
            this->EnableDeepScanDissasmOnStart = sect.GetValue("DeepScanDissasmOnStart").ToBool(false);
            foundSettings                      = true;
        }
    }
    if (!foundSettings) {
        this->ShowFileContent              = true;
        this->ShowOnlyDissasm              = false;
        this->EnableDeepScanDissasmOnStart = false;
    }

    this->Loaded = true;
}

KeyConfigDisplayWindow::KeyConfigDisplayWindow() : Window("Available keys", "d:c,w:160,h:30", Controls::WindowFlags::Sizeable)
{
    auto list =
          Factory::ListView::Create(this, "x:1,y:1,w:99%,h:99%", { "n:Caption,w:30%", "n:Description,w:50%", "n:Key,w:20%" }, ListViewFlags::PopupSearchBar);

    LocalString<32> buffer;

    for (const auto& key : Config::AllKeyboardCommands) {
        buffer.Clear();
        if (!KeyUtils::ToString(key.get().Key, buffer))
            buffer.SetFormat("Failed to convert key");
        const std::initializer_list<ConstString> items = { key.get().Caption, key.get().Explanation, buffer.GetText() };
        list->AddItem(items);
    }
}

bool KeyConfigDisplayWindow::OnEvent(Utils::Reference<Control> reference, Controls::Event eventType, int ID)
{
    switch (eventType) {
    case Event::ButtonClicked:
    case Event::WindowAccept:
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}

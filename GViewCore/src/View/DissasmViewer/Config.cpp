#include "Config.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;
using namespace AppCUI::Graphics;
using namespace AppCUI::Controls;
using AppCUI::Graphics::Color;

void ColorManager::InitFromConfigColors(DissasmColors& configColors)
{
    this->Colors      = configColors;
    this->SavedColors = configColors;
}

void ColorManager::OnLostFocus()
{
    SavedColors = Colors;
    SetAllColorsInactive();
}

void ColorManager::SetAllColorsInactive()
{
    this->Colors.Normal                        = this->Colors.Inactive;
    this->Colors.Highlight                     = this->Colors.Inactive;
    this->Colors.HighlightCursorLine           = this->Colors.Inactive;
    this->Colors.Cursor                        = this->Colors.Inactive;
    this->Colors.Line                          = this->Colors.Inactive;
    this->Colors.Selection                     = this->Colors.Inactive;
    this->Colors.OutsideZone                   = this->Colors.Inactive;
    this->Colors.StructureColor                = this->Colors.Inactive;
    this->Colors.DataTypeColor                 = this->Colors.Inactive;
    this->Colors.AsmOffsetColor                = this->Colors.Inactive;
    this->Colors.AsmIrrelevantInstructionColor = this->Colors.Inactive;
    this->Colors.AsmWorkRegisterColor          = this->Colors.Inactive;
    this->Colors.AsmStackRegisterColor         = this->Colors.Inactive;
    this->Colors.AsmCompareInstructionColor    = this->Colors.Inactive;
    this->Colors.AsmFunctionColor              = this->Colors.Inactive;
    this->Colors.AsmLocationInstruction        = this->Colors.Inactive;
    this->Colors.AsmJumpInstruction            = this->Colors.Inactive;
    this->Colors.AsmComment                    = this->Colors.Inactive;
    this->Colors.AsmDefaultColor               = this->Colors.Inactive;
    this->Colors.AsmTitleColumnColor           = this->Colors.Inactive;

    this->Colors.CursorNormal      = this->Colors.Inactive;
    this->Colors.CursorHighlighted = this->Colors.Inactive;
    this->Colors.CursorLine        = this->Colors.Inactive;

    this->Colors.AsmTitleColor.Foreground = this->Colors.Inactive.Foreground;
}

void ColorManager::OnGainedFocus()
{
    Colors = SavedColors;
}

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
    this->ConfigColors.Inactive                      = ColorPair{ Color::Gray, Color::Transparent };
    this->ConfigColors.Cursor                        = ColorPair{ Color::Black, Color::Yellow };
    this->ConfigColors.Line                          = ColorPair{ Color::Gray, Color::DarkBlue };
    this->ConfigColors.Normal                        = ColorPair{ Color::Silver, Color::DarkBlue };
    this->ConfigColors.Highlight                     = ColorPair{ Color::Yellow, Color::DarkBlue };
    this->ConfigColors.HighlightCursorLine           = ColorPair{ Color::Teal, Color::Gray };
    this->ConfigColors.Selection                     = ColorPair{ Color::Black, Color::White };
    this->ConfigColors.OutsideZone                   = ColorPair{ Color::Gray, Color::DarkBlue };
    this->ConfigColors.StructureColor                = ColorPair{ Color::Magenta, Color::DarkBlue };
    this->ConfigColors.DataTypeColor                 = ColorPair{ Color::Green, Color::DarkBlue };
    this->ConfigColors.AsmOffsetColor                = ColorPair{ Color::White, Color::DarkBlue };
    this->ConfigColors.AsmIrrelevantInstructionColor = ColorPair{ Color::Gray, Color::DarkBlue };
    this->ConfigColors.AsmWorkRegisterColor          = ColorPair{ Color::Aqua, Color::DarkBlue };
    this->ConfigColors.AsmStackRegisterColor         = ColorPair{ Color::Magenta, Color::DarkBlue };
    this->ConfigColors.AsmCompareInstructionColor    = ColorPair{ Color::Olive, Color::DarkBlue };
    this->ConfigColors.AsmFunctionColor              = ColorPair{ Color::Pink, Color::DarkBlue };
    this->ConfigColors.AsmLocationInstruction        = ColorPair{ Color::Teal, Color::DarkBlue };
    this->ConfigColors.AsmJumpInstruction            = ColorPair{ Color::Silver, Color::DarkBlue };
    this->ConfigColors.AsmComment                    = ColorPair{ Color::Silver, Color::DarkBlue };
    this->ConfigColors.AsmDefaultColor               = ColorPair{ Color::Green, Color::DarkBlue };
    this->ConfigColors.AsmTitleColor                 = ColorPair{ Color::Silver, Color::Magenta };
    this->ConfigColors.AsmTitleColumnColor           = ColorPair{ Color::Yellow, Color::DarkBlue };

    this->ConfigColors.CursorNormal      = ConfigColors.Normal;
    this->ConfigColors.CursorHighlighted = ConfigColors.Highlight;
    this->ConfigColors.CursorLine        = ConfigColors.Line;

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

#include "Config.hpp"
#include <cassert>
using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;
using namespace AppCUI::Graphics;
using namespace AppCUI::Controls;
using AppCUI::Graphics::Color;

void ColorManager::InitFromConfigColors(const DissasmColors& configColors, bool hasFocus)
{
    this->Colors      = configColors;
    this->SavedColors = configColors;
    if (!hasFocus)
        OnLostFocus();
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
    //this->Colors.OutsideZone                   = this->Colors.Inactive;
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
    LocalString<128> buffer;
    for (const auto& cmd : AllKeyboardCommands) {
        buffer.SetFormat("Key.%s", cmd.get().Caption);
        sect.UpdateValue(buffer.GetText(), cmd.get().Key, true);
    }

    sect.UpdateValue("Config.ShowFileContent", true, true);
    sect.UpdateValue("Config.ShowOnlyDissasm", false, true);
    sect.UpdateValue("Config.DeepScanDissasmOnStart", false, true);
    sect.UpdateValue("Config.CacheSameLocationAsAnalyzedFile", true, true);
}

void Config::UpdateColors(const AppCUI::Application::Config& config)
{
    const auto backGroundColor             = config.Text.Normal.Background;
    this->ConfigColors.Inactive            = config.Text.Inactive;
    this->ConfigColors.Cursor              = config.Cursor.Normal;
    this->ConfigColors.Line                = config.Lines.Normal;
    this->ConfigColors.Normal              = config.Text.Focused;
    this->ConfigColors.Highlight           = config.Text.Highlighted;
    this->ConfigColors.HighlightCursorLine = ColorPair{ Color::Teal, Color::Gray }; // Commented its use for now
    this->ConfigColors.Selection           = config.Cursor.OverSelection;
    // this->ConfigColors.OutsideZone                   = ColorPair{ Color::Gray, Color::DarkBlue };
    this->ConfigColors.StructureColor                = ColorPair{ Color::Magenta, backGroundColor };
    this->ConfigColors.DataTypeColor                 = config.Symbol.Arrows;
    this->ConfigColors.AsmOffsetColor                = ColorPair{ Color::White, backGroundColor };
    this->ConfigColors.AsmIrrelevantInstructionColor = ColorPair{ Color::Gray, backGroundColor };
    this->ConfigColors.AsmWorkRegisterColor          = ColorPair{ Color::Aqua, backGroundColor };
    this->ConfigColors.AsmStackRegisterColor         = ColorPair{ Color::Magenta, backGroundColor };
    this->ConfigColors.AsmCompareInstructionColor    = ColorPair{ Color::Olive, backGroundColor };
    this->ConfigColors.AsmFunctionColor              = ColorPair{ Color::Pink, backGroundColor };
    this->ConfigColors.AsmLocationInstruction        = ColorPair{ Color::Teal, backGroundColor };
    this->ConfigColors.AsmJumpInstruction            = ColorPair{ Color::Silver, backGroundColor };
    this->ConfigColors.AsmComment                    = ColorPair{ Color::Silver, backGroundColor };
    this->ConfigColors.AsmDefaultColor               = ColorPair{ Color::Green, backGroundColor };
    this->ConfigColors.AsmTitleColor                 = config.Header.Text.Focused;
    this->ConfigColors.AsmTitleColumnColor           = config.Border.Focused;

    this->ConfigColors.CursorNormal      = ConfigColors.Normal;
    this->ConfigColors.CursorHighlighted = ConfigColors.Highlight;
    this->ConfigColors.CursorLine        = ConfigColors.Line;
}

void Config::Initialize(const AppCUI::Application::Config& config)
{
    UpdateColors(config);
    bool foundSettings = false;
    auto ini           = AppCUI::Application::GetAppSettings();
    if (ini) {
        auto sect = ini->GetSection("View.Dissasm");
        if (sect.Exists()) {
            for (auto& cmd : AllKeyboardCommands) {
                cmd.get().Key = sect.GetValue(cmd.get().Caption).ToKey(cmd.get().Key);
            }

            this->ShowFileContent                 = sect.GetValue("Config.ShowFileContent").ToBool(true);
            this->ShowOnlyDissasm                 = sect.GetValue("Config.ShowOnlyDissasm").ToBool(false);
            this->EnableDeepScanDissasmOnStart    = sect.GetValue("Config.DeepScanDissasmOnStart").ToBool(false);
            this->CacheSameLocationAsAnalyzedFile = sect.GetValue("Config.CacheSameLocationAsAnalyzedFile").ToBool(true);
            foundSettings                         = true;
        }
    }
    if (!foundSettings) {
        this->ShowFileContent                 = true;
        this->ShowOnlyDissasm                 = false;
        this->EnableDeepScanDissasmOnStart    = false;
        this->CacheSameLocationAsAnalyzedFile = true;
    }

    this->Loaded = true;
}

KeyConfigDisplayWindow::KeyConfigDisplayWindow() : Window("Available keys", "d:c", Controls::WindowFlags::Sizeable)
{
    auto list =
          Factory::ListView::Create(this, "x:1,y:0,w:99%,h:99%", { "n:Caption,w:30%", "n:Description,w:50%", "n:Key,w:20%" }, ListViewFlags::PopupSearchBar);

    LocalString<32> buffer;

    for (const auto& key : Config::AllKeyboardCommands) {
        buffer.Clear();
        if (!KeyUtils::ToString(key.get().Key, buffer))
            buffer.SetFormat("Failed to convert key");
        const std::initializer_list<ConstString> items = { key.get().Caption, key.get().Explanation, buffer.GetText() };
        list->AddItem(items);
    }
}

bool KeyConfigDisplayWindow::OnEvent(AppCUI::Utils::Reference<Control> reference, Controls::Event eventType, int ID)
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

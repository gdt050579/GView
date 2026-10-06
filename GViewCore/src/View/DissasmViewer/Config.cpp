#include "Config.hpp"
#include <cassert>

#include "DissasmViewer.hpp"
using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;
using namespace AppCUI::Graphics;
using namespace AppCUI::Controls;
using AppCUI::Graphics::Color;
using AppCUI::Graphics::CustomColor;

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
    this->Colors.AsmLocalVariableColor         = this->Colors.Inactive;
    this->Colors.AsmDefaultColor               = this->Colors.Inactive;
    this->Colors.AsmTitleColumnColor           = this->Colors.Inactive;

    this->Colors.CursorNormal      = this->Colors.Inactive;
    this->Colors.CursorHighlighted = this->Colors.Inactive;
    this->Colors.CursorLine        = this->Colors.Inactive;

    this->Colors.AsmTitleColor.Foreground = this->Colors.Inactive.Foreground;
}

void ColorManager::OnGainedFocus()
{
    if (Instance::ConfigColorsHaveChanges()) {
        auto& configColors = Instance::GetConfigColors();
        InitFromConfigColors(configColors, true);
        configColors.hasChanges = false;
        return;
    }
    Colors = SavedColors;
    
}

void Config::Update(AppCUI::Utils::IniSection sect)
{
    // keys are handled by the key bindings registry ([Keys.View.Dissasm], "Keyboard shortcuts" window)
    sect.UpdateValue("Config.ShowFileContent", true, true);
    sect.UpdateValue("Config.ShowOnlyDissasm", false, true);
    sect.UpdateValue("Config.DeepScanDissasmOnStart", false, true);
    sect.UpdateValue("Config.CacheSameLocationAsAnalyzedFile", true, true);
}

#define LOAD_COLOR_IF_EXISTS(name) \
{\
    auto colorIt = colors.find(#name);\
    if (colorIt != colors.end()) {\
        auto colorPtr = colorIt->second.TryGetColorPair();\
        if (colorPtr)\
            ConfigColors.name = *colorPtr;\
    }\
}

void Config::UpdateColors(const AppCUI::Application::Config& config)
{
    this->ConfigColors.Inactive            = config.Text.Inactive;
    this->ConfigColors.Cursor              = config.Cursor.Normal;
    this->ConfigColors.Line                = config.Lines.Normal;
    this->ConfigColors.Normal              = config.Text.Focused;
    this->ConfigColors.Highlight           = config.Text.Highlighted;
    this->ConfigColors.HighlightCursorLine = ColorPair{ Color::Teal, Color::Gray }; // Commented its use for now
    this->ConfigColors.Selection           = config.Cursor.OverSelection;
    // this->ConfigColors.OutsideZone                   = ColorPair{ Color::Gray, Color::DarkBlue };
    this->ConfigColors.StructureColor                = ColorPair{ Color::Magenta, Color::Transparent };
    this->ConfigColors.DataTypeColor                 = config.Symbol.Arrows;
    this->ConfigColors.AsmOffsetColor                = ColorPair{ Color::White, Color::Transparent };
    this->ConfigColors.AsmIrrelevantInstructionColor = ColorPair{ Color::Gray, Color::Transparent };
    this->ConfigColors.AsmWorkRegisterColor          = ColorPair{ Color::Aqua, Color::Transparent };
    this->ConfigColors.AsmStackRegisterColor         = ColorPair{ Color::Magenta, Color::Transparent };
    this->ConfigColors.AsmCompareInstructionColor    = ColorPair{ Color::Olive, Color::Transparent };
    this->ConfigColors.AsmFunctionColor              = ColorPair{ Color::Pink, Color::Transparent };
    this->ConfigColors.AsmLocationInstruction        = ColorPair{ Color::Teal, Color::Transparent };
    this->ConfigColors.AsmJumpInstruction            = ColorPair{ Color::Silver, Color::Transparent };
    this->ConfigColors.AsmComment                    = ColorPair{ Color::Silver, Color::Transparent };
    this->ConfigColors.AsmLocalVariableColor         = ColorPair{ Color::Yellow, Color::Transparent };
    this->ConfigColors.AsmDefaultColor               = ColorPair{ Color::Green, Color::Transparent };
    this->ConfigColors.AsmTitleColor                 = config.Header.Text.Focused;
    this->ConfigColors.AsmTitleColumnColor           = config.Border.Focused;

    this->ConfigColors.CursorNormal      = ConfigColors.Normal;
    this->ConfigColors.CursorHighlighted = ConfigColors.Highlight;
    this->ConfigColors.CursorLine        = ConfigColors.Line;

    auto dissamColors = config.CustomColors.find("DissamColors");
    if (dissamColors!= config.CustomColors.end()) {
        auto& colors = dissamColors->second.data;
        LOAD_COLOR_IF_EXISTS(StructureColor);
        LOAD_COLOR_IF_EXISTS(AsmOffsetColor);
        LOAD_COLOR_IF_EXISTS(AsmIrrelevantInstructionColor);
        LOAD_COLOR_IF_EXISTS(AsmWorkRegisterColor);
        LOAD_COLOR_IF_EXISTS(AsmStackRegisterColor);
        LOAD_COLOR_IF_EXISTS(AsmCompareInstructionColor);
        LOAD_COLOR_IF_EXISTS(AsmFunctionColor);
        LOAD_COLOR_IF_EXISTS(AsmLocationInstruction);
        LOAD_COLOR_IF_EXISTS(AsmJumpInstruction);
        LOAD_COLOR_IF_EXISTS(AsmComment);
        LOAD_COLOR_IF_EXISTS(AsmLocalVariableColor);
        LOAD_COLOR_IF_EXISTS(AsmDefaultColor);
    }
}

void Config::Initialize(const AppCUI::Application::Config& config)
{
    UpdateColors(config);
    bool foundSettings = false;
    auto ini           = AppCUI::Application::GetAppSettings();
    if (ini) {
        auto sect = ini->GetSection("View.Dissasm");
        if (sect.Exists()) {
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

    Application::Config::CustomColorNameStorage dissamColors = {
        { "StructureColor", CustomColor(ConfigColors.StructureColor) }, { "AsmOffsetColor", CustomColor(ConfigColors.AsmOffsetColor) },
        { "AsmIrrelevantInstructionColor", CustomColor(ConfigColors.AsmIrrelevantInstructionColor) },
        { "AsmWorkRegisterColor", CustomColor(ConfigColors.AsmWorkRegisterColor) },
        { "AsmStackRegisterColor", CustomColor(ConfigColors.AsmStackRegisterColor) },
        { "AsmCompareInstructionColor", CustomColor(ConfigColors.AsmCompareInstructionColor) },
        { "AsmFunctionColor", CustomColor(ConfigColors.AsmFunctionColor) },
        { "AsmLocationInstruction", CustomColor(ConfigColors.AsmLocationInstruction) },
        { "AsmJumpInstruction", CustomColor(ConfigColors.AsmJumpInstruction) },
        { "AsmComment", CustomColor(ConfigColors.AsmComment) },
        { "AsmLocalVariableColor", CustomColor(ConfigColors.AsmLocalVariableColor) },
        { "AsmDefaultColor", CustomColor(ConfigColors.AsmDefaultColor) },
    };
    if (!Dialogs::ThemeEditor::RegisterCustomColors("DissamColors", dissamColors, this)) {
        Dialogs::MessageBox::ShowError("Error", "Failed to register dissasm colors");
        assert(false);//abort on debug
    }
    Dialogs::ThemeEditor::RegisterOnThemeChangeCallback(this);
    this->Loaded = true;
}

Config::~Config()
{
    Dialogs::ThemeEditor::RemovePreviewDrawListener(this);
    Dialogs::ThemeEditor::RemoveOnThemeChangeCallback(this);
}

void Config::OnPreviewWindowDraw(
    std::string_view categoryName,
    Graphics::Renderer& r,
    int startingX,
    int startingY,
    Graphics::Size sz,
    const Application::Config::CustomColorNameStorage& colors)
{
    auto StructureColorTheme                = colors.at("StructureColor").TryGetColorPair();
    auto AsmOffsetColorTheme                = colors.at("AsmOffsetColor").TryGetColorPair();
    auto AsmIrrelevantInstructionColorTheme = colors.at("AsmIrrelevantInstructionColor").TryGetColorPair();
    auto AsmWorkRegisterColorTheme          = colors.at("AsmWorkRegisterColor").TryGetColorPair();
    auto AsmStackRegisterColorTheme         = colors.at("AsmStackRegisterColor").TryGetColorPair();
    auto AsmCompareInstructionColorTheme    = colors.at("AsmCompareInstructionColor").TryGetColorPair();
    auto AsmFunctionColorTheme              = colors.at("AsmFunctionColor").TryGetColorPair();
    auto AsmLocationInstructionTheme        = colors.at("AsmLocationInstruction").TryGetColorPair();
    auto AsmJumpInstructionTheme            = colors.at("AsmJumpInstruction").TryGetColorPair();
    auto AsmCommentTheme                    = colors.at("AsmComment").TryGetColorPair();
    auto AsmDefaultColorTheme               = colors.at("AsmDefaultColor").TryGetColorPair();

    const bool allValid = StructureColorTheme && AsmOffsetColorTheme && AsmIrrelevantInstructionColorTheme && AsmWorkRegisterColorTheme &&
                          AsmStackRegisterColorTheme && AsmCompareInstructionColorTheme && AsmFunctionColorTheme &&
                          AsmLocationInstructionTheme && AsmJumpInstructionTheme && AsmCommentTheme && AsmDefaultColorTheme;
    if (!allValid) {
        assert(false);
        return;
    }
    r.WriteSingleLineText(startingX + 3, startingY, "Collapsible zone:", *StructureColorTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; StructureColor", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "mov", *AsmDefaultColorTheme);
    r.WriteSingleLineText(startingX + 6, startingY, "ebp", *AsmStackRegisterColorTheme);
    r.WriteSingleLineText(startingX + 9, startingY, ",", *AsmStackRegisterColorTheme);
    r.WriteSingleLineText(startingX + 10, startingY, "esp", *AsmStackRegisterColorTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; AsmStackRegisterColorTheme", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "push", *AsmDefaultColorTheme);
    r.WriteSingleLineText(startingX + 6, startingY, "ebx", *AsmWorkRegisterColorTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; AsmWorkRegisterColorTheme", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "cmp", *AsmCompareInstructionColorTheme);
    r.WriteSingleLineText(startingX + 6, startingY, "ebx, eax", *AsmWorkRegisterColorTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; AsmCompareInstructionColorTheme", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "jmp", *AsmJumpInstructionTheme);
    r.WriteSingleLineText(startingX + 6, startingY, "offset_0x0000", *AsmOffsetColorTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; AsmJumpInstructionTheme", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "call", *AsmFunctionColorTheme);
    r.WriteSingleLineText(startingX + 6, startingY, "sub_0x3121", *AsmDefaultColorTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; AsmFunctionColorTheme", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "mov", *AsmDefaultColorTheme);
    r.WriteSingleLineText(startingX + 6, startingY, "dword ptr [...]", *AsmLocationInstructionTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; AsmLocationInstructionTheme", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "int3", *AsmIrrelevantInstructionColorTheme);
    r.WriteSingleLineText(startingX + 20, startingY, "; AsmIrrelevantInstructionColorTheme", *AsmCommentTheme);
    ++startingY;

    r.WriteSingleLineText(startingX + 1, startingY, "ret", *AsmFunctionColorTheme);
    ++startingY;

    // older themes may not define it
    const auto localVariableColor = colors.find("AsmLocalVariableColor");
    const auto AsmLocalVariableColorTheme = localVariableColor != colors.end() ? localVariableColor->second.TryGetColorPair() : nullptr;
    if (AsmLocalVariableColorTheme) {
        r.WriteSingleLineText(startingX + 1, startingY, "var_8", *AsmLocalVariableColorTheme);
        r.WriteSingleLineText(startingX + 20, startingY, "; AsmLocalVariableColor", *AsmCommentTheme);
    }

    // ret + call -> AsmFunctionColor

    //
}

void Config::OnThemeChanged(const Application::Config& config)
{
    UpdateColors(config);
    ConfigColors.hasChanges = true;
}

void GView::View::DissasmViewer::RegisterKeys(KeyboardControlsInterface* interface)
{
    for (auto& key : Config::AllKeyboardCommands)
        interface->RegisterKey(&key.get());
    interface->BeginCategory("Navigation & editing");
    for (auto key : Config::NavigationCommands)
        interface->RegisterKey(key);
    interface->RegisterKeyText("Escape", "SaveCacheOnEscape", "Escape also saves the disassembly cache");
}
void GView::View::DissasmViewer::OnKeysChanged()
{
    Config::Map.Build(Config::KeyEventCommands);
}

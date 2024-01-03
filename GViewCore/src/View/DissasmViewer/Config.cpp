#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("AddNewType", Key::F5, true);
    sect.UpdateValue("ShowFileContentKey", Key::F9, true);
    sect.UpdateValue("ShowFileContent", true, true);
    sect.UpdateValue("AsmExportToFile", Key::F8, true);
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
    if (ini)
    {
        auto sect = ini->GetSection("DissasmView");
        if (sect.Exists())
        {
            this->Keys.AddNewType              = sect.GetValue("AddNewType").ToKey(Key::F6);
            this->Keys.ShowFileContentKey      = sect.GetValue("ShowFileContentKey").ToKey(Key::F9);
            this->Keys.ExportAsmToFile         = sect.GetValue("AsmExportToFile").ToKey(Key::F8);
            this->Keys.JumpBack                = sect.GetValue("JumpBack").ToKey(Key::Ctrl | Key::Q);
            this->Keys.JumpForward             = sect.GetValue("JumpForward").ToKey(Key::Ctrl | Key::E);
            this->Keys.DissasmGotoEntrypoint   = sect.GetValue("Entrypoint").ToKey(Key::F2);
            this->ShowFileContent              = sect.GetValue("ShowFileContent").ToBool(true);
            this->EnableDeepScanDissasmOnStart = sect.GetValue("DeepScanDissasmOnStart").ToBool(false);
            foundSettings                      = true;
        }
    }
    if (!foundSettings)
    {
        this->Keys.AddNewType              = Key::F6;
        this->Keys.ShowFileContentKey      = Key::F9;
        this->Keys.ExportAsmToFile         = Key::F8;
        this->Keys.JumpBack                = Key::Ctrl | Key::Q;
        this->Keys.JumpForward             = Key::Ctrl | Key::E;
        this->Keys.DissasmGotoEntrypoint   = Key::F2;
        this->ShowFileContent              = true;
        this->EnableDeepScanDissasmOnStart = false;
    }

    this->Loaded = true;
}

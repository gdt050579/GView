#include "pe.hpp"

using namespace AppCUI::Controls;

constexpr auto ID_CHECKBOX_ALL    = 0x1001U;
constexpr auto ID_CHECKBOX_HEADER = 0x1002U;
constexpr auto ID_CHECKBOX_CALL   = 0x1003U;
constexpr auto ID_CHECKBOX_LCALL  = 0x1004U;
constexpr auto ID_CHECKBOX_JMP    = 0x1005U;
constexpr auto ID_CHECKBOX_LJMP   = 0x1006U;
constexpr auto ID_CHECKBOX_BP     = 0x1007U;
constexpr auto ID_CHECKBOX_FSTART = 0x1008U;
constexpr auto ID_CHECKBOX_FEND   = 0x1009U;

namespace GView::Type::PE::Panels
{
OpCodes::OpCodes(Reference<Object> _object, Reference<GView::Type::PE::PEFile> _pe) : TabPage("Op&Codes"), object(_object), pe(_pe)
{
    value = Factory::Label::Create(this, "Mask", "x:1,y:1,w:60");

    list = Factory::ListView::Create(
          this,
          "x:1,y:2,h:20,w:60",
          { "n:Enabled,a:l,w:60" },
          AppCUI::Controls::ListViewFlags::CheckBoxes | AppCUI::Controls::ListViewFlags::HideSearchBar);

    all = list->AddItem("All");
    all.SetData(ID_CHECKBOX_ALL);

    header = list->AddItem("Executable header(s)");
    header.SetColor(PE::EXE_MARKER_COLOR);
    header.SetData(ID_CHECKBOX_HEADER);

    call = list->AddItem("CALL");
    call.SetColor(PE::INS_CALL_COLOR);
    call.SetData(ID_CHECKBOX_CALL);

    lcall = list->AddItem("LCALL");
    lcall.SetColor(PE::INS_LCALL_COLOR);
    lcall.SetData(ID_CHECKBOX_LCALL);

    jmp = list->AddItem("JMP");
    jmp.SetColor(PE::INS_JUMP_COLOR);
    jmp.SetData(ID_CHECKBOX_JMP);

    ljmp = list->AddItem("LJMP");
    ljmp.SetColor(PE::INS_LJUMP_COLOR);
    ljmp.SetData(ID_CHECKBOX_LJMP);

    bp = list->AddItem("Breakpoints");
    bp.SetColor(PE::INS_BREAKPOINT_COLOR);
    bp.SetData(ID_CHECKBOX_BP);

    fstart = list->AddItem("Function Start");
    fstart.SetColor(PE::START_FUNCTION_COLOR);
    fstart.SetData(ID_CHECKBOX_FSTART);

    fend = list->AddItem("Function End");
    fend.SetColor(PE::END_FUNCTION_COLOR);
    fend.SetData(ID_CHECKBOX_FEND);

    Update();
}

void OpCodes::Update()
{
    pe->showOpcodesMask = 0;
    auto settings       = Application::GetAppSettings();
    if (settings->HasSection("Type.PE"))
    {
        auto peSection = settings->GetSection("Type.PE");
        auto optValue  = peSection["OpCodes.Mask"];
        if (optValue.HasValue())
        {
            auto optUInt32 = optValue.AsUInt32();
            if (optUInt32.has_value())
            {
                pe->showOpcodesMask = *optUInt32;
            }
        }
    }

    header.SetCheck((pe->showOpcodesMask >> 0) & 1U);
    call.SetCheck((pe->showOpcodesMask >> 1) & 1U);
    lcall.SetCheck((pe->showOpcodesMask >> 2) & 1U);
    jmp.SetCheck((pe->showOpcodesMask >> 3) & 1U);
    ljmp.SetCheck((pe->showOpcodesMask >> 4) & 1U);
    bp.SetCheck((pe->showOpcodesMask >> 5) & 1U);
    fstart.SetCheck((pe->showOpcodesMask >> 6) & 1U);
    fend.SetCheck((pe->showOpcodesMask >> 7) & 1U);

    all.SetCheck(AllChecked());

    SetMaskText();
}

bool OpCodes::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return false;
}

inline bool OpCodes::AllChecked()
{
    return header.IsChecked() && call.IsChecked() && lcall.IsChecked() && jmp.IsChecked() && ljmp.IsChecked() && bp.IsChecked() &&
           fstart.IsChecked() && fend.IsChecked();
}

inline bool OpCodes::AllUnChecked()
{
    return !AllChecked();
}

inline void OpCodes::SetMaskText()
{
    auto settings = Application::GetAppSettings();
    if (settings->HasSection("Type.PE"))
    {
        auto pe        = settings->GetSection("Type.PE");
        auto optValue  = pe["OpCodes.Mask"];
        uint32 mask    = 0;
        auto optUInt32 = optValue.AsUInt32();
        if (optValue.HasValue() && optUInt32.has_value())
        {
            mask = *optUInt32;
            LocalString<32> ls;
            value->SetText(ls.Format("Mask: 0x%X", mask));
        }
        else
        {
            value->SetText("Mask: 0x0");
        }
    }
}

inline void OpCodes::SetConfig(bool checked, uint16 position)
{
    auto settings = Application::GetAppSettings();
    if (settings->HasSection("Type.PE"))
    {
        auto viewBuffer = settings->GetSection("Type.PE");
        auto optValue   = viewBuffer["OpCodes.Mask"];
        uint32 value    = 0;
        if (optValue.HasValue())
        {
            value = *optValue.AsUInt32();
        }
        if (checked)
        {
            value |= 1UL << position;
        }
        else
        {
            value &= ~(1UL << position);
        }
        viewBuffer["OpCodes.Mask"] = value;

        settings->Save(Application::GetAppSettingsFile());
    }

    Update();
}

bool OpCodes::OnEvent(Reference<Control>, Event evnt, int controlID)
{
    CHECK(evnt == Event::ListViewItemChecked, false, "");
    const auto& item = list->GetCurrentItem();
    const auto& id   = item.GetData(-1);

    switch (id)
    {
    case ID_CHECKBOX_ALL:
    {
        const auto isChecked = all.IsChecked();

        header.SetCheck(isChecked);
        call.SetCheck(isChecked);
        lcall.SetCheck(isChecked);
        jmp.SetCheck(isChecked);
        ljmp.SetCheck(isChecked);
        bp.SetCheck(isChecked);
        fstart.SetCheck(isChecked);
        fend.SetCheck(isChecked);

        auto settings = Application::GetAppSettings();
        if (settings->HasSection("Type.PE"))
        {
            auto viewBuffer            = settings->GetSection("Type.PE");
            viewBuffer["OpCodes.Mask"] = isChecked ? 0xFFFFFFFF : 0;
            settings->Save(Application::GetAppSettingsFile());
        }

        Update();

        return true;
    }
    case ID_CHECKBOX_HEADER:
    {
        all.SetCheck(AllChecked());
        SetConfig(header.IsChecked(), 0);
        return true;
    }
    case ID_CHECKBOX_CALL:
    {
        all.SetCheck(AllChecked());
        SetConfig(call.IsChecked(), 1);
        return true;
    }
    case ID_CHECKBOX_LCALL:
    {
        all.SetCheck(AllChecked());
        SetConfig(lcall.IsChecked(), 2);
        return true;
    }
    case ID_CHECKBOX_JMP:
    {
        all.SetCheck(AllChecked());
        SetConfig(jmp.IsChecked(), 3);
        return true;
    }
    case ID_CHECKBOX_LJMP:
    {
        all.SetCheck(AllChecked());
        SetConfig(ljmp.IsChecked(), 4);
        return true;
    }
    case ID_CHECKBOX_BP:
    {
        all.SetCheck(AllChecked());
        SetConfig(bp.IsChecked(), 5);
        return true;
    }
    case ID_CHECKBOX_FSTART:
    {
        all.SetCheck(AllChecked());
        SetConfig(fstart.IsChecked(), 6);
        return true;
    }
    case ID_CHECKBOX_FEND:
    {
        all.SetCheck(AllChecked());
        SetConfig(fend.IsChecked(), 7);
        return true;
    }
    default:
        break;
    }

    return false;
}
} // namespace GView::Type::PE::Panels

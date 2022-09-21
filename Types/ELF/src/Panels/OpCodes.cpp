#include "elf.hpp"

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

namespace GView::Type::ELF::Panels
{
OpCodes::OpCodes(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> _elf) : TabPage("Op&Codes"), object(_object), elf(_elf)
{
    value = Factory::Label::Create(this, "Mask", "x:1,y:1,w:60");

    all    = Factory::CheckBox::Create(this, "All", "x:1,y:3,w:60", ID_CHECKBOX_ALL);
    header = Factory::CheckBox::Create(this, "Executable header(s)", "x:1,y:4,w:60", ID_CHECKBOX_HEADER);
    call   = Factory::CheckBox::Create(this, "CALL", "x:1,y:5,w:60", ID_CHECKBOX_CALL);
    lcall  = Factory::CheckBox::Create(this, "LCALL", "x:1,y:6,w:60", ID_CHECKBOX_LCALL);
    jmp    = Factory::CheckBox::Create(this, "JMP", "x:1,y:7,w:60", ID_CHECKBOX_JMP);
    ljmp   = Factory::CheckBox::Create(this, "LJMP", "x:1,y:8,w:60", ID_CHECKBOX_LJMP);
    bp     = Factory::CheckBox::Create(this, "Breakpoints", "x:1,y:9,w:60", ID_CHECKBOX_BP);
    fstart = Factory::CheckBox::Create(this, "Function Start", "x:1,y:10,w:60", ID_CHECKBOX_FSTART);
    fend   = Factory::CheckBox::Create(this, "Function End", "x:1,y:11,w:60", ID_CHECKBOX_FEND);

    Update();
}

void OpCodes::Update()
{
    elf->showOpcodesMask = 0;
    auto settings        = Application::GetAppSettings();
    if (settings->HasSection("Type.PE"))
    {
        auto pe       = settings->GetSection("Type.PE");
        auto optValue = pe["OpCodes.Mask"];
        if (optValue.HasValue())
        {
            auto optUInt32 = optValue.AsUInt32();
            if (optUInt32.has_value())
            {
                elf->showOpcodesMask = *optUInt32;
            }
        }
    }

    header->SetChecked((elf->showOpcodesMask >> 0) & 1U);
    call->SetChecked((elf->showOpcodesMask >> 1) & 1U);
    lcall->SetChecked((elf->showOpcodesMask >> 2) & 1U);
    jmp->SetChecked((elf->showOpcodesMask >> 3) & 1U);
    ljmp->SetChecked((elf->showOpcodesMask >> 4) & 1U);
    bp->SetChecked((elf->showOpcodesMask >> 5) & 1U);
    fstart->SetChecked((elf->showOpcodesMask >> 6) & 1U);
    fend->SetChecked((elf->showOpcodesMask >> 7) & 1U);

    all->SetChecked(AllChecked());

    SetMaskText();
}

bool OpCodes::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return false;
}

inline bool OpCodes::AllChecked()
{
    return header->IsChecked() && call->IsChecked() && lcall->IsChecked() && jmp->IsChecked() && ljmp->IsChecked() && bp->IsChecked() &&
           fstart->IsChecked() && fend->IsChecked();
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
    switch (controlID)
    {
    case ID_CHECKBOX_ALL:
    {
        const auto isChecked = all->IsChecked();

        header->SetChecked(isChecked);
        call->SetChecked(isChecked);
        lcall->SetChecked(isChecked);
        jmp->SetChecked(isChecked);
        ljmp->SetChecked(isChecked);
        bp->SetChecked(isChecked);
        fstart->SetChecked(isChecked);
        fend->SetChecked(isChecked);

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
        all->SetChecked(AllChecked());
        SetConfig(header->IsChecked(), 0);
        return true;
    }
    case ID_CHECKBOX_CALL:
    {
        all->SetChecked(AllChecked());
        SetConfig(call->IsChecked(), 1);
        return true;
    }
    case ID_CHECKBOX_LCALL:
    {
        all->SetChecked(AllChecked());
        SetConfig(lcall->IsChecked(), 2);
        return true;
    }
    case ID_CHECKBOX_JMP:
    {
        all->SetChecked(AllChecked());
        SetConfig(jmp->IsChecked(), 3);
        return true;
    }
    case ID_CHECKBOX_LJMP:
    {
        all->SetChecked(AllChecked());
        SetConfig(ljmp->IsChecked(), 4);
        return true;
    }
    case ID_CHECKBOX_BP:
    {
        all->SetChecked(AllChecked());
        SetConfig(bp->IsChecked(), 5);
        return true;
    }
    case ID_CHECKBOX_FSTART:
    {
        all->SetChecked(AllChecked());
        SetConfig(fstart->IsChecked(), 6);
        return true;
    }
    case ID_CHECKBOX_FEND:
    {
        all->SetChecked(AllChecked());
        SetConfig(fend->IsChecked(), 7);
        return true;
    }
    default:
        break;
    }

    return false;
}
} // namespace GView::Type::ELF::Panels

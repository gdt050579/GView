#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK                    = 1;
constexpr int32 BTN_ID_CANCEL                = 2;
constexpr int32 RADIOBOX_ID_ARCHITECTURE_X86 = 3;
constexpr int32 RADIOBOX_ID_ARCHITECTURE_X64 = 4;
constexpr int32 RADIOBOX_ID_DEISGN_INTEL     = 5;
constexpr int32 RADIOBOX_ID_DEISGN_ARM       = 6;

constexpr int32 GROUPD_ID_ARCHITECTURE_TYPE = 1;
constexpr int32 GROUPD_ID_DESIGN_TYPE       = 2;

DissasmDialog::DissasmDialog(BufferView _buffer, uint64 _fa, uint64 _size)
    : Window("Dissasm", "d:c,w:60%,h:60%", WindowFlags::ProcessReturn), buffer(_buffer), fa(_fa), size(_size)
{
    list = Factory::ListView::Create(
          this, "x:0,y:0,w:100%,h:90%", { "n:FA,w:10%", "n:Bytes,w:20%", "n:Instructions,w:50%", "n:Options,w:20%" }, ListViewFlags::None);
    list->SetFocus();

    architecture = Factory::Label::Create(this, "Architecture", "x:82%,y:2,w:18%,h:1");
    x86          = Factory::RadioBox::Create(this, "x&64", "x:82%,y:3,w:18%,h:1", GROUPD_ID_ARCHITECTURE_TYPE, RADIOBOX_ID_ARCHITECTURE_X86, true);
    x64          = Factory::RadioBox::Create(this, "x&86", "x:82%,y:4,w:18%,h:1", GROUPD_ID_ARCHITECTURE_TYPE, RADIOBOX_ID_ARCHITECTURE_X64);

    design = Factory::Label::Create(this, "Design", "x:82%,y:6,w:100%,h:1");
    intel  = Factory::RadioBox::Create(this, "&Intel", "x:82%,y:7,w:18%,h:1", GROUPD_ID_DESIGN_TYPE, RADIOBOX_ID_DEISGN_INTEL, true);
    arm    = Factory::RadioBox::Create(this, "&ARM", "x:82%,y:8,w:18%,h:1", GROUPD_ID_DESIGN_TYPE, RADIOBOX_ID_DEISGN_ARM);

    CHECKRET(dissasembler.Init(true, true, true), "");

    LocalString<128> tmp;
    LocalString<128> tmp3;

    GView::Dissasembly::Instruction instruction{ 0 };
    uint64 offset = 0;
    bool ok       = dissasembler.DissasembleInstruction(buffer, offset, instruction);
    while (ok && offset < size)
    {
        LocalString<128> tmp2;
        for (auto i = 0U; i < std::min<uint32>(instruction.size, GView::Dissasembly::BYTES_SIZE); i++)
        {
            tmp2.AddFormat("%02X ", instruction.bytes[i]);
        }

        list->AddItem({ tmp3.Format("0x%llx", fa + offset), tmp2, tmp.Format("%s %s", instruction.mnemonic, instruction.opStr) });
        offset += instruction.size;
        ok = dissasembler.DissasembleInstruction({ buffer.GetData() + offset, size - offset }, offset, instruction);
    }

    Factory::Button::Create(this, "&Cancel", "x:45%,y:95%,w:10%,h:10%", BTN_ID_CANCEL);
}

void DissasmDialog::Validate()
{
    Exit(Dialogs::Result::Ok);
}

bool DissasmDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::ButtonClicked)
    {
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            Validate();
            return true;
        }
    }

    switch (eventType)
    {
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
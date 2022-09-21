#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

DissasmDialog::DissasmDialog(
      BufferView _buffer, uint64 _fa, uint64 _size, GView::Dissasembly::Architecture _arch, GView::Dissasembly::Mode _mode)
    : Window("Dissasm", "d:c,w:60%,h:60%", WindowFlags::ProcessReturn), buffer(_buffer), fa(_fa), size(_size), arch(_arch), mode(_mode)
{
    list = Factory::ListView::Create(
          this, "x:0,y:0,w:100%,h:90%", { "n:FA,w:10%", "n:Bytes,w:20%", "n:Instructions,w:70%" }, ListViewFlags::None);
    list->SetFocus();

    LocalString<128> tmp;
    LocalString<128> tmp3;

    GView::Dissasembly::Instruction instruction{ 0 };
    uint64 offset = 0;
    bool ok       = GView::Dissasembly::DissasembleInstruction(buffer, arch, offset, mode, instruction);
    while (ok && offset < size)
    {
        LocalString<128> tmp2;
        for (auto i = 0U; i < std::min<uint32>(instruction.size, GView::Dissasembly::BYTES_SIZE); i++)
        {
            tmp2.AddFormat("%02X ", instruction.bytes[i]);
        }

        list->AddItem({ tmp3.Format("0x%llx", fa + offset), tmp2, tmp.Format("%s %s", instruction.mnemonic, instruction.opStr) });
        offset += instruction.size;
        ok = GView::Dissasembly::DissasembleInstruction({ buffer.GetData() + offset, size - offset }, arch, offset, mode, instruction);
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
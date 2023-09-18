#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK                    = 1;
constexpr int32 BTN_ID_CANCEL                = 2;
constexpr int32 RADIOBOX_ID_ARCHITECTURE_X86 = 3;
constexpr int32 RADIOBOX_ID_ARCHITECTURE_X64 = 4;
constexpr int32 RADIOBOX_ID_DESIGN_INTEL     = 5;
constexpr int32 RADIOBOX_ID_DESIGN_ARM       = 6;
constexpr int32 RADIOBOX_ID_ENDIANESS_LITTLE = 7;
constexpr int32 RADIOBOX_ID_ENDIANESS_BIG    = 8;

constexpr int32 GROUPD_ID_ARCHITECTURE_TYPE = 1;
constexpr int32 GROUPD_ID_DESIGN_TYPE       = 2;
constexpr int32 GROUPD_ID_ENDIANESS_TYPE    = 3;

DissasmDialog::DissasmDialog(Reference<Instance> instance) : Window("Dissasm", "d:c,w:100%,h:60%", WindowFlags::ProcessReturn), instance(instance)
{
    list = Factory::ListView::Create(
          this,
          "x:5,y:1,w:85%,h:85%",
          { "n:FA,w:10%", "n:Bytes,w:30%", "n:Instructions,w:35%", "n:Groups,w:35%" },
          ListViewFlags::AllowMultipleItemsSelection | ListViewFlags::PopupSearchBar);
    list->SetFocus();

    architecture             = Factory::Label::Create(this, "Architecture", "x:90%,y:2,w:11%,h:1");
    x64                      = Factory::RadioBox::Create(this, "x&64", "x:90%,y:3,w:11%,h:1", GROUPD_ID_ARCHITECTURE_TYPE, RADIOBOX_ID_ARCHITECTURE_X86);
    x86                      = Factory::RadioBox::Create(this, "x&86", "x:90%,y:4,w:11%,h:1", GROUPD_ID_ARCHITECTURE_TYPE, RADIOBOX_ID_ARCHITECTURE_X64);
    x64->Handlers()->OnCheck = this;
    x86->Handlers()->OnCheck = this;

    design                     = Factory::Label::Create(this, "Design", "x:90%,y:6,w:10%,h:1");
    intel                      = Factory::RadioBox::Create(this, "&Intel", "x:90%,y:7,w:10%,h:1", GROUPD_ID_DESIGN_TYPE, RADIOBOX_ID_DESIGN_INTEL);
    arm                        = Factory::RadioBox::Create(this, "&ARM", "x:90%,y:8,w:10%,h:1", GROUPD_ID_DESIGN_TYPE, RADIOBOX_ID_DESIGN_ARM);
    intel->Handlers()->OnCheck = this;
    arm->Handlers()->OnCheck   = this;

    endianess                   = Factory::Label::Create(this, "Endianess", "x:90%,y:10,w:10%,h:1");
    little                      = Factory::RadioBox::Create(this, "&Little", "x:90%,y:11,w:10%,h:1", GROUPD_ID_ENDIANESS_TYPE, RADIOBOX_ID_ENDIANESS_LITTLE);
    big                         = Factory::RadioBox::Create(this, "&Big", "x:90%,y:12,w:10%,h:1", GROUPD_ID_ENDIANESS_TYPE, RADIOBOX_ID_ENDIANESS_BIG);
    little->Handlers()->OnCheck = this;
    big->Handlers()->OnCheck    = this;

    switch (instance->GetSettings()->design)
    {
    case GView::Dissasembly::Design::Intel:
        intel->SetChecked(true);
        break;
    case GView::Dissasembly::Design::ARM:
        arm->SetChecked(true);
        break;
    case GView::Dissasembly::Design::Invalid:
    default:
        instance->GetSettings()->design = GView::Dissasembly::Design::Intel;
        intel->SetChecked(true);
        break;
    }

    switch (instance->GetSettings()->architecture)
    {
    case GView::Dissasembly::Architecture::x86:
        x86->SetChecked(true);
        break;
    case GView::Dissasembly::Architecture::x64:
        x64->SetChecked(true);
        break;
    case GView::Dissasembly::Architecture::Invalid:
    default:
        instance->GetSettings()->architecture = GView::Dissasembly::Architecture::x86;
        x86->SetChecked(true);
        break;
    }

    switch (instance->GetSettings()->endianess)
    {
    case GView::Dissasembly::Endianess::Little:
        little->SetChecked(true);
        break;
    case GView::Dissasembly::Endianess::Big:
        big->SetChecked(true);
        break;
    case GView::Dissasembly::Endianess::Invalid:
    default:
        instance->GetSettings()->endianess = GView::Dissasembly::Endianess::Little;
        little->SetChecked(true);
        break;
    }

    Factory::Button::Create(this, "&OK", "x:25%,y:100%,a:b,w:12", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL);

    CHECKRET(Update(), "");
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

void DissasmDialog::OnCheck(Reference<Controls::Control> control, bool value)
{
    const auto id = control->GetControlID();
    switch (id)
    {
    case RADIOBOX_ID_ARCHITECTURE_X86:
        if (value)
        {
            instance->GetSettings()->architecture = GView::Dissasembly::Architecture::x86;
        }
        CHECKRET(Update(), "");
        break;
    case RADIOBOX_ID_ARCHITECTURE_X64:
        if (value)
        {
            instance->GetSettings()->architecture = GView::Dissasembly::Architecture::x64;
        }
        CHECKRET(Update(), "");
        break;
    case RADIOBOX_ID_DESIGN_INTEL:
        if (value)
        {
            instance->GetSettings()->design = GView::Dissasembly::Design::Intel;
        }
        CHECKRET(Update(), "");
        break;
    case RADIOBOX_ID_DESIGN_ARM:
        if (value)
        {
            instance->GetSettings()->design = GView::Dissasembly::Design::ARM;
        }
        CHECKRET(Update(), "");
        break;
    case RADIOBOX_ID_ENDIANESS_LITTLE:
        if (value)
        {
            instance->GetSettings()->endianess = GView::Dissasembly::Endianess::Little;
        }
        CHECKRET(Update(), "");
        break;
    case RADIOBOX_ID_ENDIANESS_BIG:
        if (value)
        {
            instance->GetSettings()->endianess = GView::Dissasembly::Endianess::Big;
        }
        CHECKRET(Update(), "");
        break;
    default:
        break;
    }
}

bool DissasmDialog::Update()
{
    CHECK(list.IsValid(), false, "");
    CHECK(instance.IsValid(), false, "");
    list->DeleteAllItems();

    const auto addressColumnName = instance->GetSettings()->translationMethods[instance->GetCurrentAddressMode()].name.GetText();
    CHECK(list->GetColumn(0).SetText(addressColumnName), false, "");

    CHECK(dissasembler.Init(instance->GetSettings()->design, instance->GetSettings()->architecture, instance->GetSettings()->endianess), false, "");

    std::vector<GView::Dissasembly::Instruction> instructions{};

    auto address = instance->GetCursorCurrentPosition();
    if (instance->GetSettings()->offsetTranslateCallback)
    {
        address = instance->GetSettings()->offsetTranslateCallback->TranslateFromFileOffset(address, instance->GetCurrentAddressMode());
    }
    const auto buffer = instance->GetObject()->GetData().Get(instance->GetCursorCurrentPosition(), 0x2000, false);

    CHECK(dissasembler.DissasembleInstructions(buffer, address, instructions), false, "");

    LocalString<128> tmp;
    LocalString<128> tmp3;

    uint64 offset = 0;
    for (const auto& instruction : instructions)
    {
        LocalString<128> tmp2;
        for (auto i = 0U; i < std::min<uint32>(instruction.size, GView::Dissasembly::BYTES_SIZE); i++)
        {
            tmp2.AddFormat("%02X ", instruction.bytes[i]);
        }

        LocalString<128> tmp4;
        bool first{ true };
        bool branchRelative{ false };
        for (auto i = 0U; i < instruction.groupsCount; i++)
        {
            const auto t = instruction.groups[i];
            if (t == GView::Dissasembly::GroupType::Jump || t == GView::Dissasembly::GroupType::Call || t == GView::Dissasembly::GroupType::BranchRelative)
            {
                branchRelative = true;
            }

            const auto name = dissasembler.GetInstructionGroupName((uint8) t);
            if (first == false)
            {
                tmp4.Add(" | ");
            }
            tmp4.AddFormat("%.*s", name.size(), name.data());
            first = false;
        }

        auto item = list->AddItem({ tmp3.Format("0x%llX", address + offset), tmp2, tmp.Format("%s %s", instruction.mnemonic, instruction.opStr), tmp4 });
        if (branchRelative)
        {
            item.SetType(ListViewItem::Type::SubItemColored);
            item.SetColor(2, { Color::Pink, Color::Transparent });
        }

        item.SetData((uint8) GView::Dissasembly::GroupType::Invalid);
        for (auto i = 0U; i < instruction.groupsCount; i++)
        {
            const auto t = instruction.groups[i];
            if (t == GView::Dissasembly::GroupType::Jump || t == GView::Dissasembly::GroupType::Call || t == GView::Dissasembly::GroupType::BranchRelative)
            {
                item.SetData((uint8) t);
                break;
            }
        }

        offset += instruction.size;
    }

    return true;
}

#include "pe.hpp"

namespace GView::Type::PE::Commands
{
using namespace AppCUI::Controls;

enum class Action : int32
{
    Dummy = 1
};

DigitalSignature::DigitalSignature(Reference<PEFile> pe)
    : Window("Digital Signature", "x:25%,y:25%,w:50%,h:50%", WindowFlags::Sizeable | WindowFlags::ProcessReturn), pe(pe)
{
    general = Factory::ListView::Create(
          this, "x:0,y:0,w:100%,h:100%", { "n:Key,w:30%", "n:Value,w:70%" }, ListViewFlags::AllowMultipleItemsSelection);

    Update();
}

void DigitalSignature::Update()
{
    general->DeleteAllItems();

    LocalString<1024> ls;

    constexpr auto COLOR_SUCCESS = ColorPair{ Color::Green, Color::Transparent };
    constexpr auto COLOR_FAILURE = ColorPair{ Color::Red, Color::Transparent };

    general->AddItem({ "WinTrust", "" }).SetType(ListViewItem::Type::Category);
    general->AddItem({ "Call Successful", pe->signatureData->winTrust.callSuccessful ? "True" : "False" })
          .SetColor(pe->signatureData->winTrust.callSuccessful ? COLOR_SUCCESS : COLOR_FAILURE);
    general->AddItem({ "Error code", ls.Format("0x%X", pe->signatureData->winTrust.errorCode) })
          .SetColor(pe->signatureData->winTrust.errorCode == 0 ? COLOR_SUCCESS : COLOR_FAILURE);
    general->AddItem({ "Error message", ls.Format("%s", pe->signatureData->winTrust.errorMessage.GetText()) })
          .SetColor(pe->signatureData->winTrust.errorCode == 0 ? COLOR_SUCCESS : COLOR_FAILURE);

    general->AddItem({ "Certificate Information", "" }).SetType(ListViewItem::Type::Category);
    general->AddItem({ "Call Successful", pe->signatureData->information.callSuccessfull ? "True" : "False" })
          .SetType(pe->signatureData->information.callSuccessfull ? ListViewItem::Type::Normal : ListViewItem::Type::ErrorInformation);
    general->AddItem({ "Error code", ls.Format("0x%X", pe->signatureData->information.errorCode) })
          .SetType(pe->signatureData->information.errorCode == 0 ? ListViewItem::Type::Normal : ListViewItem::Type::ErrorInformation);
    general->AddItem({ "Error message", ls.Format("%s", pe->signatureData->information.errorMessage.GetText()) })
          .SetType(pe->signatureData->information.errorCode == 0 ? ListViewItem::Type::Normal : ListViewItem::Type::ErrorInformation);

    general->AddItem({ "Program Name", ls.Format("%s", pe->signatureData->information.programName.GetText()) });
    general->AddItem({ "Publish Link", ls.Format("%s", pe->signatureData->information.publishLink.GetText()) });
    general->AddItem({ "More Info Link", ls.Format("%s", pe->signatureData->information.moreInfoLink.GetText()) });

    general->AddItem({ "Signer", "" }).SetType(ListViewItem::Type::Category);
    general->AddItem({ "Issuer", ls.Format("%s", pe->signatureData->information.signer.issuer.GetText()) });
    general->AddItem({ "Subject", ls.Format("%s", pe->signatureData->information.signer.subject.GetText()) });
    general->AddItem({ "Date", ls.Format("%s", pe->signatureData->information.signer.date.GetText()) });
    general->AddItem({ "Serial Number", ls.Format("%s", pe->signatureData->information.signer.serialNumber.GetText()) });
    general->AddItem({ "Signature Algorithm", ls.Format("%s", pe->signatureData->information.signer.signatureAlgorithm.GetText()) });

    std::string validSigner;
    switch (pe->signatureData->information.signer.timevalidity)
    {
    case GView::DigitalSignature::TimeValidity::AfterNotAfter:
        validSigner = "AfterNotAfter";
        break;
    case GView::DigitalSignature::TimeValidity::Valid:
        validSigner = "Valid";
        break;
    case GView::DigitalSignature::TimeValidity::BeforeNotBefore:
        validSigner = "BeforeNotBefore";
        break;
    default:
        validSigner = "Unknown";
        break;
    }
    general->AddItem({ "Time Validity", validSigner.c_str() })
          .SetColor(
                pe->signatureData->information.signer.timevalidity == GView::DigitalSignature::TimeValidity::Valid ? COLOR_SUCCESS
                                                                                                                   : COLOR_FAILURE);

    general->AddItem({ "Counter Signer", "" }).SetType(ListViewItem::Type::Category);
    general->AddItem({ "Issuer", ls.Format("%s", pe->signatureData->information.counterSigner.issuer.GetText()) });
    general->AddItem({ "Subject", ls.Format("%s", pe->signatureData->information.counterSigner.subject.GetText()) });
    general->AddItem({ "Date", ls.Format("%s", pe->signatureData->information.counterSigner.date.GetText()) });
    general->AddItem({ "Serial Number", ls.Format("%s", pe->signatureData->information.counterSigner.serialNumber.GetText()) });
    general->AddItem({ "Signature Algorithm", ls.Format("%s", pe->signatureData->information.counterSigner.signatureAlgorithm.GetText()) });

    switch (pe->signatureData->information.counterSigner.timevalidity)
    {
    case GView::DigitalSignature::TimeValidity::AfterNotAfter:
        validSigner = "AfterNotAfter";
        break;
    case GView::DigitalSignature::TimeValidity::Valid:
        validSigner = "Valid";
        break;
    case GView::DigitalSignature::TimeValidity::BeforeNotBefore:
        validSigner = "BeforeNotBefore";
        break;
    default:
        validSigner = "Unknown";
        break;
    }
    general->AddItem({ "Time Validity", validSigner.c_str() })
          .SetColor(
                pe->signatureData->information.counterSigner.timevalidity == GView::DigitalSignature::TimeValidity::Valid ? COLOR_SUCCESS
                                                                                                                          : COLOR_FAILURE);

    general->AddItem({ "Formats", "" }).SetType(ListViewItem::Type::Category);
}

bool DigitalSignature::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(AppCUI::Input::Key::Ctrl | AppCUI::Input::Key::Enter, "Dummy", static_cast<int32_t>(Action::Dummy));

    return true;
}

bool DigitalSignature::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    switch (evnt)
    {
    case Event::ListViewItemPressed:
        return true;
    case Event::WindowClose:
        return Exit();
    case Event::Command:
        switch (static_cast<Action>(controlID))
        {
        case Action::Dummy:
            return Exit();
        default:
            break;
        }
    default:
        return false;
    }
}
} // namespace GView::Type::PE::Commands

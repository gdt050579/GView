#include "pe.hpp"

namespace GView::Type::PE::Commands
{
using namespace AppCUI::Controls;

enum class Action : int32
{
    Dummy = 1
};

constexpr auto COLOR_SUCCESS = ColorPair{ Color::Green, Color::Transparent };
constexpr auto COLOR_FAILURE = ColorPair{ Color::Red, Color::Transparent };

DigitalSignature::DigitalSignature(Reference<PEFile> pe)
    : Window("Digital Signature", "x:25%,y:5%,w:50%,h:90%", WindowFlags::Sizeable | WindowFlags::ProcessReturn), pe(pe)
{
    general = Factory::ListView::Create(
          this, "x:0,y:0,w:100%,h:100%", { "n:Key,w:30%", "n:Value,w:70%" }, ListViewFlags::AllowMultipleItemsSelection);

    Update();
}

void PopulateSignerInfo(
      Reference<AppCUI::Controls::ListView>& list,
      std::string_view name,
      const GView::DigitalSignature::SignatureData::Information::Certificate& certificate)
{
    LocalString<1024> ls;

    list->AddItem({ name.data(), "" }).SetType(ListViewItem::Type::Category);

    list->AddItem({ "Program Name", ls.Format("%s", certificate.programName.GetText()) });
    list->AddItem({ "Publish Link", ls.Format("%s", certificate.publishLink.GetText()) });
    list->AddItem({ "More Info Link", ls.Format("%s", certificate.moreInfoLink.GetText()) });
    list->AddItem({ "Email", ls.Format("%s", certificate.email.GetText()) });

    list->AddItem({ "Issuer", ls.Format("%s", certificate.issuer.GetText()) });
    list->AddItem({ "Subject", ls.Format("%s", certificate.subject.GetText()) });
    list->AddItem({ "Date", ls.Format("%s", certificate.date.GetText()) });
    list->AddItem({ "Serial Number", ls.Format("%s", certificate.serialNumber.GetText()) });
    list->AddItem({ "Digest Algorithm", ls.Format("%s", certificate.digestAlgorithm.GetText()) });
    list->AddItem({ "Not Before", ls.Format("%s", certificate.dateNotBefore.GetText()) });
    list->AddItem({ "Not After", ls.Format("%s", certificate.dateNotAfter.GetText()) });

    std::string validSigner;
    switch (certificate.timevalidity)
    {
    case GView::DigitalSignature::TimeValidity::Expired:
        validSigner = "Expired";
        break;
    case GView::DigitalSignature::TimeValidity::Valid:
        validSigner = "Valid";
        break;
    case GView::DigitalSignature::TimeValidity::Earlier:
        validSigner = "Earlier";
        break;
    default:
        validSigner = "Unknown";
        break;
    }
    list->AddItem({ "Time Validity", validSigner.c_str() })
          .SetColor(certificate.timevalidity == GView::DigitalSignature::TimeValidity::Valid ? COLOR_SUCCESS : COLOR_FAILURE);

    switch (certificate.type)
    {
    case GView::DigitalSignature::CounterSignatureType::None:
        break;
    case GView::DigitalSignature::CounterSignatureType::Authenticode:
        list->AddItem({ "Timestamp Type", "Authenticode" });
        break;
    case GView::DigitalSignature::CounterSignatureType::RFC3161:
        list->AddItem({ "Timestamp Type", "RFC3161" });
        break;
    default:
        break;
    }
}

void DigitalSignature::Update()
{
    general->DeleteAllItems();

    LocalString<1024> ls;

    general->AddItem({ "WinTrust", "" }).SetType(ListViewItem::Type::Category);
    general
          ->AddItem({ "Validation",
                      ls.Format("%s (0x%x)", pe->signatureData->winTrust.errorMessage.GetText(), pe->signatureData->winTrust.errorCode) })
          .SetColor(pe->signatureData->winTrust.errorCode == 0 ? COLOR_SUCCESS : COLOR_FAILURE);

    constexpr auto SIGNATURE_NOT_FOUND = 0x800B0100;
    CHECKRET(pe->signatureData->winTrust.errorCode != SIGNATURE_NOT_FOUND, "");

    general->AddItem({ "Certificate Information", "" }).SetType(ListViewItem::Type::Category);
    general
          ->AddItem(
                { "Validation",
                  ls.Format("%s (0x%x)", pe->signatureData->information.errorMessage.GetText(), pe->signatureData->information.errorCode) })
          .SetColor(pe->signatureData->winTrust.errorCode == 0 ? COLOR_SUCCESS : COLOR_FAILURE);

    PopulateSignerInfo(general, "Signature #0", pe->signatureData->information.signature0);
    PopulateSignerInfo(general, "Counter Signature #0", pe->signatureData->information.counterSignature0);
    PopulateSignerInfo(general, "Signature #1", pe->signatureData->information.signature1);
    PopulateSignerInfo(general, "Counter Signature #1", pe->signatureData->information.counterSignature1);
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

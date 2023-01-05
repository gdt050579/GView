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
      const GView::DigitalSignature::AuthenticodeMS::Data::Signature::Signer& certificate)
{
    LocalString<1024> ls;

    list->AddItem({ name.data(), "" }).SetType(ListViewItem::Type::Category);

    list->AddItem({ "Program Name", ls.Format("%s", certificate.programName.GetText()) });
    list->AddItem({ "Publish Link", ls.Format("%s", certificate.publishLink.GetText()) });
    list->AddItem({ "More Info Link", ls.Format("%s", certificate.moreInfoLink.GetText()) });
    // list->AddItem({ "Email", ls.Format("%s", certificate.email.GetText()) });

    // list->AddItem({ "Issuer", ls.Format("%s", certificate.issuer.GetText()) });
    // list->AddItem({ "Subject", ls.Format("%s", certificate.subject.GetText()) });
    // if (certificate.signatureType == GView::DigitalSignature::SignatureType::CounterSignature)
    // {
    //     list->AddItem({ "Date", ls.Format("%s", certificate.date.GetText()) });
    // }
    // list->AddItem({ "Serial Number", ls.Format("%s", certificate.serialNumber.GetText()) });
    // list->AddItem({ "Digest Algorithm", ls.Format("%s", certificate.digestAlgorithm.GetText()) });
    // list->AddItem({ "Not Before", ls.Format("%s", certificate.dateNotBefore.GetText()) });
    // list->AddItem({ "Not After", ls.Format("%s", certificate.dateNotAfter.GetText()) });
    // 
    // switch (certificate.signatureType)
    // {
    // case GView::DigitalSignature::SignatureType::Signature:
    //     list->AddItem({ "Signature Type", "Signature" });
    //     break;
    // case GView::DigitalSignature::SignatureType::CounterSignature:
    //     list->AddItem({ "Signature Type", "Counter Signature" });
    //     break;
    // case GView::DigitalSignature::SignatureType::Unknown:
    // default:
    //     list->AddItem({ "Signature Type", "Unknown" });
    //     break;
    // }
    // 
    // if (certificate.signatureType == GView::DigitalSignature::SignatureType::CounterSignature)
    // {
    //     switch (certificate.counterSignatureType)
    //     {
    //     case GView::DigitalSignature::CounterSignatureType::None:
    //         break;
    //     case GView::DigitalSignature::CounterSignatureType::Authenticode:
    //         list->AddItem({ "Timestamp Type", "Authenticode" });
    //         break;
    //     case GView::DigitalSignature::CounterSignatureType::RFC3161:
    //         list->AddItem({ "Timestamp Type", "RFC3161" });
    //         break;
    //     default:
    //         break;
    //     }
    // }
}

void DigitalSignature::Update()
{
    general->DeleteAllItems();

    LocalString<1024> ls;

#ifdef BUILD_FOR_WINDOWS
    general->AddItem({ "WinTrust", "" }).SetType(ListViewItem::Type::Category);
    general
          ->AddItem({ "Validation",
                      ls.Format("%s (0x%x)", pe->signatureData->winTrust.errorMessage.GetText(), pe->signatureData->winTrust.errorCode) })
          .SetColor(pe->signatureData->winTrust.errorCode == 0 ? COLOR_SUCCESS : COLOR_FAILURE);
#endif

    general->AddItem({ "OpenSSL", "" }).SetType(ListViewItem::Type::Category);
    general->AddItem({ "Validation", ls.Format("%s", pe->signatureData->openssl.errorMessage.GetText()) })
          .SetColor(pe->signatureData->openssl.errorMessage.Contains("error:00000000:lib(0)::reason(0)") ? COLOR_SUCCESS : COLOR_FAILURE);

    uint8 signatureIndex = -1;
    for (const auto& signature : pe->signatureData->data.signatures)
    {

        // if (signature.signatureType == GView::DigitalSignature::SignatureType::Signature)
        // {
        //     ls.Format("Signature #%d", ++signatureIndex);
        // }
        // else
        // {
        //     ls.Format("Counter Signature #%d", signatureIndex);
        // }
        // PopulateSignerInfo(general, ls.GetText(), signature);
    }
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

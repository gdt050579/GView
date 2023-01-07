#include "pe.hpp"

namespace GView::Type::PE::Commands
{
using namespace AppCUI::Controls;

enum class Action : int32
{
    MoreInfo = 1
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
      Reference<AppCUI::Controls::ListView>& list, const GView::DigitalSignature::AuthenticodeMS::Data::Signature::Signer& signer)
{
    LocalString<1024> ls;

    list->AddItem({ "(Signer) Program Name", ls.Format("%s", signer.programName.GetText()) });
    list->AddItem({ "(Signer) Publish Link", ls.Format("%s", signer.publishLink.GetText()) });
    list->AddItem({ "(Signer) More Info Link", ls.Format("%s", signer.moreInfoLink.GetText()) });
}

void PopulateCertificateInfo(
      Reference<AppCUI::Controls::ListView>& list,
      const GView::DigitalSignature::AuthenticodeMS::Data::Signature::Certificate& certificate,
      uint32 index)
{
    LocalString<1024> ls;
    LocalString<1024> ls2;

    list->AddItem({ "", ls2.Format("------------- Certificate (#%u) -----------", index) }).SetType(ListViewItem::Type::Emphasized_1);
    list->AddItem({ ls2.Format("Certificate (#%u) Issuer", index), ls.Format("%s", certificate.issuer.GetText()) });
    list->AddItem({ ls2.Format("Certificate (#%u) Subject", index), ls.Format("%s", certificate.subject.GetText()) });
    list->AddItem({ ls2.Format("Certificate (#%u) Email", index), ls.Format("%s", certificate.email.GetText()) });
    list->AddItem({ ls2.Format("Certificate (#%u) Date", index), ls.Format("%s", certificate.date.GetText()) });
    list->AddItem({ ls2.Format("Certificate (#%u) Serial Number", index), ls.Format("%s", certificate.serialNumber.GetText()) });
    list->AddItem({ ls2.Format("Certificate (#%u) Digest Algorithm", index), ls.Format("%s", certificate.digestAlgorithm.GetText()) });
    list->AddItem({ ls2.Format("Certificate (#%u) Not After", index), ls.Format("%s", certificate.notAfter.GetText()) });
    list->AddItem({ ls2.Format("Certificate (#%u) Not Before", index), ls.Format("%s", certificate.notBefore.GetText()) });

    list->AddItem({ ls2.Format("Certificate (#u) CRL Point", index), ls.Format("%s", certificate.crlPoint.GetText()) });
    list->AddItem({ "", ls2.Format("---------- End certificate (#%u) ---------", index) }).SetType(ListViewItem::Type::Emphasized_1);
}

void DigitalSignature::MoreInfo()
{
    if (humanReadable.IsValid() && humanReadable.IsCurrent())
    {
        GView::App::OpenBuffer(
              BufferView{ pe->signatureData->data.humanReadable.GetText(), pe->signatureData->data.humanReadable.Len() },
              "Digital Signature - PKCS#7 Human Readable",
              GView::App::OpenMethod::BestMatch);
    }

    if (PEMs.IsValid() && PEMs.IsCurrent())
    {
        std::string input;

        for (uint32 i = 0U; i < pe->signatureData->data.pemCerts.size(); i++)
        {
            const auto& pem = pe->signatureData->data.pemCerts.at(i);
            input += pem;
            input += "\n";
        }

        GView::App::OpenBuffer(
              BufferView{ input.c_str(), input.size() }, "Digital Signature - PEM Certificates", GView::App::OpenMethod::BestMatch);
    }
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
    general
          ->AddItem({ "Validation",
                      (pe->signatureData->openssl.verified ? "OK" : ls.Format("%s", pe->signatureData->openssl.errorMessage.GetText())) })
          .SetColor(pe->signatureData->openssl.verified ? COLOR_SUCCESS : COLOR_FAILURE);

    if (pe->signatureData.has_value() && pe->signatureData->data.signatures.empty() == false)
    {
        general->AddItem({ "More Info", "" }).SetType(ListViewItem::Type::Category);
        humanReadable = general->AddItem(
              { "Human Readable", "Signature parsed - press CTRL + ENTER for details!", pe->signatureData->data.humanReadable.GetText() });
        PEMs = general->AddItem(
              { "PEMs", ls.Format("(%d) PEMs parsed - press CTRL + ENTER for details!", pe->signatureData->data.pemCerts.size()) });
    }

    uint16 signatureIndex                       = 0;
    GView::DigitalSignature::SignatureType type = GView::DigitalSignature::SignatureType::Unknown;
    for (const auto& signature : pe->signatureData->data.signatures)
    {
        if (signature.signatureType == GView::DigitalSignature::SignatureType::Signature)
        {
            ls.Format("Signature #%u", signatureIndex);
        }
        else
        {
            ls.Format("Counter Signature #%u", signatureIndex);
        }

        general->AddItem({ ls.GetText(), "" }).SetType(ListViewItem::Type::Category);

        signatureIndex += (type == GView::DigitalSignature::SignatureType::Signature);
        type = signature.signatureType;

        switch (signature.signatureType)
        {
        case GView::DigitalSignature::SignatureType::Signature:
            general->AddItem({ "Signature Type", "Signature" });
            break;
        case GView::DigitalSignature::SignatureType::CounterSignature:
            general->AddItem({ "Signature Type", "Counter Signature" });
            break;
        case GView::DigitalSignature::SignatureType::Unknown:
        default:
            general->AddItem({ "Signature Type", "Unknown" });
            break;
        }

        if (signature.signatureType == GView::DigitalSignature::SignatureType::CounterSignature)
        {
            switch (signature.counterSignatureType)
            {
            case GView::DigitalSignature::CounterSignatureType::Unknown:
                break;
            case GView::DigitalSignature::CounterSignatureType::Authenticode:
                general->AddItem({ "Timestamp Type", "Authenticode" });
                break;
            case GView::DigitalSignature::CounterSignatureType::RFC3161:
                general->AddItem({ "Timestamp Type", "RFC3161" });
                break;
            default:
                break;
            }

            general->AddItem({ "Signing time", ls.Format("%s", signature.signingTime.GetText()) })
                  .SetType(ListViewItem::Type::Emphasized_3);
        }

        PopulateSignerInfo(general, signature.signer);

        auto j = 0;
        for (const auto& certificate : signature.certificates)
        {
            PopulateCertificateInfo(general, certificate, j++);
        }
    }
}

bool DigitalSignature::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(AppCUI::Input::Key::Ctrl | AppCUI::Input::Key::Enter, "More Info", static_cast<int32_t>(Action::MoreInfo));

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
        case Action::MoreInfo:
            MoreInfo();
            return Exit();
        default:
            break;
        }
    default:
        return false;
    }
}
} // namespace GView::Type::PE::Commands

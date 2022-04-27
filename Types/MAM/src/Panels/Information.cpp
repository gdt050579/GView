#include "MAM.hpp"

using namespace GView::Type::MAM;
using namespace GView::Type::MAM::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::Controls;

constexpr auto CMD_ID_DECOMPRESS = 1U;

Information::Information(Reference<Object> _object, Reference<GView::Type::MAM::MAMFile> _mam) : TabPage("Informa&tion")
{
    mam     = _mam;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } },
          ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });

    const auto fileSize    = nf.ToString(mam->obj->GetData().GetSize(), dec);
    const auto hexfileSize = nf2.ToString(mam->obj->GetData().GetSize(), hex);
    general->AddItem({ "Size", ls.Format("%-14s (%s)", fileSize.data(), hexfileSize.data()) });

    general->AddItem("Content").SetType(ListViewItem::Type::Category);

    const auto signature    = nf.ToString(mam->signature, dec);
    const auto hexSignature = nf2.ToString(mam->signature, hex);
    general->AddItem({ "Signature", ls.Format("%-14s (%s)", signature.data(), hexSignature.data()) });

    const auto uncompressedSize    = nf.ToString(mam->uncompressedSize, dec);
    const auto hexUncompressedSize = nf2.ToString(mam->uncompressedSize, hex);
    general->AddItem({ "Uncompressed Size", ls.Format("%-14s (%s)", uncompressedSize.data(), hexUncompressedSize.data()) });

    const auto compressedSize    = nf.ToString(mam->compressedSize, dec);
    const auto hexCompressedSize = nf2.ToString(mam->compressedSize, hex);
    general->AddItem({ "Compressed Size", ls.Format("%-14s (%s)", compressedSize.data(), hexCompressedSize.data()) });
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), general->GetItemsCount() + 3);

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

bool Information::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "Decompress", CMD_ID_DECOMPRESS);
    return true;
}

bool Information::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        case CMD_ID_DECOMPRESS:
        {
            Buffer uncompressed;
            uncompressed.Resize(mam->uncompressedSize);

            const auto chunk = mam->obj->GetData().GetCacheSize();
            auto pos         = 8ULL;
            const auto size  = mam->obj->GetData().GetSize() - 8;

            Buffer compressed;
            compressed.Resize(size);

            while (pos < mam->obj->GetData().GetSize())
            {
                auto toRead    = std::min<>((uint64) chunk, mam->obj->GetData().GetSize() - pos);
                const Buffer b = mam->obj->GetData().CopyToBuffer(pos, chunk, false);
                memcpy(compressed.GetData() + pos - 8ULL, b.GetData(), toRead);
                pos += toRead;
            }

            CHECK(GView::Compression::LZXPRESS::Huffman::Decompress(compressed, uncompressed), false, "");

            GView::App::OpenBuffer(uncompressed, mam->obj->GetName());

            return true;
        }
        }
    }

    return false;
}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

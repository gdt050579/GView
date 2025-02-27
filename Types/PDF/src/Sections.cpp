#include "pdf.hpp"

using namespace GView::Type::PDF;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr int PDF_SECTIONS_GOTO   = 1;
constexpr int PDF_SECTIONS_SELECT = 2;
constexpr int PDF_TEXTVIEWER      = 3;
constexpr int PDF_SAVEASTXT       = 4;

Panels::Sections::Sections(Reference<GView::Type::PDF::PDFFile> _pdf, Reference<GView::View::WindowInterface> _win) : TabPage("&Sections")
{
    pdf  = _pdf;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(this, "d:c", { "n:Name,w:16", "n:ObjectPos,a:r,w:12", "n:Size,a:r,w:12" }, ListViewFlags::AllowMultipleItemsSelection);
    Update();
}

void Panels::Sections::GoToSelectedSection()
{
    auto sect = list->GetCurrentItem().GetData<PDF::PDFObject>();
    if (sect.IsValid()) {
        win->GetCurrentView()->GoTo(sect->startBuffer);
    }
}

void Panels::Sections::SelectCurrentSection()
{
    auto sect = list->GetCurrentItem().GetData<PDF::PDFObject>();
    if (sect.IsValid()) {
        win->GetCurrentView()->Select(sect->startBuffer, (sect->endBuffer - sect->startBuffer));
    }
}

void Panels::Sections::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    for (auto& object : pdf->pdfObjects) {
        temp.Clear();
        switch (object.type) {
        case PDF::SectionPDFObjectType::Object:
            temp.Add("Object ");
            temp.Add(std::to_string(object.number));
            break;
        case PDF::SectionPDFObjectType::CrossRefTable:
            temp.Add("Cross-ref Table");
            break;
        case PDF::SectionPDFObjectType::CrossRefStream:
            temp.Add("Cross-ref Stream");
            break;
        case PDF::SectionPDFObjectType::Trailer:
            temp.Add("Trailer");
            break;
        }
        auto item = list->AddItem(temp);

        item.SetData<PDF::PDFObject>(&object);

        item.SetText(1, GetValue(n, object.startBuffer));
        item.SetText(2, GetValue(n, object.endBuffer - object.startBuffer));
    }
}

std::string_view Panels::Sections::GetValue(NumericFormatter& n, uint32 value)
{
    if (Base == 10)
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    else
        return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

bool Panels::Sections::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PDF_SECTIONS_GOTO);
    commandBar.SetCommand(Key::F9, "Select", PDF_SECTIONS_SELECT);
    commandBar.SetCommand(Key::F10, "Text Viewer", PDF_TEXTVIEWER);
    commandBar.SetCommand(Key::F11, "Save as .txt file", PDF_SAVEASTXT);
    return true;
}

bool Panels::Sections::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ListViewItemPressed) {
        GoToSelectedSection();
        return true;
    }
    if (evnt == Event::Command) {
        switch (controlID) {
        case PDF_SECTIONS_GOTO:
            GoToSelectedSection();
            return true;
        case PDF_SECTIONS_SELECT:
            SelectCurrentSection();
            return true;
        case PDF_TEXTVIEWER:
            pdf->ExtractAndOpenText(pdf);
            return true;
        case PDF_SAVEASTXT:
            pdf->ExtractAndSaveText(pdf);
        }
    }
    return false;
}
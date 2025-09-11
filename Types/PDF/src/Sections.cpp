#include "pdf.hpp"

using namespace GView::Type::PDF;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr int PDF_OBJECTS_GOTO   = 1;
constexpr int PDF_OBJECTS_SELECT  = 2;
constexpr int PDF_TEXTVIEWER      = 3;
constexpr int PDF_SAVEASTXT       = 4;

Panels::Sections::Sections(Reference<GView::Type::PDF::PDFFile> _pdf, Reference<GView::View::WindowInterface> _win) : TabPage("&Objects")
{
    pdf  = _pdf;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(this, "d:c", { 
                "n:Name,w:16", 
                "n:ObjectPos,a:r,w:12", 
                "n:Size,a:r,w:12",
                "n:Has Stream,a:r,w:12",
                "n:Filters,a:r,w:30",
                "n:Dictionary Types,a:r,w:25",
                "n:Dictionary Subtypes,a:r,w:25",
                "n:&Has JS?,a:r,w:10"
        }, ListViewFlags::AllowMultipleItemsSelection);
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

        // Object type
        item.SetData<PDF::PDFObject>(&object);
        // Start buffer
        item.SetText(1, GetValue(n, object.startBuffer));
        // Size
        item.SetText(2, GetValue(n, object.endBuffer - object.startBuffer));
        // Has Stream
        if (object.hasStream) {
            item.SetText(3, "Yes");
        } else {
            item.SetText(3, "No");
        }
        // Filters
        LocalUnicodeStringBuilder<512> ub;
        bool first = true;
        for (const auto& filter : object.filters) {
            if (!first) {
                ub.Add(u", ");
            }
            ub.Add(filter);
            first = false;
        }
        item.SetText(4, ub);
        // Types
        ub.Clear();
        first = true;
        for (const auto& type : object.dictionaryTypes) {
            if (!first) {
                ub.Add(u", ");
            }
            ub.Add(type);
            first = false;
        }
        item.SetText(5, ub);
        // Subtypes
        ub.Clear();
        first = true;
        for (const auto& subtypes : object.dictionarySubtypes) {
            if (!first) {
                ub.Add(u", ");
            }
            ub.Add(subtypes);
            first = false;
        }
        item.SetText(6, ub);
        if (object.hasJS == false) {
            item.SetText(7, "No");
        } else {
            item.SetText(7, "Yes");
        }
    }
}

std::string_view Panels::Sections::GetValue(NumericFormatter& n, uint32 value)
{
    if (Base == 10) {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    } else {
        return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
    }
}

bool Panels::Sections::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PDF_OBJECTS_GOTO);
    commandBar.SetCommand(Key::F9, "Select", PDF_OBJECTS_SELECT);
    commandBar.SetCommand(Key::F10, "Text Viewer", PDF_TEXTVIEWER);
    commandBar.SetCommand(Key::F11, "Save as .txt file", PDF_SAVEASTXT);
    return true;
}

bool Panels::Sections::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID)) {
        return true;
    }
    if (evnt == Event::ListViewItemPressed) {
        GoToSelectedSection();
        return true;
    }
    if (evnt == Event::Command) {
        switch (controlID) {
        case PDF_OBJECTS_GOTO:
            GoToSelectedSection();
            return true;
        case PDF_OBJECTS_SELECT:
            SelectCurrentSection();
            return true;
        case PDF_TEXTVIEWER:
            pdf->ExtractAndOpenText(pdf);
            return true;
        case PDF_SAVEASTXT:
            pdf->ExtractAndSaveTextWithDialog(pdf);
        }
    }
    return false;
}
#include "pdf.hpp"
#include <podofo/podofo.h>
#include <codecvt>
#include <cmath>

using namespace GView::Type::PDF;
using namespace AppCUI::Controls;
using namespace PoDoFo;

static bool Approximately(const double value, const double standard, const double tolerance = 2.0)
{
    return (fabs(value - standard) <= tolerance);
}

static std::string GuessPageFormat(const double widthMm, const double heightMm)
{
    static const struct {
        const char* name;
        double w;
        double h;
    } Formats[] = {
        { "A6", 105.0, 148.0 },
        { "A5", 148.0, 210.0 },
        { "A4", 210.0, 297.0 },
        { "A3", 297.0, 420.0 },
        { "A2", 420.0, 594.0 },
        { "A1", 594.0, 841.0 },
        { "A0", 841.0, 1189.0 },
        { "Letter", 215.9, 279.4 }, // 8.5 x 11 inches
        { "Legal", 215.9, 355.6 },  // 8.5 x 14 inches
        { "Tabloid", 279.4, 431.8 } // 11 x 17 inches
    };

    for (const auto& fmt : Formats) {
        const bool direct  = Approximately(widthMm, fmt.w) && Approximately(heightMm, fmt.h);
        const bool swapped = Approximately(widthMm, fmt.h) && Approximately(heightMm, fmt.w);
        if (direct || swapped) {
            return fmt.name;
        }
    }
    return "Unknown";
}

static std::pair<std::string, std::string> GetPageFormatAndOrientation(PoDoFo::PdfMemDocument& doc, GView::Utils::ErrorList &errList)
{
    try {
        PoDoFo::PdfIndirectObjectList& objects = doc.GetObjects();
        for (auto* obj : objects) {
            if (!obj || !obj->IsDictionary()) {
                continue;
            }
            // Check if this object has Type = Page
            PoDoFo::PdfDictionary& dict = obj->GetDictionary();
            const PoDoFo::PdfObject* typeItem = dict.GetKey(PoDoFo::PdfName("Type"));
            if (!typeItem || !typeItem->IsName()) {
                continue;
            }
            if (typeItem->GetName() == PoDoFo::PdfName("Page")) {
                PoDoFo::PdfObject* mediaBoxObj = dict.GetKey(PoDoFo::PdfName("MediaBox"));
                if (!mediaBoxObj || !mediaBoxObj->IsArray()) {
                    Dialogs::MessageBox::ShowError("Error!", "Page has no /MediaBox array.");
                    errList.AddError("Page has no /MediaBox array");
                    return { "Unknown", "Unknown" };
                }

                const PoDoFo::PdfArray& mediaBoxArr = mediaBoxObj->GetArray();
                if (mediaBoxArr.size() < 4) {
                    Dialogs::MessageBox::ShowError("Error!", "MediaBox array has fewer than 4 numbers.");
                    errList.AddError("MediaBox array has fewer than 4 numbers");
                    return { "Unknown", "Unknown" };
                }

                // [ left, bottom, right, top ] in PDF points
                const double left   = mediaBoxArr[0].GetReal();
                const double bottom = mediaBoxArr[1].GetReal();
                const double right  = mediaBoxArr[2].GetReal();
                const double top    = mediaBoxArr[3].GetReal();

                const double widthPoints  = right - left;
                const double heightPoints = top - bottom;
                if (widthPoints <= 0.0 || heightPoints <= 0.0) {
                    Dialogs::MessageBox::ShowError("Error!", "Invalid MediaBox coordinates.");
                    errList.AddError("Invalid MediaBox coordinates");
                    return { "Unknown", "Unknown" };
                }

                // Convert from points -> millimeters
                const double widthMm  = widthPoints * 25.4 / 72.0;
                const double heightMm = heightPoints * 25.4 / 72.0;

                // Determine orientation
                const bool isLandscape = (widthPoints > heightPoints);
                const std::string format      = GuessPageFormat(widthMm, heightMm);
                const std::string orientation = isLandscape ? "Landscape" : "Portrait";
                return { format, orientation };
            }
        }
        Dialogs::MessageBox::ShowError("Error!", "No /Page object found in PDF.");
        errList.AddError("No /Page object found in PDF");
        return { "Unknown", "Unknown" };
    } catch (const std::exception& e) {
        Dialogs::MessageBox::ShowError("Error!", "Failed to process the file while loading the buffer.");
        errList.AddError("Failed to process the file while loading the buffer");
        return { "Unknown", "Unknown" };
    }
}


static int GetPDFPageCount(const PoDoFo::PdfMemDocument& doc)
{
    try {
        return static_cast<int>(doc.GetPages().GetCount());
    } catch (const PoDoFo::PdfError& e) {
        return 0;
    }
}

static bool LoadPDFDocumentFromBuffer(Reference<GView::Type::PDF::PDFFile> pdf, PoDoFo::PdfMemDocument& doc)
{
    auto& dataCache       = pdf->obj->GetData();
    const auto fileBuffer = dataCache.GetEntireFile();
    PoDoFo::bufferview buffer(reinterpret_cast<const char*>(fileBuffer.GetData()), fileBuffer.GetLength());

    try {
        doc.LoadFromBuffer(buffer);
        return true;
    } catch (const PoDoFo::PdfError& e) {
        std::string errorMessage = "Failed to process the file: ";
        errorMessage += e.what();
        Dialogs::MessageBox::ShowError("Error!", errorMessage);
        return false;
    }
}

Panels::Information::Information(Reference<GView::Type::PDF::PDFFile> _pdf) : TabPage("&Information")
{
    pdf     = _pdf;
    general = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:100%", { "n:Field,w:15", "n:Value,w:100" }, ListViewFlags::None);
    this->Update();
}

void Panels::Information::UpdateGeneralInformation()
{
    PoDoFo::PdfMemDocument doc;
    const bool validFile = LoadPDFDocumentFromBuffer(pdf, doc);

    // Filename
    general->DeleteAllItems();
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    std::string fileName = convert.to_bytes(pdf->obj->GetPath().data(), pdf->obj->GetPath().data() + pdf->obj->GetPath().size());
    general->AddItem({ "File", fileName });

    // File size
    LocalString<256> tempStr;
    NumericFormatter n;
    auto fileSize = pdf->obj->GetData().GetSize();
    tempStr.Format("%s bytes", n.ToString(fileSize, { NumericFormatFlags::None, 10, 3, ',' }).data());
    general->AddItem({ "Size", tempStr });

    // Version of the file
    tempStr.Format("%u.%u", pdf->header.version - '0', pdf->header.subVersion - '0');
    general->AddItem({ "Version", tempStr });

    // Number of pages in the file
    if (validFile) {
        int pageCount = GetPDFPageCount(doc);
        general->AddItem({ "Pages", std::to_string(pageCount) });
    } else {
        general->AddItem({ "Pages", "Unknown" });
    }

    // Format and Orientation of the file
    if (validFile) {
        auto [format, orientation] = GetPageFormatAndOrientation(doc, pdf->errList);
        general->AddItem({ "Format", format });
        general->AddItem({ "Orientation", orientation });
    } else {
        general->AddItem({ "Format", "Unknown" });
        general->AddItem({ "Orientation", "Unknown" });
    }
    // Metadata part
    // Title
    if (pdf->pdfMetadata.title.empty()) {
        general->AddItem({ "Title", "Unknown" });
    } else {
        general->AddItem({ "Title", pdf->pdfMetadata.title });
    }
    // Author
    if (pdf->pdfMetadata.author.empty()) {
        general->AddItem({ "Author", "Unknown" });
    } else {
        general->AddItem({ "Author", pdf->pdfMetadata.author });
    }
    // Creator
    if (pdf->pdfMetadata.creator.empty()) {
        general->AddItem({ "Creator", "Unknown" });
    } else {
        general->AddItem({ "Creator", pdf->pdfMetadata.creator });
    }
    // Producer
    if (pdf->pdfMetadata.producer.empty()) {
        general->AddItem({ "Producer", "Unknown" });
    } else {
        general->AddItem({ "Producer", pdf->pdfMetadata.producer });
    }
    // Creation Date
    if (pdf->pdfMetadata.creationDate.empty()) {
        general->AddItem({ "Creation Date", "Unknown" });
    } else {
        general->AddItem({ "Creation Date", pdf->pdfMetadata.creationDate });
    }
    // Modify Date
    if (pdf->pdfMetadata.modifyDate.empty()) {
        general->AddItem({ "Modify Date", "Unknown" });
    } else {
        general->AddItem({ "Modify Date", pdf->pdfMetadata.modifyDate });
    }
}

void Panels::Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();

    if ((!general.IsValid()) || (!issues.IsValid()))
        return;

    issues->SetVisible(false);
    this->general->Resize(w, h);
}

void Panels::Information::Update()
{
    UpdateGeneralInformation();
    RecomputePanelsPositions();
}

#include "doc.hpp"

using namespace GView::Type::DOC;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::DOC::DOCFile> _doc) : TabPage("&Information")
{
    doc     = _doc;
    general = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:5", { "n:Field,w:16", "n:Value,w:100" }, ListViewFlags::None);
    compoundFileInfo = Factory::ListView::Create(this, "x:0,y:5,w:100%,h:10", { "n:Field,w:16", "n:Value,w:10000" }, ListViewFlags::None);
    vbaStreamsInfo = Factory::ListView::Create(this, "x:0,y:15,w:100%,h:20", { "n:Field,w:16", "n:Value,w:10000" }, ListViewFlags::None);

    this->Update();
}
void Panels::Information::UpdateGeneralInformation()
{
    general->DeleteAllItems();

    general->AddItem("File");
    // size
    {
        LocalString<256> tempStr;
        auto sizeString = NumericFormatter().ToString(doc->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data();
        auto value      = tempStr.Format("%s bytes", sizeString);
        general->AddItem({ "Size", value });
    }

    NumericFormatter nf;

    compoundFileInfo->AddItem("Compound file");
    vbaStreamsInfo->AddItem({ "Project name", doc->projectName });
    compoundFileInfo->AddItem({ "Minor version", nf.ToString(doc->cfMinorVersion, hex) });
    compoundFileInfo->AddItem({ "Major version", nf.ToString(doc->cfMajorVersion, hex) });
    compoundFileInfo->AddItem({ "Transaction signature number", nf.ToString(doc->transactionSignatureNumber, dec) });
    compoundFileInfo->AddItem({ "FAT sectors count", nf.ToString(doc->numberOfFatSectors, dec) });
    compoundFileInfo->AddItem({ "MiniFAT sectors count", nf.ToString(doc->numberOfMiniFatSectors, dec) });
    compoundFileInfo->AddItem({ "DIFAT sectors count", nf.ToString(doc->numberOfDifatSectors, dec) });
    compoundFileInfo->AddItem({ "First directory sector", nf.ToString(doc->firstDirectorySectorLocation, hex) });
    compoundFileInfo->AddItem({ "First MiniFAT sector", nf.ToString(doc->firstMiniFatSectorLocation, hex) });
    compoundFileInfo->AddItem({ "First DIFAT sector", nf.ToString(doc->firstDifatSectorLocation, hex) });

    vbaStreamsInfo->AddItem("VBA streams");
    vbaStreamsInfo->AddItem({ "Major version", nf.ToString(doc->dirMajorVersion, hex) });
    vbaStreamsInfo->AddItem({ "Minor version", nf.ToString(doc->dirMinorVersion, hex) });
    vbaStreamsInfo->AddItem({ "Modules path", doc->modulesPath });

    switch (doc->sysKind) {
    case Win16Bit:
        vbaStreamsInfo->AddItem({ "System kind", "Win16Bit" });
        break;
    case Win32Bit:
        vbaStreamsInfo->AddItem({ "System kind", "Win32Bit" });
        break;
    case Macintosh:
        vbaStreamsInfo->AddItem({ "System kind", "Macintosh" });
        break;
    case Win64Bit:
        vbaStreamsInfo->AddItem({ "System kind", "Win64Bit" });
        break;
    default:
        vbaStreamsInfo->AddItem({ "System kind", "Unknown" });
        break;
    }
    
    vbaStreamsInfo->AddItem({ "Doc string", doc->docString });
    vbaStreamsInfo->AddItem({ "Help file", doc->helpFile });
    vbaStreamsInfo->AddItem({ "Constants", doc->constants });
    vbaStreamsInfo->AddItem({ "Modules count", nf.ToString(doc->modulesCount, dec) });

    LocalString<256> header;
    uint32 index;

    index = 0;
    for (const auto& record : doc->referenceControlRecords) {
        vbaStreamsInfo->AddItem("");
        header.Format("Reference control record #%s", nf.ToString(index++, dec).data());
        vbaStreamsInfo->AddItem(header);

        vbaStreamsInfo->AddItem({ "Libid twiddled", record.libidTwiddled });
        vbaStreamsInfo->AddItem({ "Name record extended", record.nameRecordExtended });
        vbaStreamsInfo->AddItem({ "Libid extended", record.libidExtended });
        vbaStreamsInfo->AddItem({ "Cookie", nf.ToString(record.cookie, hex) });
    }

    index = 0;
    for (const auto& record : doc->referenceOriginalRecords) {
        vbaStreamsInfo->AddItem("");
        header.Format("Reference original record #%s", nf.ToString(index++, dec).data());
        vbaStreamsInfo->AddItem(header);

        vbaStreamsInfo->AddItem({ "Libid original", record.libidOriginal });
        vbaStreamsInfo->AddItem({ "Libid twiddled", record.referenceControl.libidTwiddled });
        vbaStreamsInfo->AddItem({ "Name record extended", record.referenceControl.nameRecordExtended });
        vbaStreamsInfo->AddItem({ "Libid extended", record.referenceControl.libidExtended });
        vbaStreamsInfo->AddItem({ "Cookie", nf.ToString(record.referenceControl.cookie, hex) });
    }

    index = 0;
    for (const auto& record : doc->referenceRegisteredRecords) {
        vbaStreamsInfo->AddItem("");
        header.Format("Reference registered record #%s", nf.ToString(index++, dec).data());
        vbaStreamsInfo->AddItem(header);

        vbaStreamsInfo->AddItem({ "Libid", record.libid });
    }

    index = 0;
    for (const auto& record : doc->referenceProjectRecords) {
        vbaStreamsInfo->AddItem("");
        header.Format("Reference absolute record #%s", nf.ToString(index++, dec).data());
        vbaStreamsInfo->AddItem(header);

        vbaStreamsInfo->AddItem({ "Libid absolute", record.libidAbsolute });
        vbaStreamsInfo->AddItem({ "Libid relative", record.libidRelative });
        vbaStreamsInfo->AddItem({ "Major version", nf.ToString(record.majorVersion, hex) });
        vbaStreamsInfo->AddItem({ "Minor version", nf.ToString(record.minorVersion, hex) });
    }
}

void Panels::Information::UpdateIssues()
{
}
void Panels::Information::RecomputePanelsPositions()
{
    int w = this->GetWidth();
    int h = this->GetHeight();

    if (!general.IsValid())
        return;

    this->general->Resize(w, h);
}
void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

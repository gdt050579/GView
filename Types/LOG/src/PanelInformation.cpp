#include "log.hpp"

using namespace GView::Type::LOG;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::LOG::LogFile> _log) : TabPage("&Information")
{
    log     = _log;
    general = Factory::ListView::Create(this, "x:0,y:0,w:50%,h:10", { "n:Field,w:12", "n:Value,w:100" }, ListViewFlags::None);

    issues = Factory::ListView::Create(this, "x:0,y:21,w:50%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    this->Update();
}

void Panels::Information::UpdateGeneralInformation()
{
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    general->AddItem("File");

    // size of the file
    general->AddItem({ "Size", tempStr.Format("%s bytes", n.ToString(log->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()) });

    // number of log entries
    general->AddItem({ "Entries", n.ToString(log->entryCount, { NumericFormatFlags::None, 10, 3, ',' }) });

    // number of error entries
    general->AddItem({ "Errors", n.ToString(log->errorCount, { NumericFormatFlags::None, 10, 3, ',' }) });

    // number of warnings
    general->AddItem({ "Warnings", n.ToString(log->warningCount, { NumericFormatFlags::None, 10, 3, ',' }) });

    // number of informational entries
    general->AddItem({ "Infos", n.ToString(log->infoCount, { NumericFormatFlags::None, 10, 3, ',' }) });

    // first and last timestamps
    general->AddItem({ "First Timestamp", log->firstTimestamp.data() });
    general->AddItem({ "Last Timestamp", log->lastTimestamp.data() });

    // ip addresses
    general->AddItem("IP Addresses");
    for (const auto& ip : log->ipAddresses) {
        general->AddItem({ "", ip.c_str() });
    }
}


void Panels::Information::UpdateIssues()
{
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
    general->Resize(w, h);
}

void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

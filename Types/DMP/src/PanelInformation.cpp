#include "dmp.hpp"

using namespace GView::Type::DMP;
using namespace AppCUI::Controls;



Panels::Information::Information(Reference<GView::Type::DMP::DMPFile> _dmp) : TabPage("&Information")
{
    dmp = _dmp;

    general   = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:6", { "n:General,w:24", "n:Value,w:100" }, ListViewFlags::None);
    streams   = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:10", { "n:Stream Type,w:24", "n:RVA,w:15", "n:Size,w:15" }, ListViewFlags::None);
    system    = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:8", { "n:System Field,w:24", "n:Value,w:100" }, ListViewFlags::None);
    exception = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:6", { "n:Exception Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    this->Update();
}

void Panels::Information::UpdateIssues()
{

}

void Panels::Information::UpdateGeneralInformation()
{
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    general->AddItem({ "Modules found", tempStr.Format("%u", dmp->moduleList.NumberOfModules) });
    general->AddItem({ "Threads found", tempStr.Format("%u", dmp->threadList.NumberOfThreads) });
    general->AddItem({ "File Size", tempStr.Format("%s bytes", n.ToString(dmp->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()) });
    general->AddItem({ "Version", tempStr.Format("0x%08X", dmp->header.Version) });


    streams->DeleteAllItems();
    for (const auto& dir : dmp->directories) {
        streams->AddItem(
              { dmp->getStreamTypeName(dir.StreamType), tempStr.Format("0x%08X", dir.Location.Rva), tempStr.Format("0x%08X", dir.Location.DataSize) });
    }


    system->DeleteAllItems();
    const auto& si = dmp->systemInfo;
    system->AddItem({ "Architecture", dmp->getArchitecture() });
    system->AddItem({ "OS Build", tempStr.Format("%u", si.BuildNumber) });
    system->AddItem({ "Processors", tempStr.Format("%u", si.NumberOfProcessors) });


    exception->DeleteAllItems();
    const auto& es = dmp->exception;
    if (es.ThreadId > 0) { 
        exception->AddItem({ "Thread ID", tempStr.Format("%u", es.ThreadId) });
        exception->AddItem({ "Code", tempStr.Format("0x%08X", es.ExceptionRecord.ExceptionCode) });
        exception->AddItem({ "Address", tempStr.Format("0x%08X", es.ExceptionRecord.ExceptionAddress) });
    } else {
        exception->AddItem({ "Status", "No exception record found" });
    }
}
void Panels::Information::RecomputePanelsPositions()
{
    int w = this->GetWidth();
    int y = 0;

    if (general.IsValid()) {
        general->MoveTo(0, y);
        general->Resize(w, 6);
        y += 6;
    }

    if (streams.IsValid()) {
        streams->MoveTo(0, y);
        streams->Resize(w, 8); 
        y += 8;
    }

    if (system.IsValid()) {
        system->MoveTo(0, y);
        system->Resize(w, 8);
        y += 8;
    }

    if (exception.IsValid()) {
        exception->MoveTo(0, y);
        exception->Resize(w, 5);
        y += 5;
    }
}
void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

#include "log.hpp"

using namespace GView::Type::LOG;
using namespace AppCUI::Controls;

Panels::LogData::LogData(Reference<GView::Type::LOG::LogFile> _log) : TabPage("&LogData")
{
    log     = _log;
    general = Factory::ListView::Create(this, "x:0,y:0,w:50%,h:10", { "n:Field,w:12", "n:Value,w:100" }, ListViewFlags::None);

    issues = Factory::ListView::Create(this, "x:0,y:21,w:50%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    this->Update();
}


void Panels::LogData::UpdateGeneralInformation()
{
    LocalString<256> tempStr;
    constexpr uint32 truncSize = 100;

    // messages info
    general->AddItem("Log Categories");
    for (const auto& [category, summary] : log->logCategories) {
        // category name and count
        general->AddItem({ category.c_str(), tempStr.Format("%d entries", summary.count) });

        // recent X messages for the category
        for (const auto& msg : summary.recentMessages) {
            std::string truncatedMsg = msg.substr(0, truncSize);
            if (msg.length() > truncSize)
                truncatedMsg += "...";
            general->AddItem({ "  - Message", truncatedMsg.c_str() });
        }
    }
}

void Panels::LogData::UpdateIssues()
{
}

void Panels::LogData::RecomputePanelsPositions()
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

void Panels::LogData::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

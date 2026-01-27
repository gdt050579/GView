#include "msi.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

// 1 = Transparent/Background
// w = White/Foreground
constexpr std::string_view MSI_ICON = "1111111111111111"
                                      "1111111111111111"
                                      "wwwwwwwwwwwwwwww"
                                      "1111111111111111"
                                      "1111111111111111"
                                      "w1111w1wwwww1www"
                                      "ww11ww1w111111w1"
                                      "w1ww1w1www1111w1"
                                      "w1111w111www11w1"
                                      "w1111w11111w11w1"
                                      "w1111w1wwwww1www"
                                      "1111111111111111"
                                      "1111111111111111"
                                      "wwwwwwwwwwwwwwww"
                                      "1111111111111111"
                                      "1111111111111111";

extern "C" {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    // Basic Header Size Check
    if (buf.GetLength() < sizeof(MSI::OLEHeader))
        return false;

    // Signature Check
    auto h = buf.GetObject<MSI::OLEHeader>();
    if (h->signature != MSI::OLE_SIGNATURE)
        return false;

    // Strict Size Calculation
    uint32 sectorSize = 1 << h->sectorShift;
    if (sectorSize < 512 || sectorSize > 4096)
        return false;

    /*uint64 minFileSize = 512;
    minFileSize += (uint64) h->numFatSectors * sectorSize;
    minFileSize += (uint64) h->numDirSectors * sectorSize;
    minFileSize += (uint64) h->numMiniFatSectors * sectorSize;

    if (buf.GetLength() < minFileSize)
        return false;*/

    return true;
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new MSI::MSIFile();
}

void CreateBufferView(Reference<WindowInterface> win, Reference<MSI::MSIFile> msi)
{
    BufferViewer::Settings settings;
    msi->UpdateBufferViewZones(settings);
    win->CreateViewer(settings);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto msi = win->GetObject()->GetContentType<MSI::MSIFile>();

    if (!msi->Update()) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Failed to parse MSI file structure.");
        return false;
    }

    // Container View
    ContainerViewer::Settings settings;
    settings.SetIcon(MSI_ICON);

    // Updated Columns for MSI Files
    settings.SetColumns({ 
        "n:&Name,a:l,w:40", 
        "n:&Directory,a:l,w:20", 
        "n:&Component,a:l,w:20", 
        "n:&Size,a:r,w:10", 
        "n:&Version,a:l,w:15" 
    });

    settings.SetEnumerateCallback(msi.ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(msi.ToObjectRef<ContainerViewer::OpenItemInterface>());
    win->CreateViewer(settings);

    // Buffer View
    CreateBufferView(win, msi);

    // Panels
    win->AddPanel(Pointer<TabPage>(new MSI::Panels::Information(msi)), true);
    win->AddPanel(Pointer<TabPage>(new MSI::Panels::Tables(msi)), true);

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"]     = "magic:D0 CF 11 E0 A1 B1 1A E1";
    sect["Priority"]    = 1;
    sect["Description"] = "Windows Installer Database (*.msi)";
}
}

// Information Panel Implementation
namespace GView::Type::MSI::Panels
{
Information::Information(Reference<MSIFile> _msi) : TabPage("&Information")
{
    msi     = _msi;
    general = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:100%", { "n:Field,w:20", "n:Value,w:80" }, ListViewFlags::None);
    UpdateGeneralInformation();
}

void Information::UpdateGeneralInformation()
{
    general->DeleteAllItems();
    general->AddItem({ "Type", "MSI (Compound File)" });
    general->AddItem({ "Sector Size", std::to_string(msi->sectorSize) });
    general->AddItem({ "Mini Sector Size", std::to_string(msi->miniSectorSize) });

    if (msi->GetStringPool().size() > 1) {
        general->AddItem({ "Strings in Pool", std::to_string(msi->GetStringPool().size()) });
    }

    // Metadata
    // helper local pentru time_t -> string
    auto TimeToString = [](std::time_t t) -> std::string {
        if (t == 0)
            return "";

        std::tm tm{};
#if defined(_WIN32)
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%d.%m.%Y %H:%M:%S", &tm);
        return buf;
    };

    // --- SummaryInformation ---
    general->AddItem({ "Title", msi->msiMeta.title });
    general->AddItem({ "Subject", msi->msiMeta.subject });
    general->AddItem({ "Author", msi->msiMeta.author });
    general->AddItem({ "Keywords", msi->msiMeta.keywords });
    general->AddItem({ "Comments", msi->msiMeta.comments });

    general->AddItem({ "Template", msi->msiMeta.templateStr });
    general->AddItem({ "Last Saved By", msi->msiMeta.lastSavedBy });

    general->AddItem({ "UUID (Revision)", msi->msiMeta.revisionNumber });
    general->AddItem({ "Creating Application", msi->msiMeta.creatingApp });

    general->AddItem({ "Codepage", msi->msiMeta.codepage ? std::to_string(msi->msiMeta.codepage) : "" });

    // --- Timestamps ---
    general->AddItem({ "Created", TimeToString(msi->msiMeta.createTime) });
    general->AddItem({ "Last Saved", TimeToString(msi->msiMeta.lastSaveTime) });
    general->AddItem({ "Last Printed", TimeToString(msi->msiMeta.lastPrintedTime) });

    // --- Counters ---
    general->AddItem({ "Page Count", msi->msiMeta.pageCount ? std::to_string(msi->msiMeta.pageCount) : "" });
    general->AddItem({ "Word Count", msi->msiMeta.wordCount ? std::to_string(msi->msiMeta.wordCount) : "" });
    general->AddItem({ "Character Count", msi->msiMeta.characterCount ? std::to_string(msi->msiMeta.characterCount) : "" });

    // --- Security ---
    general->AddItem({ "Security",
                       msi->msiMeta.security == 0   ? "None"
                       : msi->msiMeta.security == 2 ? "Read-only recommended"
                                                    : std::to_string(msi->msiMeta.security) });

    // --- Stream info ---
    general->AddItem({ "SummaryInformation Size", std::to_string(msi->msiMeta.totalSize) + " bytes" });
}

void Information::RecomputePanelsPositions()
{
    if (general.IsValid())
        general->Resize(GetWidth(), GetHeight());
}

// Tables Panel Implementation 
Tables::Tables(Reference<MSIFile> _msi) : TabPage("&Tables")
{
    msi  = _msi;
    list = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:100%", { "n:Table Name,w:30", "n:Type,w:15", "n:Rows (Approx),w:15,a:r" }, ListViewFlags::None);
    Update();
}

void Tables::Update()
{
    list->DeleteAllItems();
    const auto& dbTables = msi->GetTableList();

    for (const auto& tbl : dbTables) {
        LocalString<32> rowStr;
        if (tbl.rowCount == 0)
            rowStr.Set("Unknown");
        else
            rowStr.Format("%u", tbl.rowCount);

        list->AddItem({ tbl.name, tbl.type, rowStr });
    }
}
} // namespace GView::Type::MSI::Panels
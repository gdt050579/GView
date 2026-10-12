// File > Stored files (web build): the files GView keeps in the storage of the browser (BrowserStorage.cpp). Lists
// them, opens the ones that were not copied back into memory at startup, downloads (export - gated by the course
// policy), deletes them, and forgets the saved Learning connection.

#include "Internal.hpp"

#include <cstdio>
#include <ctime>

using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;

namespace GView::App::Browser
{
namespace
{
    constexpr int BTN_OPEN       = 1;
    constexpr int BTN_DOWNLOAD   = 2;
    constexpr int BTN_DELETE     = 3;
    constexpr int BTN_DELETE_ALL = 4;
    constexpr int BTN_FORGET     = 5;
    constexpr int BTN_CLOSE      = 6;

    std::string FormatSize(uint64 size)
    {
        char buf[32];
        if (size >= 1024ull * 1024 * 1024)
            snprintf(buf, sizeof(buf), "%.1f GiB", static_cast<double>(size) / (1024.0 * 1024.0 * 1024.0));
        else if (size >= 1024 * 1024)
            snprintf(buf, sizeof(buf), "%.1f MiB", static_cast<double>(size) / (1024.0 * 1024.0));
        else if (size >= 1024)
            snprintf(buf, sizeof(buf), "%.1f KiB", static_cast<double>(size) / 1024.0);
        else
            snprintf(buf, sizeof(buf), "%u B", static_cast<uint32>(size));
        return buf;
    }

    std::string FormatTime(int64 ms)
    {
        const std::time_t t = static_cast<std::time_t>(ms / 1000);
        std::tm tmv{};
        if (ms <= 0 || gmtime_r(&t, &tmv) == nullptr)
            return "-";
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tmv);
        return buf;
    }

    class StoredFilesWindow : public Window
    {
        Reference<Label> status;
        Reference<ListView> list;
        Reference<Button> forget;
        std::vector<StoredFile> files;

        void Refresh()
        {
            status->SetText(StorageStatus());
            files = StoredFiles();
            list->DeleteAllItems();
            for (uint32 i = 0; i < files.size(); i++)
            {
                const auto& f = files[i];
                auto item     = list->AddItem({ f.path, FormatSize(f.size), FormatTime(f.storedAtMs), f.materialized ? "yes" : "no" });
                item.SetData(i);
            }
            forget->SetEnabled(Secrets::Get(Secrets::LEARNING_CONNECTION).has_value());
        }

        const StoredFile* Current()
        {
            auto item = list->GetCurrentItem();
            if (!item.IsValid())
                return nullptr;
            const auto index = item.GetData(UINT64_MAX);
            return index < files.size() ? &files[static_cast<size_t>(index)] : nullptr;
        }

      public:
        std::filesystem::path toOpen;

        StoredFilesWindow() : Window("Stored files", "d:c,w:96%,h:90%", WindowFlags::Sizeable)
        {
            status = Factory::Label::Create(this, "", "l:1,t:0,r:1,h:2");
            list   = Factory::ListView::Create(
                  this,
                  "l:1,t:2,r:1,b:3",
                  { "n:File (in the home folder),w:52%", "n:Size,a:r,w:12%", "n:Stored,w:24%", "n:In memory,w:12%" },
                  ListViewFlags::PopupSearchBar);
            Factory::Label::Create(
                  this,
                  "Everything under the home folder is kept in this browser. Clearing the site data removes it.",
                  "l:1,b:2,r:1,h:1");
            Factory::Button::Create(this, "&Open", "l:1,b:0,w:10", BTN_OPEN);
            Factory::Button::Create(this, "Do&wnload", "l:12,b:0,w:12", BTN_DOWNLOAD);
            Factory::Button::Create(this, "&Delete", "l:25,b:0,w:10", BTN_DELETE);
            Factory::Button::Create(this, "Delete &all", "l:36,b:0,w:14", BTN_DELETE_ALL);
            forget = Factory::Button::Create(this, "&Forget Learning connection", "l:51,b:0,w:30", BTN_FORGET);
            Factory::Button::Create(this, "&Close", "r:1,b:0,w:10", BTN_CLOSE);
            Refresh();
            list->SetFocus();
        }

        bool OnEvent(Reference<Control> control, Event eventType, int ID) override
        {
            if (Window::OnEvent(control, eventType, ID))
                return true;
            if (eventType == Event::ListViewItemPressed)
            {
                ID        = BTN_OPEN;
                eventType = Event::ButtonClicked;
            }
            if (eventType != Event::ButtonClicked)
                return false;
            switch (ID)
            {
            case BTN_OPEN:
                if (const auto* f = Current(); f != nullptr)
                {
                    std::filesystem::path path;
                    if (MaterializeStoredFile(f->path, path))
                    {
                        toOpen = std::move(path);
                        Exit(Dialogs::Result::Ok);
                    }
                    else
                        Dialogs::MessageBox::ShowError("Stored files", "The file could not be loaded from the storage of the browser.");
                }
                return true;
            case BTN_DOWNLOAD:
                if (const auto* f = Current(); f != nullptr)
                {
                    // a download hands the file to the machine of the user: an export for the course policy
                    if (GView::App::IsBlockedByPolicy(GView::Security::RestrictedMode::Feature::Export, "downloading a stored file"))
                        return true;
                    std::filesystem::path path;
                    if (!MaterializeStoredFile(f->path, path) || !AppCUI::OS::DownloadFile(path))
                        Dialogs::MessageBox::ShowError("Stored files", "The file could not be downloaded.");
                    Refresh();
                }
                return true;
            case BTN_DELETE:
                if (const auto* f = Current(); f != nullptr)
                {
                    LocalString<512> msg;
                    msg.Format("Delete '%s' from this browser? An open window keeps showing it.", f->path.c_str());
                    if (Dialogs::MessageBox::ShowOkCancel("Stored files", msg) == Dialogs::Result::Ok)
                    {
                        ForgetStoredFile(f->path);
                        Refresh();
                    }
                }
                return true;
            case BTN_DELETE_ALL:
                if (Dialogs::MessageBox::ShowOkCancel("Stored files", "Delete every file kept in this browser? Settings are kept.") ==
                    Dialogs::Result::Ok)
                {
                    ForgetAllStoredFiles();
                    Refresh();
                }
                return true;
            case BTN_FORGET:
                Secrets::Remove(Secrets::LEARNING_CONNECTION);
                Dialogs::MessageBox::ShowNotification("Stored files", "The Learning connection string was forgotten.");
                Refresh();
                return true;
            case BTN_CLOSE:
                Exit(Dialogs::Result::Cancel);
                return true;
            }
            return false;
        }
    };
} // namespace

void ShowStoredFilesWindow()
{
    StoredFilesWindow w;
    w.Show();
    if (!w.toOpen.empty())
        GView::App::OpenFile(w.toOpen, OpenMethod::FirstMatch, "", nullptr, "stored file");
}
} // namespace GView::App::Browser

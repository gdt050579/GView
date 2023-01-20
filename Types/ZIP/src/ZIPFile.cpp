#include "zip.hpp"

#include <queue>
#include <map>

namespace GView::Type::ZIP
{

ZIPFile::ZIPFile()
{
}

bool ZIPFile::Update()
{
    LocalUnicodeStringBuilder<1024> ub;
    ub.Set(obj->GetPath());
    std::u16string sv{ ub.GetString(), ub.Len() };

    isTopContainer = std::filesystem::exists(sv);
    if (isTopContainer) // top container (exists on disk)
    {
        CHECK(GView::ZIP::GetInfo(obj->GetPath(), this->info), false, "");
    }
    else // child container (does not exist on disk)
    {
        CHECK(GView::ZIP::GetInfo(obj->GetData(), this->info), false, "");
    }

    return true;
}

bool ZIPFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    const auto count = this->info.GetCount();
    CHECK(count > 0, false, "");

    currentItemIndex = 0;
    curentChildIndexes.clear();

    if (path.empty())
    {
        for (uint32 i = 0; i < count; i++)
        {
            GView::ZIP::Entry entry{ 0 };
            CHECK(this->info.GetEntry(i, entry), false, "");

            auto filename        = entry.GetFilename();
            const auto entryType = entry.GetType();

            const auto f = filename.find_first_of('/');

            if ((entryType == GView::ZIP::EntryType::Directory && f == filename.size() - 1) ||
                (entryType != GView::ZIP::EntryType::Directory && f == std::string::npos))
            {
                curentChildIndexes.push_back(i);
            }
        }

        return currentItemIndex != this->curentChildIndexes.size();
    }

    UnicodeStringBuilder usb;
    for (uint32 i = 0; i < count; i++)
    {
        GView::ZIP::Entry entry{ 0 };
        CHECK(this->info.GetEntry(i, entry), false, "");

        auto filename        = entry.GetFilename();
        const auto entryType = entry.GetType();

        if (entryType == GView::ZIP::EntryType::Directory)
        {
            if (filename[filename.size() - 1] == '/')
            {
                filename = { filename.data(), filename.size() - 1 };
            }

            CHECK(usb.Set(filename), false, "");

            const auto sv = usb.ToStringView();
            if (sv.size() != path.size() && sv.starts_with(path))
            {
                const auto tmpSV = std::u16string_view{ sv.data() + path.size(), sv.size() - path.size() };
                if (tmpSV.find_first_of('/') == tmpSV.find_last_of('/'))
                {
                    curentChildIndexes.push_back(i);
                }
            }
        }
    }

    if (curentChildIndexes.empty())
    {
        for (uint32 i = 0; i < count; i++)
        {
            GView::ZIP::Entry entry{ 0 };
            CHECK(this->info.GetEntry(i, entry), false, "");

            auto filename        = entry.GetFilename();
            const auto entryType = entry.GetType();

            if (entryType == GView::ZIP::EntryType::Directory)
            {
                if (filename[filename.size() - 1] == '/')
                {
                    filename = { filename.data(), filename.size() - 1 };
                }
            }

            CHECK(usb.Set(filename), false, "");

            const auto sv = usb.ToStringView();
            if (sv != path && usb.ToStringView().starts_with(path))
            {
                curentChildIndexes.push_back(i);
            }
        }
    }

    return currentItemIndex != this->curentChildIndexes.size();
}

bool ZIPFile::PopulateItem(TreeViewItem item)
{
    LocalString<128> tmp;
    NumericFormatter n;

    const static NumericFormat NUMERIC_FORMAT{ NumericFormatFlags::HexPrefix, 16 };

    const auto realIndex = curentChildIndexes.at(currentItemIndex);
    GView::ZIP::Entry entry{ 0 };
    CHECK(this->info.GetEntry(realIndex, entry), false, "");

    auto filename = entry.GetFilename();

    const auto entryType = entry.GetType();
    item.SetPriority(entryType == GView::ZIP::EntryType::Directory);
    item.SetExpandable(entryType == GView::ZIP::EntryType::Directory);

    if (entryType == GView::ZIP::EntryType::Directory)
    {
        if (filename[filename.size() - 1] == '/')
        {
            filename = { filename.data(), filename.size() - 1 };
        }
    }

    const auto f = filename.find_last_of('/');
    if (f != std::string::npos)
    {
        filename = { filename.data() + f + 1, filename.size() - f - 1 };
    }

    item.SetText(filename);
    item.SetText(1, tmp.Format("%s (%s)", entry.GetTypeName().data(), n.ToString((uint32) entryType, NUMERIC_FORMAT).data()));
    item.SetText(2, tmp.Format("%s (%s)", entry.GetFlagNames().c_str(), n.ToString(entry.GetFlags(), NUMERIC_FORMAT).data()));
    item.SetText(3, tmp.Format("%s", n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(4, tmp.Format("%s", n.ToString(entry.GetUncompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(
          5, tmp.Format("%s (%s)", entry.GetCompressionMethodName().data(), n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(6, tmp.Format("%s", n.ToString(entry.GetDiskNumber(), NUMERIC_FORMAT).data()));
    item.SetText(7, tmp.Format("%s", n.ToString(entry.GetDiskOffset(), NUMERIC_FORMAT).data()));

    item.SetData(realIndex);

    currentItemIndex++;

    return currentItemIndex != this->curentChildIndexes.size();
}

constexpr int32 CMD_BUTTON_CLOSE  = 1;
constexpr int32 CMD_BUTTON_OK     = 2;
constexpr int32 CMD_BUTTON_CANCEL = 3;

class PasswordDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<Password> input;
    Reference<CheckBox> savePasswordAsDefault;

    Reference<Button> close;
    Reference<Button> cancel;
    Reference<Button> ok;

    std::string password;

  public:
    PasswordDialog() : Window("Enter Password", "d:c,w:25%,h:15%", WindowFlags::ProcessReturn)
    {
        input = Factory::Password::Create(this, "", "x:1,y:1,w:100%,h:1%");

        savePasswordAsDefault = Factory::CheckBox::Create(this, "Save password as default", "x:1,y:3,w:100%,h:1%", 1);
        savePasswordAsDefault->SetChecked(true);

        ok                              = Factory::Button::Create(this, "&Ok", "x:25%,y:100%,a:b,w:12", CMD_BUTTON_OK);
        ok->Handlers()->OnButtonPressed = this;
        ok->SetFocus();

        cancel                              = Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", CMD_BUTTON_CANCEL);
        cancel->Handlers()->OnButtonPressed = this;

        input->SetFocus();
    }

    void OnButtonPressed(Reference<Button> b) override
    {
        if (b->GetControlID() == CMD_BUTTON_CLOSE || b->GetControlID() == CMD_BUTTON_CANCEL)
        {
            Exit(Dialogs::Result::Cancel);
            return;
        }

        if (b->GetControlID() == CMD_BUTTON_OK)
        {
            CHECKRET(input.IsValid(), "");
            CHECKRET(input->GetText().ToString(password), "");

            Exit(Dialogs::Result::Ok);
            return;
        }

        Exit(Dialogs::Result::Cancel);
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (Window::OnEvent(c, eventType, id))
        {
            return true;
        }

        if (eventType == Event::WindowAccept || eventType == Event::PasswordValidate)
        {
            OnButtonPressed(ok);
            return true;
        }

        return false;
    }

    bool SavePasswordAsDefault()
    {
        CHECK(savePasswordAsDefault.IsValid(), false, "");
        return savePasswordAsDefault->IsChecked();
    }

    const std::string& GetPassword() const
    {
        return password;
    }
};

void ZIPFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    CHECKRET(item.GetParent().GetHandle() != InvalidItemHandle, "");

    const auto index = item.GetData(-1);
    CHECKRET(index != -1, "");
    GView::ZIP::Entry entry{ 0 };
    CHECKRET(this->info.GetEntry((uint32) index, entry), "");

    Buffer buffer{};
    bool decompressed{ false };

    if (entry.IsEncrypted() == false || password.empty() == false)
    {
        if (isTopContainer)
        {
            decompressed = this->info.Decompress(buffer, (uint32) index, password);
        }
        else
        {
            const auto cache = obj->GetData().GetEntireFile();
            if (cache.IsValid())
            {
                decompressed == this->info.Decompress(cache, buffer, (uint32) index, password);
            }
        }

        if (decompressed)
        {
            const auto name = entry.GetFilename();
            GView::App::OpenBuffer(buffer, name, name, GView::App::OpenMethod::BestMatch);
            return;
        }

        if (entry.IsEncrypted())
        {
            Dialogs::MessageBox::ShowError("Error!", "Wrong default password!");
        }
        else
        {
            Dialogs::MessageBox::ShowError("Error!", "Failed to decompress!");
            return;
        }
    }

    PasswordDialog pd;
    while (pd.Show() == Dialogs::Result::Ok)
    {
        if (isTopContainer)
        {
            decompressed = this->info.Decompress(buffer, (uint32) index, pd.GetPassword());
        }
        else
        {
            const auto cache = obj->GetData().GetEntireFile();
            if (cache.IsValid())
            {
                decompressed == this->info.Decompress(cache, buffer, (uint32) index, pd.GetPassword());
            }
        }

        if (decompressed)
        {
            if (pd.SavePasswordAsDefault())
            {
                this->password = pd.GetPassword();
            }

            const auto name = entry.GetFilename();
            GView::App::OpenBuffer(buffer, name, name, GView::App::OpenMethod::BestMatch);
            return;
        }

        Dialogs::MessageBox::ShowError("Error!", "Wrong password!");
    }

    Dialogs::MessageBox::ShowError("Error!", "Unable to decompress without a password!");
}
} // namespace GView::Type::ZIP

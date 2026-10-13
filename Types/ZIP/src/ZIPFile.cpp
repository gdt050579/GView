#include <map>
#include <queue>

#include "zip.hpp"

namespace GView::Type::ZIP
{

ZIPFile::ZIPFile()
{
}

bool ZIPFile::Update()
{
    // top container: minizip-ng reads the file itself
    // (decided by the object type: the logical path of a child may also exist on disk and be a different file)
    if (obj->GetObjectType() == GView::Object::Type::File) {
        isTopContainer = true;
        CHECK(GView::Decoding::ZIP::GetInfo(obj->GetPath(), this->info), false, "");
        return true;
    }

    // child container that fits in the cache: read in memory (nothing written to disk)
    if (obj->GetData().GetSize() <= obj->GetData().GetCacheSize()) {
        isTopContainer = false;
        CHECK(GView::Decoding::ZIP::GetInfo(obj->GetData(), this->info), false, "");
        return true;
    }

    // larger child container: read from a copy in GView's private temporary folder (refused for Learning and Evaluation
    // Mode memory-only content and when the policy restricts Export)
    GView::App::TemporaryFile copy;
    const auto dropped = GView::App::DropToTemporaryFile(obj, copy);
    CHECK(dropped.ok, false, "Archive larger than the cache that can not be copied to the temporary folder: %s", dropped.message.c_str());
    const bool opened = GView::Decoding::ZIP::GetInfo(copy.GetPath().u16string(), this->info);
    // kept even on failure (the reader may still have it open); GetInfo closed the previous copy, which is removed here
    tempCopy = std::move(copy);
    CHECK(opened, false, "");
    isTopContainer = true; // the reader owns a file
    return true;
}

bool ZIPFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    const auto count = this->info.GetCount();
    CHECK(count > 0, false, "");

    currentItemIndex = 0;
    curentChildIndexes.clear();

    if (path.empty()) {
        for (uint32 i = 0; i < count; i++) {
            GView::Decoding::ZIP::Entry entry{};
            CHECK(this->info.GetEntry(i, entry), false, "");

            auto filename        = entry.GetFilename();
            const auto entryType = entry.GetType();

            const auto f = filename.find_first_of('/');

            if ((entryType == GView::Decoding::ZIP::EntryType::Directory && f == filename.size() - 1) ||
                (entryType != GView::Decoding::ZIP::EntryType::Directory && f == std::string::npos)) {
                curentChildIndexes.push_back(i);
            }
        }

        if (this->curentChildIndexes.size() > 0) {
            return currentItemIndex != this->curentChildIndexes.size();
        }
    }

    UnicodeStringBuilder usb;
    for (uint32 i = 0; i < count; i++) {
        GView::Decoding::ZIP::Entry entry{};
        CHECK(this->info.GetEntry(i, entry), false, "");

        auto filename        = entry.GetFilename();
        const auto entryType = entry.GetType();

        if (entryType == GView::Decoding::ZIP::EntryType::Directory) {
            if (filename[filename.size() - 1] == '/') {
                filename = { filename.data(), filename.size() - 1 };
            }
        }
        CHECK(usb.Set(filename), false, "");

        const auto sv = usb.ToStringView();
        if (sv.size() > path.size() && sv.starts_with(path) && sv[path.size()] == '/') {
            const auto tmpSV = std::u16string_view{ sv.data() + path.size(), sv.size() - path.size() };
            if (tmpSV.find_first_of('/') == tmpSV.find_last_of('/')) {
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
    GView::Decoding::ZIP::Entry entry{};
    CHECK(this->info.GetEntry(realIndex, entry), false, "");

    auto filename = entry.GetFilename();

    const auto entryType = entry.GetType();
    item.SetPriority(entryType == GView::Decoding::ZIP::EntryType::Directory);
    item.SetExpandable(entryType == GView::Decoding::ZIP::EntryType::Directory);

    if (entryType == GView::Decoding::ZIP::EntryType::Directory) {
        if (filename[filename.size() - 1] == '/') {
            filename = { filename.data(), filename.size() - 1 };
        }
    }

    const auto f = filename.find_last_of('/');
    if (f != std::string::npos) {
        filename = { filename.data() + f + 1, filename.size() - f - 1 };
    }

    item.SetText(filename);
    item.SetText(1, tmp.Format("%s (%s)", entry.GetTypeName().data(), n.ToString((uint32) entryType, NUMERIC_FORMAT).data()));
    item.SetText(2, tmp.Format("%s (%s)", entry.GetFlagNames().c_str(), n.ToString(entry.GetFlags(), NUMERIC_FORMAT).data()));
    item.SetText(3, tmp.Format("%s", n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(4, tmp.Format("%s", n.ToString(entry.GetUncompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(5, tmp.Format("%s (%s)", entry.GetCompressionMethodName().data(), n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
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
    PasswordDialog() : Window("Enter Password", "d:c,w:60,h:9", WindowFlags::ProcessReturn)
    {
        input = Factory::Password::Create(this, "", "x:1,y:1,w:56,h:1");

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
        if (b->GetControlID() == CMD_BUTTON_CLOSE || b->GetControlID() == CMD_BUTTON_CANCEL) {
            Exit(Dialogs::Result::Cancel);
            return;
        }

        if (b->GetControlID() == CMD_BUTTON_OK) {
            CHECKRET(input.IsValid(), "");
            CHECKRET(input->GetText().ToString(password), "");

            Exit(Dialogs::Result::Ok);
            return;
        }

        Exit(Dialogs::Result::Cancel);
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (Window::OnEvent(c, eventType, id)) {
            return true;
        }

        if (eventType == Event::WindowAccept || eventType == Event::PasswordValidate) {
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

    const auto index = item.GetData(static_cast<uint64>(-1));
    CHECKRET(index != static_cast<uint64>(-1), "");
    GView::Decoding::ZIP::Entry entry{};
    CHECKRET(this->info.GetEntry((uint32) index, entry), "");

    Buffer buffer{};
    bool decompressed{ false };

    if (entry.IsEncrypted() == false || password.empty() == false) {
        if (isTopContainer) {
            decompressed = this->info.Decompress(buffer, (uint32) index, password);
        } else {
            const auto cache = obj->GetData().GetEntireFile();
            if (cache.IsValid()) {
                decompressed = this->info.Decompress(cache, buffer, (uint32) index, password);
            }
        }

        if (decompressed) {
            std::u16string path{ obj->GetPath() };
            path.append(u".drop");
            path.push_back((char16_t) std::filesystem::path::preferred_separator);

            LocalUnicodeStringBuilder<1024> ub;
            const auto name = entry.GetFilename();
            CHECKRET(ub.Set(name), "");

            path.append(ub.ToStringView());

            if (std::filesystem::path::preferred_separator == u'\\') // if on windows
            {
                std::replace(path.begin(), path.end(), u'/', u'\\');
            }
            GView::App::OpenBuffer(buffer, name, path, GView::App::OpenMethod::BestMatch,"",Application::GetCurrentWindow(),"extraction and decompression");

            return;
        }

        if (entry.IsEncrypted()) {
            Dialogs::MessageBox::ShowError("Error!", "Wrong default password!");
        } else {
            Dialogs::MessageBox::ShowError("Error!", "Failed to decompress!");
            return;
        }
    }

    PasswordDialog pd;
    while (pd.Show() == Dialogs::Result::Ok) {
        if (isTopContainer) {
            decompressed = this->info.Decompress(buffer, (uint32) index, pd.GetPassword());
        } else {
            const auto cache = obj->GetData().GetEntireFile();
            if (cache.IsValid()) {
                decompressed = this->info.Decompress(cache, buffer, (uint32) index, pd.GetPassword());
            }
        }

        if (decompressed) {
            if (pd.SavePasswordAsDefault()) {
                this->password = pd.GetPassword();
            }

            const auto name = entry.GetFilename();
            GView::App::OpenBuffer(buffer, name, name, GView::App::OpenMethod::BestMatch, "", Application::GetCurrentWindow(), "extraction");
            return;
        }

        Dialogs::MessageBox::ShowError("Error!", "Wrong password!");
    }

    Dialogs::MessageBox::ShowError("Error!", "Unable to decompress without a password!");
}

GView::Utils::JsonBuilderInterface* ZIPFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    builder->AddUInt("EntriesCount", info.GetCount());
    return builder;
}
} // namespace GView::Type::ZIP

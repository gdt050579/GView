#include "Artefacts.hpp"
#include "SpecialStrings.hpp"

namespace GView::GenericPlugins::Droppper
{
ArtefactType IdentifyArtefact(DataCache& cache, Subcategory subcategory, uint64 start, uint64 end, Result result)
{
    CHECK(subcategory == Subcategory::Filepath || subcategory == Subcategory::Registry, ArtefactType::None, "");

    BufferView bf = cache.Get(start, static_cast<uint32>(end - start), true);
    CHECK(bf.IsValid(), ArtefactType::None, "");

    switch (subcategory) {
    case GView::GenericPlugins::Droppper::Subcategory::Filepath:
        if (std::string_view{ bf }.ends_with(result == Result::Ascii ? R"(\StartUp)" : "\\\0S\0t\0a\0r\0t\0U\0p\0")) {
            return ArtefactType::Persistence;
        }
        if (std::string_view{ bf }.ends_with(result == Result::Ascii ? R"(/passwd)" : "/\0p\0a\0s\0s\0w\0d\0")) {
            return ArtefactType::Credentials;
        }
        return ArtefactType::None;
    case GView::GenericPlugins::Droppper::Subcategory::Registry:
        if (std::string_view{ bf }.ends_with(result == Result::Ascii ? R"(\Run)" : "\\\0R\0u\0n\0")) {
            return ArtefactType::Persistence;
        }
        return ArtefactType::None;
    default:
        return ArtefactType::None;
    }
}

ArtefactsUI::ArtefactsUI(DataCache& cache, const std::vector<Finding>& findings) : Window("Artefacts", "d:c,w:80%,h:90%", WindowFlags::Sizeable)
{
    this->lv = Factory::ListView::Create(
          this,
          "x:0,y:0,w:100%,h:90%",
          { "n:Type,w:10%", "n:Artefact,w:10%", "n:Offset,w:5%", "n:Value,w:35%", "n:Hint,w:40%" },
          ListViewFlags::AllowMultipleItemsSelection);

    NumericFormatter n;
    const auto AddItems = [&findings, this, &n, &cache](Subcategory sc) {
        for (const auto& f : findings) {
            if (f.subcategory != sc) {
                continue;
            }

            auto& b        = this->entries.emplace_back(Buffer());
            b              = cache.CopyToBuffer(f.start, static_cast<uint32>(f.end - f.start), true);
            const auto svp = n.ToString(f.start, { NumericFormatFlags::HexPrefix, 16 });

            std::string_view artefact = "-";
            std::string_view hint     = "";
            std::optional<ListViewItem::Type> itemType;
            if (sc == Subcategory::Wallet) {
                artefact = SpecialStrings::WALLET_TYPE_NAMES.at(static_cast<SpecialStrings::WalletType>(f.details));
            }

            switch (f.artefact) {
            case ArtefactType::None:
                break;
            case ArtefactType::Persistence:
                artefact = "Persistence";
                itemType = ListViewItem::Type::Emphasized_2;
                if (sc == Subcategory::Filepath) {
                    hint = "Everything that is in this folder gets executed as start up, as long as it is in an executable format.";
                } else if (sc == Subcategory::Registry) {
                    hint = "The command added here gets executed everytime an user logs in (HCKU) or the system boots up (HKLM).";
                }
                break;
            case ArtefactType::Credentials:
                itemType = ListViewItem::Type::Emphasized_2;
                artefact = "Credentials";
                break;
            default:
                break;
            }

            auto item = lv->AddItem(
                  { TYPES_MAP.at(f.subcategory).name, artefact, svp.data(), std::string_view{ reinterpret_cast<char*>(b.GetData()), b.GetLength() }, hint });
            if (itemType.has_value()) {
                item.SetType(*itemType);
            }
        }
    };

    auto emails = lv->AddItem({ "Emails" }).SetType(ListViewItem::Type::Category);
    AddItems(Subcategory::Email);
    auto urls = lv->AddItem({ "URLs" }).SetType(ListViewItem::Type::Category);
    AddItems(Subcategory::URL);
    auto ips = lv->AddItem({ "IPs" }).SetType(ListViewItem::Type::Category);
    AddItems(Subcategory::IP);
    auto wallets = lv->AddItem({ "Wallets" }).SetType(ListViewItem::Type::Category);
    AddItems(Subcategory::Wallet);
    auto paths = lv->AddItem({ "Paths" }).SetType(ListViewItem::Type::Category);
    AddItems(Subcategory::Filepath);
    auto registries = lv->AddItem({ "Registries" }).SetType(ListViewItem::Type::Category);
    AddItems(Subcategory::Registry);
    auto strings = lv->AddItem({ "Strings" }).SetType(ListViewItem::Type::Category);
    AddItems(Subcategory::Text);
}
} // namespace GView::GenericPlugins::Droppper

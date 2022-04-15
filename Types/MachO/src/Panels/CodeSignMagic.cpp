#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;

enum class Action : int32
{
    GoTo     = 1,
    Select   = 2,
    MoreInfo = 3
};

CodeSignMagic::CodeSignMagic(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("CodeSign&Magic")
{
    machO   = _machO;
    win     = _win;
    general = Factory::ListView::Create(
          this, "x:0,y:0,w:100%,h:10", { { "Key", TextAlignament::Left, 18 }, { "Value", TextAlignament::Left, 48 } }, ListViewFlags::None);

    Update();
}

void CodeSignMagic::UpdateLinkeditDataCommand()
{
    CHECKRET(machO->codeSignature.has_value(), "");

    NumericFormatter nf;
    NumericFormatter nf2;
    LocalString<1024> ls;

    general->AddItem("Code Sign Magic").SetType(ListViewItem::Type::Category);

    const auto& lcName    = MAC::LoadCommandNames.at(machO->codeSignature->ledc.cmd);
    const auto hexCommand = nf.ToString(static_cast<uint32_t>(machO->codeSignature->ledc.cmd), hex);
    general->AddItem({ "Command", ls.Format("%-14s (%s)", lcName.data(), hexCommand.data()) });

    const auto cmdSize    = nf.ToString(machO->codeSignature->ledc.cmdsize, dec);
    const auto hexCmdSize = nf2.ToString(machO->codeSignature->ledc.cmdsize, hex);
    general->AddItem({ "Cmd Size", ls.Format("%-14s (%s)", cmdSize.data(), hexCmdSize.data()) });

    const auto dataOffset    = nf.ToString(machO->codeSignature->ledc.dataoff, dec);
    const auto hexDataOffset = nf2.ToString(machO->codeSignature->ledc.dataoff, hex);
    general->AddItem({ "Data Offset", ls.Format("%-14s (%s)", dataOffset.data(), hexDataOffset.data()) });

    const auto dataSize    = nf.ToString(machO->codeSignature->ledc.datasize, dec);
    const auto hexDataSize = nf2.ToString(machO->codeSignature->ledc.datasize, hex);
    general->AddItem({ "Data Size", ls.Format("%-14s (%s)", dataSize.data(), hexDataSize.data()) });
}

void CodeSignMagic::UpdateSuperBlob()
{
    CHECKRET(machO->codeSignature.has_value(), "");

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Super Blob").SetType(ListViewItem::Type::Category);

    const auto& magic   = MAC::CodeSignMagicNames.at(machO->codeSignature->superBlob.magic);
    const auto hexMagic = nf2.ToString(static_cast<uint32_t>(machO->codeSignature->superBlob.magic), hex);
    general->AddItem({ "Magic", ls.Format("%-26s (%s)", magic.data(), hexMagic.data()) });

    const auto length    = nf.ToString(machO->codeSignature->superBlob.length, dec);
    const auto hexLength = nf2.ToString(machO->codeSignature->superBlob.length, hex);
    general->AddItem({ "Length", ls.Format("%-26s (%s)", length.data(), hexLength.data()) });

    const auto count    = nf.ToString(machO->codeSignature->superBlob.count, dec);
    const auto hexCount = nf2.ToString(machO->codeSignature->superBlob.count, hex);
    general->AddItem({ "Count", ls.Format("%-26s (%s)", count.data(), hexCount.data()) });
}

void CodeSignMagic::UpdateSlots()
{
    CHECKRET(machO->codeSignature.has_value(), "");

    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Slots").SetType(ListViewItem::Type::Category);

    for (const auto& blob : machO->codeSignature->blobs)
    {
        const auto& slot   = MAC::CodeSignSlotNames.at(blob.type);
        const auto hexSlot = nf2.ToString(static_cast<uint32_t>(blob.type), hex);
        general->AddItem({ "Slot Type", ls.Format("%-32s (%s)", slot.data(), hexSlot.data()) });

        const auto offset    = nf.ToString(blob.offset, dec);
        const auto hexOffset = nf2.ToString(blob.offset, hex);
        general->AddItem({ "Offset", ls.Format("%-32s (%s)", offset.data(), hexOffset.data()) });
    }
}

void CodeSignMagic::UpdateBlobs()
{
    CHECKRET(machO->codeSignature.has_value(), "");

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto alternateDirectoryCount = 0U;
    for (const auto& blob : machO->codeSignature->blobs)
    {
        const auto& slot = MAC::CodeSignSlotNames.at(blob.type);
        general->AddItem(slot.data()).SetType(ListViewItem::Type::Category);

        switch (blob.type)
        {
        case MAC::CodeSignMagic::CSSLOT_CODEDIRECTORY:
        {
            const auto& code = machO->codeSignature->codeDirectory;
            UpdateCodeDirectory(
                  code, machO->codeSignature->cdHash, machO->codeSignature->codeDirectoryIdentifier, machO->codeSignature->cdSlotsHashes);
        }
        break;
        case MAC::CodeSignMagic::CSSLOT_INFOSLOT:
            break;
        case MAC::CodeSignMagic::CSSLOT_REQUIREMENTS:
        {
            const auto& r = machO->codeSignature->requirements.blob;

            const auto& magic   = MAC::CodeSignMagicNames.at(r.magic);
            const auto hexMagic = nf2.ToString(static_cast<uint32_t>(r.magic), hex);
            general->AddItem({ "Magic", ls.Format("%-26s (%s)", magic.data(), hexMagic.data()) });

            const auto length    = nf.ToString(r.length, dec);
            const auto hexLength = nf2.ToString(r.length, hex);
            general->AddItem({ "Offset", ls.Format("%-26s (%s)", length.data(), hexLength.data()) });

            // const auto data    = nf.ToString(r.data, dec);
            // const auto hexData = nf2.ToString(r.data, hex);
            // general->AddItem({"Data", ls.Format("%-26s (%s)", data.data(), hexData.data()));
        }
        break;
        case MAC::CodeSignMagic::CSSLOT_RESOURCEDIR:
            break;
        case MAC::CodeSignMagic::CSSLOT_APPLICATION:
            break;
        case MAC::CodeSignMagic::CSSLOT_ENTITLEMENTS:
        {
            const auto& b = machO->codeSignature->entitlements.blob;

            const auto& magic   = MAC::CodeSignMagicNames.at(b.magic);
            const auto hexMagic = nf2.ToString(static_cast<uint32_t>(b.magic), hex);
            general->AddItem({ "Magic", ls.Format("%-26s (%s)", magic.data(), hexMagic.data()) });

            const auto offset    = nf.ToString(blob.offset, dec);
            const auto hexOffset = nf2.ToString(blob.offset, hex);
            general->AddItem({ "Offset", ls.Format("%-26s (%s)", offset.data(), hexOffset.data()) });

            const auto& data       = machO->codeSignature->entitlements.data;
            const auto dataSize    = nf.ToString(static_cast<uint64>(data.size()), dec);
            const auto hexDataSize = nf2.ToString(static_cast<uint64>(data.size()), hex);
            general->AddItem({ "Data", ls.Format("%-26s (%s)", dataSize.data(), hexDataSize.data()) });

            std::vector<std::string> lines;
            auto pos  = 0ULL;
            auto prev = 0ULL;
            while ((pos = data.find("\n", prev)) != std::string::npos)
            {
                lines.push_back(data.substr(prev, pos - prev));
                prev = pos + 1;
            }
            lines.push_back(data.substr(prev));

            for (auto i = 0U; i < lines.size(); i++)
            {
                general->AddItem({ "", ls.Format("%s", lines[i].c_str()) });
            }
        }
        break;
        case MAC::CodeSignMagic::CSSLOT_ALTERNATE_CODEDIRECTORIES:
        {
            const auto& code = machO->codeSignature->alternateDirectories[alternateDirectoryCount];
            UpdateCodeDirectory(
                  code,
                  machO->codeSignature->acdHashes[alternateDirectoryCount],
                  machO->codeSignature->alternateDirectoriesIdentifiers[alternateDirectoryCount],
                  machO->codeSignature->acdSlotsHashes[alternateDirectoryCount]);
            alternateDirectoryCount++;
        }
        break;
        case MAC::CodeSignMagic::CSSLOT_SIGNATURESLOT:
        {
            const auto& signature = machO->codeSignature->signature;

            const auto offset    = nf.ToString(signature.offset, dec);
            const auto hexOffset = nf2.ToString(signature.offset, hex);
            cmsOffset            = general->AddItem({ "Offset", ls.Format("%-26s (%s)", offset.data(), hexOffset.data()) });
            cmsOffset.SetData(signature.offset);

            const auto size    = nf.ToString(signature.size, dec);
            const auto hexSize = nf2.ToString(signature.size, hex);
            cmsSize            = general->AddItem({ "Length", ls.Format("%-26s (%s)", size.data(), hexSize.data()) });
            cmsSize.SetData(signature.size);

            humanReadable =
                  general->AddItem({ "Human Readable", "Signature parsed - press ENTER for details!", signature.humanReadable.GetText() });
            humanReadable.SetType(signature.errorHumanReadable ? ListViewItem::Type::ErrorInformation : ListViewItem::Type::Emphasized_2);

            PEMs = general->AddItem({ "PEMs", ls.Format("(%d) PEMs parsed - press ENTER for details!", signature.PEMsCount) });
            PEMs.SetType(signature.errorPEMs ? ListViewItem::Type::ErrorInformation : ListViewItem::Type::Emphasized_2);
        }
        break;
        default:
            break;
        }
    }
}

void CodeSignMagic::UpdateCodeDirectory(
      const MAC::CS_CodeDirectory& code,
      const std::string& cdHash,
      const std::string& identifier,
      const std::vector<std::pair<std::string, std::string>>& slotsHashes)
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto identifierItem = general->AddItem({ "Identifier", ls.Format("%s", identifier.c_str()) });
    identifierItem.SetType(ListViewItem::Type::Emphasized_2);

    const auto& magic   = MAC::CodeSignMagicNames.at(code.magic);
    const auto hexMagic = nf2.ToString(static_cast<uint32_t>(code.magic), hex);
    general->AddItem({ "Magic", ls.Format("%-26s (%s)", magic.data(), hexMagic.data()) });

    auto cdHashItem = general->AddItem({ "CD Hash", ls.Format("%s", cdHash.c_str()) });

    bool validHash = false;
    auto& signers  = machO->codeSignature->signature.sig.signers;
    for (const auto& signer : signers)
    {
        for (const auto& attribute : signer.attributes)
        {
            for (const auto& hash : attribute.CDHashes)
            {
                if (hash.GetText() != nullptr && cdHash == hash.GetText())
                {
                    validHash = true;
                    break;
                }
            }

            if (validHash)
            {
                break;
            }
        }

        if (validHash)
        {
            break;
        }
    }
    if (validHash)
    {
        cdHashItem.SetType(ListViewItem::Type::Emphasized_2);
    }
    else
    {
        cdHashItem.SetType(ListViewItem::Type::ErrorInformation);
    }

    const auto length    = nf.ToString(code.length, dec);
    const auto hexLength = nf2.ToString(code.length, hex);
    general->AddItem({ "Offset", ls.Format("%-26s (%s)", length.data(), hexLength.data()) });

    const auto version    = nf.ToString(code.version, dec);
    const auto hexVersion = nf2.ToString(code.version, hex);
    general->AddItem({ "Version", ls.Format("%-26s (%s)", version.data(), hexVersion.data()) });

    const auto flags    = nf.ToString(code.flags, dec);
    const auto hexFlags = nf2.ToString(code.flags, hex);
    general->AddItem({ "Flags", ls.Format("%-26s (%s)", flags.data(), hexFlags.data()) });

    const auto flagsData = MAC::GetCodeSignFlagsData(code.flags);
    for (const auto& flag : flagsData)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName        = MAC::CodeSignFlagNames.at(flag).data();
        const auto flagDescription = MAC::CodeSignFlagsDescriptions.at(flag).data();

        general->AddItem({ "", ls.Format("%-26s %-12s %s", flagName, hfls.GetText(), flagDescription) })
              .SetType(ListViewItem::Type::Emphasized_2);
    }

    const auto hashOffset    = nf.ToString(code.hashOffset, dec);
    const auto hexHashOffset = nf2.ToString(code.hashOffset, hex);
    general->AddItem({ "Hash Offset", ls.Format("%-26s (%s)", hashOffset.data(), hexHashOffset.data()) });

    const auto identOffset    = nf.ToString(code.identOffset, dec);
    const auto hexIdentOffset = nf2.ToString(code.identOffset, hex);
    general->AddItem({ "Ident Offset", ls.Format("%-26s (%s)", identOffset.data(), hexIdentOffset.data()) });

    const auto nSpecialSlots   = nf.ToString(code.nSpecialSlots, dec);
    const auto hexSpecialSlots = nf2.ToString(code.nSpecialSlots, hex);
    general->AddItem({ "Special Slots", ls.Format("%-26s (%s)", nSpecialSlots.data(), hexSpecialSlots.data()) });

    const auto nCodeSlots   = nf.ToString(code.nCodeSlots, dec);
    const auto hexCodeSlots = nf2.ToString(code.nCodeSlots, hex);
    general->AddItem({ "Code Slots", ls.Format("%-26s (%s)", nCodeSlots.data(), hexCodeSlots.data()) });

    {
        auto i = 0U;
        for (const auto& [found, computed] : slotsHashes)
        {
            if (found == computed)
            {
                auto hash = general->AddItem({ "", ls.Format("Slot #(%u) %s", i, found.c_str()) });
                hash.SetType(ListViewItem::Type::Emphasized_2);
            }
            else
            {
                auto hash = general->AddItem({ "", ls.Format("Slot #(%u) %s (%s)", i, found.c_str(), computed.c_str()) });
                hash.SetType(ListViewItem::Type::ErrorInformation);
            }
            i++;
        }
    }

    const auto codeLimit    = nf.ToString(code.codeLimit, dec);
    const auto hexCodeLimit = nf2.ToString(code.codeLimit, hex);
    general->AddItem({ "Code Limit", ls.Format("%-26s (%s)", codeLimit.data(), hexCodeLimit.data()) });

    const auto hashSize    = nf.ToString(code.hashSize, dec);
    const auto hexHashSize = nf2.ToString(code.hashSize, hex);
    general->AddItem({ "Hash Size", ls.Format("%-26s (%s)", hexHashSize.data(), hexHashSize.data()) });

    const auto& hashType   = MAC::CodeSignHashTypeNames.at(static_cast<MAC::CodeSignMagic>(code.hashType));
    const auto hexHashType = nf2.ToString(code.hashType, hex);
    general->AddItem({ "Hash Type", ls.Format("%-26s (%s)", hashType.data(), hexHashType.data()) });

    const auto& platform   = MAC::CodeSignPlatformNames.at(code.platform);
    const auto hexPlatform = nf2.ToString(static_cast<uint32_t>(code.platform), hex);
    general->AddItem({ "Platform", ls.Format("%-26s (%s)", platform.data(), hexPlatform.data()) });

    const auto realPageSize = static_cast<uint32>(1 << code.pageSize);
    const auto pageSize     = nf.ToString(static_cast<uint32>(code.pageSize), dec);
    const auto hexPageSize  = nf2.ToString(static_cast<uint32>(code.pageSize), hex);
    general->AddItem(
          { "Page Size",
            ls.Format("%-26s (%s) -> 1 << (%s) = 0x%x", pageSize.data(), hexPageSize.data(), hexPageSize.data(), realPageSize) });

    const auto spare2    = nf.ToString(code.spare2, dec);
    const auto hexSpare2 = nf2.ToString(code.spare2, hex);
    general->AddItem({ "Spare2", ls.Format("%-26s (%s)", spare2.data(), hexSpare2.data()) });

    if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSSCATTER))
    {
        const auto scatterOffset    = nf.ToString(code.scatterOffset, dec);
        const auto hexScatterOffset = nf2.ToString(code.scatterOffset, hex);
        general->AddItem({ "Scatter Offset", ls.Format("%-26s (%s)", scatterOffset.data(), hexScatterOffset.data()) });
    }

    if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSTEAMID))
    {
        const auto teamOffset    = nf.ToString(code.teamOffset, dec);
        const auto hexTeamOffset = nf2.ToString(code.teamOffset, hex);
        general->AddItem({ "Team Offset", ls.Format("%-26s (%s)", teamOffset.data(), hexTeamOffset.data()) });
    }

    if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSCODELIMIT64))
    {
        const auto spare3    = nf.ToString(code.spare3, dec);
        const auto hexSpare3 = nf2.ToString(code.spare3, hex);
        general->AddItem({ "Spare3", ls.Format("%-26s (%s)", spare3.data(), hexSpare3.data()) });

        const auto codeLimit64    = nf.ToString(code.codeLimit64, dec);
        const auto hexCodeLimit64 = nf2.ToString(code.codeLimit64, hex);
        general->AddItem({ "Code Limit", ls.Format("%-26s (%s)", codeLimit64.data(), hexCodeLimit64.data()) });
    }

    if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSEXECSEG))
    {
        const auto execSegBase    = nf.ToString(code.execSegBase, dec);
        const auto hexExecSegBase = nf2.ToString(code.execSegBase, hex);
        general->AddItem({ "Exec Seg Base", ls.Format("%-26s (%s)", execSegBase.data(), hexExecSegBase.data()) });

        const auto execSegLimit    = nf.ToString(code.execSegLimit, dec);
        const auto hexExecSegLimit = nf2.ToString(code.execSegLimit, hex);
        general->AddItem({ "Exec Seg Limit", ls.Format("%-26s (%s)", execSegLimit.data(), hexExecSegLimit.data()) });

        const auto execSegFlags    = nf.ToString(code.execSegFlags, dec);
        const auto hexExecSegFlags = nf2.ToString(code.execSegFlags, hex);
        general->AddItem({ "Exec Seg Flags", ls.Format("%-26s (%s)", execSegFlags.data(), hexExecSegFlags.data()) });

        const auto execFlagsData = MAC::GetCodeSignExecSegFlagsData(code.execSegFlags);
        for (const auto& flag : execFlagsData)
        {
            LocalString<16> hfls;
            hfls.Format("(0x%X)", flag);

            const auto flagName        = MAC::CodeSignExecSegFlagNames.at(flag).data();
            const auto flagDescription = MAC::CodeSignExecSegFlagsDescriptions.at(flag).data();

            general->AddItem({ "", ls.Format("%-26s %-12s %s", flagName, hfls.GetText(), flagDescription) })
                  .SetType(ListViewItem::Type::Emphasized_2);
        }
    }

    if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSRUNTIME))
    {
        // TODO: ??
    }

    if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSLINKAGE))
    {
        // TODO: ??
    }
}

void CodeSignMagic::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), std::min<>(static_cast<int>(general->GetItemsCount() + 3), GetHeight()));
}

void CodeSignMagic::GoToSelectedOffset()
{
    CHECKRET(cmsOffset.IsValid(), "");
    CHECKRET(cmsOffset.IsCurrent(), "");

    win->GetCurrentView()->GoTo(cmsOffset.GetData(0));
}

void CodeSignMagic::SelectArea()
{
    CHECKRET(cmsOffset.IsValid(), "");
    CHECKRET(cmsOffset.IsCurrent(), "");

    win->GetCurrentView()->Select(cmsOffset.GetData(0), cmsSize.GetData(0));
}

void CodeSignMagic::MoreInfo()
{
    class Dialog : public Window
    {
        Reference<GView::Object> object;
        Reference<TextArea> text = Factory::TextArea::Create(
              this,
              "Digital Signature",
              "d:c",
              TextAreaFlags::Border | TextAreaFlags::ScrollBars | TextAreaFlags::Readonly | TextAreaFlags::DisableAutoSelectOnFocus);

      public:
        Dialog(Reference<GView::Object> _object, std::string_view name, std::string_view layout)
            : Window(name, layout, WindowFlags::ProcessReturn | WindowFlags::Sizeable)
        {
            object = _object;
        }

        bool SetText(ConstString _text)
        {
            text->SetText(_text);
        }

        void SetWidth(uint32 width)
        {
            this->Resize(width, this->GetHeight());
            text->Resize(width - 10, text->GetHeight());
        }
    };

    if (humanReadable.IsValid() && humanReadable.IsCurrent())
    {
        LocalString<128> ls;
        ls.Format("d:c,w:150,h:%d", this->GetHeight());
        Dialog dialog(nullptr, "CMS human readable", ls.GetText());
        dialog.SetText(machO->codeSignature->signature.humanReadable.GetText());
        dialog.Show();
    }

    if (PEMs.IsValid() && PEMs.IsCurrent())
    {
        std::string input;

        for (uint32 i = 0U; i < machO->codeSignature->signature.PEMsCount; i++)
        {
            const auto& pem = machO->codeSignature->signature.PEMs[i];
            input += pem;
            input += "\n";
        }

        LocalString<128> ls;
        ls.Format("d:c,w:70,h:%d", this->GetHeight());
        Dialog dialog(nullptr, "PEM Certificates", ls.GetText());
        dialog.SetText(input.c_str());
        dialog.Show();
    }
}

void CodeSignMagic::Update()
{
    general->DeleteAllItems();

    UpdateLinkeditDataCommand();
    UpdateSuperBlob();
    UpdateSlots();
    UpdateBlobs();
    RecomputePanelsPositions();
}

bool CodeSignMagic::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(AppCUI::Input::Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(AppCUI::Input::Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(AppCUI::Input::Key::Ctrl | AppCUI::Input::Key::Enter, "More Info", static_cast<int32_t>(Action::MoreInfo));

    return true;
}

bool CodeSignMagic::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemPressed)
    {
        GoToSelectedOffset();
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (static_cast<Action>(controlID))
        {
        case Action::GoTo:
            GoToSelectedOffset();
            return true;
        case Action::Select:
            SelectArea();
            return true;
        case Action::MoreInfo:
            MoreInfo();
            return true;
        }
    }

    return false;
}
} // namespace GView::Type::MachO::Panels

#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;

CodeSignMagic::CodeSignMagic(Reference<MachOFile> _machO) : TabPage("CodeSign&Magic")
{
    machO   = _machO;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Key", TextAlignament::Left, 18);
    general->AddColumn("Value", TextAlignament::Left, 48);

    Update();
}

void CodeSignMagic::UpdateLinkeditDataCommand()
{
    CHECKRET(machO->codeSignature.isSet, "");

    NumericFormatter nf;
    NumericFormatter nf2;
    LocalString<1024> ls;

    general->SetItemType(general->AddItem("Code Sign Magic"), ListViewItemType::Category);

    const auto& lcName    = MAC::LoadCommandNames.at(machO->codeSignature.ledc.cmd);
    const auto hexCommand = nf.ToString(static_cast<uint32_t>(machO->codeSignature.ledc.cmd), hex);
    general->AddItem("Command", ls.Format("%-14s (%s)", lcName.data(), hexCommand.data()));

    const auto cmdSize    = nf.ToString(machO->codeSignature.ledc.cmdsize, dec);
    const auto hexCmdSize = nf2.ToString(machO->codeSignature.ledc.cmdsize, hex);
    general->AddItem("Cmd Size", ls.Format("%-14s (%s)", cmdSize.data(), hexCmdSize.data()));

    const auto dataOffset    = nf.ToString(machO->codeSignature.ledc.dataoff, dec);
    const auto hexDataOffset = nf2.ToString(machO->codeSignature.ledc.dataoff, hex);
    general->AddItem("Data Offset", ls.Format("%-14s (%s)", dataOffset.data(), hexDataOffset.data()));

    const auto dataSize    = nf.ToString(machO->codeSignature.ledc.datasize, dec);
    const auto hexDataSize = nf2.ToString(machO->codeSignature.ledc.datasize, hex);
    general->AddItem("Data Size", ls.Format("%-14s (%s)", dataSize.data(), hexDataSize.data()));
}

void CodeSignMagic::UpdateSuperBlob()
{
    CHECKRET(machO->codeSignature.isSet, "");

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->SetItemType(general->AddItem("Super Blob"), ListViewItemType::Category);

    const auto& magic   = MAC::CodeSignMagicNames.at(machO->codeSignature.superBlob.magic);
    const auto hexMagic = nf2.ToString(static_cast<uint32_t>(machO->codeSignature.superBlob.magic), hex);
    general->AddItem("Magic", ls.Format("%-26s (%s)", magic.data(), hexMagic.data()));

    const auto length    = nf.ToString(machO->codeSignature.superBlob.length, dec);
    const auto hexLength = nf2.ToString(machO->codeSignature.superBlob.length, hex);
    general->AddItem("Length", ls.Format("%-26s (%s)", length.data(), hexLength.data()));

    const auto count    = nf.ToString(machO->codeSignature.superBlob.count, dec);
    const auto hexCount = nf2.ToString(machO->codeSignature.superBlob.count, hex);
    general->AddItem("Count", ls.Format("%-26s (%s)", count.data(), hexCount.data()));
}

void CodeSignMagic::UpdateSlots()
{
    CHECKRET(machO->codeSignature.isSet, "");

    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->SetItemType(general->AddItem("Slots"), ListViewItemType::Category);

    for (const auto& blob : machO->codeSignature.blobs)
    {
        const auto& slot   = MAC::SlotNames.at(blob.type);
        const auto hexSlot = nf2.ToString(static_cast<uint32_t>(blob.type), hex);
        general->AddItem("Slot Type", ls.Format("%-32s (%s)", slot.data(), hexSlot.data()));

        const auto offset    = nf.ToString(blob.offset, dec);
        const auto hexOffset = nf2.ToString(blob.offset, hex);
        general->AddItem("Offset", ls.Format("%-32s (%s)", offset.data(), hexOffset.data()));
    }
}

void CodeSignMagic::UpdateBlobs()
{
    CHECKRET(machO->codeSignature.isSet, "");

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    for (const auto& blob : machO->codeSignature.blobs)
    {
        const auto& slot = MAC::SlotNames.at(blob.type);
        general->SetItemType(general->AddItem(slot.data()), ListViewItemType::Category);

        switch (blob.type)
        {
        case MAC::CodeSignMagic::CSSLOT_CODEDIRECTORY:
        {
            const auto& code = machO->codeSignature.codeDirectory;

            const auto& magic   = MAC::CodeSignMagicNames.at(code.magic);
            const auto hexMagic = nf2.ToString(static_cast<uint32_t>(code.magic), hex);
            general->AddItem("Type", ls.Format("%-26s (%s)", magic.data(), hexMagic.data()));

            const auto length    = nf.ToString(code.length, dec);
            const auto hexLength = nf2.ToString(code.length, hex);
            general->AddItem("Offset", ls.Format("%-26s (%s)", length.data(), hexLength.data()));

            const auto version    = nf.ToString(code.version, dec);
            const auto hexVersion = nf2.ToString(code.version, hex);
            general->AddItem("Version", ls.Format("%-26s (%s)", version.data(), hexVersion.data()));

            const auto flags    = nf.ToString(code.flags, dec);
            const auto hexFlags = nf2.ToString(code.flags, hex);
            general->AddItem("Flags", ls.Format("%-26s (%s)", flags.data(), hexFlags.data()));

            const auto flagsData = MAC::GetCodeSignFlagsData(code.flags);
            for (const auto& flag : flagsData)
            {
                LocalString<16> hfls;
                hfls.Format("(0x%X)", flag);

                const auto flagName        = MAC::CodeSignFlagNames.at(flag).data();
                const auto flagDescription = MAC::CodeSignFlagsDescriptions.at(flag).data();

                const auto fh = general->AddItem("", ls.Format("%-26s %-12s %s", flagName, hfls.GetText(), flagDescription));
                general->SetItemType(fh, ListViewItemType::Emphasized_2);
            }

            const auto hashOffset    = nf.ToString(code.hashOffset, dec);
            const auto hexHashOffset = nf2.ToString(code.hashOffset, hex);
            general->AddItem("Hash Offset", ls.Format("%-26s (%s)", hashOffset.data(), hexHashOffset.data()));

            const auto identOffset    = nf.ToString(code.identOffset, dec);
            const auto hexIdentOffset = nf2.ToString(code.identOffset, hex);
            general->AddItem("Ident Offset", ls.Format("%-26s (%s)", identOffset.data(), hexIdentOffset.data()));

            const auto nSpecialSlots   = nf.ToString(code.nSpecialSlots, dec);
            const auto hexSpecialSlots = nf2.ToString(code.nSpecialSlots, hex);
            general->AddItem("Special Slots", ls.Format("%-26s (%s)", nSpecialSlots.data(), hexSpecialSlots.data()));

            const auto nCodeSlots   = nf.ToString(code.nCodeSlots, dec);
            const auto hexCodeSlots = nf2.ToString(code.nCodeSlots, hex);
            general->AddItem("Code Slots", ls.Format("%-26s (%s)", nCodeSlots.data(), hexCodeSlots.data()));

            const auto codeLimit    = nf.ToString(code.codeLimit, dec);
            const auto hexCodeLimit = nf2.ToString(code.codeLimit, hex);
            general->AddItem("Code Limit", ls.Format("%-26s (%s)", codeLimit.data(), hexCodeLimit.data()));

            const auto hashSize    = nf.ToString(code.hashSize, dec);
            const auto hexHashSize = nf2.ToString(code.hashSize, hex);
            general->AddItem("Hash Size", ls.Format("%-26s (%s)", hexHashSize.data(), hexHashSize.data()));

            const auto& hashType   = MAC::CodeSignHashTypeNames.at(static_cast<MAC::CodeSignMagic>(code.hashType));
            const auto hexHashType = nf2.ToString(code.hashType, hex);
            general->AddItem("Hash Type", ls.Format("%-26s (%s)", hashType.data(), hexHashType.data()));

            const auto& platform   = MAC::CodeSignPlatformNames.at(code.platform);
            const auto hexPlatform = nf2.ToString(static_cast<uint32_t>(code.platform), hex);
            general->AddItem("Platform", ls.Format("%-26s (%s)", platform.data(), hexPlatform.data()));

            const auto pageSize    = nf.ToString(code.pageSize, dec);
            const auto hexPageSize = nf2.ToString(code.pageSize, hex);
            general->AddItem("Page Size", ls.Format("%-26s (%s)", pageSize.data(), hexPageSize.data()));

            const auto spare2    = nf.ToString(code.spare2, dec);
            const auto hexSpare2 = nf2.ToString(code.spare2, hex);
            general->AddItem("Spare2", ls.Format("%-26s (%s)", spare2.data(), hexSpare2.data()));

            if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSSCATTER))
            {
                const auto scatterOffset    = nf.ToString(code.scatterOffset, dec);
                const auto hexScatterOffset = nf2.ToString(code.scatterOffset, hex);
                general->AddItem("Scatter Offset", ls.Format("%-26s (%s)", scatterOffset.data(), hexScatterOffset.data()));
            }

            if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSTEAMID))
            {
                const auto teamOffset    = nf.ToString(code.teamOffset, dec);
                const auto hexTeamOffset = nf2.ToString(code.teamOffset, hex);
                general->AddItem("Team Offset", ls.Format("%-26s (%s)", teamOffset.data(), hexTeamOffset.data()));
            }

            if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSCODELIMIT64))
            {
                const auto spare3    = nf.ToString(code.spare3, dec);
                const auto hexSpare3 = nf2.ToString(code.spare3, hex);
                general->AddItem("Spare3", ls.Format("%-26s (%s)", spare3.data(), hexSpare3.data()));

                const auto codeLimit64    = nf.ToString(code.codeLimit64, dec);
                const auto hexCodeLimit64 = nf2.ToString(code.codeLimit64, hex);
                general->AddItem("Code Limit", ls.Format("%-26s (%s)", codeLimit64.data(), hexCodeLimit64.data()));
            }

            if (code.version >= static_cast<uint32>(MAC::CodeSignMagic::CS_SUPPORTSEXECSEG))
            {
                const auto execSegBase    = nf.ToString(code.execSegBase, dec);
                const auto hexExecSegBase = nf2.ToString(code.execSegBase, hex);
                general->AddItem("Exec Seg Base", ls.Format("%-26s (%s)", execSegBase.data(), hexExecSegBase.data()));

                const auto execSegLimit    = nf.ToString(code.execSegLimit, dec);
                const auto hexExecSegLimit = nf2.ToString(code.execSegLimit, hex);
                general->AddItem("Exec Seg Limit", ls.Format("%-26s (%s)", execSegLimit.data(), hexExecSegLimit.data()));

                const auto execSegFlags    = nf.ToString(code.execSegFlags, dec);
                const auto hexExecSegFlags = nf2.ToString(code.execSegFlags, hex);
                general->AddItem("Exec Seg Flags", ls.Format("%-26s (%s)", execSegFlags.data(), hexExecSegFlags.data()));

                const auto execFlagsData = MAC::GetCodeSignExecSegFlagsData(code.execSegFlags);
                for (const auto& flag : execFlagsData)
                {
                    LocalString<16> hfls;
                    hfls.Format("(0x%X)", flag);

                    const auto flagName        = MAC::CodeSignExecSegFlagNames.at(flag).data();
                    const auto flagDescription = MAC::CodeSignExecSegFlagsDescriptions.at(flag).data();

                    const auto fh = general->AddItem("", ls.Format("%-26s %-12s %s", flagName, hfls.GetText(), flagDescription));
                    general->SetItemType(fh, ListViewItemType::Emphasized_2);
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
        break;
        default:
            break;
        }
    }
}

void CodeSignMagic::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), general->GetItemsCount() + 3);
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
} // namespace GView::Type::MachO::Panels

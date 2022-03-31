#include "Hashes.hpp"

namespace GView::GenericPlugins::Hashes
{
HashesDialog::HashesDialog() : Window("Hashes", "d:c,w:70,h:20", WindowFlags::Sizeable | WindowFlags::Maximized)
{
    hashesList = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:20");
    hashesList->AddColumn("Type", TextAlignament::Left, 12);
    hashesList->AddColumn("Value", TextAlignament::Left, 100);

    close                              = Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE);
    close->Handlers()->OnButtonPressed = this;
}

bool HashesDialog::ComputeHashes(Reference<GView::Object> object)
{
    CHECK(adler32.Init(), false, "");
    CHECK(crc16.Init(), false, "");
    CHECK(crc32Zero.Init(CRC32Type::ZERO), false, "");
    CHECK(crc32Neg.Init(CRC32Type::NEGL), false, "");
    CHECK(crc64Zero.Init(CRC64Type::ECMA_182), false, "");
    CHECK(crc64Neg.Init(CRC64Type::WE), false, "");
    CHECK(md2.Init(), false, "");
    CHECK(md4.Init(), false, "");
    CHECK(md5.Init(), false, "");

    constexpr auto block = 0x1000ULL;
    auto offset          = 0ULL;
    auto left            = object->cache.GetSize();

    Buffer buffer;
    do
    {
        const auto sizeToRead = (left >= block ? block : left);
        left -= (left >= block ? block : left);

        buffer = object->cache.CopyToBuffer(offset, static_cast<uint32>(sizeToRead), true);
        CHECK(buffer.IsValid(), false, "");

        CHECK(adler32.Update(buffer), false, "");
        CHECK(crc16.Update(buffer), false, "");
        CHECK(crc32Zero.Update(buffer), false, "");
        CHECK(crc32Neg.Update(buffer), false, "");
        CHECK(crc64Zero.Update(buffer), false, "");
        CHECK(crc64Neg.Update(buffer), false, "");
        CHECK(md2.Update(buffer), false, "");
        CHECK(md4.Update(buffer), false, "");
        CHECK(md5.Update(buffer), false, "");

        offset += sizeToRead;
    } while (left > 0);

    uint32 adler32hash = 0;
    CHECK(adler32.Final(adler32hash), false, "");
    uint16 crc16Hash = 0;
    CHECK(crc16.Final(crc16Hash), false, "");
    uint32 crc32Zerohash = 0;
    CHECK(crc32Zero.Final(crc32Zerohash), false, "");
    uint32 crc32NegHash = 0;
    CHECK(crc32Neg.Final(crc32NegHash), false, "");
    uint64 crc64Zerohash = 0;
    CHECK(crc64Zero.Final(crc64Zerohash), false, "");
    uint64 crc64Neghash = 0;
    CHECK(crc64Neg.Final(crc64Neghash), false, "");
    uint8 md2Hash[16] = { 0 };
    CHECK(md2.Final(md2Hash), false, "");
    uint8 md4Hash[16] = { 0 };
    CHECK(md4.Final(md4Hash), false, "");
    uint8 md5Hash[16] = { 0 };
    CHECK(md5.Final(md5Hash), false, "");

    LocalString<256> ls;
    NumericFormatter nf;
    hashesList->AddItem("Adler32", ls.Format("0x%.8X", adler32hash));
    hashesList->AddItem("CRC16", ls.Format("0x%.8X", crc16Hash));
    hashesList->AddItem("CRC32(0)", ls.Format("0x%.8X", crc32Zerohash));
    hashesList->AddItem("CRC32(-1)", ls.Format("0x%.8X", crc32NegHash));
    hashesList->AddItem("CRC64(0)", ls.Format("0x%.16llX", crc64Zerohash));
    hashesList->AddItem("CRC64(-1)", ls.Format("0x%.16llX", crc64Neghash));
    hashesList->AddItem(
          "MD2",
          ls.Format(
                "0x%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X",
                md2Hash[0],
                md2Hash[1],
                md2Hash[2],
                md2Hash[3],
                md2Hash[4],
                md2Hash[5],
                md2Hash[6],
                md2Hash[7],
                md2Hash[8],
                md2Hash[9],
                md2Hash[10],
                md2Hash[11],
                md2Hash[12],
                md2Hash[13],
                md2Hash[14],
                md2Hash[15]));
    hashesList->AddItem(
          "MD4",
          ls.Format(
                "0x%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X",
                md4Hash[0],
                md4Hash[1],
                md4Hash[2],
                md4Hash[3],
                md4Hash[4],
                md4Hash[5],
                md4Hash[6],
                md4Hash[7],
                md4Hash[8],
                md4Hash[9],
                md4Hash[10],
                md4Hash[11],
                md4Hash[12],
                md4Hash[13],
                md4Hash[14],
                md4Hash[15]));
    hashesList->AddItem(
          "MD5",
          ls.Format(
                "0x%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X",
                md5Hash[0],
                md5Hash[1],
                md5Hash[2],
                md5Hash[3],
                md5Hash[4],
                md5Hash[5],
                md5Hash[6],
                md5Hash[7],
                md5Hash[8],
                md5Hash[9],
                md5Hash[10],
                md5Hash[11],
                md5Hash[12],
                md5Hash[13],
                md5Hash[14],
                md5Hash[15]));

    return true;
}

void HashesDialog::OnButtonPressed(Reference<Button>)
{
    Exit(0);
}
} // namespace GView::GenericPlugins::Hashes

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
    {
        if (command == "Hashes")
        {
            GView::GenericPlugins::Hashes::HashesDialog dlg;
            dlg.ComputeHashes(object);
            dlg.Show();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.Hashes"] = Input::Key::Shift | Input::Key::F5;
    }
}

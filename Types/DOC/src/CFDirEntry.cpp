#include "doc.hpp"


using namespace GView::Type::DOC;


CFDirEntry::CFDirEntry()
{
}

CFDirEntry::CFDirEntry(BufferView _directoryData, uint32 _entryId)
{
    Load(_directoryData, _entryId);
}

void CFDirEntry::AppendChildren(uint32 childId)
{
    if (childId == NOSTREAM) {
        return;
    }

    CFDirEntry child(directoryData, childId);

    AppendChildren(child.data.leftSiblingId);
    size_t childIndex = children.size();
    children.emplace_back();
    AppendChildren(child.data.rightSiblingId);

    child.BuildStorageTree();

    children[childIndex] = child;
};


bool CFDirEntry::Load(BufferView _directoryData, uint32 _entryId)
{
    CHECK(!initialized, false, "already initialized");
    initialized = true;

    directoryData = _directoryData;
    entryId       = _entryId;
    data          = ByteStream(directoryData).Seek(entryId * sizeof(CFDirEntry_Data)).ReadAs<CFDirEntry_Data>();

    CHECK(data.nameLength % 2 == 0, false, "nameLength");
    CHECK(data.objectType == 0x00 || data.objectType == 0x01 || data.objectType == 0x02 || data.objectType == 0x05, false, "objectType");
    CHECK(data.colorFlag == 0x00 || data.colorFlag == 0x01, false, "colorFlag");

    return true;
}


void CFDirEntry::BuildStorageTree()
{
    if (data.childId == NOSTREAM) {
        return;
    }

    // add children
    AppendChildren(data.childId);
}

bool CFDirEntry::FindChildByName(std::u16string_view entryName, CFDirEntry& entry)
{
    std::u16string_view currentEntryName((char16_t*) this->data.nameUnicode, this->data.nameLength / 2 - 1);
    if (!entryName.starts_with(currentEntryName)) {
        return false;
    }

    auto pos = entryName.find_first_of(u'/');
    if (pos == std::u16string::npos) {
        entry = *this;
        return true;
    }

    for (CFDirEntry& child : children) {
        std::u16string_view newEntryName = entryName.substr(pos + 1);
        if (child.FindChildByName(newEntryName, entry)) {
            return true;
        }
    }
    return false;
}


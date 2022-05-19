#include "sqlite.hpp"

using namespace GView::Type::SQLite;

std::string_view SQLiteFile::GetTypeName()
{
    return "SQLite";
}

bool SQLiteFile::Update()
{
    // memvfs requires a non-const buffer in order to load an in-memory database.
    // Therefore, a copy is required.
    // memOpen() -> https://www.sqlite.org/src/file/ext/misc/memvfs.c
    buf = obj->GetData().CopyEntireFile();
    CHECK(buf.IsValid(), false, "Fail to copy entire file");

    db = DB(buf);

    return true;
}
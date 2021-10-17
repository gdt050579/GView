#include "GViewApp.hpp"

using namespace GView::View;

Buffer::Factory::Factory(const std::string_view& name)
{
    for (unsigned int tr = 0; tr < 10; tr++)
        this->bookmarks[tr] = GView::Utils::INVALID_OFFSET;
    this->translationMethodsCount = 0;
    queryInterface = nullptr;
}
void Buffer::Factory::AddZone(unsigned long long start, unsigned long long size, AppCUI::Graphics::ColorPair col, std::string_view name)
{
    this->zList.Add(start, size, col, name);
}
void Buffer::Factory::AddBookmark(unsigned char index, unsigned long long fileOffset)
{
    if (index < 10)
        this->bookmarks[index] = fileOffset;
}
void Buffer::Factory::AddOffsetTranslationMethod(std::string_view name, MethodID ID)
{
    // check if method ID is unique
    for (unsigned int tr = 0; tr < translationMethodsCount; tr++)
        if (this->translationMethods[tr].methodID == ID)
            return;
    if (translationMethodsCount >= sizeof(translationMethods) / sizeof(OffsetTranslationMethod))
        return;
    auto m = &translationMethods[translationMethodsCount];
    m->methodID = ID;
    m->nameLength = (unsigned char)std::min(name.length(), sizeof(m->name));
    if (m->nameLength == 0)
        return;
    memcpy(m->name, name.data(), m->nameLength);
    translationMethodsCount++;
}
void Buffer::Factory::SetQueryInterface(QueryInterface* _queryInterface)
{
    this->queryInterface = _queryInterface;
}
Pointer<Control> Buffer::Factory::Build(GView::Object& obj)
{
    return Pointer<Control>(new Buffer::ViewerControl(obj, this));
}
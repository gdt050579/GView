#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

void FoldColumn::SetBlock(int32 index, uint32 blockID)
{
    if ((index >= 0) && (index < this->count))
    {
        auto* p = this->indexes + index;
        if ((*p) == BlockObject::INVALID_ID)
        {
            *p = blockID;
        }
    }
}
void FoldColumn::Clear(int32 height)
{
    if (height < 0)
        height = 0;
    this->count = std::min<>(height, MAX_INDEXES);
    auto* p     = this->indexes;
    auto* e     = p + this->count;
    for (; p < e; p++)
        (*p) = BlockObject::INVALID_ID;
}
void FoldColumn::Paint(AppCUI::Graphics::Renderer& renderer, int32 x, Instance* instance)
{

}
} // namespace GView::View::LexicalViewer
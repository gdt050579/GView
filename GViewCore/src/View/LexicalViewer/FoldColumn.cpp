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
void FoldColumn::Clear(int32 _height)
{
    if (_height < 0)
        _height = 0;
    this->count  = std::min<>(_height, MAX_INDEXES);
    this->height = _height;
    auto* p      = this->indexes;
    auto* e      = p + this->count;
    for (; p < e; p++)
        (*p) = BlockObject::INVALID_ID;
}
void FoldColumn::Paint(AppCUI::Graphics::Renderer& renderer, int32 x, Instance* instance)
{
    auto state        = instance->HasFocus() ? ControlState::Focused : ControlState::Normal;
    auto cfg          = instance->GetConfig();
    auto lineSepColor = cfg->Lines.GetColor(state);
    const uint32* p   = this->indexes;
    const uint32* e   = p + this->count;

    renderer.DrawVerticalLine(x, 0, this->height, lineSepColor);
    for (; p < e; p++)
    {
        if ((*p) == BlockObject::INVALID_ID)
            continue;
        auto yPoz           = static_cast<int32>(p - this->indexes);
        auto symbolSepColor = yPoz == this->mouseHoverIndex ? cfg->Symbol.Hovered : cfg->Symbol.Arrows;
        if (instance->tokens[instance->blocks[*p].tokenStart].IsFolded())
            renderer.WriteCharacter(x, yPoz, '+', symbolSepColor);
        else
            renderer.WriteCharacter(x, yPoz, '-', symbolSepColor);
    }
}
} // namespace GView::View::LexicalViewer
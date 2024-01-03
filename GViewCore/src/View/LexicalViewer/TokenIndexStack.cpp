#include <GView.hpp>

namespace GView::View::LexicalViewer
{
constexpr uint32 MAX_ITEMS = 0x10000;
TokenIndexStack::TokenIndexStack()
{
    this->stack     = nullptr;
    this->count     = 0;
    this->allocated = TokenIndexStack::LOCAL_SIZE;    
}
TokenIndexStack::~TokenIndexStack()
{
    if (this->stack)
        delete[] this->stack;
    this->stack     = nullptr;
    this->count     = 0;
    this->allocated = 0;
}
bool TokenIndexStack::Push(uint32 index)
{
    if (this->stack)
    {
        if (this->count < this->allocated)
        {
            this->stack[this->count++] = index;
        }
        else
        {
            if (this->allocated > MAX_ITEMS)
                return false; // can not allocate more that 0x10000 items
            // double the size
            try
            {
                auto* temp = new uint32[this->allocated * 2ull];
                memcpy(temp, this->stack, this->count * sizeof(uint32));
                delete[] this->stack;
                this->stack                = temp;
                this->allocated            = this->allocated * 2;
                this->stack[this->count++] = index;
            }
            catch (...)
            {
                return false;
            }
        }
    }
    else
    {
        if (this->count < TokenIndexStack::LOCAL_SIZE)
        {
            this->local[this->count++] = index;
        }
        else
        {
            // need to allocate on heap
            try
            {
                this->stack     = new uint32[TokenIndexStack::LOCAL_SIZE * 2];
                this->allocated = TokenIndexStack::LOCAL_SIZE * 2;
                memcpy(this->stack, this->local, TokenIndexStack::LOCAL_SIZE * sizeof(uint32));
                this->stack[this->count++] = index;
            }
            catch (...)
            {
                this->stack = nullptr;
                return false;
            }
        }
    }
    return true;
}
uint32 TokenIndexStack::Pop(uint32 errorValue)
{
    if (this->count == 0)
        return errorValue;
    this->count--;
    if (this->stack)
        return this->stack[this->count];
    else
        return this->local[this->count];
}
} // namespace GView::View::LexicalViewer
#include "GViewApp.hpp"

using namespace GView::View::Buffer;

const char hexCharsList[] = "0123456789ABCDEF";
const unsigned int characterFormatModeSize[] = {2 /*Hex*/,3 /*Oct*/,4 /*signed 8*/,3 /*unsigned 8*/};

/*
- full, 8 col, 16 col, 32 col
        [for col only: hex/dec]
        [for col only: signed 8/16/32/64, unsigned 8/16/32/64, float 32/64]
        => char => hex[8,16,32,64], dec[s|u + 8,16,32,64], F32|F64
*/

ViewerControl::ViewerControl(GView::Object& obj, Buffer::Factory* setting) : UserControl("d:c"), fileObj(obj)
{
    this->chars.Fill('-', 1024, ColorPair{ Color::Black,Color::DarkBlue });
    this->nrCols = 0;
    this->charFormatMode = CharacterFormatMode::Hex;
    this->LineOffsetSize = 8;
    this->LineNameSize = 8;
}
void ViewerControl::PrepareDrawLineInfo(DrawLineInfo& dli)
{
    if (dli.recomputeOffsets)
    {
        // need to recompute all offsets
        dli.offsetAndNameSize = this->LineOffsetSize;
        if (this->LineNameSize > 0)
        {
            if (dli.offsetAndNameSize > 0)
                dli.offsetAndNameSize += this->LineNameSize + 1; // one extra space
            else
                dli.offsetAndNameSize += this->LineNameSize;
        }
        if (dli.offsetAndNameSize > 0)
            dli.offsetAndNameSize += 3; // 3 extra spaces between offset (address) and characters
        if (nrCols == 0)
        {
            // full screen --> ascii only
            auto width = (unsigned int)this->GetWidth();
            dli.numbersSize = 0;
            if (dli.offsetAndNameSize + 1 < width)
                dli.textSize = width - (1 + dli.offsetAndNameSize);
            else
                dli.textSize = 0;
        }
        else {
            auto sz = characterFormatModeSize[(unsigned int)this->charFormatMode];
            dli.numbersSize = nrCols * (sz + 1)+ 3 ; // one extra space between chrars + 3 spaces at the end
            dli.textSize = nrCols;
        }
        // make sure that we have enough buffer
        this->chars.Resize(dli.offsetAndNameSize + dli.textSize + dli.numbersSize);
        dli.recomputeOffsets = false;
    }
    auto buf            = this->fileObj.cache.Get(dli.offset, dli.textSize);
    dli.start           = buf.data;
    dli.end             = buf.data + buf.length;
    dli.chNameAndSize   = this->chars.GetBuffer();
    dli.chText          = dli.chNameAndSize + (dli.offsetAndNameSize + dli.numbersSize);
    dli.chNumbers       = dli.chNameAndSize + dli.offsetAndNameSize;

}
void ViewerControl::WriteLineTextToChars(DrawLineInfo& dli)
{

    auto cp = NoColorPair;


    while (dli.start < dli.end)
    {
        cp = ColorPair{ Color::White,Color::Black };

        dli.chText->Code = *dli.start; dli.chText->Color = cp; dli.chText++;
        dli.start++;
    }
}
void ViewerControl::WriteLineNumbersToChars(DrawLineInfo& dli)
{
    auto c   = dli.chNumbers;
    auto cp  = NoColorPair;
    auto ut  = (unsigned char)0;

    while (dli.start < dli.end)
    {
        cp = ColorPair{ Color::White,Color::Black };
        switch (charFormatMode)
        {
        case CharacterFormatMode::Hex:
            c->Code = hexCharsList[(*dli.start) >> 4]; c->Color = cp; c++;
            c->Code = hexCharsList[(*dli.start) & 0x0F]; c->Color = cp; c++;
            break;
        case CharacterFormatMode::Octal:
            c->Code = '0' + ((*dli.start) >> 6); c->Color = cp; c++;
            c->Code = '0' + (((*dli.start) >> 3) & 0x7); c->Color = cp; c++;
            c->Code = '0' + ((*dli.start) & 0x7); c->Color = cp; c++;
            break;
        case CharacterFormatMode::UnsignedDecimal:
            if ((*dli.start) < 10)
            {
                c->Code = ' '; c->Color = cp; c++;
                c->Code = ' '; c->Color = cp; c++;
                c->Code = '0' + *dli.start; c->Color = cp; c++;
            }
            else if ((*dli.start) < 100)
            {
                c->Code = ' '; c->Color = cp; c++;
                c->Code = '0' + ((*dli.start) / 10); c->Color = cp; c++;
                c->Code = '0' + ((*dli.start) % 10); c->Color = cp; c++;
            }
            else {
                ut = *dli.start;
                c->Code = '0' + (ut / 100); c->Color = cp; c++; ut = ut % 100;
                c->Code = '0' + (ut / 10); c->Color = cp; c++; ut = ut % 10;
                c->Code = '0' + ut; c->Color = cp; c++;
            }
            break;
        case CharacterFormatMode::SignedDecimal:
            // Not implemented
            break;
        }
        c->Code = ' '; c->Color = cp; c++;
        dli.chText->Code = *dli.start; dli.chText->Color = cp; dli.chText++;
        dli.start++;
    }

}
void ViewerControl::Paint(Renderer& renderer)
{
    renderer.Clear(' ', ColorPair{ Color::White,Color::Black });
    DrawLineInfo dli;
    for (unsigned int tr = 0; tr < 20; tr++)
    {
        dli.offset = tr * 128;
        PrepareDrawLineInfo(dli);
        if (nrCols == 0)
            WriteLineTextToChars(dli);
        else
            WriteLineNumbersToChars(dli);
        renderer.WriteSingleLineCharacterBuffer(0, tr, chars);
    }
}
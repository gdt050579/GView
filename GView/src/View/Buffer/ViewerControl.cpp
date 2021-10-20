#include "GViewApp.hpp"

using namespace GView::View::Buffer;
using namespace AppCUI::Input;

const char hexCharsList[] = "0123456789ABCDEF";
const unsigned int characterFormatModeSize[] = { 2 /*Hex*/,3 /*Oct*/,4 /*signed 8*/,3 /*unsigned 8*/ };

const char16_t CodePage_437[] = { 0x0020,0x263A,0x263B,0x2665,0x2666,0x2663,0x2660,0x2022,0x25D8,0x25CB,0x25D9,0x2642,0x2640,0x266A,0x266B,0x263C,0x25BA,0x25C4,0x2195,0x203C,0x00B6,0x00A7,0x25AC,0x21A8,0x2191,0x2193,0x2192,0x2190,0x221F,0x2194,0x25B2,0x25BC,0x0020,0x0021,0x0022,0x0023,0x0024,0x0025,0x0026,0x0027,0x0028,0x0029,0x002A,0x002B,0x002C,0x002D,0x002E,0x002F,0x0030,0x0031,0x0032,0x0033,0x0034,0x0035,0x0036,0x0037,0x0038,0x0039,0x003A,0x003B,0x003C,0x003D,0x003E,0x003F,0x0040,0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,0x0049,0x004A,0x004B,0x004C,0x004D,0x004E,0x004F,0x0050,0x0051,0x0052,0x0053,0x0054,0x0055,0x0056,0x0057,0x0058,0x0059,0x005A,0x005B,0x005C,0x005D,0x005E,0x005F,0x0060,0x0061,0x0062,0x0063,0x0064,0x0065,0x0066,0x0067,0x0068,0x0069,0x006A,0x006B,0x006C,0x006D,0x006E,0x006F,0x0070,0x0071,0x0072,0x0073,0x0074,0x0075,0x0076,0x0077,0x0078,0x0079,0x007A,0x007B,0x007C,0x007D,0x007E,0x2302,0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,0x00FF,0x00D6,0x00DC,0x00A2,0x00A3,0x00A5,0x20A7,0x0192,0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,0x00BF,0x2310,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,0x03B1,0x00DF,0x0393,0x03C0,0x03A3,0x03C3,0x00B5,0x03C4,0x03A6,0x0398,0x03A9,0x03B4,0x221E,0x03C6,0x03B5,0x2229,0x2261,0x00B1,0x2265,0x2264,0x2320,0x2321,0x00F7,0x2248,0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x0020 };

ViewerControl::ViewerControl(GView::Object& obj, Buffer::Factory* setting) : UserControl("d:c"), fileObj(obj)
{
	this->chars.Fill('-', 1024, ColorPair{ Color::Black,Color::DarkBlue });
	this->nrCols = 0;
	this->charFormatMode = CharacterFormatMode::Hex;
	this->LineOffsetSize = 8;
	this->LineNameSize = 8;
	this->CharactersPerLine = 1;
	this->VisibleRows = 1;
	this->CodePage = CodePage_437;
	this->fileObj.currentPos = 0;
	this->OffsetStartView = 0;
}
void ViewerControl::MoveTo(unsigned long long offset, bool select)
{
	if (this->fileObj.cache.GetSize() == 0)
		return;
	if (offset > (fileObj.cache.GetSize() - 1))
		offset = fileObj.cache.GetSize() - 1;

	auto h = this->VisibleRows;
	auto sz = this->CharactersPerLine * h;
	if ((this->OffsetStartView >= offset) && (offset < this->OffsetStartView + sz))
		return; // nothing to do ... already in visual space
	if (offset < this->OffsetStartView)
		this->OffsetStartView = offset;
	else {
		if (offset >= (sz + 1))
			this->OffsetStartView = offset - (sz + 1);
		else
			this->OffsetStartView = 0;
	}
}
void ViewerControl::MoveScrollTo(unsigned long long offset)
{
	if (this->fileObj.cache.GetSize() == 0)
		return;
	if (offset > (fileObj.cache.GetSize() - 1))
		offset = fileObj.cache.GetSize() - 1;
	auto old = this->OffsetStartView;
	this->OffsetStartView = offset;
	if (this->OffsetStartView > old)
		MoveTo(this->fileObj.currentPos + (this->OffsetStartView - old), false);
	else {
		auto dif = old - OffsetStartView;
		if (dif > this->fileObj.currentPos)
			MoveTo(this->fileObj.currentPos - dif, false);
		else
			MoveTo(0, false);
	}
}
void ViewerControl::MoveToSelection(unsigned int selIndex)
{
	unsigned long long start, end;

	if (this->fileObj.selection.GetSelection(selIndex, start, end))
	{
		if (this->fileObj.currentPos != start)
			MoveTo(start, false);
		else
			MoveTo(end, false);
	}
}

void ViewerControl::UpdateViewSizes()
{
	// need to recompute all offsets
	auto sz = this->LineOffsetSize;

	if (this->LineNameSize > 0)
	{
		if (sz > 0)
			sz += this->LineNameSize + 1; // one extra space
		else
			sz += this->LineNameSize;
	}
	if (sz > 0)
		sz += 3; // 3 extra spaces between offset (address) and characters
	if (nrCols == 0)
	{
		// full screen --> ascii only
		auto width = (unsigned int)this->GetWidth();
		if (sz + 1 < width)
			this->CharactersPerLine = width - (1 + sz);
		else
			this->CharactersPerLine = 1;
	}
	else {
		this->CharactersPerLine = nrCols;
	}
	// compute visible rows 
	this->VisibleRows = this->GetHeight();
	if (this->VisibleRows > 0)
		this->VisibleRows--;
	if (this->VisibleRows == 0)
		this->VisibleRows = 1;

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
			dli.numbersSize = nrCols * (sz + 1) + 3; // one extra space between chrars + 3 spaces at the end
			dli.textSize = nrCols;
		}
		// make sure that we have enough buffer
		this->chars.Resize(dli.offsetAndNameSize + dli.textSize + dli.numbersSize);
		dli.recomputeOffsets = false;
	}
	auto buf = this->fileObj.cache.Get(dli.offset, dli.textSize);
	dli.start = buf.data;
	dli.end = buf.data + buf.length;
	dli.chNameAndSize = this->chars.GetBuffer();
	dli.chText = dli.chNameAndSize + (dli.offsetAndNameSize + dli.numbersSize);
	dli.chNumbers = dli.chNameAndSize + dli.offsetAndNameSize;

}
void ViewerControl::WriteLineTextToChars(DrawLineInfo& dli)
{

	auto cp = NoColorPair;


	while (dli.start < dli.end)
	{
		cp = ColorPair{ Color::White,Color::Black };

		dli.chText->Code = CodePage[*dli.start]; dli.chText->Color = cp; dli.chText++;
		dli.start++;
	}
}
void ViewerControl::WriteLineNumbersToChars(DrawLineInfo& dli)
{
	auto c = dli.chNumbers;
	auto cp = NoColorPair;
	auto ut = (unsigned char)0;

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
		dli.chText->Code = CodePage[*dli.start]; dli.chText->Color = cp; dli.chText++;
		dli.start++;
	}

}
void ViewerControl::Paint(Renderer& renderer)
{
	renderer.Clear(' ', ColorPair{ Color::White,Color::Black });
	DrawLineInfo dli;


	for (unsigned int tr = 0; tr < this->VisibleRows; tr++)
	{
		dli.offset = ((unsigned long long)this->CharactersPerLine) * tr + this->OffsetStartView;
		if (dli.offset >= this->fileObj.cache.GetSize())
			break;
		PrepareDrawLineInfo(dli);
		if (nrCols == 0)
			WriteLineTextToChars(dli);
		else
			WriteLineNumbersToChars(dli);
		renderer.WriteSingleLineCharacterBuffer(0, tr, chars);
	}
}
void ViewerControl::OnAfterResize(int width, int height)
{
	this->UpdateViewSizes();
}

bool ViewerControl::OnKeyEvent(AppCUI::Input::Key keyCode, char16_t charCode)
{
	bool select = ((keyCode & Key::Shift) != Key::None);
	if (select)
		keyCode = static_cast<Key>((unsigned int)keyCode - (unsigned int)Key::Shift);

	// tratare cazuri editare
	if (this->EditMode)
	{
		if ((KeyCode == Key::Tab) || (KeyCode == (Key::Tab | Key::Ctrl)))
		{
			if (IsNormalRow()) { editNumbers = !editNumbers; editNumbersOfs = 0; }
			return true;
		}
		if (KeyCode == Key::Backspace)
		{
			if (editNumbersOfs > 0) editNumbersOfs--;
			return true;
		}
		if (charCode >= 32)
		{
			AddChar(charCode);
			return true;
		}
	}

	switch (keyCode)
	{
	case Key::Down:
		MoveTo(this->fileObj.currentPos + this->CharactersPerLine, select);
		return true;
	case Key::Up:
		if (this->fileObj.currentPos > this->CharactersPerLine)
			MoveTo(this->fileObj.currentPos - this->CharactersPerLine, select);
		else
			MoveTo(0, select);
		return true;
	case Key::Left: if (this->fileObj.currentPos > 0) MoveTo(this->fileObj.currentPos - 1, select); return true;
	case Key::Right: MoveTo(this->fileObj.currentPos + 1, select); return true;
	case Key::PageDown: MoveTo(this->fileObj.currentPos + GetTotalViewSize(), select); return true;
	case Key::PageUp: if (this->fileObj.currentPos > GetTotalViewSize()) MoveTo(this->fileObj.currentPos - GetTotalViewSize(), select); else MoveTo(0, select); return true;
	case Key::Home: MoveTo(this->fileObj.currentPos - (this->fileObj.currentPos - this->OffsetStartView) % this->CharactersPerLine, select); return true;
	case Key::End: MoveTo(this->fileObj.currentPos - (this->fileObj.currentPos - this->OffsetStartView) % this->CharactersPerLine + this->CharactersPerLine - 1, select); return true;

	case Key::Ctrl | Key::Up: if (this->OffsetStartView > this->CharactersPerLine) MoveScrollTo(this->OffsetStartView - this->CharactersPerLine); else MoveScrollTo(0); return true;
	case Key::Ctrl | Key::Down: MoveScrollTo(this->OffsetStartView + this->CharactersPerLine); return true;
	case Key::Ctrl | Key::Left: if (this->OffsetStartView >= 1) MoveScrollTo(this->OffsetStartView - 1); return true;
	case Key::Ctrl | Key::Right: MoveScrollTo(this->OffsetStartView + 1); return true;


	case Key::Ctrl | Key::Home: MoveTo(0, select); return true;
	case Key::Ctrl | Key::End: MoveTo(this->File->Cache.GetFileSize(), select); return true;
	case Key::Ctrl | Key::PageUp: MoveToEndOrStartZone(select, true); return true;
	case Key::Ctrl | Key::PageDown: MoveToEndOrStartZone(select, false); return true;

	case Key::Ctrl | Key::Alt | Key::PageUp: MoveTillNextBlock(select, -1); return true;
	case Key::Ctrl | Key::Alt | Key::PageDown: MoveTillNextBlock(select, 1); return true;

	case Key::Alt | Key::N1: MoveToSelection(0); return true;
	case Key::Alt | Key::N2: MoveToSelection(1); return true;
	case Key::Alt | Key::N3: MoveToSelection(2); return true;
	case Key::Alt | Key::N4: MoveToSelection(3); return true;
	case Key::Alt | Key::N0: MoveToSelection(4); return true;

	case Key::E: MoveTillEndBlock(select); return true;
	case Key::S: SkipCurentCaracter(select); return true;
		//case VK_MULTIPLY: if (this->File->Bookmarks[0]!=INVALID_FILE_POSITION) MoveTo(this->File->Bookmarks[0],select); return true;
		//case VK_NUMPAD0	: this->startViewPoz=this->fileObj.currentPos; return true;

		//case VK_NUMPAD8	: MoveScrollTo(this->startViewPoz-nrX); return true;
		//case VK_NUMPAD2	: MoveScrollTo(this->startViewPoz+nrX); return true;
		//case VK_NUMPAD4	: MoveScrollTo(this->startViewPoz-1); return true;
		//case VK_NUMPAD6	: MoveScrollTo(this->startViewPoz+1); return true;
		//case VK_NUMPAD5	: MoveScrollTo(this->fileObj.currentPos-(nrX*(ObjectR.h-2)/2)); return true;
		//case VK_NUMPAD9 : MoveToPrevSection(); return true;
		//case VK_NUMPAD3 : MoveToNextSection(); return true;
		//case VK_NUMPAD7 : this->startViewPoz=this->fileObj.currentPos; return true;
		//case VK_NUMPAD0	: MoveToAlignSection();return true;

		//case VK_MULTIPLY: MoveTo(GetInfo()->F.g->GetEntryPoint(),select); return true;

	};

	if ((charCode >= '0') && (charCode <= '9'))
	{
		auto addr = this->Bookmarks.Get(charCode - '0');
		if (addr != GView::Utils::INVALID_OFFSET)
			MoveTo(addr, select);
		return true;
	}

	switch (charCode)
	{
	case '[':
		if (this->LineOffsetSize > 0)
			LineOffsetSize--;
		this->UpdateViewSizes();
		return true;
	case ']':
		if (this->LineOffsetSize < 32)
			this->LineOffsetSize++;
		this->UpdateViewSizes();
		return true;
	case '{':
		if (this->LineNameSize > 0)
			this->LineNameSize--;
		this->UpdateViewSizes();
		return true;
	case '}':
		if (this->LineNameSize < 32)
			this->LineNameSize++;
		this->UpdateViewSizes();
		return true;
	}

	return false;
}
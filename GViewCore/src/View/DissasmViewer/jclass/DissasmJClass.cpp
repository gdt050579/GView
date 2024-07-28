#include "class_parser.hpp"
#include "DissasmViewer.hpp"
#include "DissasmCodeZone.hpp"

using namespace GView::View::DissasmViewer;
using namespace GView::View::DissasmViewer::JClass;

inline void PopulateZoneTextToDissasmAsmPreCacheLine(DissasmCodeZone* zone, const char* text, uint32 len)
{
    DissasmAsmPreCacheLine line = {};
    line.op_str                 = strdup(text);
    line.op_str_size            = len;
    zone->asmPreCacheData.cachedAsmLines.push_back(std::move(line));
}

bool Instance::DrawDissasmJavaByteCodeZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (!zone->isInit) {
        const auto buffer = this->obj->GetData().GetEntireFile();
        vector<ColoredArea> areas;
        areas.reserve(32);

        ClassParser parser;
        BufferReader reader{ buffer.GetData(), buffer.GetLength() };
        FCHECK(parser.parse(reader, areas));

        AstCreator creator{ parser };

        auto clazz = creator.create();
        if (clazz) {
            PopulateZoneTextToDissasmAsmPreCacheLine(zone, "Constant data:", strlen("Constant data:"));
            if (parser.constant_data.empty()) {
                PopulateZoneTextToDissasmAsmPreCacheLine(zone, "No constant data!", strlen("No constant data!"));
            }

            LocalString<64> line;
            for (auto& constantData : parser.constant_data) {
                line.SetFormat("    %s", ConstantKindNames[static_cast<uint32>(constantData.kind)]);
                PopulateZoneTextToDissasmAsmPreCacheLine(zone, line.GetText(), line.Len());
            }
        } else {
            const char* msg = "Failed to parse class file, there are still some features in progress!";
            PopulateZoneTextToDissasmAsmPreCacheLine(zone, msg, strlen(msg));
        }

        AdjustZoneExtendedSize(zone, zone->asmPreCacheData.cachedAsmLines.size());

        zone->isInit = true;
    }

    chars.Clear();

    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    LocalString<256> spaces;
    spaces.SetChars(' ', std::min<uint16>(256, Layout.startingTextLineOffset));
    chars.Set(spaces);

    if (dli.textLineToDraw == 0) {
        constexpr std::string_view zoneName = "[JClass] JavaBytecode";
        chars.Add(zoneName.data(), ColorMan.Colors.StructureColor);

        HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(zoneName.size()), static_cast<uint32>(zoneName.size()) + Layout.startingTextLineOffset);

        RegisterStructureCollapseButton(dli.screenLineToDraw + 1, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);
        return true;
    }

    const uint32 currentLine = dli.textLineToDraw - 1u;

    const char* lineText = zone->asmPreCacheData.cachedAsmLines[currentLine].op_str;
    chars.Add(lineText, ColorMan.Colors.AsmJumpInstruction);

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };
    HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(bufferToDraw.length()), static_cast<uint32>(bufferToDraw.length()));

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    return true;
}
#include "class_parser.hpp"
#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace GView::View::DissasmViewer::JClass;

bool Instance::DrawJavaBytecodeZone(DrawLineInfo& dli, JavaBytecodeZone* zone)
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
            zone->bytecodeLines.emplace_back("Constant data:");
            if (parser.constant_data.empty()) {
                zone->bytecodeLines.emplace_back("No constant data!");
            }

            LocalString<64> line;
            for (auto& constantData : parser.constant_data) {
                line.SetFormat("    %s", ConstantKindNames[static_cast<uint32>(constantData.kind)]);
                zone->bytecodeLines.emplace_back(line.GetText());
            }
        }else {
            zone->bytecodeLines.emplace_back("Failed to parse class file, there are still some features in progress!");
        }

        AdjustZoneExtendedSize(zone, zone->bytecodeLines.size());

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

    chars.Add(zone->bytecodeLines[currentLine].c_str(), ColorMan.Colors.AsmJumpInstruction);

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };
    HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(bufferToDraw.length()), static_cast<uint32>(bufferToDraw.length()));

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    return true;
}
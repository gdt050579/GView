#include "decompiler.hpp"
#include "distorm.h"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        if (buf.GetLength() < DECOMPILER_RZA_MAGIC_LENGTH)
            return false;
        return memcmp(buf.GetData(), DECOMPILER_RZA_MAGIC, DECOMPILER_RZA_MAGIC_LENGTH) == 0;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new DECOMPILER::DecompilerFile(file);
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto decompiler = reinterpret_cast<DECOMPILER::DecompilerFile*>(win->GetObject()->type);
        decompiler->win_interface = win;

        auto b = win->AddBufferViewer("Buffer View");
        decompiler->UpdateBufferViewZones(b);

        win->AddPanel(Pointer<TabPage>(new DECOMPILER::Panels::Sections(decompiler, win)), false);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect.UpdateValue("Pattern", "##RZABINARY", false);
        sect.UpdateValue("Priority", 1, false);
    }
}

int main()
{
    return 0;
}

void GView::Type::DECOMPILER::DecompilerFile::StartDecompiling()
{
    auto buffer = file->CopyToBuffer(DECOMPILER_RZA_MAGIC_LENGTH, file->GetSize() - DECOMPILER_RZA_MAGIC_LENGTH);
    _CodeInfo code{ 0, 0, 0, buffer.GetData(), buffer.GetLength() };
    _DInst* decodedInstructions = new _DInst[1000];
    _DecodedInst di;
    unsigned int decodedInstructionsCount = 0;
    auto res                              = distorm_decompose(&code, decodedInstructions, 1000, &decodedInstructionsCount);
    res                                   = res;

    char buffer_aux[1024];

    AppCUI::OS::File new_file;
    new_file.Create("E:\\asm_decompiled.text");
    unsigned int written = 0;
    new_file.WriteBuffer("##RZADECOMPILED", 15, written);
    written = 0;


    for (int i = 0; i < decodedInstructionsCount; i++)
    {
        distorm_format(&code, &decodedInstructions[i], &di);
        unsigned int print_bytes = snprintf(
              buffer_aux,
              1023,
              "%08I64x (%02d) %-24s %s%s%s\r\n",
              di.offset,
              di.size,
              (char*) di.instructionHex.p,
              (char*) di.mnemonic.p,
              di.operands.length != 0 ? " " : "",
              (char*) di.operands.p);

        new_file.WriteBuffer(buffer_aux, print_bytes, written);
    }

    delete[] decodedInstructions;
    
    new_file.Close();

    win_interface->AddNewGenericFileWindow("E:\\asm_decompiled.text");
}

GView::Type::DECOMPILER::DecompilerFile::DecompilerFile(Reference<GView::Utils::FileCache> file) : file(file)
{
}

void GView::Type::DECOMPILER::DecompilerFile::UpdateBufferViewZones(Reference<GView::View::BufferViewerInterface> bufferView)
{
    bufferView->AddZone(0, DECOMPILER_RZA_MAGIC_LENGTH, { Color::Red, Color::Transparent }, "RZAMAGIC");
}

std::string_view GView::Type::DECOMPILER::DecompilerFile::GetTypeName()
{
    return "decompiler";
}

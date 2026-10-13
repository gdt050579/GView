// The vocabulary declared by the core modules: the engine (built-ins) and every smart viewer. Plugins declare theirs
// through their RegisterPlugin export; the core modules are listed here because they are not loaded dynamically.

#include "VocabularyRegistry.hpp"

#include "BufferViewer.hpp"
#include "ContainerViewer.hpp"
#include "DissasmViewer.hpp"
#include "GridViewer.hpp"
#include "ImageViewer.hpp"
#include "LexicalViewer.hpp"
#include "TextViewer.hpp"

namespace GView::HDF
{
namespace
{
    const CoreModule CORE_MODULES[] = {
        { "Core:HDF", &DeclareBuiltins },
        { "SmartViewer:Buffer", &GView::View::BufferViewer::RegisterHDFVocabulary },
        { "SmartViewer:Container", &GView::View::ContainerViewer::RegisterHDFVocabulary },
        { "SmartViewer:Dissasm", &GView::View::DissasmViewer::RegisterHDFVocabulary },
        { "SmartViewer:Grid", &GView::View::GridViewer::RegisterHDFVocabulary },
        { "SmartViewer:Image", &GView::View::ImageViewer::RegisterHDFVocabulary },
        { "SmartViewer:Lexical", &GView::View::LexicalViewer::RegisterHDFVocabulary },
        { "SmartViewer:Text", &GView::View::TextViewer::RegisterHDFVocabulary },
    };
} // namespace

std::span<const CoreModule> CoreModules()
{
    return CORE_MODULES;
}

} // namespace GView::HDF

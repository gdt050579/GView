#include "Internal.hpp"
#include "BufferViewer.hpp"
#include "ImageViewer.hpp"
#include "GridViewer.hpp"
#include "DissasmViewer.hpp"
#include "TextViewer.hpp"
#include "ContainerViewer.hpp"
#include "LexicalViewer.hpp"

using namespace GView::App;
using namespace GView::View;

namespace
{
const Keys::ViewerKeys VIEWER_KEYS[] = {
    { "View.Buffer", "Buffer viewer", &BufferViewer::Commands::RegisterKeys, &BufferViewer::Commands::OnKeysChanged },
    { "View.Text", "Text viewer", &TextViewer::Commands::RegisterKeys, &TextViewer::Commands::OnKeysChanged },
    { "View.Image", "Image viewer", &ImageViewer::Commands::RegisterKeys, nullptr },
    { "View.Grid", "Grid viewer", &GridViewer::Commands::RegisterKeys, nullptr },
    { "View.Dissasm", "Disassembly viewer", &DissasmViewer::RegisterKeys, &DissasmViewer::OnKeysChanged },
    { "View.Container", "Container viewer", &ContainerViewer::RegisterKeys, nullptr },
    { "View.Lexical", "Lexical viewer", &LexicalViewer::Commands::RegisterKeys, &LexicalViewer::Commands::OnKeysChanged },
};
} // namespace

std::span<const Keys::ViewerKeys> Keys::GetAllViewerKeys()
{
    return std::span<const ViewerKeys>(VIEWER_KEYS);
}

const Keys::ViewerKeys* Keys::GetViewerKeys(Reference<ViewControl> view)
{
    if (!view.IsValid())
        return nullptr;
    auto* control = &static_cast<ViewControl&>(view);
    if (dynamic_cast<BufferViewer::Instance*>(control))
        return &VIEWER_KEYS[0];
    if (dynamic_cast<TextViewer::Instance*>(control))
        return &VIEWER_KEYS[1];
    if (dynamic_cast<ImageViewer::Instance*>(control))
        return &VIEWER_KEYS[2];
    if (dynamic_cast<GridViewer::Instance*>(control))
        return &VIEWER_KEYS[3];
    if (dynamic_cast<DissasmViewer::Instance*>(control))
        return &VIEWER_KEYS[4];
    if (dynamic_cast<ContainerViewer::Instance*>(control))
        return &VIEWER_KEYS[5];
    if (dynamic_cast<LexicalViewer::Instance*>(control))
        return &VIEWER_KEYS[6];
    return nullptr;
}

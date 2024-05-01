#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Images
{
enum class Types { BMP, JPG, PNG, GIF };

static const std::map<Types, Metadata> TYPES_MAP{
    { Types::BMP,
      { "BMP",
        "The BMP file format or bitmap, is a raster graphics image file format used to store bitmap digital images, independently of the display device.",
        false } },
    { Types::JPG,
      { "JPG",
        "JP(E)G (Joint Photographic Experts Group) is a commonly used method of lossy compression for digital images, particularly "
        "for those images produced by digital photography.",
        false } },
    { Types::PNG, { "PNG", "Portable Network Graphics is a raster-graphics file format that supports lossless data compression.", false } },
    { Types::GIF,
      { "GIF",
        "GIF stands for Graphics Interchange Format. GIF is a raster file format designed for relatively basic images that appear mainly on the internet.",
        false } },
};

class PNG : public IDrop
{
  private:
  public:
    PNG() = default;

    virtual const std::string_view GetName() const override;
    virtual ObjectCategory GetGroup() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;

    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) override;
};
} // namespace GView::GenericPlugins::Droppper::Images

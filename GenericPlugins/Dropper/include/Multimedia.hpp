#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Multimedia
{

enum class Types { RIFF, SWF };

static const std::map<Types, Metadata> TYPES_MAP{
    { Types::RIFF,
      { "RIFF",
        "Resource Interchange File Format (RIFF) is a generic file container format for storing data in tagged chunks. It is primarily used for audio and "
        "video, though it can be used for arbitrary data.",
        false } },
    { Types::SWF, { "SWF", "SWF is a defunct Adobe Flash file format that was used for multimedia, vector graphics and ActionScript.", false } },
};
} // namespace GView::GenericPlugins::Droppper::Multimedia

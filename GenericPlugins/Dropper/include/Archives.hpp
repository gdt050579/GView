#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Archives
{
enum class Types { MSCAB, RAR, ZIP };

static const std::map<Types, Metadata> TYPES_MAP{
    { Types::MSCAB,
      { "MSCAB",
        "Cabinet (or CAB) is an archive-file format for Microsoft Windows that supports lossless data compression and embedded digital certificates used for "
        "maintaining archive integrity.",
        false } },
    { Types::RAR, { "RAR", "RAR is a proprietary archive file format that supports data compression, error correction and file spanning.", false } },
    { Types::ZIP, { "ZIP", "ZIP is an archive file format that supports lossless data compression.", false } },
};
} // namespace GView::GenericPlugins::Droppper::Archives

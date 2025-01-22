#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{
using namespace GView::Hashes;

Reference<std::array<uint8, 32>> HashSHA256(Reference<GView::Object> object);

};
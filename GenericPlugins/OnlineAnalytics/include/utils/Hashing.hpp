#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{
using namespace GView::Hashes;

std::string_view HashSHA256(Reference<GView::Object> object);

};
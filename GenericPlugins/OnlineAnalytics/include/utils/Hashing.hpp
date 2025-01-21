#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{
using namespace GView::Hashes;

String hashSha256(Reference<GView::Object> object);

};
#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics
{
using namespace GView::Hashes;

String hashSha256(Reference<GView::Object> object);

};
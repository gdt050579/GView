#pragma once

#include <vector>
#include <memory>

#include "SpecialStrings.hpp"

using namespace GView::Utils;
using namespace GView::GenericPlugins::Droppper::SpecialStrings;

namespace GView::GenericPlugins::Droppper
{
class Instance
{
  private:
    std::vector<std::unique_ptr<IDrop>> droppers;

  public:
    bool Init()
    {
        // dummy init for now
        std::unique_ptr<IDrop> a = std::make_unique<IpAddress>();
        droppers.push_back(std::move(a));

        return true;
    }

    bool Process()
    {
        for (auto& dropper : droppers) {
            // TODO: something
        }

        return true;
    }
};
} // namespace GView::GenericPlugins::Droppper

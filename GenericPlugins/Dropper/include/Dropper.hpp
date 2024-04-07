#pragma once

#include <vector>
#include <memory>

#include "SpecialStrings.hpp"
#include "Executables.hpp"

using namespace GView::Utils;
using namespace GView::GenericPlugins::Droppper::SpecialStrings;
using namespace GView::GenericPlugins::Droppper::Executables;

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
        std::unique_ptr<IDrop> a = std::make_unique<IpAddress>(false, true);
        std::unique_ptr<IDrop> b = std::make_unique<MZPE>();
        droppers.push_back(std::move(a));
        droppers.push_back(std::move(b));

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

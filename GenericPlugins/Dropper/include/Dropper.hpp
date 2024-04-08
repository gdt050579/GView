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

    bool Process(Reference<GView::Object> object)
    {
        CHECK(object.IsValid(), false, "");

        DataCache& cache = object->GetData();
        uint64 offset    = 1;

        // TODO: replace these
        unsigned char* buffer = nullptr;
        uint32 bufferSize     = 0;

        for (uint32 i = 0; i < static_cast<uint32>(Priority::Count); i++) {
            const auto priority = static_cast<Priority>(i);
            for (auto& dropper : droppers) {
                if (dropper->GetPriority() != priority) {
                    continue;
                }

                uint64 start = 0;
                uint64 end   = 0;
                if (dropper->Check(offset, cache, buffer, bufferSize, start, end) != Result::NotFound) {
                    // TODO:
                }
            }
        }

        return true;
    }
};
} // namespace GView::GenericPlugins::Droppper

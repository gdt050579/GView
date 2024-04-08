#pragma once

#include <vector>
#include <memory>

#include "SpecialStrings.hpp"
#include "Executables.hpp"
#include "Multimedia.hpp"

using namespace GView::Utils;
using namespace GView::GenericPlugins::Droppper::SpecialStrings;
using namespace GView::GenericPlugins::Droppper::Executables;
using namespace GView::GenericPlugins::Droppper::Multimedia;

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
        std::unique_ptr<IDrop> c = std::make_unique<PNG>();
        droppers.push_back(std::move(a));
        droppers.push_back(std::move(b));
        droppers.push_back(std::move(c));

        return true;
    }

    BufferView GetPrecachedBuffer(uint64 offset, DataCache& cache)
    {
        return cache.Get(offset, MAX_PRECACHED_BUFFER_SIZE, true);
    }

    bool Process(Reference<GView::Object> object)
    {
        CHECK(object.IsValid(), false, "");

        DataCache& cache  = object->GetData();
        uint64 offset     = 1;
        uint64 nextOffset = 1;

        const auto objectSize = object->GetData().GetSize();

        while (offset < objectSize) {
            auto buffer = GetPrecachedBuffer(offset, cache);
            nextOffset  = offset + 1;

            for (uint32 i = 0; i < static_cast<uint32>(Priority::Count); i++) {
                const auto priority = static_cast<Priority>(i);
                auto found          = false;
                for (auto& dropper : droppers) {
                    if (dropper->GetPriority() != priority) {
                        continue;
                    }

                    uint64 start      = 0;
                    uint64 end        = 0;
                    const auto result = dropper->Check(offset, cache, buffer, start, end);
                    found             = result != Result::NotFound;

                    switch (result) {
                    case Result::Buffer:
                        nextOffset = end + 1;
                        break;
                    case Result::Ascii:
                        nextOffset = end + 1;
                        break;
                    case Result::Unicode:
                        nextOffset = end + 1;
                        break;
                    case Result::NotFound:
                    default:
                        break;
                    }

                    if (found) {
                        break;
                    }
                }
            }

            offset = nextOffset;
        }

        return true;
    }
};
} // namespace GView::GenericPlugins::Droppper

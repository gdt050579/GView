#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
ObjectCategory SpecialStrings::GetGroup() const
{
    return ObjectCategory::SpecialStrings;
}

Priority SpecialStrings::GetPriority() const
{
    return Priority::Text;
}

bool SpecialStrings::ShouldGroupInOneFile() const
{
    return true;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings

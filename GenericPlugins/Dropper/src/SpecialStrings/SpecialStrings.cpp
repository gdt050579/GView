#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
ObjectCategory SpecialStrings::GetGroup()
{
    return ObjectCategory::SpecialStrings;
}

Priority SpecialStrings::GetPriority()
{
    return Priority::Text;
}

bool SpecialStrings::ShouldGroupInOneFile()
{
    return true;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings

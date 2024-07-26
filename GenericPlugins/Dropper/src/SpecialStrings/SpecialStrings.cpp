#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
Category SpecialStrings::GetCategory() const
{
    return Category::SpecialStrings;
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

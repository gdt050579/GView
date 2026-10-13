#include "SubjectRegistry.hpp"

namespace GView::HDF
{
SubjectId SubjectRegistry::Create(std::string_view name, SubjectId parent, uint32 session, bool hasContent)
{
    if (entries.size() >= INVALID_SUBJECT_ID - 1)
        return INVALID_SUBJECT_ID;
    const auto id = static_cast<SubjectId>(entries.size());
    SubjectEntry entry;
    entry.name       = std::string(name.substr(0, MAX_SUBJECT_NAME_LEN));
    entry.parent     = IsValid(parent) ? parent : INVALID_SUBJECT_ID;
    entry.session    = session;
    entry.hasContent = hasContent;
    entry.depth      = IsValid(parent) ? entries[parent].depth + 1 : 0;
    entries.push_back(std::move(entry));
    if (IsValid(parent))
        entries[parent].children.push_back(id);
    return id;
}

SubjectId SubjectRegistry::Root(SubjectId id) const
{
    // parents are always created before their children: the walk is bounded by the number of subjects
    for (uint32 guard = 0; IsValid(id) && entries[id].parent != INVALID_SUBJECT_ID && guard <= entries.size(); guard++)
        id = entries[id].parent;
    return id;
}

std::vector<SubjectId> SubjectRegistry::ProvenancePath(SubjectId from, SubjectId ancestor) const
{
    std::vector<SubjectId> path;
    for (SubjectId current = from; IsValid(current) && path.size() <= entries.size(); current = entries[current].parent) {
        path.push_back(current);
        if (current == ancestor)
            return path;
    }
    return {};
}

uint32 SubjectRegistry::Distance(SubjectId descendant, SubjectId ancestor) const
{
    const auto path = ProvenancePath(descendant, ancestor);
    return path.empty() ? INVALID_INDEX : static_cast<uint32>(path.size() - 1);
}

void SubjectRegistry::Descendants(SubjectId root, std::vector<SubjectId>& out) const
{
    out.clear();
    if (!IsValid(root))
        return;
    std::vector<SubjectId> stack{ root };
    while (!stack.empty() && out.size() <= entries.size()) {
        const auto id = stack.back();
        stack.pop_back();
        out.push_back(id);
        const auto& children = entries[id].children;
        for (auto it = children.rbegin(); it != children.rend(); ++it)
            stack.push_back(*it);
    }
}

} // namespace GView::HDF

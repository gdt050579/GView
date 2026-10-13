#pragma once

// Runtime registry of the subjects (constants of sort Subject). It is an implementation structure, not formal state:
// every subject also appears in Gamma through HasName(Y, ..), HasContent(Y) and, for non-roots, ExtractedFrom(Y, X).

#include "Term.hpp"

namespace GView::HDF
{
struct SubjectEntry {
    std::string name;
    SubjectId parent{ INVALID_SUBJECT_ID }; // provenance parent (ExtractedFrom(this, parent))
    uint32 session{ INVALID_INDEX };        // the disclosure session that owns the subject
    ConstantId constant{ INVALID_CONSTANT_ID };
    uint32 depth{ 0 }; // distance to the root of the provenance tree
    Reference<AppCUI::Controls::Window> window;
    bool hasContent{ false };
    std::vector<SubjectId> children;
};

class SubjectRegistry
{
    std::vector<SubjectEntry> entries;

  public:
    SubjectId Create(std::string_view name, SubjectId parent, uint32 session, bool hasContent);
    inline bool IsValid(SubjectId id) const
    {
        return id < entries.size();
    }
    inline const SubjectEntry& Get(SubjectId id) const
    {
        return entries[id];
    }
    inline SubjectEntry& GetMutable(SubjectId id)
    {
        return entries[id];
    }
    inline uint32 Count() const
    {
        return static_cast<uint32>(entries.size());
    }
    // root of the provenance tree of id
    SubjectId Root(SubjectId id) const;
    // [from, parent(from), ..., ancestor]; empty when ancestor is not an ancestor of (or equal to) from
    std::vector<SubjectId> ProvenancePath(SubjectId from, SubjectId ancestor) const;
    // root and all its descendants, pre-order, children in creation order (deterministic)
    void Descendants(SubjectId root, std::vector<SubjectId>& out) const;
    // distance from descendant up to ancestor (INVALID_INDEX when not an ancestor)
    uint32 Distance(SubjectId descendant, SubjectId ancestor) const;
};

} // namespace GView::HDF

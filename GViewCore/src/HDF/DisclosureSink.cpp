// Public API classes of GView.hpp that operate on a disclosure session: DisclosureSink (Gamma_beta collector),
// ObservationScope (RAII observation transition) and GroundActionView (argument decoding for executors).

#include "DisclosureSession.hpp"

namespace GView::HDF
{
DisclosureSink::DisclosureSink(DisclosureSession* owner, Subject selfSubject) : session(owner), self(selfSubject)
{
}

bool DisclosureSink::Assert(PredicateId p, std::initializer_list<ArgValue> args, std::string_view explanation)
{
    return Assert(p, std::span<const ArgValue>(args.begin(), args.size()), explanation);
}

bool DisclosureSink::Assert(PredicateId p, std::span<const ArgValue> args, std::string_view explanation)
{
    if (!session)
        return false;
    std::string error;
    if (!session->Disclose(p, args, explanation, &error)) {
        LOG_ERROR("HDF: DisclosureSink::Assert rejected: %s", error.c_str());
        return false;
    }
    return true;
}

Subject DisclosureSink::CreateSubject(std::string_view name, Subject parent)
{
    if (!session)
        return {};
    return { session->CreateSubject(name, parent.id, true, true) };
}

Subject DisclosureSink::Self() const
{
    return self;
}

ObservationScope::ObservationScope(DisclosureSession* owner) : session(owner)
{
}
ObservationScope::ObservationScope(ObservationScope&& other) noexcept : session(other.session)
{
    other.session = nullptr;
}
ObservationScope& ObservationScope::operator=(ObservationScope&& other) noexcept
{
    if (this != &other) {
        if (session)
            session->EndObservation();
        session       = other.session;
        other.session = nullptr;
    }
    return *this;
}
ObservationScope::~ObservationScope()
{
    if (session)
        session->EndObservation();
}

Subject GroundActionView::SubjectArg(uint32 i) const
{
    return { (pool && i < args.size()) ? pool->AsSubject(args[i]) : INVALID_SUBJECT_ID };
}
std::string_view GroundActionView::StringArg(uint32 i) const
{
    return (pool && i < args.size()) ? pool->AsString(args[i]) : std::string_view();
}
int64 GroundActionView::IntArg(uint32 i) const
{
    return (pool && i < args.size()) ? pool->AsInt(args[i]) : 0;
}
double GroundActionView::RealArg(uint32 i) const
{
    return (pool && i < args.size()) ? pool->AsReal(args[i]) : 0.0;
}
bool GroundActionView::BoolArg(uint32 i) const
{
    return (pool && i < args.size()) ? pool->AsBool(args[i]) : false;
}

} // namespace GView::HDF

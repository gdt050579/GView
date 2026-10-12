#pragma once

// Re-runnable jobs - how the web build (BUILD_FOR_WASM) waits for the network without threads and without switching
// stacks.
//
// A web page has no threads (they need SharedArrayBuffer, which needs COOP/COEP headers that a static host such as
// GitHub Pages can not send), and suspending the C++ stack (Asyncify) in the middle of a job would interleave with the
// suspensions AppCUI already uses for its modal loops. So a job of a BackgroundWorker (BackgroundWorkerWasm.cpp) runs
// synchronously on the UI thread and is simply run AGAIN, from the start, every time one of its requests completes:
//
//   run 1   ... transport.Post(A): A is unknown  -> fetch(A) starts, the run is abandoned (NetworkPending)
//   (later) fetch(A) completes                   -> response A is recorded
//   run 2   ... transport.Post(A) returns A (replayed) ... Post(B): unknown -> fetch(B), abandoned
//   run 3   ... A (replayed) ... B (replayed) ... the job returns its completion
//
// A job is therefore a pure function of its inputs and of the responses it receives (true for every Perform* of
// LearningSession: their inputs are captured when the job is created). The few side effects that happen BEFORE a
// request (a telemetry batch taken from the collector) or between two requests are wrapped in Once(): they run once,
// later runs get the stored result. On the desktop (threads) a job runs once and Once() simply calls the function.
//
// Rules for code on the job path: NetworkPending must never be swallowed (every catch (...) between the job entry
// point and IHttpTransport::Post rethrows it), and the requests of a job must not depend on anything that changes
// between runs (the transport checks that a replayed response belongs to the same request path).

#include <functional>
#include <memory>
#include <string_view>

namespace GView::Security::Learning::JobReplay
{
#ifdef BUILD_FOR_WASM
// control flow only: thrown by the transport inside a job that needs a response it does not have yet; caught by the
// job runner. Deliberately not derived from std::exception.
struct NetworkPending {
};

// true while a job of a BackgroundWorker runs
bool Active() noexcept;

namespace Detail
{
    // the slot of the next Once() of the running job (empty the first time); nullptr outside a job
    std::shared_ptr<void>* NextMemoSlot();
} // namespace Detail

// Runs fn once per job: later runs of the same job get the value stored by the first one.
template <typename F>
auto Once(F&& fn) -> decltype(fn())
{
    using T    = decltype(fn());
    auto* slot = Detail::NextMemoSlot();
    if (slot == nullptr)
        return fn();
    if (*slot)
        return *std::static_pointer_cast<T>(*slot);
    auto value = std::make_shared<T>(fn());
    *slot      = value;
    return *value;
}
#else
template <typename F>
auto Once(F&& fn) -> decltype(fn())
{
    return fn();
}
#endif
} // namespace GView::Security::Learning::JobReplay

// BackgroundWorker for WebAssembly (see BackgroundWorker.hpp and JobReplay.hpp).
//
// A web page has no threads, so the jobs of a worker run on the UI thread, one at a time. A job never waits: when it
// needs a network response that has not arrived yet, the transport starts the request and abandons the run
// (JobReplay::Wait throws NetworkPending). Every frame, Pump() checks the request; once it has completed, the response
// is recorded and the job is run again from the start - this time the transport returns the recorded response, and the
// job goes on to its next request or to its end. No stack is ever suspended or switched, so this composes with the
// Asyncify suspensions AppCUI uses for its modal loops and with C++ exceptions, and it works the same with JSPI.

#include "BackgroundWorker.hpp"
#include "LearningHttp.hpp"

#include <vector>

namespace GView::Security::Learning
{
namespace
{
    // a job that needs more requests than this is not a protocol job: refuse it instead of looping
    constexpr size_t MAX_REQUESTS_PER_JOB = 16;
} // namespace

struct BackgroundWorker::RunningJob {
    Job job;
    std::vector<std::string> requestPaths;   // the requests of the job, in order
    std::vector<HttpResponse> responses;     // what they got (same order)
    std::vector<std::shared_ptr<void>> memo; // results of JobReplay::Once, in order
    size_t nextResponse{ 0 };
    size_t nextMemo{ 0 };
    bool waiting{ false };
    JobReplay::PendingRequest pending;
    bool discardCompletion{ false }; // set by Stop()
};

namespace
{
    BackgroundWorker* g_workers                = nullptr; // registry used by Cooperative::Pump
    BackgroundWorker::RunningJob* g_currentRun = nullptr; // the job running right now (nullptr = none)

    HttpResponse TransportFailure(std::string message)
    {
        HttpResponse r;
        r.transportError = std::move(message);
        return r;
    }

    // takes the response of the request the job waits for (aborted first when abortFirst)
    HttpResponse TakePending(BackgroundWorker::RunningJob& run, bool abortFirst)
    {
        if (abortFirst && run.pending.abort)
            run.pending.abort();
        HttpResponse response = run.pending.collect ? run.pending.collect() : TransportFailure("aborted");
        run.pending           = {};
        run.waiting           = false;
        return response;
    }
} // namespace

// grants the free functions of this file access to the private parts of BackgroundWorker
struct CooperativeAccess {
    static BackgroundWorker*& Next(BackgroundWorker* w)
    {
        return w->nextWorker;
    }
    static void Pump(BackgroundWorker* w)
    {
        w->PumpOnce();
    }
};

bool JobReplay::Active() noexcept
{
    return g_currentRun != nullptr;
}

std::shared_ptr<void>* JobReplay::Detail::NextMemoSlot()
{
    auto* run = g_currentRun;
    if (run == nullptr)
        return nullptr;
    if (run->nextMemo == run->memo.size())
        run->memo.emplace_back();
    return &run->memo[run->nextMemo++];
}

std::optional<HttpResponse> JobReplay::ReplayNext(std::string_view path)
{
    auto* run = g_currentRun;
    if (run == nullptr || run->nextResponse >= run->responses.size())
        return std::nullopt;
    const size_t index = run->nextResponse++;
    // a job must issue the same requests on every run; anything else is refused (fail closed)
    if (run->requestPaths[index] != path)
        return TransportFailure("internal error: the network job is not deterministic");
    return run->responses[index];
}

void JobReplay::Wait(PendingRequest pending)
{
    auto* run = g_currentRun;
    if (run != nullptr)
    {
        run->requestPaths.push_back(pending.path);
        run->pending = std::move(pending);
        run->waiting = true;
    }
    throw NetworkPending{};
}

BackgroundWorker::BackgroundWorker() = default;

BackgroundWorker::~BackgroundWorker()
{
    Stop();
    if (registered)
    {
        for (auto** p = &g_workers; *p != nullptr; p = &CooperativeAccess::Next(*p))
        {
            if (*p == this)
            {
                *p = nextWorker;
                break;
            }
        }
        registered = false;
    }
}

void BackgroundWorker::Start()
{
    stopRequested = false;
    if (!registered)
    {
        nextWorker = g_workers;
        g_workers  = this;
        registered = true;
    }
    started = true;
}

void BackgroundWorker::RunCurrent()
{
    // a job never runs another job: RunCurrent is only reached from the UI context (Post, Pump, Stop)
    while (running && g_currentRun == nullptr)
    {
        auto* run         = running.get();
        run->nextResponse = 0;
        run->nextMemo     = 0;
        run->waiting      = false;
        Completion done;
        bool waits   = false;
        g_currentRun = run;
        try
        {
            done = run->job();
        }
        catch (const JobReplay::NetworkPending&)
        {
            waits = run->waiting; // otherwise thrown outside the transport: a failed job
        }
        catch (...)
        {
        }
        g_currentRun = nullptr;

        if (waits)
        {
            if (run->responses.size() < MAX_REQUESTS_PER_JOB)
                return; // PumpOnce runs it again once the response is there
            // runaway job: its request is answered with a failure and the job runs to its end
            TakePending(*run, true);
            run->responses.push_back(TransportFailure("internal error: too many requests in one network job"));
            continue;
        }
        // done: the completion (unless the worker was stopped meanwhile) goes to the UI thread
        const bool discard = run->discardCompletion;
        running.reset(); // also wipes the recorded responses (SecureBytes)
        if (!discard)
        {
            if (done)
                completions.push_back(std::move(done));
            if (busy > 0)
                busy--;
        }
        return;
    }
}

void BackgroundWorker::StartNextJob()
{
    if (running || jobs.empty() || stopRequested || g_currentRun != nullptr)
        return;
    running      = std::make_unique<RunningJob>();
    running->job = std::move(jobs.front());
    jobs.pop_front();
    RunCurrent();
}

void BackgroundWorker::Stop()
{
    if (!started)
        return;
    stopRequested = true;
    jobs.clear();
    // Like the native worker, the running job is waited for: every request it makes from now on is aborted, so it runs
    // to its end at once with transport errors. Its completion is discarded.
    if (running && g_currentRun == nullptr)
    {
        running->discardCompletion = true;
        for (size_t round = 0; round <= MAX_REQUESTS_PER_JOB && running && running->waiting; round++)
        {
            auto response = TakePending(*running, true);
            running->responses.push_back(std::move(response));
            RunCurrent();
        }
        running.reset();
    }
    completions.clear();
    busy    = 0;
    started = false;
}

bool BackgroundWorker::Post(Job job)
{
    if (!job || !started || stopRequested)
        return false;
    jobs.push_back(std::move(job));
    busy++;
    // the first run happens now: the request leaves immediately, not on the next frame
    StartNextJob();
    return true;
}

void BackgroundWorker::PumpOnce()
{
    if (g_currentRun != nullptr)
        return;
    if (running && running->waiting)
    {
        auto& pending = running->pending;
        if (pending.cancel != nullptr && pending.cancel->load(std::memory_order_acquire))
            pending.abort(); // collect() reports the abort; the job then ends with a transport error
        if (!pending.ready())
            return;
        auto response = TakePending(*running, false);
        running->responses.push_back(std::move(response));
        RunCurrent();
    }
    if (!running)
        StartNextJob();
}

size_t BackgroundWorker::DrainCompletions()
{
    PumpOnce();
    if (completions.empty())
        return 0;
    std::deque<Completion> ready;
    ready.swap(completions);
    size_t n = 0;
    for (auto& c : ready)
    {
        try
        {
            c();
        }
        catch (...)
        {
        }
        n++;
    }
    return n;
}

bool BackgroundWorker::IsBusy()
{
    return busy > 0 || !completions.empty();
}

void Cooperative::Pump()
{
    for (auto* w = g_workers; w != nullptr; w = CooperativeAccess::Next(w))
        CooperativeAccess::Pump(w);
}
} // namespace GView::Security::Learning

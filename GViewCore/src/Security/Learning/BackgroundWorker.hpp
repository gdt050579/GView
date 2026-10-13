#pragma once

// Single background thread that executes network jobs for the learning UI.
//
// AppCUI has no timers or cross-thread event posting: jobs run on the worker and hand back a completion callback
// that is executed on the UI thread by DrainCompletions(), which is called from OnFrameUpdate (FPS mode is enabled
// by GView for this purpose). Frontends that never deliver frame updates (ncurses) use synchronous execution
// instead (see LearningSession::RunJob).
//
// WebAssembly (BUILD_FOR_WASM, BackgroundWorkerWasm.cpp): a web page has no threads. The jobs run, one at a time, on
// the UI thread, and a job that needs a network response is re-run once the response has arrived (JobReplay.hpp):
// nothing ever waits, so the UI stays responsive. Same public API, same guarantees for the callers: jobs never touch
// the UI, completions run on the UI thread from DrainCompletions().

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#ifndef BUILD_FOR_WASM
#    include <thread>
#endif

namespace GView::Security::Learning
{
class BackgroundWorker
{
  public:
    using Completion = std::function<void()>;
    using Job        = std::function<Completion()>; // runs on the worker, returns what to run on the UI thread
#ifdef BUILD_FOR_WASM
    struct RunningJob; // opaque, BackgroundWorkerWasm.cpp
#endif

  private:
#ifdef BUILD_FOR_WASM
    std::unique_ptr<RunningJob> running;     // the job being run (and re-run until it completes)
    BackgroundWorker* nextWorker{ nullptr }; // every started worker is pumped by Cooperative::Pump
    bool registered{ false };
    bool started{ false };

    void PumpOnce();
    void RunCurrent();   // runs the current job once more (it either completes or waits for a response)
    void StartNextJob(); // takes the next queued job, if any, and runs it
    friend struct CooperativeAccess;
#else
    std::thread worker;
    std::mutex mtx;
    std::condition_variable cv;

    void Run();
#endif
    std::deque<Job> jobs;
    std::deque<Completion> completions;
    bool stopRequested{ false };
    size_t busy{ 0 };

  public:
#ifdef BUILD_FOR_WASM
    BackgroundWorker(); // out of line: RunningJob is incomplete here
#else
    BackgroundWorker() = default;
#endif
    ~BackgroundWorker();
    BackgroundWorker(const BackgroundWorker&)            = delete;
    BackgroundWorker& operator=(const BackgroundWorker&) = delete;

    void Start();
    // pending jobs are discarded; the running job (if any) is waited for
    // (WebAssembly: its request in flight is aborted and the job is run to its end, its completion is discarded)
    void Stop();
    bool Post(Job job);
    // UI thread: runs every completion that is ready. Returns the number executed.
    size_t DrainCompletions();
    bool IsBusy();
};

#ifdef BUILD_FOR_WASM
namespace Cooperative
{
    // UI thread, outside of any job: re-runs the jobs whose response arrived. Called on every frame of the desktop
    // (BrowserHost.cpp) - also from DrainCompletions of each worker.
    void Pump();
} // namespace Cooperative
#endif
} // namespace GView::Security::Learning

#pragma once

// Single background thread that executes network jobs for the learning UI.
//
// AppCUI has no timers or cross-thread event posting: jobs run on the worker and hand back a completion callback
// that is executed on the UI thread by DrainCompletions(), which is called from OnFrameUpdate (FPS mode is enabled
// by GView for this purpose). Frontends that never deliver frame updates (ncurses) use synchronous execution
// instead (see LearningSession::RunJob).

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

namespace GView::Security::Learning
{
class BackgroundWorker
{
  public:
    using Completion = std::function<void()>;
    using Job        = std::function<Completion()>; // runs on the worker, returns what to run on the UI thread

  private:
    std::thread worker;
    std::mutex mtx;
    std::condition_variable cv;
    std::deque<Job> jobs;
    std::deque<Completion> completions;
    bool stopRequested{ false };
    size_t busy{ 0 };

    void Run();

  public:
    BackgroundWorker() = default;
    ~BackgroundWorker();
    BackgroundWorker(const BackgroundWorker&)            = delete;
    BackgroundWorker& operator=(const BackgroundWorker&) = delete;

    void Start();
    // pending jobs are discarded; the running job (if any) is waited for
    void Stop();
    bool Post(Job job);
    // UI thread: runs every completion that is ready. Returns the number executed.
    size_t DrainCompletions();
    bool IsBusy();
};
} // namespace GView::Security::Learning

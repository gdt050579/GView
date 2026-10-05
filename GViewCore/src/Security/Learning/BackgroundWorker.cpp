#include "BackgroundWorker.hpp"

namespace GView::Security::Learning
{
BackgroundWorker::~BackgroundWorker()
{
    Stop();
}

void BackgroundWorker::Start()
{
    if (worker.joinable())
        return;
    {
        std::lock_guard<std::mutex> lk(mtx);
        stopRequested = false;
    }
    worker = std::thread([this]() { Run(); });
}

void BackgroundWorker::Stop()
{
    if (!worker.joinable())
        return;
    {
        std::lock_guard<std::mutex> lk(mtx);
        stopRequested = true;
        jobs.clear();
    }
    cv.notify_all();
    worker.join();
    std::lock_guard<std::mutex> lk(mtx);
    completions.clear();
    busy = 0;
}

bool BackgroundWorker::Post(Job job)
{
    if (!job)
        return false;
    {
        std::lock_guard<std::mutex> lk(mtx);
        if (!worker.joinable() || stopRequested)
            return false;
        jobs.push_back(std::move(job));
        busy++;
    }
    cv.notify_one();
    return true;
}

void BackgroundWorker::Run()
{
    while (true)
    {
        Job job;
        {
            std::unique_lock<std::mutex> lk(mtx);
            cv.wait(lk, [this]() { return stopRequested || !jobs.empty(); });
            if (stopRequested)
                return;
            job = std::move(jobs.front());
            jobs.pop_front();
        }
        Completion done;
        try
        {
            done = job();
        }
        catch (...)
        {
            done = nullptr;
        }
        std::lock_guard<std::mutex> lk(mtx);
        if (done)
            completions.push_back(std::move(done));
        if (busy > 0)
            busy--;
    }
}

size_t BackgroundWorker::DrainCompletions()
{
    std::deque<Completion> ready;
    {
        std::lock_guard<std::mutex> lk(mtx);
        if (completions.empty())
            return 0;
        ready.swap(completions);
    }
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
    std::lock_guard<std::mutex> lk(mtx);
    return busy > 0 || !completions.empty();
}
} // namespace GView::Security::Learning

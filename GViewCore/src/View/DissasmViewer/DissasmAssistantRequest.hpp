#pragma once

#include "Internal.hpp"

#include <future>
#include <string>
#include <vector>

namespace GView::View::DissasmViewer
{
struct DissasmAssistantAnswer {
    std::string text;
    bool success = false;
};

// A request to the smart assistant that does not freeze the UI: the assistant (the HTTP call of its plugin) answers on a worker thread and
// the answer is taken on the UI thread once it is ready. The wasm build has no threads: the request is answered at once.
// A request that is not waited for any more (Esc) goes on in the background: Abandon moves it to a list that waits for it when the view is
// destroyed (the assistant belongs to the window, which outlives its controls).
class DissasmAssistantRequest
{
  public:
    using Assistant = GView::CommonInterfaces::SmartAssistants::SmartAssistantPromptInterface;
    using AbandonedRequests = std::vector<std::future<DissasmAssistantAnswer>>;

    // asked at once when the course policy blocks the assistant: its notification is shown on the UI thread
    void Start(Assistant* assistant, std::string prompt, std::string displayPrompt, bool onWorkerThread = true);
    bool IsRunning() const
    {
        return answer.valid();
    }
    // running and answered
    bool IsReady() const;
    // the answer (waits for it when it is not ready); the request is not running any more
    DissasmAssistantAnswer Take();
    // the answer is not needed: the request goes on in `abandoned` (finished requests are removed from it)
    void Abandon(AbandonedRequests& abandoned);

  private:
    std::future<DissasmAssistantAnswer> answer;
};
} // namespace GView::View::DissasmViewer

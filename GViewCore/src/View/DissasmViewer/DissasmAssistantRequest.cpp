#include "DissasmAssistantRequest.hpp"

#include <chrono>

using namespace GView::View::DissasmViewer;

namespace
{
DissasmAssistantAnswer Ask(DissasmAssistantRequest::Assistant* assistant, const std::string& prompt, const std::string& displayPrompt)
{
    DissasmAssistantAnswer result;
    try {
        result.text = assistant->AskSmartAssistant(prompt, displayPrompt, result.success);
    } catch (const std::exception& exception) {
        result = { std::string("The assistant failed: ") + exception.what(), false };
    } catch (...) {
        result = { "The assistant failed!", false };
    }
    return result;
}
} // namespace

void DissasmAssistantRequest::Start(Assistant* assistant, std::string prompt, std::string displayPrompt, bool onWorkerThread)
{
#ifdef BUILD_FOR_WASM
    onWorkerThread = false; // no threads
#endif
    // the proxy of the assistants shows the notification of the course policy: the UI thread only
    if (GView::App::IsFeatureRestricted(GView::Security::RestrictedMode::Feature::LLMHints))
        onWorkerThread = false;
    if (!onWorkerThread) {
        std::promise<DissasmAssistantAnswer> ready;
        ready.set_value(Ask(assistant, prompt, displayPrompt));
        answer = ready.get_future();
        return;
    }
    answer = std::async(std::launch::async, [assistant, prompt = std::move(prompt), displayPrompt = std::move(displayPrompt)]() {
        return Ask(assistant, prompt, displayPrompt);
    });
}

bool DissasmAssistantRequest::IsReady() const
{
    return answer.valid() && answer.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}

DissasmAssistantAnswer DissasmAssistantRequest::Take()
{
    if (!answer.valid())
        return { "No request was made!", false };
    return answer.get(); // Ask catches the exceptions of the assistant
}

void DissasmAssistantRequest::Abandon(AbandonedRequests& abandoned)
{
    std::erase_if(abandoned, [](const std::future<DissasmAssistantAnswer>& request) {
        return request.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    });
    if (answer.valid())
        abandoned.push_back(std::move(answer));
}

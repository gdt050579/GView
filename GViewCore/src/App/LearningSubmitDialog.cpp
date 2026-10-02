// Flag submission dialog for Learning and Evaluation Mode (spec §4).
// Retries of an unchanged answer reuse the same clientSubmissionId (idempotency); editing the answer creates a new one.

#include "Internal.hpp"
#include "Learning/LearningSession.hpp"

#undef MessageBox

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;
namespace Learning = GView::Security::Learning;

namespace
{
constexpr int BTN_SEND  = 1;
constexpr int BTN_CLOSE = 2;

class LearningSubmitDialog : public Window
{
    std::string problem;
    Reference<TextField> flagField;
    Reference<TextArea> explanationArea;
    Reference<Label> counterLabel, resultLabel;
    Reference<Button> sendButton;
    uint32 maxChars;
    bool required;
    bool waiting{ false };
    size_t lastLength{ static_cast<size_t>(-1) };
    std::shared_ptr<bool> alive = std::make_shared<bool>(true);

  public:
    LearningSubmitDialog(std::string_view problemName, std::string_view title, bool requireExplanation, uint32 explanationMaxChars)
        : Window("Submit flag", "d:c,w:90,h:22", WindowFlags::Sizeable), problem(problemName), maxChars(explanationMaxChars),
          required(requireExplanation)
    {
        LocalString<256> tmp;
        tmp.SetFormat("Problem: %.*s (%.*s)", (int) title.size(), title.data(), (int) problemName.size(), problemName.data());
        Factory::Label::Create(this, tmp, "l:1,t:0,r:1,h:1");
        Factory::Label::Create(this, "Flag:", "l:1,t:2,w:12");
        flagField = Factory::TextField::Create(this, "", "l:14,t:2,r:1");
        Factory::Label::Create(this, required ? "Explanation (required):" : "Explanation (optional):", "l:1,t:4,r:1,h:1");
        explanationArea = Factory::TextArea::Create(this, "", "l:1,t:5,r:1,b:5", TextAreaFlags::Border | TextAreaFlags::ScrollBars);
        counterLabel    = Factory::Label::Create(this, "", "l:1,b:4,r:1,h:1");
        resultLabel     = Factory::Label::Create(this, "", "l:1,b:2,r:1,h:2");
        sendButton      = Factory::Button::Create(this, "&Submit", "l:1,b:0,w:14", BTN_SEND, ButtonFlags::Flat);
        Factory::Button::Create(this, "&Close", "r:1,b:0,w:12", BTN_CLOSE, ButtonFlags::Flat);
        flagField->SetFocus();
        UpdateCounter();
    }
    ~LearningSubmitDialog() override
    {
        *alive = false;
    }

    bool OnFrameUpdate() override
    {
        auto& s = Learning::GetSession();
        s.NotifyFrameUpdatesAvailable();
        bool repaint = s.DrainCompletions() > 0;
        s.Tick();
        repaint |= UpdateCounter();
        return repaint;
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::ButtonClicked && id == BTN_SEND)
        {
            Send();
            return true;
        }
        if ((eventType == Event::ButtonClicked && id == BTN_CLOSE) || eventType == Event::WindowClose)
        {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }

  private:
    bool UpdateCounter()
    {
        const size_t len = explanationArea->GetText().Len();
        if (len == lastLength)
            return false;
        lastLength = len;
        LocalString<96> tmp;
        tmp.SetFormat("%zu / %u characters", len, maxChars);
        if (len > maxChars)
            tmp.Add("  - too long!");
        counterLabel->SetText(tmp);
        return true;
    }

    void Send()
    {
        if (waiting)
            return;
        std::string flagUtf8, explanationUtf8;
        flagField->GetText().ToString(flagUtf8);
        explanationArea->GetText().ToString(explanationUtf8);
        Learning::SecureString flag(flagUtf8.data(), flagUtf8.size());
        Learning::SecureString explanation(explanationUtf8.data(), explanationUtf8.size());
        Learning::WipeString(flagUtf8);
        Learning::WipeString(explanationUtf8);

        std::weak_ptr<bool> weak = alive;
        auto st                  = Learning::GetSession().Submit(problem, std::move(flag), std::move(explanation), [this, weak](const Learning::SubmitOutcome& o) {
            auto a = weak.lock();
            if (!a || !*a)
                return;
            waiting = false;
            sendButton->SetEnabled(true);
            ShowOutcome(o);
        });
        if (!st.ok)
        {
            resultLabel->SetText(st.message);
            return;
        }
        if (Learning::GetSession().GetStatus().busy)
        {
            waiting = true;
            sendButton->SetEnabled(false);
            resultLabel->SetText("Submitting...");
        }
    }

    void ShowOutcome(const Learning::SubmitOutcome& o)
    {
        LocalString<512> tmp;
        if (!o.status.ok)
        {
            if (!o.definitive)
            {
                tmp.SetFormat("Not delivered: %s\nPress Retry: the same submission id is reused, no extra attempt is counted.", o.status.message.c_str());
                sendButton->SetText("&Retry");
            }
            else
                tmp.SetFormat("Rejected: %s", o.status.message.c_str());
            resultLabel->SetText(tmp);
            return;
        }
        sendButton->SetText("&Submit");
        const auto& r = o.result;
        if (r.alreadySolved)
            tmp.SetFormat("Already solved. %s", r.details.c_str());
        else if (r.correct)
            tmp.SetFormat("CORRECT! +%lld points (attempt %u)%s %s", (long long) r.points, r.attempts, r.duplicate ? " [duplicate]" : "", r.details.c_str());
        else
            tmp.SetFormat("Incorrect (attempt %u). %s", r.attempts, r.details.c_str());
        if (r.hasTotalScore)
            tmp.AddFormat("\nTotal score: %lld", (long long) r.totalScore);
        resultLabel->SetText(tmp);
    }
};
} // namespace

void GView::App::ShowLearningSubmitDialog(std::string_view problemName)
{
    auto& session = Learning::GetSession();
    if (!session.CanSubmit())
    {
        Dialogs::MessageBox::ShowError(
              "Submit flag",
              session.GetState() == Learning::SessionState::Expired ? "The course policy has expired."
                                                                     : "Submissions from GView are not enabled for this course.");
        return;
    }
    const auto status        = session.GetStatus();
    bool required            = status.requireExplanation;
    std::string title(problemName);
    if (const auto* item = session.GetCatalogue().Find(problemName, true); item != nullptr)
    {
        title    = item->title;
        required = required || item->requireExplanation;
    }
    LearningSubmitDialog dlg(problemName, title, required, status.explanationMaxChars);
    dlg.Show();
}

void GView::Security::Learning::Hooks::ShowSubmitDialogForObject(const GView::Object* obj)
{
    const auto* b = Learning::GetSession().FindBinding(obj);
    if (b == nullptr || !b->problem)
        return;
    const std::string name = b->item;
    GView::App::ShowLearningSubmitDialog(name);
}

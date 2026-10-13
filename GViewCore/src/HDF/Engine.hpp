#pragma once

// GView::HDF::Engine: the HDF instance of the application. Owns Sigma/H/I compiled from HDF.json, the subject registry,
// one DisclosureSession per input subject X (top-level window) and the executors registered by plugins (the tool T).

#include "VocabularyRegistry.hpp"

#include <functional>
#include <memory>

namespace GView::HDF
{
class HDFWindow;

// [HDF] section of gview.ini
struct EngineConfig {
    std::string specificationFile{ "HDF.json" };
    bool stopOnVerdict{ false }; // overrides "stopping.on_verdict" when true
    uint32 maxSteps{ 0 };        // overrides "stopping.max_steps" when > 0
    uint32 maxDerivedPerStep{ DEFAULT_MAX_DERIVED };

    static void Update(AppCUI::Utils::IniSection sect);
    static EngineConfig Read(); // from the application settings (defaults when absent)
};

class Engine final : public EngineInterface, public SessionHost, public ActionExecutorInterface
{
    struct ExecutorEntry {
        ActionId action;
        SubjectId owner; // INVALID_SUBJECT_ID: global executor
        Reference<ActionExecutorInterface> executor;
    };

    EngineConfig config;
    std::unique_ptr<LoadedSpecification> spec;
    Diagnostics loadDiagnostics;
    std::filesystem::path specificationPath;
    SubjectRegistry registry;
    std::vector<std::unique_ptr<DisclosureSession>> sessions;
    std::vector<ExecutorEntry> executors;
    std::vector<uint8> rejectedPredicates; // runtime drift (module vs HDF.json)
    std::vector<uint8> rejectedActions;
    std::vector<std::string> checkedModules;
    std::unique_ptr<HDFWindow> window;
    DisclosureSession* steppingSession{ nullptr };
    uint64 generation{ 0 };
    // ReanalyzeSelection (the engine is its executor): the open-selection code of the viewer that asked for it
    const std::function<bool()>* reanalyzeOpen{ nullptr };
    std::string reanalyzeName;

    DisclosureSession& NewSession();

  public:
    Engine();
    ~Engine() override;

    // loads gview.ini [HDF] and the specification (cwd, then the executable's folder); never fails: a missing or broken
    // file leaves the built-ins and the parts that loaded, the problems are logged
    bool Init();
    bool LoadSpecification(const std::filesystem::path& path);

    // ---- EngineInterface --------------------------------------------------------------------------------------
    PredicateId Predicate(std::string_view name) const override;
    ActionId Action(std::string_view name) const override;
    bool RegisterActionExecutor(ActionId a, Subject owner, Reference<ActionExecutorInterface> executor) override;
    void UnregisterActionExecutor(Reference<ActionExecutorInterface> executor) override;
    bool Disclose(Subject s, PredicateId p, std::initializer_list<ArgValue> args, std::string_view explanation = {}) override;
    ObservationScope BeginObservation(Subject s, std::string_view label) override;
    void ShowWindow() override;

    // ---- SessionHost -------------------------------------------------------------------------------------------
    ActionExecutorInterface* ExecutorFor(const DisclosureSession& session, GroundActionId beta) override;
    void OnTransition(DisclosureSession& session, uint32 transition) override;
    bool IsPredicateRejected(PredicateId p) const override;

    // ---- ActionExecutorInterface: <ReanalyzeSelection>(x) ------------------------------------------------------
    ActionStatus Execute(const GroundActionView& action, const ActionInput* input, DisclosureSink& out) override;

    // ---- application integration -------------------------------------------------------------------------------
    // the subject of a new window: the pending subject of a running step, a child of parent (Init_T(y) is opened), or the
    // root of a new disclosure session; EndAttach closes the initial extraction once PopulateWindow returned
    Subject AttachWindow(Reference<AppCUI::Controls::Window> win, std::string_view name, bool hasContent, Subject parent);
    void EndAttach(Subject s);
    // the window of s is closing: drop the window reference and the executors owned by s
    void DetachWindow(Subject s);
    // <ReanalyzeSelection>(s) with the selected range as execution input; open() opens the new object (its window attaches
    // to the subject created by the step). Falls back to open() alone when the action is not selectable.
    bool ReanalyzeSelection(Subject s, const ActionInput& input, std::string_view name, const std::function<bool()>& open);
    // runtime drift check of a module that was just loaded (RegisterPlugin export)
    void OnModuleLoaded(std::string_view generator, void (*fnRegisterPlugin)(Reference<GView::PluginRegistry>));
    // a step selected in the UI
    StepResult Step(DisclosureSession& session, GroundActionId beta, const ActionInput* input = nullptr);
    bool HasExecutor(const DisclosureSession& session, GroundActionId beta);

    // ---- read-only views ----------------------------------------------------------------------------------------
    DisclosureSession* SessionOf(Subject s);
    inline uint32 SessionsCount() const
    {
        return static_cast<uint32>(sessions.size());
    }
    inline DisclosureSession& SessionAt(uint32 index)
    {
        return *sessions[index];
    }
    inline const LoadedSpecification& Spec() const
    {
        return *spec;
    }
    inline const SubjectRegistry& Registry() const
    {
        return registry;
    }
    inline const Diagnostics& LoadDiagnostics() const
    {
        return loadDiagnostics;
    }
    inline const std::filesystem::path& SpecificationPath() const
    {
        return specificationPath;
    }
    inline uint64 Generation() const
    {
        return generation;
    }
    Reference<AppCUI::Controls::Window> WindowOf(SubjectId s) const;
};

} // namespace GView::HDF

#include "Engine.hpp"
#include "HDFWindow.hpp"

#include <algorithm>
#include <limits>

namespace GView::HDF
{
namespace
{
    constexpr std::string_view SECTION_HDF           = "HDF";
    constexpr std::string_view KEY_SPECIFICATION     = "SpecificationFile";
    constexpr std::string_view KEY_STOPPING_POLICY   = "StoppingPolicy";
    constexpr std::string_view KEY_MAX_STEPS         = "MaxSteps";
    constexpr std::string_view KEY_MAX_DERIVED       = "MaxDerivedPerStep";
    constexpr std::string_view DEFAULT_SPECIFICATION = "HDF.json";
    // StoppingPolicy = specification: the "stopping.policy" of the specification applies
    constexpr std::string_view STOPPING_FROM_SPECIFICATION = "specification";
} // namespace

// ---- EngineConfig ----------------------------------------------------------------------------------------------------

void EngineConfig::Update(AppCUI::Utils::IniSection sect)
{
    sect.UpdateValue(KEY_SPECIFICATION, DEFAULT_SPECIFICATION, true);
    sect.UpdateValue(KEY_STOPPING_POLICY, STOPPING_FROM_SPECIFICATION, true);
    sect.UpdateValue(KEY_MAX_STEPS, static_cast<uint32>(0), true);
    sect.UpdateValue(KEY_MAX_DERIVED, static_cast<uint32>(DEFAULT_MAX_DERIVED), true);
}

EngineConfig EngineConfig::Read()
{
    EngineConfig cfg;
    const auto ini = AppCUI::Application::GetAppSettings();
    if (!ini)
        return cfg;
    auto sect = ini->GetSection(SECTION_HDF);
    if (!sect.Exists())
        return cfg;
    const auto file = sect.GetValue(KEY_SPECIFICATION).ToStringView(DEFAULT_SPECIFICATION);
    if (!file.empty())
        cfg.specificationFile = std::string(file);
    const auto policy = sect.GetValue(KEY_STOPPING_POLICY).ToStringView(STOPPING_FROM_SPECIFICATION);
    if (!policy.empty() && policy != STOPPING_FROM_SPECIFICATION) {
        cfg.stoppingPolicy = StoppingPolicyKindFromName(policy);
        if (!cfg.stoppingPolicy.has_value()) {
            LOG_WARNING(
                  "HDF: unknown StoppingPolicy '%.*s' in gview.ini (conclusive, manual, exhaustive or specification), the specification decides",
                  static_cast<int>(std::min<size_t>(policy.size(), 64)),
                  policy.data());
        }
    }
    cfg.maxSteps          = sect.GetValue(KEY_MAX_STEPS).ToUInt32(0);
    cfg.maxDerivedPerStep = sect.GetValue(KEY_MAX_DERIVED).ToUInt32(DEFAULT_MAX_DERIVED);
    if (cfg.maxDerivedPerStep == 0)
        cfg.maxDerivedPerStep = DEFAULT_MAX_DERIVED;
    return cfg;
}

// ---- EngineInterface helpers (GView.hpp) ------------------------------------------------------------------------------

bool EngineInterface::LookupPredicates(std::span<const std::string_view> names, std::span<PredicateId> out, Lookup* report) const
{
    bool ok = names.size() <= out.size();
    for (size_t i = 0; i < names.size(); i++) {
        const auto id = Predicate(names[i]);
        if (i < out.size())
            out[i] = id;
        if (id == INVALID_PREDICATE_ID) {
            ok = false;
            if (report)
                report->missing.emplace_back(names[i]);
        }
    }
    return ok;
}

bool EngineInterface::LookupActions(std::span<const std::string_view> names, std::span<ActionId> out, Lookup* report) const
{
    bool ok = names.size() <= out.size();
    for (size_t i = 0; i < names.size(); i++) {
        const auto id = Action(names[i]);
        if (i < out.size())
            out[i] = id;
        if (id == INVALID_ACTION_ID) {
            ok = false;
            if (report)
                report->missing.emplace_back(names[i]);
        }
    }
    return ok;
}

// ---- Engine -----------------------------------------------------------------------------------------------------------

Engine::Engine() : spec(MakeBuiltinSpecification())
{
}

Engine::~Engine() = default;

bool Engine::Init()
{
    config = EngineConfig::Read();
    std::filesystem::path file(config.specificationFile);
    std::vector<std::filesystem::path> candidates;
    if (file.is_absolute()) {
        candidates.push_back(file);
    } else {
        candidates.push_back(std::filesystem::current_path() / file);
        auto appPath = AppCUI::OS::GetCurrentApplicationPath();
        if (appPath.has_filename())
            candidates.push_back(appPath.remove_filename() / file);
    }
    bool loaded = false;
    for (const auto& candidate : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(candidate, ec)) {
            loaded = LoadSpecification(candidate);
            break;
        }
    }
    if (!loaded && specificationPath.empty()) {
        loadDiagnostics.Warning("", "specification file '" + config.specificationFile + "' not found: only the HDF built-ins are available");
        LOG_WARNING("HDF: %s not found, only the built-ins are available", config.specificationFile.c_str());
    }
    if (config.stoppingPolicy.has_value())
        spec->stopping.kind = *config.stoppingPolicy;
    if (config.maxSteps > 0)
        spec->stopping.maxSteps = config.maxSteps;
    // the engine executes <ReanalyzeSelection>(x) itself
    RegisterActionExecutor(spec->signature.reanalyzeSelection, Subject{}, this);
    return true;
}

bool Engine::LoadSpecification(const std::filesystem::path& path)
{
    Diagnostics d;
    auto loaded       = LoadSpecificationFile(path, d);
    loadDiagnostics   = d;
    specificationPath = path;
    for (const auto& item : d.items) {
        if (item.severity == Diagnostic::Severity::Error)
            LOG_ERROR("HDF: %s: %s", item.path.c_str(), item.message.c_str());
        else
            LOG_WARNING("HDF: %s: %s", item.path.c_str(), item.message.c_str());
    }
    if (!loaded)
        return false;
    // a specification with errors is still used: the rules/symbols that failed are skipped (stale JSON is tolerated)
    spec = std::move(loaded);
    return true;
}

PredicateId Engine::Predicate(std::string_view name) const
{
    return spec->signature.predicates.Find(name);
}

ActionId Engine::Action(std::string_view name) const
{
    return spec->signature.actions.Find(name);
}

bool Engine::RegisterActionExecutor(ActionId a, Subject owner, Reference<ActionExecutorInterface> executor)
{
    if (!spec->signature.actions.IsValid(a) || !executor.IsValid())
        return false;
    if (a < rejectedActions.size() && rejectedActions[a]) {
        LOG_ERROR("HDF: action %s differs between the module and HDF.json, its executor is ignored", spec->signature.actions.Get(a).name.c_str());
        return false;
    }
    const SubjectId ownerId = registry.IsValid(owner.id) ? owner.id : INVALID_SUBJECT_ID;
    for (auto& entry : executors)
        if (entry.action == a && entry.owner == ownerId) {
            entry.executor = executor; // one executor per (action, owner)
            return true;
        }
    executors.push_back({ a, ownerId, executor });
    return true;
}

void Engine::UnregisterActionExecutor(Reference<ActionExecutorInterface> executor)
{
    std::erase_if(executors, [&](const ExecutorEntry& e) { return e.executor == executor; });
}

DisclosureSession* Engine::SessionOf(Subject s)
{
    if (!registry.IsValid(s.id))
        return nullptr;
    const auto index = registry.Get(s.id).session;
    return index < sessions.size() ? sessions[index].get() : nullptr;
}

Reference<AppCUI::Controls::Window> Engine::WindowOf(SubjectId s) const
{
    return registry.IsValid(s) ? registry.Get(s).window : Reference<AppCUI::Controls::Window>();
}

bool Engine::Disclose(Subject s, PredicateId p, std::initializer_list<ArgValue> args, std::string_view explanation)
{
    auto* session = SessionOf(s);
    if (!session) {
        LOG_ERROR("HDF: Disclose on an unknown subject");
        return false;
    }
    std::string error;
    if (!session->Disclose(p, std::span<const ArgValue>(args.begin(), args.size()), explanation, &error)) {
        LOG_ERROR("HDF: disclosure rejected: %s", error.c_str());
        return false;
    }
    return true;
}

ObservationScope Engine::BeginObservation(Subject s, std::string_view label)
{
    auto* session = SessionOf(s);
    if (!session)
        return {};
    session->BeginObservation(s.id, label);
    return ObservationScope(session);
}

void Engine::ShowWindow()
{
    Subject current;
    auto active = AppCUI::Application::GetCurrentWindow();
    if (active.IsValid()) {
        auto wi = active.ToObjectRef<GView::View::WindowInterface>();
        if (wi.IsValid())
            current = wi->GetSubject();
    }
    if (!window)
        window = std::make_unique<HDFWindow>(*this);
    window->Open(current);
}

ActionExecutorInterface* Engine::ExecutorFor(const DisclosureSession& session, GroundActionId beta)
{
    if (beta >= session.Enabled().Size())
        return nullptr;
    const auto& ga    = session.Enabled().Get(beta);
    SubjectId subject = INVALID_SUBJECT_ID;
    for (const auto c : session.Enabled().Args(beta))
        if (session.Pool().Kind(c) == SortKind::Subject) {
            subject = session.Pool().AsSubject(c);
            break;
        }
    // the executor owned by the closest ancestor of the subject (the plugin instance of the window it came from)
    for (uint32 guard = 0; registry.IsValid(subject) && guard <= registry.Count(); guard++, subject = registry.Get(subject).parent)
        for (auto& entry : executors)
            if (entry.action == ga.action && entry.owner == subject && entry.executor.IsValid())
                return entry.executor.operator->();
    for (auto& entry : executors)
        if (entry.action == ga.action && entry.owner == INVALID_SUBJECT_ID && entry.executor.IsValid())
            return entry.executor.operator->();
    return nullptr;
}

bool Engine::HasExecutor(const DisclosureSession& session, GroundActionId beta)
{
    return ExecutorFor(session, beta) != nullptr;
}

void Engine::OnTransition([[maybe_unused]] DisclosureSession& session, [[maybe_unused]] uint32 transition)
{
    generation++;
}

bool Engine::IsPredicateRejected(PredicateId p) const
{
    return p < rejectedPredicates.size() && rejectedPredicates[p] != 0;
}

DisclosureSession& Engine::NewSession()
{
    sessions.push_back(std::make_unique<DisclosureSession>(
          static_cast<uint32>(sessions.size()),
          spec->signature,
          spec->specification,
          spec->interpretation,
          spec->pool,
          registry,
          this,
          spec->stopping,
          config.maxDerivedPerStep));
    return *sessions.back();
}

Subject Engine::AttachWindow(Reference<AppCUI::Controls::Window> win, std::string_view name, bool hasContent, Subject parent)
{
    // 1. the window of a subject created by the running step (DisclosureSink::CreateSubject + open)
    if (steppingSession && steppingSession->PendingSubject() != INVALID_SUBJECT_ID) {
        const auto y = steppingSession->PendingSubject();
        steppingSession->ConsumePendingSubject();
        registry.GetMutable(y).window = win;
        steppingSession->BeginInitialExtraction(y); // nested: PopulateWindow discloses into Gamma_beta
        return { y };
    }
    // 2. a child of parent (an item opened by the analyst, or a window opened by a step without CreateSubject)
    SubjectId parentId = parent.id;
    if (steppingSession && !registry.IsValid(parentId))
        parentId = steppingSession->ScopeSubject();
    if (registry.IsValid(parentId)) {
        auto* session = sessions[registry.Get(parentId).session].get();
        if (!session->IsFinished()) {
            const auto y = session->BeginChild(name, parentId, hasContent);
            if (y != INVALID_SUBJECT_ID) {
                registry.GetMutable(y).window = win;
                return { y };
            }
        }
        LOG_WARNING("HDF: the disclosure session of the parent is finished, the new window starts its own session");
    }
    // 3. a new input subject X: a new disclosure session
    auto& session = NewSession();
    const auto x  = session.BeginRoot(name, hasContent);
    if (x != INVALID_SUBJECT_ID)
        registry.GetMutable(x).window = win;
    return { x };
}

void Engine::EndAttach(Subject s)
{
    if (auto* session = SessionOf(s))
        session->EndInitialExtraction();
}

void Engine::DetachWindow(Subject s)
{
    if (!registry.IsValid(s.id))
        return;
    registry.GetMutable(s.id).window.Reset();
    std::erase_if(executors, [&](const ExecutorEntry& e) { return e.owner == s.id; });
}

StepResult Engine::Step(DisclosureSession& session, GroundActionId beta, const ActionInput* input)
{
    auto* previous  = steppingSession;
    steppingSession = &session;
    const auto r    = session.Step(beta, input);
    steppingSession = previous;
    return r;
}

bool Engine::ReanalyzeSelection(Subject s, const ActionInput& input, std::string_view name, const std::function<bool()>& open)
{
    auto* session = SessionOf(s);
    if (!session || session->IsFinished() || session->IsStepInProgress() || session->IsScopeOpen())
        return open();
    const ConstantId c = session->SubjectConstant(s.id);
    const auto beta    = session->FindSelectable(spec->signature.reanalyzeSelection, std::span<const ConstantId>(&c, 1));
    if (beta == INVALID_GROUND_ACTION_ID)
        return open();
    reanalyzeOpen = &open;
    reanalyzeName = std::string(name);
    const auto r  = Step(*session, beta, &input);
    reanalyzeOpen = nullptr;
    if (r.status != StepStatus::Executed)
        return open();
    return r.actionStatus == ActionStatus::Success;
}

ActionStatus Engine::Execute(const GroundActionView& action, const ActionInput* input, DisclosureSink& out)
{
    if (action.action != spec->signature.reanalyzeSelection)
        return ActionStatus::Failed;
    // only a viewer knows the selected range and how to open it: selecting the action elsewhere is a cancelled execution
    if (!reanalyzeOpen || !input)
        return ActionStatus::Cancelled;
    auto* session = SessionOf(out.Self());
    if (!session)
        return ActionStatus::Failed;
    const auto y = out.CreateSubject(reanalyzeName, out.Self());
    if (!y.IsValid())
        return ActionStatus::Failed;
    // the selected range is execution input; the new subject records where it came from
    // a byte range of the parent (selectionSize > 0) is recorded; derived selections (e.g. disassembly text) are not
    const auto maxInt = static_cast<uint64>(std::numeric_limits<int64>::max());
    if (input->selectionSize > 0 && input->selectionOffset <= maxInt && input->selectionSize <= maxInt) {
        const auto& sig            = spec->signature;
        const ConstantId offset[2] = { session->SubjectConstant(y.id), *spec->pool.InternInt(sig.intSort, static_cast<int64>(input->selectionOffset)) };
        const ConstantId size[2]   = { session->SubjectConstant(y.id), *spec->pool.InternInt(sig.intSort, static_cast<int64>(input->selectionSize)) };
        session->AssertGround(sig.hasOffset, offset);
        session->AssertGround(sig.hasSize, size);
    }
    return (*reanalyzeOpen)() ? ActionStatus::Success : ActionStatus::Failed;
}

void Engine::OnModuleLoaded(std::string_view generator, void (*fnRegisterPlugin)(Reference<GView::PluginRegistry>))
{
    for (const auto& m : checkedModules)
        if (m == generator)
            return;
    checkedModules.emplace_back(generator);
    if (!fnRegisterPlugin) {
        LOG_INFO("HDF: module %.*s declares no metadata (no RegisterPlugin export)", static_cast<int>(generator.size()), generator.data());
        return;
    }
    RuntimeRegistry registryForModule(std::string(generator), spec->signature);
    fnRegisterPlugin(&registryForModule);
    const auto report = registryForModule.Apply(*spec, rejectedPredicates, rejectedActions);
    for ([[maybe_unused]] const auto& s : report.appended)
        LOG_WARNING(
              "HDF: %.*s declares %s, which is not in HDF.json (no rule can use it; run 'GView hdf augment')",
              static_cast<int>(generator.size()),
              generator.data(),
              s.c_str());
    for ([[maybe_unused]] const auto& s : report.rejected)
        LOG_ERROR(
              "HDF: %.*s: %s differs from HDF.json; its disclosures are rejected (run 'GView hdf validate')",
              static_cast<int>(generator.size()),
              generator.data(),
              s.c_str());
}

} // namespace GView::HDF

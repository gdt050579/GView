#include "SpecificationLoader.hpp"

#include <fstream>

namespace GView::HDF
{
using nlohmann::ordered_json;

namespace
{
    constexpr size_t MAX_SPECIFICATION_FILE = 16 * 1024 * 1024;

    std::string Path(std::string_view base, size_t index)
    {
        return std::string(base) + "[" + std::to_string(index) + "]";
    }
    std::string Path(std::string_view base, std::string_view key)
    {
        return std::string(base) + "." + std::string(key);
    }

    // the string at key (nullopt + error when present with a wrong type; nullopt when absent and not required)
    std::optional<std::string> GetString(const ordered_json& obj, std::string_view key, const std::string& path, Diagnostics& d, bool required)
    {
        auto it = obj.find(key);
        if (it == obj.end()) {
            if (required)
                d.Error(path, "missing \"" + std::string(key) + "\"");
            return std::nullopt;
        }
        if (!it->is_string()) {
            d.Error(Path(path, key), "must be a string");
            return std::nullopt;
        }
        return it->get_ref<const std::string&>();
    }

    void WarnUnknownKeys(const ordered_json& obj, std::initializer_list<std::string_view> known, const std::string& path, Diagnostics& d)
    {
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            bool found = false;
            for (auto k : known)
                if (it.key() == k)
                    found = true;
            if (!found)
                d.Warning(path, "unknown key \"" + it.key() + "\" (ignored)");
        }
    }

    // "arity": [ { "name": "x", "sort": "Subject" } ]
    bool ReadArity(const ordered_json& entry, const std::string& path, Diagnostics& d, std::vector<std::string>& storage, std::vector<ArgumentDeclaration>& out)
    {
        out.clear();
        storage.clear();
        auto it = entry.find("arity");
        if (it == entry.end())
            return true; // arity 0
        if (!it->is_array()) {
            d.Error(Path(path, "arity"), "must be an array");
            return false;
        }
        if (it->size() > MAX_ARITY) {
            d.Error(Path(path, "arity"), "more than MAX_ARITY (" + std::to_string(MAX_ARITY) + ") arguments");
            return false;
        }
        storage.reserve(it->size() * 2); // stable addresses for the views below
        for (size_t i = 0; i < it->size(); i++) {
            const auto& arg    = (*it)[i];
            const auto argPath = Path(Path(path, "arity"), i);
            if (!arg.is_object()) {
                d.Error(argPath, "must be an object { \"name\": .., \"sort\": .. }");
                return false;
            }
            auto name = GetString(arg, "name", argPath, d, true);
            auto sort = GetString(arg, "sort", argPath, d, true);
            if (!name || !sort)
                return false;
            if (!IsIdentifier(*name)) {
                d.Error(argPath, "argument name '" + *name + "' is not an identifier");
                return false;
            }
            storage.push_back(*name);
            storage.push_back(*sort);
        }
        for (size_t i = 0; i < storage.size(); i += 2)
            out.push_back({ storage[i], storage[i + 1] });
        return true;
    }

    // "generator": [ "Plugin:PE", ... ]
    void ReadGenerators(
          const ordered_json& entry, const std::string& path, Diagnostics& d, const LoaderOptions& options, Signature& signature, std::vector<GeneratorId>& out)
    {
        auto it = entry.find("generator");
        if (it == entry.end()) {
            if (options.requireGenerators)
                d.Error(path, "missing \"generator\" list");
            return;
        }
        if (!it->is_array()) {
            d.Error(Path(path, "generator"), "must be an array of strings");
            return;
        }
        if (it->empty() && options.requireGenerators)
            d.Error(Path(path, "generator"), "empty generator list");
        for (size_t i = 0; i < it->size(); i++) {
            if (!(*it)[i].is_string()) {
                d.Error(Path(Path(path, "generator"), i), "must be a string");
                continue;
            }
            const auto id = signature.generators.Intern((*it)[i].get_ref<const std::string&>());
            if (std::find(out.begin(), out.end(), id) == out.end())
                out.push_back(id);
        }
    }

    void LoadSorts(const ordered_json& doc, LoadedSpecification& spec, Diagnostics& d)
    {
        auto it = doc.find("sorts");
        if (it == doc.end())
            return;
        if (!it->is_array()) {
            d.Error("sorts", "must be an array");
            return;
        }
        for (size_t i = 0; i < it->size(); i++) {
            const auto& entry = (*it)[i];
            const auto path   = Path("sorts", i);
            if (!entry.is_object()) {
                d.Error(path, "must be an object");
                continue;
            }
            WarnUnknownKeys(entry, { "name", "kind", "generator", "description" }, path, d);
            auto name = GetString(entry, "name", path, d, true);
            auto kind = GetString(entry, "kind", path, d, true);
            if (!name || !kind)
                continue;
            const auto k = SortKindFromName(*kind);
            if (!k) {
                d.Error(Path(path, "kind"), "unknown sort kind '" + *kind + "' (Subject, String, Int, Real or Bool)");
                continue;
            }
            if (!IsIdentifier(*name)) {
                d.Error(Path(path, "name"), "'" + *name + "' is not an identifier");
                continue;
            }
            const auto existing = spec.signature.sorts.Find(*name);
            if (existing != INVALID_SORT_ID) {
                if (spec.signature.sorts.Get(existing).isBuiltin && spec.signature.sorts.Kind(existing) == *k)
                    continue; // a built-in written down for documentation
                d.Error(path, "duplicate sort '" + *name + "'");
                continue;
            }
            if (!spec.signature.sorts.Add(*name, *k))
                d.Error(path, "cannot add sort '" + *name + "'");
        }
    }

    void LoadActions(const ordered_json& doc, LoadedSpecification& spec, Diagnostics& d, const LoaderOptions& options)
    {
        auto it = doc.find("actions");
        if (it == doc.end())
            return;
        if (!it->is_array()) {
            d.Error("actions", "must be an array");
            return;
        }
        auto& sig = spec.signature;
        std::vector<std::string> storage;
        std::vector<ArgumentDeclaration> arity;
        for (size_t i = 0; i < it->size(); i++) {
            const auto& entry = (*it)[i];
            const auto path   = Path("actions", i);
            if (!entry.is_object()) {
                d.Error(path, "must be an object");
                continue;
            }
            WarnUnknownKeys(entry, { "name", "arity", "denotation", "repeatable", "generator", "description" }, path, d);
            auto name       = GetString(entry, "name", path, d, true);
            auto denotation = GetString(entry, "denotation", path, d, false);
            if (!name || !ReadArity(entry, path, d, storage, arity))
                continue;
            if (!IsIdentifier(*name)) {
                d.Error(Path(path, "name"), "'" + *name + "' is not an identifier");
                continue;
            }
            bool repeatable = false;
            if (auto r = entry.find("repeatable"); r != entry.end()) {
                if (!r->is_boolean())
                    d.Error(Path(path, "repeatable"), "must be a boolean");
                else
                    repeatable = r->get<bool>();
            }
            const auto existing = sig.actions.Find(*name);
            if (existing != INVALID_ACTION_ID) {
                auto& symbol = sig.actions.GetMutable(existing);
                if (!symbol.isBuiltin) {
                    d.Error(path, "duplicate action '" + *name + "'");
                    continue;
                }
                if (!sig.SameArity(symbol.arity, arity) || symbol.repeatable != repeatable)
                    d.Error(
                          path,
                          "built-in action '" + *name + "' must be declared as " + *name + "(" + sig.FormatArity(symbol.arity) + ")" +
                                (symbol.repeatable ? " (repeatable)" : ""));
                ReadGenerators(entry, path, d, options, sig, symbol.generators);
                continue;
            }
            std::string error;
            auto id = sig.AddAction(*name, arity, denotation.value_or(""), repeatable, error);
            if (!id) {
                d.Error(path, error);
                continue;
            }
            ReadGenerators(entry, path, d, options, sig, sig.actions.GetMutable(*id).generators);
        }
    }

    void LoadPredicates(const ordered_json& doc, LoadedSpecification& spec, Diagnostics& d, const LoaderOptions& options)
    {
        auto it = doc.find("predicates");
        if (it == doc.end())
            return;
        if (!it->is_array()) {
            d.Error("predicates", "must be an array");
            return;
        }
        auto& sig = spec.signature;
        std::vector<std::string> storage;
        std::vector<ArgumentDeclaration> arity;
        for (size_t i = 0; i < it->size(); i++) {
            const auto& entry = (*it)[i];
            const auto path   = Path("predicates", i);
            if (!entry.is_object()) {
                d.Error(path, "must be an object");
                continue;
            }
            WarnUnknownKeys(entry, { "name", "arity", "denotation", "generator", "description" }, path, d);
            auto name       = GetString(entry, "name", path, d, true);
            auto denotation = GetString(entry, "denotation", path, d, false);
            if (!name || !ReadArity(entry, path, d, storage, arity))
                continue;
            if (!IsIdentifier(*name)) {
                d.Error(Path(path, "name"), "'" + *name + "' is not an identifier");
                continue;
            }
            const auto existing = sig.predicates.Find(*name);
            if (existing != INVALID_PREDICATE_ID) {
                // built-ins and the completion predicates Done_a may be listed (generated by "hdf augment")
                auto& symbol = sig.predicates.GetMutable(existing);
                if (!symbol.isBuiltin && !symbol.IsCompletion()) {
                    d.Error(path, "duplicate predicate '" + *name + "'");
                    continue;
                }
                if (!sig.SameArity(symbol.arity, arity)) {
                    d.Error(path, "predicate '" + *name + "' must be declared as " + *name + "(" + sig.FormatArity(symbol.arity) + ")");
                    continue;
                }
                if (denotation && !denotation->empty()) {
                    std::string error;
                    DenotationTemplate den;
                    if (den.Compile(*denotation, symbol.arity, error)) {
                        symbol.denotation       = std::move(den);
                        symbol.denotationSource = *denotation;
                    } else {
                        d.Error(Path(path, "denotation"), error);
                    }
                }
                ReadGenerators(entry, path, d, options, sig, symbol.generators);
                continue;
            }
            if (name->size() > 5 && name->starts_with("Done_")) {
                d.Warning(path, "'" + *name + "' looks like a completion predicate but no non-repeatable action '" + name->substr(5) + "' exists");
            }
            std::string error;
            auto id = sig.AddPredicate(*name, arity, denotation.value_or(""), error);
            if (!id) {
                d.Error(path, error);
                continue;
            }
            ReadGenerators(entry, path, d, options, sig, sig.predicates.GetMutable(*id).generators);
        }
    }

    void LoadVerdicts(const ordered_json& doc, LoadedSpecification& spec, Diagnostics& d)
    {
        auto it = doc.find("verdicts");
        if (it == doc.end())
            return;
        if (!it->is_array()) {
            d.Error("verdicts", "must be an array of predicate names");
            return;
        }
        for (size_t i = 0; i < it->size(); i++) {
            const auto path = Path("verdicts", i);
            if (!(*it)[i].is_string()) {
                d.Error(path, "must be a predicate name");
                continue;
            }
            const auto& name = (*it)[i].get_ref<const std::string&>();
            const auto p     = spec.signature.predicates.Find(name);
            if (p == INVALID_PREDICATE_ID) {
                d.Error(path, "unknown verdict predicate '" + name + "'");
                continue;
            }
            std::string error;
            if (!spec.specification.AddVerdictPredicate(p, spec.signature, error))
                d.Error(path, error);
        }
    }

    void LoadRules(const ordered_json& doc, LoadedSpecification& spec, Diagnostics& d, bool actionRules)
    {
        const char* section = actionRules ? "action_rules" : "assertion_rules";
        auto it             = doc.find(section);
        if (it == doc.end())
            return;
        if (!it->is_array()) {
            d.Error(section, "must be an array");
            return;
        }
        for (size_t i = 0; i < it->size(); i++) {
            const auto& entry = (*it)[i];
            const auto path   = Path(section, i);
            if (!entry.is_object()) {
                d.Error(path, "must be an object");
                continue;
            }
            WarnUnknownKeys(entry, { "name", "body", "head", "explanation", "description" }, path, d);
            auto name        = GetString(entry, "name", path, d, true);
            auto head        = GetString(entry, "head", path, d, true);
            auto explanation = GetString(entry, "explanation", path, d, false);
            if (!name || !head)
                continue;
            std::vector<ParsedLiteral> body;
            bool ok = true;
            if (auto b = entry.find("body"); b != entry.end()) {
                if (!b->is_array()) {
                    d.Error(Path(path, "body"), "must be an array of literals");
                    continue;
                }
                for (size_t l = 0; l < b->size(); l++) {
                    if (!(*b)[l].is_string()) {
                        d.Error(Path(Path(path, "body"), l), "must be a literal string");
                        ok = false;
                        break;
                    }
                    ParsedLiteral literal;
                    std::string error;
                    if (!ParseLiteral((*b)[l].get_ref<const std::string&>(), literal, error)) {
                        d.Error(Path(Path(path, "body"), l), error);
                        ok = false;
                        break;
                    }
                    body.push_back(std::move(literal));
                }
            }
            if (!ok)
                continue;
            ParsedLiteral parsedHead;
            std::string error;
            if (!ParseLiteral(*head, parsedHead, error)) {
                d.Error(Path(path, "head"), error);
                continue;
            }
            const bool added = actionRules
                                     ? spec.specification.AddActionRule(*name, body, parsedHead, explanation.value_or(""), spec.signature, spec.pool, error)
                                     : spec.specification.AddAssertionRule(*name, body, parsedHead, explanation.value_or(""), spec.signature, spec.pool, error);
            if (!added)
                d.Error(path, error);
        }
    }

    void LoadInterpretation(const ordered_json& doc, LoadedSpecification& spec, Diagnostics& d)
    {
        auto& interpretation             = spec.interpretation;
        interpretation.verdictPredicates = spec.specification.verdictPredicates;
        auto it                          = doc.find("interpretation");
        if (it == doc.end()) {
            interpretation.SetDefault();
            if (!spec.specification.verdictPredicates.empty())
                d.Warning("interpretation", "missing: every subject is interpreted as Inconclusive");
            return;
        }
        if (!it->is_object()) {
            d.Error("interpretation", "must be an object");
            interpretation.SetDefault();
            return;
        }
        WarnUnknownKeys(*it, { "outcomes", "fallback", "verdicts", "description" }, "interpretation", d);
        auto outcomes = it->find("outcomes");
        if (outcomes == it->end() || !outcomes->is_array() || outcomes->empty()) {
            d.Error("interpretation.outcomes", "must be a non-empty array of outcome labels");
            interpretation.SetDefault();
            return;
        }
        if (outcomes->size() > 255) {
            d.Error("interpretation.outcomes", "too many outcomes (max 255)");
            interpretation.SetDefault();
            return;
        }
        interpretation.outcomes.labels.clear();
        for (size_t i = 0; i < outcomes->size(); i++) {
            if (!(*outcomes)[i].is_string()) {
                d.Error(Path("interpretation.outcomes", i), "must be a string");
                continue;
            }
            const auto& label = (*outcomes)[i].get_ref<const std::string&>();
            if (interpretation.outcomes.Find(label)) {
                d.Error(Path("interpretation.outcomes", i), "duplicate outcome '" + label + "'");
                continue;
            }
            interpretation.outcomes.labels.push_back(label);
        }
        if (!interpretation.outcomes.Find("Inconclusive")) {
            d.Error("interpretation.outcomes", "the outcome set must contain \"Inconclusive\"");
            interpretation.outcomes.labels.push_back("Inconclusive");
        }
        auto fallback = GetString(*it, "fallback", "interpretation", d, false).value_or("Inconclusive");
        auto index    = interpretation.outcomes.Find(fallback);
        if (!index) {
            d.Error("interpretation.fallback", "unknown outcome '" + fallback + "'");
            index = interpretation.outcomes.Find("Inconclusive");
        }
        interpretation.outcomes.fallbackIndex = *index;
        if (*index + 1u != interpretation.outcomes.labels.size())
            d.Warning("interpretation.fallback", "the fallback outcome should be the last one (outcome order is the priority order)");

        interpretation.verdicts.clear();
        auto verdicts = it->find("verdicts");
        if (verdicts == it->end())
            return;
        if (!verdicts->is_array()) {
            d.Error("interpretation.verdicts", "must be an array");
            return;
        }
        for (size_t i = 0; i < verdicts->size(); i++) {
            const auto& entry = (*verdicts)[i];
            const auto path   = Path("interpretation.verdicts", i);
            if (!entry.is_object()) {
                d.Error(path, "must be an object");
                continue;
            }
            WarnUnknownKeys(entry, { "predicate", "aggregate", "conditions", "description" }, path, d);
            auto predicate = GetString(entry, "predicate", path, d, true);
            if (!predicate)
                continue;
            VerdictInterpretation vi;
            vi.predicate = spec.signature.predicates.Find(*predicate);
            if (vi.predicate == INVALID_PREDICATE_ID || !spec.specification.IsVerdict(vi.predicate)) {
                d.Error(Path(path, "predicate"), "'" + *predicate + "' is not a verdict predicate (list it in \"verdicts\")");
                continue;
            }
            if (interpretation.Find(vi.predicate)) {
                d.Error(Path(path, "predicate"), "verdict predicate '" + *predicate + "' is configured twice");
                continue;
            }
            const auto aggregate = GetString(entry, "aggregate", path, d, false).value_or("max");
            const auto f         = AggregateFunctionFromName(aggregate);
            if (!f) {
                d.Error(Path(path, "aggregate"), "unknown aggregate '" + aggregate + "' (max, min, mean, noisy_or)");
                continue;
            }
            vi.aggregate = *f;
            if (auto conditions = entry.find("conditions"); conditions != entry.end()) {
                if (!conditions->is_array()) {
                    d.Error(Path(path, "conditions"), "must be an array");
                    continue;
                }
                for (size_t c = 0; c < conditions->size(); c++) {
                    const auto& cond    = (*conditions)[c];
                    const auto condPath = Path(Path(path, "conditions"), c);
                    if (!cond.is_object()) {
                        d.Error(condPath, "must be an object");
                        continue;
                    }
                    auto outcome = GetString(cond, "outcome", condPath, d, true);
                    auto op      = GetString(cond, "op", condPath, d, true);
                    auto value   = cond.find("value");
                    if (!outcome || !op)
                        continue;
                    if (value == cond.end() || !value->is_number()) {
                        d.Error(condPath, "\"value\" must be a number");
                        continue;
                    }
                    const auto o  = interpretation.outcomes.Find(*outcome);
                    const auto co = ComparisonOperatorFromName(*op);
                    if (!o) {
                        d.Error(Path(condPath, "outcome"), "unknown outcome '" + *outcome + "'");
                        continue;
                    }
                    if (!co) {
                        d.Error(Path(condPath, "op"), "unknown operator '" + *op + "' (>=, >, <=, <, ==)");
                        continue;
                    }
                    vi.conditions.push_back({ *o, *co, value->get<double>() });
                }
            }
            interpretation.verdicts.push_back(std::move(vi));
        }
        for (const auto p : spec.specification.verdictPredicates)
            if (!interpretation.Find(p))
                d.Warning(
                      "interpretation.verdicts",
                      "verdict predicate '" + spec.signature.predicates.Get(p).name + "' has no interpretation (max aggregate, always the fallback outcome)");
    }

    void LoadStopping(const ordered_json& doc, LoadedSpecification& spec, Diagnostics& d)
    {
        auto it = doc.find("stopping");
        if (it == doc.end())
            return;
        if (!it->is_object()) {
            d.Error("stopping", "must be an object");
            return;
        }
        WarnUnknownKeys(*it, { "on_verdict", "max_steps", "description" }, "stopping", d);
        if (auto v = it->find("on_verdict"); v != it->end()) {
            if (v->is_boolean())
                spec.stopping.stopOnVerdict = v->get<bool>();
            else
                d.Error("stopping.on_verdict", "must be a boolean");
        }
        if (auto v = it->find("max_steps"); v != it->end()) {
            if (v->is_number_unsigned() && v->get<uint64>() <= 0xFFFFFFFFu)
                spec.stopping.maxSteps = static_cast<uint32>(v->get<uint64>());
            else if (v->is_number_integer() && v->get<int64>() == 0)
                spec.stopping.maxSteps = 0;
            else
                d.Error("stopping.max_steps", "must be a non-negative 32-bit integer");
        }
    }
} // namespace

uint32 Diagnostics::ErrorCount() const
{
    uint32 count = 0;
    for (const auto& item : items)
        if (item.severity == Diagnostic::Severity::Error)
            count++;
    return count;
}

uint32 Diagnostics::WarningCount() const
{
    return static_cast<uint32>(items.size()) - ErrorCount();
}

bool Diagnostics::Contains(std::string_view fragment, Diagnostic::Severity severity) const
{
    for (const auto& item : items)
        if (item.severity == severity && (item.message.find(fragment) != std::string::npos || item.path.find(fragment) != std::string::npos))
            return true;
    return false;
}

std::string Diagnostics::ToText() const
{
    std::string text;
    for (const auto& item : items) {
        text += item.severity == Diagnostic::Severity::Error ? "error: " : "warning: ";
        if (!item.path.empty())
            text += item.path + ": ";
        text += item.message + "\n";
    }
    return text;
}

bool IsIdentifier(std::string_view name)
{
    if (name.empty() || name.size() > 256)
        return false;
    for (size_t i = 0; i < name.size(); i++) {
        const char c  = name[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (i > 0 && c >= '0' && c <= '9');
        if (!ok)
            return false;
    }
    return true;
}

LoadedSpecification::LoadedSpecification() : pool(signature.sorts)
{
    signature.AddBuiltins();
    interpretation.SetDefault();
}

std::unique_ptr<LoadedSpecification> MakeBuiltinSpecification()
{
    auto spec = std::make_unique<LoadedSpecification>();
    spec->specification.AddBuiltinRules(spec->signature, spec->pool);
    spec->specification.Compile(spec->signature);
    return spec;
}

std::unique_ptr<LoadedSpecification> LoadSpecification(const ordered_json& doc, Diagnostics& d, const LoaderOptions& options)
{
    auto spec = std::make_unique<LoadedSpecification>();
    if (!doc.is_object()) {
        d.Error("", "the specification must be a JSON object");
        spec->specification.AddBuiltinRules(spec->signature, spec->pool);
        spec->specification.Compile(spec->signature);
        return spec;
    }
    WarnUnknownKeys(
          doc,
          { "$schema", "description", "sorts", "predicates", "actions", "verdicts", "assertion_rules", "action_rules", "interpretation", "stopping" },
          "",
          d);
    LoadSorts(doc, *spec, d);
    LoadActions(doc, *spec, d, options); // creates Done_a, which "predicates" may list
    LoadPredicates(doc, *spec, d, options);
    LoadVerdicts(doc, *spec, d);
    LoadRules(doc, *spec, d, false);
    LoadRules(doc, *spec, d, true);
    spec->specification.AddBuiltinRules(spec->signature, spec->pool);
    LoadInterpretation(doc, *spec, d);
    LoadStopping(doc, *spec, d);
    spec->specification.Compile(spec->signature);
    return spec;
}

std::unique_ptr<LoadedSpecification> LoadSpecificationText(std::string_view text, Diagnostics& d, const LoaderOptions& options)
{
    auto doc = ordered_json::parse(text.begin(), text.end(), nullptr, false);
    if (doc.is_discarded()) {
        d.Error("", "not a valid JSON document");
        return nullptr;
    }
    return LoadSpecification(doc, d, options);
}

std::unique_ptr<LoadedSpecification> LoadSpecificationFile(const std::filesystem::path& path, Diagnostics& d, const LoaderOptions& options)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        d.Error("", "cannot open " + path.string());
        return nullptr;
    }
    std::string text;
    char buffer[16384];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        text.append(buffer, static_cast<size_t>(file.gcount()));
        if (text.size() > MAX_SPECIFICATION_FILE) {
            d.Error("", "the specification file is larger than 16 MiB");
            return nullptr;
        }
    }
    return LoadSpecificationText(text, d, options);
}

} // namespace GView::HDF

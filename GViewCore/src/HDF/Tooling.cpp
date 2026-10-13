#include "Tooling.hpp"
#include "StaticPlugins.hpp"

#include <fstream>
#include <iostream>
#include <map>
#include <set>

namespace GView::HDF::Tooling
{
using nlohmann::ordered_json;

namespace
{
    constexpr std::string_view MANUAL         = "Manual";
    constexpr std::string_view RULE_PREFIX    = "Rule:";
    constexpr std::string_view CORE_GENERATOR = "Core:HDF";

    std::string Path(std::string_view base, size_t index)
    {
        return std::string(base) + "[" + std::to_string(index) + "]";
    }

    std::filesystem::path PathFromUtf8(const std::string& text)
    {
        return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size()));
    }

    // a declaration of a symbol by one generator
    struct Declarer {
        std::string generator;
        DeclaredSymbol symbol;
    };
    using DeclarationMap = std::map<std::string, std::vector<Declarer>>; // name -> declarers (generator order)

    std::string EntryName(const ordered_json& entry)
    {
        auto it = entry.find("name");
        return (it != entry.end() && it->is_string()) ? it->get<std::string>() : std::string();
    }

    std::vector<std::string> EntryGenerators(const ordered_json& entry, bool& present)
    {
        std::vector<std::string> result;
        auto it = entry.find("generator");
        present = it != entry.end();
        if (present && it->is_array())
            for (const auto& g : *it)
                if (g.is_string())
                    result.push_back(g.get<std::string>());
        return result;
    }

    std::vector<DeclaredArgument> EntryArity(const ordered_json& entry)
    {
        std::vector<DeclaredArgument> result;
        auto it = entry.find("arity");
        if (it == entry.end() || !it->is_array())
            return result;
        for (const auto& a : *it) {
            if (!a.is_object())
                continue;
            DeclaredArgument arg;
            if (auto n = a.find("name"); n != a.end() && n->is_string())
                arg.name = n->get<std::string>();
            if (auto s = a.find("sort"); s != a.end() && s->is_string())
                arg.sort = s->get<std::string>();
            result.push_back(arg);
        }
        return result;
    }

    std::string EntryDenotation(const ordered_json& entry)
    {
        auto it = entry.find("denotation");
        return (it != entry.end() && it->is_string()) ? it->get<std::string>() : std::string();
    }

    bool EntryRepeatable(const ordered_json& entry)
    {
        auto it = entry.find("repeatable");
        return it != entry.end() && it->is_boolean() && it->get<bool>();
    }

    bool SameSorts(const std::vector<DeclaredArgument>& a, const std::vector<DeclaredArgument>& b)
    {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); i++)
            if (a[i].sort != b[i].sort)
                return false;
        return true;
    }

    std::string FormatArity(const std::vector<DeclaredArgument>& arity)
    {
        std::string text = "(";
        for (size_t i = 0; i < arity.size(); i++)
            text += (i ? ", " : "") + arity[i].name + ":" + arity[i].sort;
        return text + ")";
    }

    ordered_json ArityJson(const std::vector<DeclaredArgument>& arity)
    {
        auto result = ordered_json::array();
        for (const auto& a : arity)
            result.push_back(ordered_json{ { "name", a.name }, { "sort", a.sort } });
        return result;
    }

    const ordered_json* Section(const ordered_json& doc, const char* name)
    {
        if (!doc.is_object())
            return nullptr;
        auto it = doc.find(name);
        return (it != doc.end() && it->is_array()) ? &*it : nullptr;
    }

    void Collect(const std::vector<ModuleDeclarations>& modules, bool actions, DeclarationMap& out)
    {
        for (const auto& m : modules)
            for (const auto& s : actions ? m.actions : m.predicates)
                out[s.name].push_back({ m.generator, s });
    }

    // Done_a for every non-repeatable action of an "actions" array (generator Core:HDF)
    ModuleDeclarations CompletionDeclarations(const ordered_json* actions)
    {
        ModuleDeclarations m;
        m.generator = std::string(CORE_GENERATOR);
        if (!actions)
            return m;
        for (const auto& entry : *actions) {
            if (!entry.is_object() || EntryRepeatable(entry))
                continue;
            const auto name = EntryName(entry);
            if (!IsIdentifier(name))
                continue;
            DeclaredSymbol done;
            done.name       = Signature::CompletionPredicateName(name);
            done.arity      = EntryArity(entry);
            done.denotation = "Completed: " + EntryDenotation(entry);
            m.predicates.push_back(std::move(done));
        }
        return m;
    }

    // the arity of every predicate known without inference: built-ins, modules, completions and the file itself
    std::map<std::string, std::vector<std::string>> KnownPredicateSorts(const ordered_json& doc, const std::vector<ModuleDeclarations>& modules)
    {
        std::map<std::string, std::vector<std::string>> known;
        auto add = [&](const std::string& name, const std::vector<DeclaredArgument>& arity) {
            if (known.contains(name))
                return;
            std::vector<std::string> sorts;
            for (const auto& a : arity)
                sorts.push_back(a.sort);
            known[name] = std::move(sorts);
        };
        for (const auto& m : modules)
            for (const auto& p : m.predicates)
                add(p.name, p.arity);
        if (auto* predicates = Section(doc, "predicates"))
            for (const auto& e : *predicates)
                if (e.is_object())
                    add(EntryName(e), EntryArity(e));
        for (const auto& p : CompletionDeclarations(Section(doc, "actions")).predicates)
            add(p.name, p.arity);
        return known;
    }

    bool IsModuleGenerator(std::string_view g)
    {
        return ClassifyGenerator(g) == GeneratorKind::Module;
    }

    std::string JoinSorted(const std::set<std::string>& values)
    {
        std::string text;
        for (const auto& v : values)
            text += (text.empty() ? "" : ", ") + v;
        return text;
    }
} // namespace

GeneratorKind ClassifyGenerator(std::string_view generator)
{
    if (generator == MANUAL)
        return GeneratorKind::Manual;
    if (generator.starts_with(RULE_PREFIX))
        return GeneratorKind::Rule;
    return GeneratorKind::Module;
}

std::vector<ModuleDeclarations> InferDerivedPredicates(const ordered_json& doc, const std::vector<ModuleDeclarations>& modules, Diagnostics& d)
{
    std::vector<ModuleDeclarations> result;
    const auto* rules = Section(doc, "assertion_rules");
    if (!rules)
        return result;
    auto known = KnownPredicateSorts(doc, modules);
    {
        Signature builtins;
        builtins.AddBuiltins();
        for (PredicateId p = 0; p < builtins.predicates.Count(); p++) {
            std::vector<std::string> sorts;
            for (const auto& a : builtins.predicates.Get(p).arity)
                sorts.push_back(std::string(builtins.sorts.Name(a.sort)));
            known[builtins.predicates.Get(p).name] = sorts;
        }
    }
    struct Pending {
        size_t index;
        std::string name;
        std::vector<ParsedLiteral> body;
        ParsedLiteral head;
    };
    std::vector<Pending> pending;
    for (size_t i = 0; i < rules->size(); i++) {
        const auto& rule = (*rules)[i];
        if (!rule.is_object())
            continue;
        Pending p;
        p.index = i;
        p.name  = EntryName(rule);
        std::string error;
        auto head = rule.find("head");
        if (p.name.empty() || head == rule.end() || !head->is_string() || !ParseLiteral(head->get_ref<const std::string&>(), p.head, error))
            continue; // reported by the specification validation
        bool ok = true;
        if (auto body = rule.find("body"); body != rule.end() && body->is_array()) {
            for (const auto& literal : *body) {
                ParsedLiteral parsed;
                if (!literal.is_string() || !ParseLiteral(literal.get_ref<const std::string&>(), parsed, error)) {
                    ok = false;
                    break;
                }
                p.body.push_back(std::move(parsed));
            }
        }
        if (ok)
            pending.push_back(std::move(p));
    }

    // fixpoint: a head can only be inferred once the arities of its body predicates are known
    std::map<std::string, std::pair<std::string, std::vector<std::string>>> firstHead; // head -> (rule, sorts)
    std::map<size_t, DeclaredSymbol> inferred;                                         // rule index -> head declaration
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto& p : pending) {
            if (inferred.contains(p.index))
                continue;
            std::map<std::string, std::string> varSorts;
            bool ready = true;
            for (const auto& literal : p.body) {
                auto it = known.find(literal.name);
                if (it == known.end()) {
                    ready = false;
                    break;
                }
                for (size_t t = 0; t < literal.terms.size() && t < it->second.size(); t++)
                    if (literal.terms[t].kind == ParsedTerm::Kind::Variable && !varSorts.contains(literal.terms[t].text))
                        varSorts[literal.terms[t].text] = it->second[t];
            }
            if (!ready)
                continue;
            DeclaredSymbol head;
            head.name = p.head.name;
            std::set<std::string> usedNames;
            bool safe = true;
            for (size_t t = 0; t < p.head.terms.size(); t++) {
                const auto& term = p.head.terms[t];
                DeclaredArgument arg;
                switch (term.kind) {
                case ParsedTerm::Kind::Variable:
                    if (!varSorts.contains(term.text))
                        safe = false;
                    arg.sort = varSorts[term.text];
                    arg.name = term.text;
                    break;
                case ParsedTerm::Kind::String:
                    arg.sort = "String";
                    break;
                case ParsedTerm::Kind::Number:
                    arg.sort = term.realSyntax ? "Real" : "Int";
                    break;
                case ParsedTerm::Kind::Bool:
                    arg.sort = "Bool";
                    break;
                }
                if (arg.name.empty())
                    arg.name = "arg" + std::to_string(t + 1);
                for (uint32 suffix = 2; usedNames.contains(arg.name); suffix++)
                    arg.name = (term.kind == ParsedTerm::Kind::Variable ? term.text : "arg" + std::to_string(t + 1)) + "_" + std::to_string(suffix);
                usedNames.insert(arg.name);
                head.arity.push_back(arg);
            }
            if (!safe)
                continue; // unsafe rule: reported by the specification validation
            std::string den = head.name + "(";
            for (size_t t = 0; t < head.arity.size(); t++)
                den += (t ? ", {" : "{") + head.arity[t].name + "}";
            head.denotation = den + ")";
            std::vector<std::string> sorts;
            for (const auto& a : head.arity)
                sorts.push_back(a.sort);
            auto first = firstHead.find(head.name);
            if (first == firstHead.end()) {
                firstHead[head.name] = { p.name, sorts };
            } else if (first->second.second != sorts) {
                d.Error(
                      Path("assertion_rules", p.index),
                      "the head " + head.name + " of rule " + p.name + " has another arity than in rule " + first->second.first +
                            " (derived predicates need one arity)");
            }
            if (!known.contains(head.name)) {
                known[head.name] = sorts;
            }
            inferred[p.index] = std::move(head);
            progress          = true;
        }
    }
    for (const auto& p : pending) {
        auto it = inferred.find(p.index);
        if (it == inferred.end())
            continue; // unknown body predicates / unsafe rules: reported by the specification validation
        ModuleDeclarations m;
        m.generator = std::string(RULE_PREFIX) + p.name;
        m.predicates.push_back(it->second);
        result.push_back(std::move(m));
    }
    return result;
}

void Validate(const ordered_json& doc, const std::vector<ModuleDeclarations>& modules, Diagnostics& d)
{
    // 1-3. schema, the specification (sorts, arities, terms, safety, verdicts, outcomes, interpretation) and generator lists
    LoaderOptions options;
    options.requireGenerators = true;
    LoadSpecification(doc, d, options);
    if (!doc.is_object())
        return;

    // 4. drift against the modules
    for (const auto& m : modules)
        for (const auto& e : m.errors)
            d.Error(m.generator, e);
    const auto derived                  = InferDerivedPredicates(doc, modules, d);
    std::vector<ModuleDeclarations> all = modules;
    all.insert(all.end(), derived.begin(), derived.end());
    all.push_back(CompletionDeclarations(Section(doc, "actions")));
    DeclarationMap predicates, actions;
    Collect(all, false, predicates);
    Collect(all, true, actions);

    // symbols referenced by the rules
    std::set<std::string> referenced;
    for (const char* section : { "assertion_rules", "action_rules" }) {
        const auto* rules = Section(doc, section);
        if (!rules)
            continue;
        for (const auto& rule : *rules) {
            if (!rule.is_object())
                continue;
            ParsedLiteral literal;
            std::string error;
            if (auto head = rule.find("head"); head != rule.end() && head->is_string() && ParseLiteral(head->get_ref<const std::string&>(), literal, error))
                referenced.insert(literal.name);
            if (auto body = rule.find("body"); body != rule.end() && body->is_array())
                for (const auto& b : *body)
                    if (b.is_string() && ParseLiteral(b.get_ref<const std::string&>(), literal, error))
                        referenced.insert(literal.name);
        }
    }
    std::set<std::string> verdicts;
    if (const auto* v = Section(doc, "verdicts"))
        for (const auto& name : *v)
            if (name.is_string())
                verdicts.insert(name.get<std::string>());
    // rule names (for stale Rule: generators)
    std::set<std::string> ruleNames;
    if (const auto* rules = Section(doc, "assertion_rules"))
        for (const auto& rule : *rules)
            if (rule.is_object())
                ruleNames.insert(EntryName(rule));

    auto checkSection = [&](const char* section, const DeclarationMap& declared, bool isAction) {
        std::set<std::string> present;
        const auto* entries = Section(doc, section);
        if (entries) {
            for (size_t i = 0; i < entries->size(); i++) {
                const auto& entry = (*entries)[i];
                if (!entry.is_object())
                    continue;
                const auto name = EntryName(entry);
                const auto path = Path(section, i) + " (" + name + ")";
                present.insert(name);
                bool hasGeneratorKey  = false;
                const auto generators = EntryGenerators(entry, hasGeneratorKey);
                const bool manual     = std::find(generators.begin(), generators.end(), MANUAL) != generators.end();
                const auto arity      = EntryArity(entry);
                auto it               = declared.find(name);
                std::set<std::string> declaredBy;
                if (it != declared.end())
                    for (const auto& dec : it->second)
                        declaredBy.insert(dec.generator);
                // generators in the file that no longer declare the symbol
                for (const auto& g : generators) {
                    const auto kind = ClassifyGenerator(g);
                    if (kind == GeneratorKind::Manual || declaredBy.contains(g))
                        continue;
                    if (kind == GeneratorKind::Rule) {
                        const auto rule = g.substr(RULE_PREFIX.size());
                        d.Error(
                              path,
                              ruleNames.contains(rule) ? "generator " + g + ": the head of rule " + rule + " is no longer " + name
                                                       : "stale generator " + g + ": the rule " + rule + " no longer exists");
                    } else {
                        d.Error(path, "generator " + g + " no longer declares " + name + " (run 'GView hdf augment')");
                    }
                }
                // arity / sort / denotation differences against each declarer
                if (it != declared.end()) {
                    for (const auto& dec : it->second) {
                        if (ClassifyGenerator(dec.generator) == GeneratorKind::Rule) {
                            if (!SameSorts(dec.symbol.arity, arity))
                                d.Error(
                                      path,
                                      "the arity inferred from " + dec.generator + " is " + FormatArity(dec.symbol.arity) + ", the file has " +
                                            FormatArity(arity));
                            continue;
                        }
                        if (dec.symbol.arity != arity) {
                            d.Error(path, dec.generator + " declares " + name + FormatArity(dec.symbol.arity) + ", the file has " + FormatArity(arity));
                            continue;
                        }
                        if (isAction && dec.symbol.repeatable != EntryRepeatable(entry))
                            d.Error(path, dec.generator + " declares " + name + (dec.symbol.repeatable ? " repeatable" : " non-repeatable"));
                        if (!manual && dec.symbol.denotation != EntryDenotation(entry))
                            d.Warning(path, dec.generator + " declares another denotation: \"" + dec.symbol.denotation + "\"");
                    }
                }
                // the generator list should be the set of modules/rules that declare the symbol
                std::set<std::string> listed;
                for (const auto& g : generators)
                    if (ClassifyGenerator(g) != GeneratorKind::Manual)
                        listed.insert(g);
                if (listed != declaredBy)
                    d.Warning(path, "generator list differs from the declaring modules/rules: {" + JoinSorted(declaredBy) + "}");
                // unused vocabulary / actions nobody can execute
                bool producedByModule = false;
                for (const auto& g : declaredBy)
                    producedByModule |= IsModuleGenerator(g);
                if (!isAction && !producedByModule && !referenced.contains(name) && !verdicts.contains(name))
                    d.Warning(path, "predicate " + name + " is referenced by no rule and produced by no module");
                if (isAction) {
                    bool executable = false;
                    for (const auto& g : generators)
                        executable |= IsModuleGenerator(g);
                    if (!executable)
                        d.Warning(path, "action " + name + " has no generator that can execute it (only Manual)");
                }
            }
        }
        // declared symbols missing from the file
        for (const auto& [name, declarers] : declared) {
            if (present.contains(name))
                continue;
            std::set<std::string> by;
            for (const auto& dec : declarers)
                by.insert(dec.generator);
            d.Error(
                  section,
                  std::string(isAction ? "action " : "predicate ") + name + " is declared by " + JoinSorted(by) +
                        " but missing from the file (run 'GView hdf augment')");
        }
    };
    checkSection("predicates", predicates, false);
    checkSection("actions", actions, true);

    // module sorts must be in the "sorts" section (or built-in)
    std::set<std::string> sorts = { "Subject", "String", "Int", "Real", "Bool", "URL" };
    if (const auto* s = Section(doc, "sorts"))
        for (const auto& entry : *s)
            if (entry.is_object())
                sorts.insert(EntryName(entry));
    for (const auto& m : modules)
        for (const auto& s : m.sorts)
            if (!sorts.contains(s.name))
                d.Error("sorts", "sort " + s.name + " is declared by " + m.generator + " but missing from the file (run 'GView hdf augment')");
}

bool Augment(const ordered_json& input, const std::vector<ModuleDeclarations>& modules, AugmentResult& result, Diagnostics& d)
{
    if (!input.is_object()) {
        d.Error("", "the specification must be a JSON object");
        return false;
    }
    result.document = input;
    auto& doc       = result.document;
    for (const auto& m : modules)
        for (const auto& e : m.errors)
            d.Error(m.generator, e);

    // sorts declared by modules
    {
        if (!doc.contains("sorts") || !doc["sorts"].is_array())
            doc["sorts"] = ordered_json::array();
        std::set<std::string> present = { "Subject", "String", "Int", "Real", "Bool", "URL" };
        for (const auto& e : doc["sorts"])
            if (e.is_object())
                present.insert(EntryName(e));
        std::map<std::string, std::pair<std::string, std::set<std::string>>> declared;
        for (const auto& m : modules)
            for (const auto& s : m.sorts)
                if (!present.contains(s.name)) {
                    auto& slot = declared[s.name];
                    if (slot.first.empty())
                        slot.first = s.kind;
                    else if (slot.first != s.kind)
                        d.Error("sorts", "sort " + s.name + " is declared with two kinds");
                    slot.second.insert(m.generator);
                }
        for (const auto& [name, info] : declared) {
            doc["sorts"].push_back(ordered_json{ { "name", name }, { "kind", info.first }, { "generator", info.second } });
            result.added.push_back("sort " + name);
        }
    }

    auto merge = [&](const char* section, const DeclarationMap& declared, bool isAction) -> bool {
        // the defining declaration of each symbol: a module (generator order) before a rule
        std::map<std::string, const Declarer*> defining;
        std::map<std::string, std::set<std::string>> declarers;
        bool ok = true;
        for (const auto& [name, list] : declared) {
            const Declarer* best = nullptr;
            for (const auto& dec : list) {
                declarers[name].insert(dec.generator);
                const bool isRule = ClassifyGenerator(dec.generator) == GeneratorKind::Rule;
                if (!best || (ClassifyGenerator(best->generator) == GeneratorKind::Rule && !isRule))
                    best = &dec;
            }
            for (const auto& dec : list) {
                const bool sameShape = ClassifyGenerator(dec.generator) == GeneratorKind::Rule || ClassifyGenerator(best->generator) == GeneratorKind::Rule
                                             ? SameSorts(dec.symbol.arity, best->symbol.arity)
                                             : dec.symbol.arity == best->symbol.arity;
                if (!sameShape) {
                    d.Error(section, name + " is declared with different arities by " + best->generator + " and " + dec.generator);
                    ok = false;
                }
            }
            defining[name] = best;
        }
        if (!ok)
            return false;
        auto makeEntry = [&](const std::string& name) {
            const auto& symbol = defining[name]->symbol;
            ordered_json entry;
            entry["name"]       = name;
            entry["arity"]      = ArityJson(symbol.arity);
            entry["denotation"] = symbol.denotation;
            if (isAction)
                entry["repeatable"] = symbol.repeatable;
            entry["generator"] = declarers[name];
            return entry;
        };
        if (!doc.contains(section) || !doc[section].is_array())
            doc[section] = ordered_json::array();
        auto updated = ordered_json::array();
        std::set<std::string> present;
        for (const auto& entry : doc[section]) {
            if (!entry.is_object()) {
                updated.push_back(entry);
                continue;
            }
            const auto name = EntryName(entry);
            present.insert(name);
            bool hasGeneratorKey  = false;
            const auto generators = EntryGenerators(entry, hasGeneratorKey);
            const bool manual     = !hasGeneratorKey || std::find(generators.begin(), generators.end(), MANUAL) != generators.end();
            auto it               = defining.find(name);
            if (manual) {
                // hand-written: kept verbatim; modules/rules that declare the same arity are added to its generators
                auto kept         = entry;
                ordered_json list = ordered_json::array({ std::string(MANUAL) });
                if (it != defining.end()) {
                    const auto arity = EntryArity(entry);
                    for (const auto& g : declarers[name]) {
                        const auto* dec = [&]() -> const Declarer* {
                            for (const auto& x : declared.at(name))
                                if (x.generator == g)
                                    return &x;
                            return nullptr;
                        }();
                        const bool same = ClassifyGenerator(g) == GeneratorKind::Rule ? SameSorts(dec->symbol.arity, arity) : dec->symbol.arity == arity;
                        if (same)
                            list.push_back(g);
                    }
                }
                kept["generator"] = list;
                if (kept != entry)
                    result.updated.push_back(std::string(section) + " " + name);
                updated.push_back(kept);
                continue;
            }
            if (it == defining.end()) {
                result.removed.push_back(std::string(section) + " " + name); // nobody declares it any more
                continue;
            }
            auto rewritten = makeEntry(name);
            if (rewritten != entry)
                result.updated.push_back(std::string(section) + " " + name);
            updated.push_back(rewritten);
        }
        for (const auto& [name, dec] : defining) // std::map: sorted by name
            if (!present.contains(name)) {
                updated.push_back(makeEntry(name));
                result.added.push_back(std::string(section) + " " + name);
            }
        doc[section] = updated;
        return true;
    };

    DeclarationMap actions;
    Collect(modules, true, actions);
    if (!merge("actions", actions, true))
        return false;
    // derived predicates and completion predicates are computed on the merged actions
    const auto derived = InferDerivedPredicates(doc, modules, d);
    if (d.HasErrors())
        return false;
    std::vector<ModuleDeclarations> all = modules;
    all.insert(all.end(), derived.begin(), derived.end());
    all.push_back(CompletionDeclarations(Section(doc, "actions")));
    DeclarationMap predicates;
    Collect(all, false, predicates);
    if (!merge("predicates", predicates, false))
        return false;
    return !d.HasErrors();
}

std::string Serialize(const ordered_json& document)
{
    return document.dump(2, ' ', false, ordered_json::error_handler_t::replace) + "\n";
}

std::string NormalizeLineEnds(std::string_view text)
{
    std::string result;
    result.reserve(text.size());
    for (const char c : text)
        if (c != '\r')
            result.push_back(c);
    return result;
}

std::string UnifiedDiff(std::string_view before, std::string_view after, std::string_view name)
{
    auto split = [](std::string_view text) {
        std::vector<std::string_view> lines;
        while (!text.empty()) {
            const auto end = text.find('\n');
            lines.push_back(text.substr(0, end));
            if (end == std::string_view::npos)
                break;
            text.remove_prefix(end + 1);
        }
        return lines;
    };
    const auto a = split(before), b = split(after);
    std::string out = "--- " + std::string(name) + "\n+++ " + std::string(name) + " (augmented)\n";
    // LCS over the lines (bounded: the specification is small; huge inputs fall back to remove/add everything)
    const size_t n = a.size(), m = b.size();
    if (n * m > 16 * 1024 * 1024) {
        for (auto l : a)
            out += "-" + std::string(l) + "\n";
        for (auto l : b)
            out += "+" + std::string(l) + "\n";
        return out;
    }
    std::vector<uint32> lcs((n + 1) * (m + 1), 0);
    for (size_t i = n; i-- > 0;)
        for (size_t j = m; j-- > 0;)
            lcs[i * (m + 1) + j] = a[i] == b[j] ? lcs[(i + 1) * (m + 1) + j + 1] + 1 : std::max(lcs[(i + 1) * (m + 1) + j], lcs[i * (m + 1) + j + 1]);
    size_t i = 0, j = 0;
    std::vector<std::pair<char, std::string_view>> ops;
    while (i < n || j < m) {
        if (i < n && j < m && a[i] == b[j]) {
            ops.emplace_back(' ', a[i]);
            i++;
            j++;
        } else if (i < n && (j == m || lcs[(i + 1) * (m + 1) + j] >= lcs[i * (m + 1) + j + 1])) {
            ops.emplace_back('-', a[i++]); // removals before additions (unified diff convention)
        } else {
            ops.emplace_back('+', b[j++]);
        }
    }
    // print the changes with 2 lines of context
    constexpr size_t CONTEXT = 2;
    for (size_t k = 0; k < ops.size(); k++) {
        bool near = ops[k].first != ' ';
        for (size_t c = 1; c <= CONTEXT && !near; c++)
            near = (k >= c && ops[k - c].first != ' ') || (k + c < ops.size() && ops[k + c].first != ' ');
        if (near)
            out += std::string(1, ops[k].first) + std::string(ops[k].second) + "\n";
        else if (k > 0 && out.back() != '~')
            out += "~"; // marks skipped context (rendered as "...")
    }
    std::string rendered;
    for (const char c : out) {
        if (c == '~')
            rendered += "...\n";
        else
            rendered.push_back(c);
    }
    return rendered;
}

std::vector<ModuleDeclarations> InstalledModulesCollector::CollectAll(
      const std::function<bool(std::string_view)>& knownSort, std::vector<std::string>& warnings)
{
    std::vector<ModuleDeclarations> modules;
    for (const auto& core : CoreModules()) {
        CollectingRegistry registry(std::string(core.generator), knownSort);
        core.declare(registry.HDFVocabulary());
        modules.push_back(registry.TakeDeclarations());
    }
    auto call = [&](std::string generator, void (*fn)(Reference<GView::PluginRegistry>)) {
        if (!fn) {
            warnings.push_back(generator + ": module declares no metadata (no RegisterPlugin export)");
            return;
        }
        CollectingRegistry registry(std::move(generator), knownSort);
        fn(&registry);
        modules.push_back(registry.TakeDeclarations());
    };
#ifdef GVIEW_STATIC_PLUGINS
    for (const auto& p : GView::StaticPlugins::GetTypePlugins())
        call(TypePluginGenerator(p.name), p.fnRegisterPlugin);
    for (const auto& p : GView::StaticPlugins::GetGenericPlugins())
        call(GenericPluginGenerator(p.name), p.fnRegisterPlugin);
#else
    auto root = AppCUI::OS::GetCurrentApplicationPath();
    root.remove_filename();
    auto walk = [&](const char* folder, const char* extension, bool typePlugins) {
        std::vector<std::filesystem::path> files;
        std::error_code ec;
        for (std::filesystem::directory_iterator it(root / folder, ec), end; !ec && it != end; it.increment(ec)) {
            const auto& path = it->path();
            const auto name  = path.filename().string();
            if (path.extension() == extension && name.starts_with("lib") && name.size() > 7)
                files.push_back(path);
        }
        if (ec)
            warnings.push_back(std::string("cannot list ") + (root / folder).string());
        std::sort(files.begin(), files.end()); // deterministic module order
        for (const auto& path : files) {
            const auto file = path.filename().string();
            const auto name = file.substr(3, file.size() - 7); // lib<Name>.tpl / lib<Name>.gpl
            AppCUI::OS::Library lib;
            if (!lib.Load(path)) {
                warnings.push_back("cannot load " + path.string());
                continue;
            }
            call(typePlugins ? TypePluginGenerator(name) : GenericPluginGenerator(name),
                 lib.GetFunction<void (*)(Reference<GView::PluginRegistry>)>("RegisterPlugin"));
        }
    };
    walk("Types", ".tpl", true);
    walk("GenericPlugins", ".gpl", false);
#endif
    return modules;
}

namespace
{
    bool ReadText(const std::filesystem::path& path, std::string& text)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
            return false;
        text.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        return true;
    }

    std::function<bool(std::string_view)> KnownSorts(const ordered_json& doc)
    {
        auto sorts =
              std::make_shared<std::set<std::string, std::less<>>>(std::set<std::string, std::less<>>{ "Subject", "String", "Int", "Real", "Bool", "URL" });
        if (const auto* s = Section(doc, "sorts"))
            for (const auto& e : *s)
                if (e.is_object())
                    sorts->insert(EntryName(e));
        return [sorts](std::string_view name) { return sorts->contains(name); };
    }

    void PrintReport(const Diagnostics& d, const std::vector<std::string>& collectorWarnings, bool json, std::ostream& out)
    {
        if (json) {
            auto report        = ordered_json::object();
            report["errors"]   = d.ErrorCount();
            report["warnings"] = d.WarningCount() + collectorWarnings.size();
            auto items         = ordered_json::array();
            for (const auto& w : collectorWarnings)
                items.push_back(ordered_json{ { "severity", "warning" }, { "path", "" }, { "message", w } });
            for (const auto& item : d.items)
                items.push_back(ordered_json{
                      { "severity", item.severity == Diagnostic::Severity::Error ? "error" : "warning" }, { "path", item.path }, { "message", item.message } });
            report["diagnostics"] = items;
            out << report.dump(2, ' ', false, ordered_json::error_handler_t::replace) << "\n";
            return;
        }
        for (const auto& w : collectorWarnings)
            out << "warning: " << w << "\n";
        out << d.ToText();
        out << d.ErrorCount() << " error(s), " << d.WarningCount() + collectorWarnings.size() << " warning(s)\n";
    }

    std::filesystem::path Resolve(const std::filesystem::path& file)
    {
        std::error_code ec;
        if (file.is_absolute() || std::filesystem::exists(file, ec))
            return file;
        auto app = AppCUI::OS::GetCurrentApplicationPath();
        app.remove_filename();
        if (std::filesystem::exists(app / file, ec))
            return app / file;
        return file;
    }
} // namespace

int ValidateCommand(const ValidateOptions& options, VocabularyCollector& collector, std::ostream& out)
{
    std::string text;
    if (!ReadText(options.file, text)) {
        out << "error: cannot read " << options.file.string() << "\n";
        return 1;
    }
    Diagnostics d;
    const auto doc = ordered_json::parse(text, nullptr, false);
    if (doc.is_discarded()) {
        d.Error("", "not a valid JSON document");
        PrintReport(d, {}, options.json, out);
        return 1;
    }
    std::vector<std::string> warnings;
    const auto modules = collector.CollectAll(KnownSorts(doc), warnings);
    Validate(doc, modules, d);
    PrintReport(d, warnings, options.json, out);
    return d.HasErrors() ? 1 : 0;
}

int AugmentCommand(const AugmentOptions& options, VocabularyCollector& collector, std::ostream& out)
{
    std::string text;
    if (!ReadText(options.file, text)) {
        out << "error: cannot read " << options.file.string() << "\n";
        return 1;
    }
    Diagnostics d;
    const auto doc = ordered_json::parse(text, nullptr, false);
    if (doc.is_discarded()) {
        out << "error: " << options.file.string() << " is not a valid JSON document (comments are not supported)\n";
        return 1;
    }
    std::vector<std::string> warnings;
    const auto modules = collector.CollectAll(KnownSorts(doc), warnings);
    AugmentResult result;
    if (!Augment(doc, modules, result, d)) {
        PrintReport(d, warnings, false, out);
        out << "nothing written\n";
        return 1;
    }
    for (const auto& a : result.added)
        out << "added: " << a << "\n";
    for (const auto& u : result.updated)
        out << "updated: " << u << "\n";
    for (const auto& r : result.removed)
        out << "removed: " << r << "\n";
    const auto newText = Serialize(result.document);
    const bool changed = NormalizeLineEnds(text) != newText;
    int exitCode       = 0;
    if (options.dryRun) {
        if (changed)
            out << UnifiedDiff(NormalizeLineEnds(text), newText, options.file.string());
        else
            out << "no change\n";
    } else if (options.check) {
        if (changed) {
            out << options.file.string() << " is not up to date (run 'GView hdf augment')\n";
            exitCode = 1;
        } else {
            out << options.file.string() << " is up to date\n";
        }
    } else {
        const auto target = options.output.empty() ? options.file : options.output;
        if (changed || !options.output.empty()) {
            // atomic replace: write a temporary file next to the target, then rename it over the target
            auto temp = target;
            temp += ".tmp";
            {
                std::ofstream file(temp, std::ios::binary | std::ios::trunc);
                if (!file.is_open() || !file.write(newText.data(), static_cast<std::streamsize>(newText.size()))) {
                    out << "error: cannot write " << temp.string() << "\n";
                    return 1;
                }
            }
            std::error_code ec;
            std::filesystem::rename(temp, target, ec);
            if (ec) {
                std::filesystem::remove(temp, ec);
                out << "error: cannot replace " << target.string() << "\n";
                return 1;
            }
            out << "written: " << target.string() << "\n";
        } else {
            out << "no change\n";
        }
    }
    // the result must validate
    Diagnostics validation;
    Validate(result.document, modules, validation);
    PrintReport(validation, warnings, false, out);
    if (validation.HasErrors())
        exitCode = 1;
    return exitCode;
}

int RunValidate(const std::vector<std::string>& arguments)
{
    ValidateOptions options;
    bool fileSet = false;
    for (const auto& a : arguments) {
        if (a == "--json") {
            options.json = true;
        } else if (!a.empty() && a[0] != '-' && !fileSet) {
            options.file = PathFromUtf8(a);
            fileSet      = true;
        } else {
            std::cout << "Use: GView hdf validate [file] [--json]\n";
            return 2;
        }
    }
    options.file = Resolve(options.file);
    InstalledModulesCollector collector;
    return ValidateCommand(options, collector, std::cout);
}

int RunAugment(const std::vector<std::string>& arguments)
{
    AugmentOptions options;
    bool fileSet = false;
    for (size_t i = 0; i < arguments.size(); i++) {
        const auto& a = arguments[i];
        if (a == "--dry-run") {
            options.dryRun = true;
        } else if (a == "--check") {
            options.check = true;
        } else if (a == "--output" && i + 1 < arguments.size()) {
            options.output = PathFromUtf8(arguments[++i]);
        } else if (!a.empty() && a[0] != '-' && !fileSet) {
            options.file = PathFromUtf8(a);
            fileSet      = true;
        } else {
            std::cout << "Use: GView hdf augment [file] [--output <file>] [--dry-run] [--check]\n";
            return 2;
        }
    }
    options.file = Resolve(options.file);
    InstalledModulesCollector collector;
    return AugmentCommand(options, collector, std::cout);
}

} // namespace GView::HDF::Tooling

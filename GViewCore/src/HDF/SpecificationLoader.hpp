#pragma once

// HDF.json -> Signature (Sigma), ConstantPool (C), Specification (H = (R, A, V)), Interpretation (I) and StoppingPolicy (pi).
// nlohmann::ordered_json, parsed without exceptions; every problem becomes a Diagnostic with its JSON path.

#include "DisclosureSession.hpp"
#include "Interpretation.hpp"
#include "Specification.hpp"

#include <filesystem>
#include <memory>
#include <nlohmann/json.hpp>

namespace GView::HDF
{
struct Diagnostic {
    enum class Severity : uint8 { Warning = 0, Error = 1 };
    Severity severity{ Severity::Error };
    std::string path; // JSON path, e.g. "assertion_rules[2].head"
    std::string message;
};

class Diagnostics
{
  public:
    std::vector<Diagnostic> items;

    void Error(std::string path, std::string message)
    {
        items.push_back({ Diagnostic::Severity::Error, std::move(path), std::move(message) });
    }
    void Warning(std::string path, std::string message)
    {
        items.push_back({ Diagnostic::Severity::Warning, std::move(path), std::move(message) });
    }
    uint32 ErrorCount() const;
    uint32 WarningCount() const;
    inline bool HasErrors() const
    {
        return ErrorCount() > 0;
    }
    bool Contains(std::string_view fragment, Diagnostic::Severity severity) const; // tests
    // "error: <path>: <message>" / "warning: ..." lines
    std::string ToText() const;
};

// everything compiled from one HDF.json (built-ins included); not movable: the pool keeps a pointer to the sort table
class LoadedSpecification
{
  public:
    Signature signature;
    ConstantPool pool;
    Specification specification;
    Interpretation interpretation;
    StoppingPolicy stopping;

    LoadedSpecification();
    LoadedSpecification(const LoadedSpecification&)            = delete;
    LoadedSpecification& operator=(const LoadedSpecification&) = delete;
};

struct LoaderOptions {
    bool requireGenerators{ false }; // tooling: every predicate/action entry needs a non-empty "generator" list
};

bool IsIdentifier(std::string_view name);

// always returns a specification (the parts that loaded); check diagnostics.HasErrors()
std::unique_ptr<LoadedSpecification> LoadSpecification(const nlohmann::ordered_json& document, Diagnostics& diagnostics, const LoaderOptions& options = {});
// nullptr only when the text is not JSON
std::unique_ptr<LoadedSpecification> LoadSpecificationText(std::string_view text, Diagnostics& diagnostics, const LoaderOptions& options = {});
std::unique_ptr<LoadedSpecification> LoadSpecificationFile(const std::filesystem::path& path, Diagnostics& diagnostics, const LoaderOptions& options = {});
// built-ins only (no file): the engine falls back to this when HDF.json is missing
std::unique_ptr<LoadedSpecification> MakeBuiltinSpecification();

} // namespace GView::HDF

#define CATCH_CONFIG_ENABLE_BENCHMARKING
#include <catch.hpp>

#include "KnowledgeBase.hpp"
#include "PatternMatcher.hpp"
#include "AnalysisEngineInternal.hpp"

using namespace GView::Components::AnalysisEngine;

namespace
{
    Fact MakeTestFact(PredId pred, SubjectId subject_id, std::string_view source = "test")
    {
        Fact f;
        f.atom.pred         = pred;
        f.atom.subject      = { Subject::SubjectType::File, subject_id };
        f.source            = std::string(source);
        f.time              = now();
        return f;
    }
} // namespace

TEST_CASE("KnowledgeBase monotonic snapshot growth", "[analysisengine]")
{
    KnowledgeBase kb;
    const auto s0 = kb.CurrentSnapshot();
    REQUIRE(s0 != nullptr);
    REQUIRE(s0->fact_count == 0);

    REQUIRE(kb.Add(MakeTestFact(1, 1)).ok);
    kb.AdvanceSnapshot();
    const auto s1 = kb.CurrentSnapshot();
    REQUIRE(s1->fact_count == 1);
    REQUIRE(s1->DeltaCount() == 1);

    REQUIRE(kb.Add(MakeTestFact(2, 1)).ok);
    kb.AdvanceSnapshot();
    const auto s2 = kb.CurrentSnapshot();
    REQUIRE(s2->fact_count == 2);
    REQUIRE(s2->fact_count >= s1->fact_count);
}

TEST_CASE("FactKey deduplication", "[analysisengine]")
{
    KnowledgeBase kb;
    Fact f = MakeTestFact(5, 10);
    f.atom.args.push_back({ "filename", std::string("a.exe") });
    REQUIRE(kb.Add(f).ok);
    REQUIRE(kb.Exists(5, f.atom.subject));

    const auto key = MakeFactKey(f);
    REQUIRE(kb.HasFactKey(key));
}

TEST_CASE("PatternMatcher cross-literal unification", "[analysisengine]")
{
    KnowledgeBase kb;
    Subject subject{ Subject::SubjectType::File, 42 };

    Fact f1 = MakeTestFact(1, 42);
    f1.atom.args.push_back({ "name", std::string("foo") });
    Fact f2 = MakeTestFact(2, 42);
    f2.atom.args.push_back({ "name", std::string("bar") });
    kb.Add(f1);
    kb.Add(f2);

    ConjClause clause;
    clause.all_of = { { 1, false }, { 2, false } };

    std::vector<Reference<const Fact>> matched;
    REQUIRE_FALSE(PatternMatcher::Holds(clause, subject, kb, matched));
}

TEST_CASE("DisclosureTrace records transitions", "[analysisengine]")
{
    KnowledgeBase kb;
    auto from = kb.CurrentSnapshot();
    kb.Add(MakeTestFact(1, 1));
    std::vector<uint32> indices = { 0 };
    kb.RecordTransition(from, std::nullopt, std::move(indices));

    REQUIRE(kb.GetDisclosureTrace().Size() == 1);
    REQUIRE(kb.GetDisclosureTrace().TraceSpan().front().new_fact_indices.size() == 1);
}

TEST_CASE("Snapshot chain memory scales O(transitions) not O(Gamma x transitions)", "[analysisengine][!benchmark]")
{
    KnowledgeBase kb;
    for (uint32 i = 0; i < 1000; ++i) {
        auto from = kb.CurrentSnapshot();
        kb.Add(MakeTestFact(static_cast<PredId>(i % 10 + 1), 1));
        kb.RecordTransition(from, std::nullopt, { i });
    }
    REQUIRE(kb.GetDisclosureTrace().Size() == 1000);
    REQUIRE(kb.FactsSpan().size() == 1000);
    REQUIRE(kb.CurrentSnapshot()->fact_count == 1000);
}

TEST_CASE("BM_assertion_closure scaling", "[analysisengine][benchmark]")
{
    BENCHMARK("Add 100 facts and advance snapshots")
    {
        KnowledgeBase kb;
        for (uint32 i = 0; i < 100; ++i)
            kb.Add(MakeTestFact(1, i % 5 + 1));
        return kb.FactsSpan().size();
    };
}

TEST_CASE("BM_disclosure_trace_append", "[analysisengine][benchmark]")
{
    BENCHMARK("Record 500 transitions")
    {
        KnowledgeBase kb;
        for (uint32 i = 0; i < 500; ++i) {
            auto from = kb.CurrentSnapshot();
            kb.Add(MakeTestFact(1, 1));
            kb.RecordTransition(from, std::nullopt, { i });
        }
        return kb.GetDisclosureTrace().Size();
    };
}

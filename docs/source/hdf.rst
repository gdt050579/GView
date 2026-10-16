Hybrid Disclosure Framework (HDF)
=================================

The Hybrid Disclosure Framework drives an analysis as a *disclosure process*: GView (the tool *T*) discloses ground
assertions about the analysed artifact, a rule set derives new assertions and offers the actions that make sense next,
the analyst selects one, its execution discloses more, and so on until the interpretation is conclusive and settled,
the analyst stops, or another stopping policy applies. The interpretation maps what was learned to an outcome (``Malicious``,
``Benign`` or ``Inconclusive``) and an explanation shows *why*: the clauses of the label that holds and the verdict
assertions that satisfy them, their derivation trees down to what the plugins observed, the provenance of the deciding
subject and the trace of the executed actions (or, for ``Inconclusive``, which clause failed or which labels conflict).

::

   (X, H) --disclosure process--> (Gamma_n, tau_X) --interpretation--> (outcome, explanation)

* ``X`` is the input subject (the file opened in a top-level window); every object extracted from it (an archive member,
  a connection of a capture, a selected range) is a *subject* of the same disclosure session.
* ``H = (R, A, V)`` is the specification in ``HDF.json``: assertion rules ``R``, action rules ``A`` and verdict predicates ``V``.
* ``Gamma_i`` is the knowledge state (a set of ground assertions such as ``IsPE(sample.exe)``), ``tau_X`` the trace of
  transitions ``Gamma_i --beta_i--> Gamma_i+1``.

The implementation lives in ``GViewCore/src/HDF`` (namespace ``GView::HDF``); its formal reading, the data structures and
the algorithms are described in ``plans/HDF_IMPLEMENTATION.md``.

Concepts
--------

Vocabulary
   Many-sorted: every argument has a *sort*. Built-in sorts: ``Subject``, ``String``, ``Int``, ``Real``, ``Bool`` and
   ``URL`` (a ``String`` kind). Domain sorts (``"kind": "String"`` etc.) can be added. A *predicate* ``p : s1 x .. x sk``
   names a kind of assertion, an *action* ``a : s1 x .. x sk`` a tool operation the analyst can select.

Built-ins
   ``ExtractedFrom(y, x)``, ``HasName(x, name)``, ``HasContent(x)``, ``HasOffset(x, offset)``, ``HasSize(x, size)`` are
   asserted by the engine for every subject. The action ``ReanalyzeSelection(x)`` (rule ``HasContent(x) ||- ReanalyzeSelection(x)``)
   is what *Enter / open selection* does in the Buffer, Text and Dissasm viewers. For every non-repeatable action ``a`` the
   engine adds the completion predicate ``Done_a`` with the same arity.

Rules
   Positive, safe Horn rules over literals ``Name(t1, .., tk)`` where a term is a variable (an identifier), a string
   (``"..."``), a number or ``true``/``false``. Every variable of the head must occur in the body. Joins across subjects are
   allowed: ``ExtractedFrom(y, x), IsPE(y) |- ContainsExecutable(x)``.

Actions
   ``Enabled(Gamma)`` are the ground actions produced by the action rules; ``Completed(Gamma)`` the non-repeatable ones whose
   ``Done_a`` is already known; the analyst chooses from ``Selectable = Enabled \ Completed``. ``Done_a`` is added only when
   the execution succeeds: a failed or cancelled execution is recorded in the trace and the action stays selectable.

Verdicts and interpretation
   Verdict predicates ``V`` have the arity ``Subject x Real`` (``HasMaliciousness(x, 0.75)``, ``HasBenignity(x, 0.85)``);
   they are the only predicates the interpretation reads. Rules never compare scores: a rule derives a verdict assertion
   with a constant score, and the interpretation reads the scores of ``Gamma_n``. The outcome set is
   ``Omega = Omega_c u {Inconclusive}``: ``HDF.json`` declares only the conclusive labels ``Omega_c``, each with a
   *condition* that is a conjunction of clauses over the scores of one subject ``Y``:

   * presence ``exists V(Y, c): c OP t`` and absence ``not exists V(Y, c): c OP t``, ``OP`` in ``>=``, ``>``, ``<=``, ``<``.
     Absence is evaluated by the interpretation on ``Gamma_n`` (it is not negation in the rules).
   * Several ``V(Y, c_i)`` are first combined into one score (``max`` by default; ``min``, ``mean`` or ``noisy_or`` per
     predicate) and every clause reads the combined score. For ``max`` and ``>=``/``>`` this is exactly the existential reading.
   * ``I_subj(Y)``: exactly one label holds: that label; no label holds: ``Inconclusive`` (no label satisfied); more than
     one: ``Inconclusive`` (conflict). Labels are evaluated in declaration order; there is no priority order.
   * Across the provenance tree of ``X`` (``X`` and every subject extracted from it): a label with ``"propagate": true``
     (``Malicious``) holds for ``X`` when it holds for any subject; a non-propagating label (``Benign``) holds for ``X`` when
     ``I_subj(X)`` is that label and no propagating label holds anywhere. Maliciousness propagates upward, benignity never.
     ``"aggregation": "strict"`` also blocks a non-propagating label when an extracted subject is in conflict.
   * Every label declares when a decision for it is final: ``"settle": "immediate"`` (default) or ``"exhaustion"``. The
     label *holds* in the same way in both cases; an ``exhaustion`` label is *settled* only when nothing is selectable any
     more. Absence clauses read the current knowledge, so a selectable action may still disclose the evidence they exclude:
     ``Benign`` (``no HasMaliciousness > 0.30``) settles at exhaustion, ``Malicious`` immediately.

   ``Inconclusive`` is added by the framework: it cannot be declared and has no condition; ``inconclusive_alias`` only
   changes its display name. By default the process stops as soon as the interpretation is conclusive *and settled*
   (``stopping.policy = conclusive``); a derived verdict assertion alone never stops it, a provisional (not yet settled)
   label does not stop it, and a conflict is not a stop.

``HDF.json``
------------

``HDF.json`` is loaded from the current folder, then from the folder of the executable (``[HDF] SpecificationFile`` in
``gview.ini``). A broken or stale file never stops GView: the problems are logged and the parts that load are used.
JSON does not allow comments; use ``"description"`` keys (they are ignored).

.. code-block:: json

   {
     "sorts":      [ { "name": "Domain", "kind": "String", "generator": [ "Manual" ] } ],
     "predicates": [ { "name": "IsPE", "arity": [ { "name": "x", "sort": "Subject" } ],
                       "denotation": "{x} is a PE file", "generator": [ "Plugin:PE" ] } ],
     "actions":    [ { "name": "CheckConnections", "arity": [ { "name": "x", "sort": "Subject" } ],
                       "denotation": "Identify the connections in {x}", "repeatable": false, "generator": [ "Plugin:PCAP" ] } ],
     "verdicts":   [ "HasMaliciousness", "HasBenignity" ],
     "assertion_rules": [ { "name": "InjectionFromImports", "body": [ "ImportsProcessInjectionAPIs(x, count, sample)" ],
                            "head": "IndicatesInjection(x)", "explanation": "..." } ],
     "action_rules":    [ { "name": "ConnectionsOfCapture", "body": [ "IsPCAP(x)", "HasNetworkConnections(x, count)" ],
                            "head": "CheckConnections(x)" } ],
     "interpretation": {
       "outcomes": [ "Malicious", "Benign" ],
       "inconclusive_alias": "Unknown",
       "combination": [ { "predicate": "HasMaliciousness", "aggregate": "max" } ],
       "labels": [
         { "outcome": "Malicious", "propagate": true, "settle": "immediate",
           "clauses": [ { "present": "HasMaliciousness", "op": ">=", "value": 0.70 },
                        { "absent":  "HasBenignity",     "op": ">=", "value": 0.70 } ] },
         { "outcome": "Benign", "propagate": false, "settle": "exhaustion",
           "clauses": [ { "present": "HasBenignity",     "op": ">=", "value": 0.70 },
                        { "absent":  "HasMaliciousness", "op": ">",  "value": 0.30 } ] } ],
       "aggregation": "default" },
     "stopping": { "policy": "conclusive", "max_steps": 0 }
   }

``interpretation.outcomes`` must not contain ``Inconclusive`` (in any case) and a label condition cannot name it;
the keys of the earlier interpretation and stopping schema are rejected with a pointer to the new keys. Every
clause names a verdict predicate with exactly one of ``present``/``absent``; ``settle`` is ``immediate`` or
``exhaustion``. ``stopping.policy`` is ``conclusive`` (default: stop when the interpretation is conclusive and settled), ``manual`` (only the analyst stops) or ``exhaustive`` (stop when
nothing is selectable); ``max_steps > 0`` stops after that many executed actions whatever the policy.

``denotation`` is the human reading of an assertion or action: ``{name}`` placeholders refer to argument names (``{{`` and
``}}`` escape braces). Subjects are shown by name, reals with two decimals.

Generated sections
~~~~~~~~~~~~~~~~~~

Only ``sorts``, ``verdicts``, the rules, ``interpretation``, ``stopping`` and the ``Manual`` entries are written by hand.
Every ``predicates``/``actions`` entry has a ``generator`` list naming who produces it:

========================  ==================================================================================
``Plugin:<Name>``         a type plugin (``Types/<Name>``) declares it in its ``RegisterPlugin`` export
``GenericPlugin:<Name>``  a generic plugin (``GenericPlugins/<Name>``)
``SmartViewer:<Name>``    a core viewer (``Buffer``, ``Text``, ``Dissasm``, ...)
``Core:HDF``              the engine (built-ins and ``Done_a``)
``Rule:<RuleName>``       a derived predicate: the head of that assertion rule (its arity is inferred from the body)
``Manual``                hand-written; never modified or removed by ``hdf augment``
========================  ==================================================================================

Recommended workflow: edit the rules, run ``GView hdf augment`` to regenerate the vocabulary, run ``GView hdf validate``
(also in CI). At run time, a plugin that declares a symbol missing from ``HDF.json`` gets it appended in memory with a
warning (no rule can use it); a symbol whose arity or sorts differ from ``HDF.json`` is rejected (its disclosures fail and
are logged).

Command line
------------

``GView hdf validate [file] [--json]``
   Checks the specification (sorts, arities, ill-sorted terms, unsafe rules, verdict arities, outcome set, interpretation,
   unique rule names), the generator lists and the drift against the installed modules: a symbol declared by a module but
   missing from the file, a generator that no longer declares a symbol, arity/sort differences (errors), denotation or
   generator-list differences, unused predicates and actions that only ``Manual`` can produce (warnings). Exit code 0 when
   there is no error; ``--json`` prints the report as JSON. The application is not initialised: the plugins are only loaded
   to call ``RegisterPlugin``.

``GView hdf augment [file] [--output <file>] [--dry-run] [--check]``
   Collects the declarations of the core, of every ``Types/lib*.tpl`` and ``GenericPlugins/lib*.gpl`` and infers the derived
   predicates from the rule heads (quoted constants are ``String``, numbers with ``.`` or an exponent ``Real``, other
   numbers ``Int``). ``Manual`` entries (or entries without ``generator``) are kept verbatim; module/rule entries are rewritten
   from the declarations; entries nobody declares any more are removed; new entries are appended sorted by name. The file
   is replaced atomically and the result is validated. ``--dry-run`` prints the diff and writes nothing, ``--check`` exits 1
   when the file is not up to date (use it in CI).

.. code-block:: bash

   GView hdf augment HDF.json --dry-run
   GView hdf validate HDF.json

The HDF window
--------------

``Alt+F12`` opens the window of the disclosure session of the current file:

* **Subject**: the subject tree (children are the subjects extracted from it); under each subject its assertions (``den``
  and the source or the plugin's explanation) and its selectable actions. ``Enter`` on an action executes it (the trace
  records the step); actions no tool can execute are greyed. When the action opens a new subject the window can close and
  focus it.
* **Actions**: one row per transition (initial extraction, observations, steps ``beta_i`` with their status), with the
  number of disclosed and derived assertions.
* **Summary**: ``Ctrl+R`` asks the configured smart assistant to summarise ``Gamma_i`` and recommend actions *by number*
  from ``Selectable(Gamma_i)``; ``Ctrl+E`` executes the first recommended action that is still selectable. The assistant
  never executes anything by itself and cannot add actions or rules. Disabled when the course policy disables LLM hints.
* **Report**: the explanation of the current interpretation (outcome; ``I_subj`` of the input and of the deciding subject;
  one line per clause of the label that holds, or the reason of ``Inconclusive``; the verdict assertions with their rules,
  premises and derivation trees; provenance path; trace; stop reason) and the derivation tree of the assertion selected in
  the Subject tab. The status line shows the interpretation the session computed after its last transition, e.g.
  ``Malicious (conclusive, via payload.exe)``, ``Benign (provisional, settles at exhaustion: 2 selectable action(s) remain)``,
  ``Benign (conclusive, settled: no selectable action remains)``, ``Unknown (no label satisfied)`` or
  ``Unknown (conflict: Malicious, Benign)``.

``Ctrl+F`` finishes the process (manual stop): the session is frozen and the report shows the stop reason. ``F5`` rebuilds
the views.

``gview.ini``
-------------

.. code-block:: ini

   [HDF]
   SpecificationFile = HDF.json   ; relative: current folder, then the folder of the executable
   StoppingPolicy = specification ; conclusive | manual | exhaustive (overrides HDF.json); specification: use HDF.json
   MaxSteps = 0                   ; > 0: stop after that many executed actions (overrides HDF.json)
   MaxDerivedPerStep = 1000000    ; safety cap of one closure (the closure is sound but incomplete when it is reached)

Plugin API
----------

A plugin declares its vocabulary in the (optional, mandatory for in-tree plugins) ``RegisterPlugin`` export, discloses
assertions about its window's subject from ``PopulateWindow`` (they form the initial extraction ``Init_T(x)``) and executes
the actions it owns through ``GView::HDF::ActionExecutorInterface``. A PCAP-sized example:

.. code-block:: cpp

   PLUGIN_EXPORT void RegisterPlugin(Reference<GView::PluginRegistry> registry)
   {
       auto& v = registry->HDFVocabulary();      // future metadata sections are added to PluginRegistry, never as new exports
       v.Predicate("IsPCAP", { { "x", "Subject" } }, "{x} is a network capture");
       v.Predicate("HasConnectionWithExecutable", { { "c", "Subject" }, { "name", "String" } }, "connection {c} transfers {name}");
       v.Action("CheckConnections", { { "x", "Subject" } }, "Identify the connections in {x}");
   }

   PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
   {
       auto file    = win->GetObject()->GetContentType<MyFile>();
       auto hdf     = win->GetHDF();
       auto subject = win->GetSubject();
       file->isPcap = hdf->Predicate("IsPCAP");
       hdf->Disclose(subject, file->isPcap, { subject });                       // part of Init_T(subject)
       // MyFile implements GView::HDF::ActionExecutorInterface; the executor is dropped when the window closes
       hdf->RegisterActionExecutor(hdf->Action("CheckConnections"), subject, file.ToBase<GView::HDF::ActionExecutorInterface>());
       return true;
   }

   GView::HDF::ActionStatus MyFile::Execute(const GView::HDF::GroundActionView& action, const GView::HDF::ActionInput*,
                                            GView::HDF::DisclosureSink& out)
   {
       for (auto& stream : streams) {
           auto c = out.CreateSubject(stream.name, out.Self());           // ExtractedFrom(c, x), HasName(c, name)
           out.Assert(hasConnectionWithExecutable, { c, stream.file });   // part of Gamma_beta
       }
       return GView::HDF::ActionStatus::Success;                         // Done_CheckConnections(x) is added by the engine
   }

* ``Disclose`` / ``Assert`` return ``false`` (and log) on an unknown predicate, a wrong arity, a value that is not
  representable in the declared sort, or a subject of another session. They never throw.
* A window that an executor opens after ``CreateSubject`` (``GView::App::OpenBuffer`` ...) is attached to that subject and
  its ``PopulateWindow`` disclosures belong to the same step.
* Disclosures made outside ``PopulateWindow`` and outside a step (a plugin command) should be grouped with
  ``auto scope = hdf->BeginObservation(subject, "CommandName");``: everything disclosed until ``scope`` is destroyed is one
  observation transition (the closure runs once).
* Executors are owned by a subject: a ground action is executed by the executor registered by the closest ancestor of its
  first ``Subject`` argument; executors are dropped when the window of their subject closes.

#!/usr/bin/env python3
"""Watch independent behavioral controls fail on compiled, isolated fault plants."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import sys
import tomllib

root = Path(__file__).resolve().parent.parent
temporary = root / "target"
plants = [
    ("native source identity", "src/derivation.rs", ".find(|f| f.source == *reference)", ".find(|f| f.source.digest == reference.digest)",
     "scale_cached_interpretations_and_native_source_names_are_not_clock_identity"),
    ("owner refusal", "src/derivation.rs", "Some(FactState::Refused(r)) => refused = Some(r.clone()),",
     "Some(FactState::Refused(_)) => (),", "b05_independent_standing_owners_audiences_and_structural_coverage"),
    ("missing source", "src/derivation.rs", "if !missing.sources.is_empty()", "if false && !missing.sources.is_empty()",
     "b01_sources_not_display_time_or_carrier_determine_counted_effects"),
    ("narrowing", "src/derivation.rs", "if !parent.covers(&step.scope, delegated)", "if false && !parent.covers(&step.scope, delegated)",
     "b06_narrow_native_delegation_cannot_fall_back_or_leak_credentials"),
    ("exact admission", "src/derivation.rs", "if exact != effect.fingerprint()", "if false && exact != effect.fingerprint()",
     "b08_historical_admission_binds_effect_sources_issuer_and_purpose"),
    ("historical/live separation", "src/derivation.rs", "if purpose != Purpose::HistoricalAdmission", "if false && purpose != Purpose::HistoricalAdmission",
     "b08_historical_admission_binds_effect_sources_issuer_and_purpose"),
    ("expiry", "src/derivation.rs", "if when.covered_by(interval)", "if when.covered_by(interval) || when.earliest() >= interval.until()",
     "b09_continuation_is_linear_and_rechecks_current_rights_not_old_records"),
    ("admission whole interval", "src/profile.rs", "interval.covers(window)", "interval.contains(window.from())",
     "historical_native_witness_can_attest_a_window_without_inventing_an_instant"),
    ("continuation deadline", "src/scaffold.rs", "> i64::from(self.contract.recheck_within)", "> i64::MAX",
     "b09_continuation_is_linear_and_rechecks_current_rights_not_old_records"),
    ("cached interpretation deadline", "src/profile.rs", "&& at >= deadline", "&& false && at >= deadline",
     "cached_authority_must_be_reinterpreted_at_its_declared_transition_boundary"),
    ("exact profile effect", "src/derivation.rs", "is_some_and(|f| f != effect.fingerprint())", "is_some_and(|f| false && f != effect.fingerprint())",
     "b11_activation_executes_accepted_bytes_and_surfaces_first_version_conflict"),
    ("profile actor", "src/derivation.rs", "if !policy.actor_matches(effect.exercise().credential())", "if false && !policy.actor_matches(effect.exercise().credential())",
     "visitor_scope_and_profile_specific_refusals_need_no_new_kernel_branch"),
    ("last slot", "tests/profiles/resource.rs", "if s.held >= s.capacity", "if false && s.held >= s.capacity",
     "b10_last_slot_is_atomic_and_failures_release_the_owned_reservation"),
    ("constitutional freeze", "tests/profiles/constitution.rs", "if !conflicts.is_empty()", "if false && !conflicts.is_empty()",
     "b04_genuine_forks_freeze_without_restoring_a_keeper"),
    ("bare Admit", "tests/profiles/constitution.rs", "let Some(invite) = invite else {\n                    return Err(Outcome::Refused);",
     "let Some(invite) = invite else {\n                    return Ok(());", "b03_join_link_leave_and_cut_are_one_constitutional_interpretation"),
    ("sticky cross-operation constraint", "tests/profiles/constitution.rs", "if *as_app\n", "if false && *as_app\n",
     "b13_sticky_cross_operation_history_is_not_erased_by_stop_or_code_change"),
]

cases = [(label, name, needle, replacement, "extensions", test) for label, name, needle, replacement, test in plants]
cases += [
    ("profile operations cannot erase classified app authority", "src/context.rs", "_ => Err(Invalid::Context),", "_ => Ok(()),", "profile_requests", "custom_meaning_cannot_erase_classification_or_mix_a_native_resource"),
    ("canon raw source identity before lossy dedup", "src/canon.rs", "Act::new(act.kind.clone(), act.ts_unix, act.actor.clone()).id != act.id", "false", "canon_sources", "rewritten_content_id_is_not_an_authenticated_source"),
    ("canon signature variants before lossy dedup", "src/canon.rs", ".is_some_and(|old| *old != value)", ".is_some_and(|old| false && *old != value)", "canon_sources", "conflicting_signature_variants_cannot_be_lost_by_short_id_deduplication"),
    ("canon full pin not short ID", "src/canon.rs", "digest: pin.as_bytes().to_vec(),", "digest: grant.act.as_str().as_bytes().to_vec(),", "canon_sources", "canonical_full_pins_and_exact_duplicates_survive_before_short_id_log_construction"),
    ("native verification precedes semantic projection", "src/statement.rs", "k.verify_strict(message, &s).is_err()", "false && k.verify_strict(message, &s).is_err()", "statement", "invalid_signature_never_reaches_semantic_projection_or_the_resource"),
    ("raw bytes never expand to integer frames", "src/encoding.rs", "self.bytes(8, b);", "self.number(6,b.len() as u64); for byte in b {self.number(3,u64::from(*byte));}", "lib", "encoding::tests::raw_body_has_one_length_frame_not_one_integer_frame_per_byte"),
    ("compound frame declared length", "src/encoding.rs", "if self.left == 0 && !self.key", "if !self.key", "lib", "encoding::tests::unknown_lengths_floats_and_misdeclared_counts_are_not_silent_encodings"),
    ("native ingress target is not a request claim", "src/context.rs", "|| self.resource != i.resource", "|| false && self.resource != i.resource", "actors", "public_target_substitution_is_stopped_by_ingress_even_under_the_same_lender"),
    ("same-person sessions retain ingress identity", "src/context.rs", "if self.actor != i.actor {\n            return Err(IngressMismatch::Actor);", "if false && self.actor != i.actor {\n            return Err(IngressMismatch::Actor);", "actors", "two_same_person_sessions_are_not_the_same_authenticated_ingress"),
    ("native required owner set", "src/derivation.rs", "if let Some(required) = required {", "if let Some(required) = None::<BTreeSet<Owner>> {", "actors", "a_native_operation_cannot_omit_the_person_owner_from_its_policy_set"),
    ("native class restriction", "src/identity.rs", "return Err(ContextFailure::ClassDenied);", "let _ = app.class();", "identities", "every_allowed_class_operation_reaches_the_real_owner_but_the_other_pair_does_not"),
    ("native resource family", "src/identity.rs", "resource.kind() != operation.target_kind()", "false && resource.kind() != operation.target_kind()", "identities", "wrong_family_other_apps_part_and_other_group_fail_even_with_explicit_standing"),
    ("native own part", "src/identity.rs", ".is_some_and(|id| id != app.identity())", ".is_some_and(|id| false && id != app.identity())", "identities", "wrong_family_other_apps_part_and_other_group_fail_even_with_explicit_standing"),
    ("native record realm", "src/identity.rs", "&& expected != *group", "&& false && expected != *group", "identities", "wrong_family_other_apps_part_and_other_group_fail_even_with_explicit_standing"),
    ("native context needs", "src/identity.rs", "if app.is_none() && resource.is_none() && operation.is_none()", "if app.is_none() || resource.is_none() || operation.is_none()", "identities", "partial_legacy_context_is_a_typed_need_not_a_class_or_personal_fallback"),
    ("legacy Tree cannot alias native ID", "src/profile.rs", "if root.identity().is_some() || resource.identity().is_some()", "if false && (root.identity().is_some() || resource.identity().is_some())", "identities", "legacy_tree_labels_cannot_cover_native_resource_identities"),
    ("class is hashed into authority and origin", "src/identity.rs", "ApplicationClass::Connector => 1", "ApplicationClass::Connector => 0", "identities", "independent_identity_and_full_origin_vectors_are_not_json_hashes"),
    ("invalid prefix cannot buy signature work on a suffix", "src/derivation.rs", "let mut proofs = steps(basis, policy, supplied)?;", "let mut proofs = steps(basis, policy, supplied)?.collect::<Vec<_>>().into_iter();", "adversarial", "invalid_prefix_does_not_force_verification_of_an_attackers_suffix"),
    ("stream checks cannot replay a POST", "tests/svrngs_use_lifecycle.rs", "s.checks += 1;", "s.checks += 1; s.starts.push(b\"duplicate POST\".to_vec());", "svrngs_use_lifecycle", "a_post_is_forwarded_once_and_idle_checks_keep_one_original_slot"),
    ("stream checks retain the original slot", "tests/svrngs_use_lifecycle.rs", "s.checks += 1;", "s.checks += 1; s.stage = Stage::Closed;", "svrngs_use_lifecycle", "a_post_is_forwarded_once_and_idle_checks_keep_one_original_slot"),
    ("future-only Stop is not active cancellation", "tests/svrngs_use_lifecycle.rs", "Stage::Streaming(*use_id) {\n                    FactState::Established", "Stage::Streaming(*use_id) {\n                    match inputs.choice {Choice::Yes => FactState::Established,Choice::Stop => FactState::Refused(Reason::Profile(id(\"stopped\")))}", "svrngs_use_lifecycle", "the_existing_future_only_stop_rule_is_not_silently_changed_to_cancellation"),
    ("reservation resource identity", "tests/svrngs_use_lifecycle.rs", "Rc::ptr_eq(&self.owner.service, &owner.service)\n            && self.owner.resource == owner.resource\n            && ", "", "svrngs_use_lifecycle", "a_pending_reservation_for_another_lend_cannot_satisfy_this_lends_condition"),
    # The community profile's own package (community/), run from a copy of it.
    ("another person's owned row is not written", "community/src/db.rs", "Change::Write => Verdict::Refused(Why::NotTheirs),", "Change::Write => Verdict::Taken,", "db", "an_owned_row_changes_only_by_its_person_s_devices"),
    ("an owned row's key is text of exact bytes", "community/src/db.rs", "(key.kind == Type::Text).then(", "true.then(", "db", "a_key_is_its_person_s_only_as_text_of_exactly_its_bytes"),
    ("a standing person's row is not deleted", "community/src/db.rs", "Change::Delete if gone(record, owner) => Verdict::Taken,", "Change::Delete => Verdict::Taken,", "db", "a_removed_person_s_rows_take_deletes_from_any_member"),
    ("a set waits for its signer's binding", "community/src/db.rs", "if record.person_of(signer).is_some() {", "if true {", "db", "a_removed_device_s_sets_are_taken_like_any_device_s"),
    ("a removed device's sets are taken", "community/src/db.rs", "if record.person_of(signer).is_some() {", "if record.cut(signer) {\n        Verdict::Refused(Why::NotTheirs)\n    } else if record.person_of(signer).is_some() {", "db", "a_removed_device_s_sets_are_taken_like_any_device_s"),
    ("a Remove never turns a taken set", "community/src/db.rs", "if record.person_of(signer).is_some() {", "if record.cut(signer) {\n        Verdict::Refused(Why::NotTheirs)\n    } else if record.person_of(signer).is_some() {", "db", "no_verdict_turns_as_removes_arrive"),
    ("a Remove never turns a taken row", "community/src/db.rs", "_ if owner == person => Verdict::Taken,", "_ if owner == person && !record.cut(signer) => Verdict::Taken,", "db", "no_verdict_turns_as_removes_arrive"),
    ("every order ends alike: no set refused once taken", "community/src/db.rs", "if record.person_of(signer).is_some() {", "if record.cut(signer) {\n        Verdict::Refused(Why::NotTheirs)\n    } else if record.person_of(signer).is_some() {", "db", "every_order_of_the_removes_and_sets_ends_alike"),
    ("every order ends alike: no row refused once taken", "community/src/db.rs", "_ if owner == person => Verdict::Taken,", "_ if owner == person && !record.cut(signer) => Verdict::Taken,", "db", "every_order_of_the_removes_and_sets_ends_alike"),
    ("a binding a cut retracts is not its person's key", "community/src/db.rs", "m.first == person && !self.retracted().contains(*key)", "m.first == person", "db", "a_key_bound_past_a_cut_s_reach_leaves_a_taken_delete_taken"),
    ("a cut counts once the record holds what it names", "community/src/history.rs", "reach.missing.is_empty()", "true", "db", "a_delete_waits_while_a_cut_names_a_line_the_record_lacks"),
    ("a person's own Remove is not the office's cut", "community/src/db.rs", "self.cuts().contains_key(device)", "self.cuts().contains_key(device) || self.out().get(device).is_some_and(|(_, own)| *own)", "db", "a_person_s_own_remove_holds_a_delete_until_the_office_cuts_that_key"),
    ("no verdict turns: a retracted binding", "community/src/db.rs", "m.first == person && !self.retracted().contains(*key)", "m.first == person", "db", "no_verdict_turns_as_more_of_a_removed_person_s_history_arrives"),
    ("no verdict turns: a cut's unheld reach", "community/src/history.rs", "reach.missing.is_empty()", "true", "db", "no_verdict_turns_as_more_of_a_removed_person_s_history_arrives"),
    ("no verdict turns: a person's own Remove", "community/src/db.rs", "self.cuts().contains_key(device)", "self.cuts().contains_key(device) || self.out().get(device).is_some_and(|(_, own)| *own)", "db", "no_verdict_turns_as_more_of_a_removed_person_s_history_arrives"),
]

integration = sys.argv[1:] == ["--integration"]
if sys.argv[1:] and not integration:
    raise SystemExit("usage: check_extensions.py [--integration]")
if integration:
    cases = [
        ("native device/person normalization", "integration/tests/native_bindings.rs", "scope.person = Some(self.person_hint);", "let _ = self.person_hint;", "native_bindings", "a_linked_issuer_maps_to_its_stable_person_without_reissuing_its_pass"),
        ("native app reach is not signed read-set inclusion", "integration/tests/reach_projection.rs", 'Resource::new(format!("lend/read/{lend}")).unwrap()', 'Resource::new(format!("lend/own/{lend}")).unwrap()', "reach_projection", "app_reach_does_not_allow_adding_the_app_to_the_signed_read_set"),
        ("native link preserves the bound original person", "integration/tests/reach_projection.rs", "person: Some(person),", "person: Some(if self.onward == 0 { self.issuer } else { person }),", "reach_projection", "a_lawful_holder_link_preserves_the_original_person_and_whole_scope"),
        ("native root permits its lawful holder link", "integration/tests/reach_projection.rs", "parsed(raw, 1)", "parsed(raw, 0)", "reach_projection", "a_lawful_holder_link_preserves_the_original_person_and_whole_scope"),
    ]

for label, name, needle, replacement, suite, test in cases:
    with tempfile.TemporaryDirectory(prefix="eudoxia-plant-", dir=temporary) as tmp:
        work = Path(tmp)
        for name_to_copy in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]:
            shutil.copy2(root / name_to_copy, work / name_to_copy)
        for directory in ["src", "tests", "fixtures/vectors"]:
            shutil.copytree(root / directory, work / directory)
        community = name.startswith("community/")
        if community:
            shutil.copytree(root / "community", work / "community", ignore=shutil.ignore_patterns("target"))
        if integration:
            shutil.copytree(root / "integration", work / "integration", ignore=shutil.ignore_patterns("target"))
            manifest=work / "integration/Cargo.toml"
            native=tomllib.loads((root / "integration/Cargo.toml").read_text())["dev-dependencies"]["svrngs-core"]["path"]
            manifest.write_text(manifest.read_text().replace(f'path = "{native}"',f'path = "{(root / "integration" / native).resolve()}"'))
        path = work / name
        text = path.read_text()
        assert text.count(needle) == 1, (label, "plant must have exactly one site")
        path.write_text(text.replace(needle, replacement, 1))
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target/extension-plants"))
        target = ["--lib"] if suite == "lib" else ["--test", suite]
        features = ["--features", "canon"] if suite == "canon_sources" else ["--no-default-features"]
        package = "integration" if integration else "community" if community else None
        manifest = ["--manifest-path", str(work / package / "Cargo.toml")] if package else []
        run = subprocess.run(["cargo", "test", "--offline", "--locked", *manifest, *features, *target, test, "--", "--exact"],
                             cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        output = run.stdout.decode(errors="replace")
        print(f"plant: {label}\n{output}", flush=True)
        assert run.returncode != 0 and "test result: FAILED" in output and "0 passed; 1 failed" in output and "could not compile" not in output, (label, "did not witness behavioral failure")
print(f"passed: {len(cases)} compiled behavioral fault plants detected; working tree never mutated")

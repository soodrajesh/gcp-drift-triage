import pytest

from driftriage import classify as cl
from driftriage.parse import DriftParseError, diff, parse
from driftriage.remediate import attach, hcl

from .helpers import plan, rd


def one(rtype, before, after, actions=("update",), name="x"):
    d = parse(plan(rd(rtype, name, before, after, actions)))[0]
    return cl.classify(d)


def test_not_a_drift_plan_rejected():
    for bad in ({}, [], {"resource_drift": "x"}, {"resource_drift": [{"address": "a"}]}):
        with pytest.raises(DriftParseError):
            parse(bad)


def test_noise_is_filtered_and_pure_noise_is_ignored():
    d = one(
        "google_storage_bucket",
        {"name": "b", "etag": "a", "update_time": "1"},
        {"name": "b", "etag": "b", "update_time": "2"},
    )
    assert d.decision == "ignore" and d.changes == [] and len(d.noise) == 2


def test_diff_handles_lists_and_nested():
    ch, _ = diff({"a": [1, 2], "b": {"c": 1}}, {"a": [1, 2, 3], "b": {"c": 2}})
    assert {(c.path, c.before, c.after) for c in ch} == {("a.+", None, 3), ("b.c", 1, 2)}


def test_public_iam_member_is_critical_investigate():
    d = one("google_storage_bucket_iam_member", {"member": "user:a@x.com"}, {"member": "allUsers"})
    assert (d.category, d.severity, d.decision) == ("loosening", "critical", "investigate")


def test_added_member_to_binding_is_high_not_public():
    d = one(
        "google_storage_bucket_iam_binding",
        {"members": ["user:a@x.com"]},
        {"members": ["user:a@x.com", "user:b@x.com"]},
    )
    assert d.severity == "high" and d.decision == "investigate"


def test_removed_member_is_tightening_adopt():
    d = one(
        "google_storage_bucket_iam_binding",
        {"members": ["user:a@x.com", "user:b@x.com"]},
        {"members": ["user:a@x.com"]},
    )
    assert d.category == "tightening" and d.decision == "adopt"


def test_open_cidr_critical():
    d = one(
        "google_compute_firewall",
        {"source_ranges": ["10.0.0.0/8"]},
        {"source_ranges": ["10.0.0.0/8", "0.0.0.0/0"]},
    )
    assert d.severity == "critical"


@pytest.mark.parametrize(
    "attr,b,a",
    [("deletion_protection", True, False), ("public_access_prevention", "enforced", "inherited")],
)
def test_safety_flags_loosened_are_high(attr, b, a):
    d = one("google_sql_database_instance", {attr: b}, {attr: a})
    assert d.severity == "high" and d.decision == "investigate"


def test_safety_flag_restored_is_adopt():
    d = one(
        "google_sql_database_instance",
        {"deletion_protection": False},
        {"deletion_protection": True},
    )
    assert d.decision == "adopt" and d.category == "tightening"


def test_autoscaler_node_count_is_ignored_with_hint():
    d = one("google_container_node_pool", {"node_count": 3}, {"node_count": 9})
    assert d.decision == "ignore" and "ignore_changes" in d.why


def test_cost_increase_investigate_decrease_adopt():
    up = one("google_compute_disk", {"size": 100}, {"size": 4000})
    down = one("google_compute_disk", {"size": 4000}, {"size": 100})
    assert (up.decision, up.severity) == ("investigate", "medium") and down.decision == "adopt"


def test_machine_type_change_flagged():
    assert (
        one(
            "google_compute_instance",
            {"machine_type": "e2-small"},
            {"machine_type": "n2-standard-64"},
        ).decision
        == "investigate"
    )


def test_labels_and_image_adopt():
    assert one("google_storage_bucket", {"labels": {}}, {"labels": {"a": "b"}}).decision == "adopt"
    img = one(
        "google_cloud_run_v2_service",
        {"template": [{"containers": [{"image": "a:1"}]}]},
        {"template": [{"containers": [{"image": "a:2"}]}]},
    )
    assert img.decision == "adopt" and img.category == "operational"


def test_unknown_attribute_is_not_silently_adopted():
    d = one("google_thing", {"mystery": 1}, {"mystery": 2})
    assert d.category == "unknown" and d.decision == "investigate"


def test_deleted_stateful_vs_stateless():
    s = one("google_sql_database_instance", {"name": "d"}, None, ("delete",))
    t = one("google_compute_firewall", {"name": "f"}, None, ("delete",))
    assert (s.severity, s.decision) == ("critical", "investigate") and (t.severity, t.decision) == (
        "high",
        "revert",
    )


def test_human_actor_escalates_loosening_but_automation_does_not():
    d = one("google_compute_firewall", {"source_ranges": []}, {"source_ranges": ["0.0.0.0/0"]})
    d2 = d.model_copy(deep=True)
    cl.apply_actor(d, "human")
    cl.apply_actor(d2, "automation")
    assert "human principal" in d.why and "human" not in d2.why
    m = one("google_storage_bucket_iam_binding", {"members": []}, {"members": ["user:b@x.com"]})
    cl.apply_actor(m, "human")
    assert m.severity == "critical"  # high -> critical


def test_actor_never_lowers_severity():
    d = one("google_compute_firewall", {"source_ranges": []}, {"source_ranges": ["0.0.0.0/0"]})
    cl.apply_actor(d, "automation")
    cl.apply_actor(d, "unknown")
    assert d.severity == "critical"


def test_commands_and_hcl_edits():
    d = attach(one("google_storage_bucket", {"labels": {}}, {"labels": {"a": "b"}}))
    assert (
        d.hcl == ['google_storage_bucket.x: set labels.a = "b"'] and "refresh-only" in d.commands[0]
    )
    r = attach(
        one("google_compute_firewall", {"source_ranges": []}, {"source_ranges": ["0.0.0.0/0"]})
    )
    assert "-target='google_compute_firewall.x'" in r.commands[0]
    g = attach(one("google_pubsub_topic", {"name": "t"}, None, ("delete",)))
    assert any("state rm" in c for c in g.commands)


def test_hcl_value_rendering():
    assert [hcl(v) for v in (True, None, 3, "a", ["x"])] == ["true", "null", "3", '"a"', '["x"]']


def test_reordered_scalar_lists_are_not_drift():
    """GCP returns members/source_ranges sorted; a reorder is not a change."""
    d = one(
        "google_storage_bucket_iam_binding",
        {"members": ["user:b@x.com", "user:a@x.com"]},
        {"members": ["user:a@x.com", "user:b@x.com"]},
    )
    assert d.decision == "ignore" and d.changes == []


def test_set_semantics_report_exactly_the_added_and_removed_members():
    d = one(
        "google_storage_bucket_iam_binding",
        {"members": ["user:a@x.com"]},
        {"members": ["serviceAccount:s@p.iam.gserviceaccount.com", "user:a@x.com"]},
    )
    assert [(c.path, c.after) for c in d.changes] == [
        ("members.+", "serviceAccount:s@p.iam.gserviceaccount.com")
    ]
    assert d.severity == "high"


def test_real_label_drift_arrives_via_effective_labels():
    d = one(
        "google_storage_bucket",
        {"labels": {"env": "demo"}, "effective_labels": {"env": "demo"}},
        {"labels": {"env": "demo"}, "effective_labels": {"env": "demo", "cost-center": "4410"}},
    )
    assert d.decision == "adopt" and d.changes[0].path == "effective_labels.cost-center"


def test_labels_and_effective_labels_do_not_double_report():
    d = one(
        "google_storage_bucket",
        {"labels": {}, "effective_labels": {}},
        {"labels": {"a": "1"}, "effective_labels": {"a": "1"}},
    )
    assert [c.path for c in d.changes] == ["labels.a"]


def test_terraform_labels_are_noise():
    d = one(
        "google_storage_bucket", {"terraform_labels": {"a": "1"}}, {"terraform_labels": {"a": "2"}}
    )
    assert d.decision == "ignore"


def test_hints_use_real_resource_names_not_terraform_names():
    d = parse(
        plan(
            rd(
                "google_storage_bucket_iam_binding",
                "viewers",
                {"bucket": "b-real", "members": []},
                {"bucket": "b-real", "members": ["x"]},
            )
        )
    )[0]
    assert d.hints == ["b-real"]
    from driftriage.forensics import CloudLoggingAudit

    assert CloudLoggingAudit.tokens(d) == ["b-real"]

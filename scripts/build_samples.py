"""Regenerate driftriage/samples/*.json in `terraform show -json` refresh-only shape.
`x_audit` is an optional extension (audit events by address) used by the offline demo."""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "driftriage" / "samples"


def rd(rtype, name, before, after, actions=("update",)):
    return {
        "address": f"{rtype}.{name}",
        "mode": "managed",
        "type": rtype,
        "name": name,
        "change": {"actions": list(actions), "before": before, "after": after},
    }


def ev(t, who, method, ip="203.0.113.7"):
    return {"time": t, "principal": who, "method": method, "caller_ip": ip}


NOISE_B = {"etag": "CAE=", "update_time": "2026-10-20T10:00:00Z", "generation": "1"}
NOISE_A = {"etag": "CAI=", "update_time": "2026-10-27T03:12:00Z", "generation": "2"}

SAMPLES = {
    "incident_weekend": {
        "format_version": "1.2",
        "resource_drift": [
            rd(
                "google_storage_bucket_iam_member",
                "exports_reader",
                {
                    "bucket": "acme-exports",
                    "role": "roles/storage.objectViewer",
                    "member": "user:analyst@acme.com",
                    **NOISE_B,
                },
                {
                    "bucket": "acme-exports",
                    "role": "roles/storage.objectViewer",
                    "member": "allUsers",
                    **NOISE_A,
                },
            ),
            rd(
                "google_compute_firewall",
                "app_ingress",
                {
                    "name": "app-ingress",
                    "source_ranges": ["10.0.0.0/8"],
                    "direction": "INGRESS",
                    **NOISE_B,
                },
                {
                    "name": "app-ingress",
                    "source_ranges": ["10.0.0.0/8", "0.0.0.0/0"],
                    "direction": "INGRESS",
                    **NOISE_A,
                },
            ),
            rd(
                "google_sql_database_instance",
                "orders",
                {
                    "name": "orders-db",
                    "deletion_protection": True,
                    "settings": [
                        {"tier": "db-custom-2-7680", "version": 3, "user_labels": {"env": "prod"}}
                    ],
                },
                {
                    "name": "orders-db",
                    "deletion_protection": False,
                    "settings": [
                        {
                            "tier": "db-custom-2-7680",
                            "version": 4,
                            "user_labels": {"env": "prod", "ticket": "chg-1182"},
                        }
                    ],
                },
            ),
            rd(
                "google_container_node_pool",
                "workers",
                {"name": "workers", "node_count": 3, **NOISE_B},
                {"name": "workers", "node_count": 7, **NOISE_A},
            ),
            rd(
                "google_cloud_run_v2_service",
                "api",
                {
                    "name": "api",
                    "template": [
                        {
                            "revision": "api-001",
                            "containers": [{"image": "us-docker.pkg.dev/p/r/api:1.4"}],
                        }
                    ],
                },
                {
                    "name": "api",
                    "template": [
                        {
                            "revision": "api-002",
                            "containers": [{"image": "us-docker.pkg.dev/p/r/api:1.5"}],
                        }
                    ],
                },
            ),
            rd(
                "google_storage_bucket",
                "uploads",
                {"name": "acme-uploads", "labels": {"env": "prod", "owner": "platform"}, **NOISE_B},
                {
                    "name": "acme-uploads",
                    "labels": {"env": "prod", "owner": "platform", "cost-center": "4410"},
                    **NOISE_A,
                },
            ),
            rd("google_pubsub_topic", "events", {"name": "events"}, None, actions=("delete",)),
        ],
        "x_audit": {
            "google_storage_bucket_iam_member.exports_reader": [
                ev("2026-10-25T22:41:10Z", "intern@acme.com", "SetIamPolicy", "198.51.100.23")
            ],
            "google_compute_firewall.app_ingress": [
                ev(
                    "2026-10-26T02:03:55Z",
                    "dave@acme.com",
                    "v1.compute.firewalls.patch",
                    "198.51.100.88",
                )
            ],
            "google_sql_database_instance.orders": [
                ev("2026-10-26T14:20:00Z", "dba@acme.com", "cloudsql.instances.update")
            ],
            "google_cloud_run_v2_service.api": [
                ev(
                    "2026-10-27T09:00:12Z",
                    "ci-deployer@acme-prod.iam.gserviceaccount.com",
                    "google.cloud.run.v2.Services.UpdateService",
                    "34.1.1.1",
                )
            ],
            "google_storage_bucket.uploads": [
                ev("2026-10-27T11:05:00Z", "carol@acme.com", "storage.buckets.update")
            ],
        },
    },
    "quiet_week": {
        "format_version": "1.2",
        "resource_drift": [
            rd(
                "google_container_node_pool",
                "workers",
                {"name": "workers", "node_count": 3, **NOISE_B},
                {"name": "workers", "node_count": 4, **NOISE_A},
            ),
            rd(
                "google_storage_bucket",
                "logs",
                {"name": "acme-logs", **NOISE_B},
                {"name": "acme-logs", **NOISE_A},
            ),
            rd(
                "google_cloud_run_v2_service",
                "web",
                {
                    "name": "web",
                    "template": [{"revision": "web-001"}],
                    "labels": {"goog-managed": "x"},
                },
                {
                    "name": "web",
                    "template": [{"revision": "web-002"}],
                    "labels": {"goog-managed": "y"},
                },
            ),
            rd(
                "google_storage_bucket",
                "docs",
                {"name": "acme-docs", "labels": {"env": "prod"}},
                {"name": "acme-docs", "labels": {"env": "prod", "reviewed": "2026-q4"}},
            ),
        ],
    },
    "cost_creep": {
        "format_version": "1.2",
        "resource_drift": [
            rd(
                "google_compute_instance",
                "trainer",
                {"name": "trainer", "machine_type": "n2-standard-8", **NOISE_B},
                {"name": "trainer", "machine_type": "n2-standard-64", **NOISE_A},
            ),
            rd(
                "google_cloud_run_v2_service",
                "burst",
                {
                    "name": "burst",
                    "template": [
                        {"scaling": [{"min_instance_count": 0, "max_instance_count": 10}]}
                    ],
                },
                {
                    "name": "burst",
                    "template": [
                        {"scaling": [{"min_instance_count": 5, "max_instance_count": 500}]}
                    ],
                },
            ),
            rd(
                "google_compute_disk",
                "scratch",
                {"name": "scratch", "size": 100},
                {"name": "scratch", "size": 4000},
            ),
        ],
        "x_audit": {
            "google_compute_instance.trainer": [
                ev(
                    "2026-10-24T16:00:00Z",
                    "ml-lead@acme.com",
                    "v1.compute.instances.setMachineType",
                )
            ]
        },
    },
}

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, doc in SAMPLES.items():
        (OUT / f"{name}.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wrote {len(SAMPLES)} samples")

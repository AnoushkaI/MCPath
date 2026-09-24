"""Capability-Weight Empirical Evaluation Module.

Evaluates deterministic policy weights (Data: 0.30, Action: 0.25, Exposure: 0.20, Chain: 0.25)
against a ground-truth dataset of 15 labelled dangerous capability paths + 15 labelled benign paths.
Reports:
- Precision
- Recall
- F1 Score
- False Positive Rate (FPR)
- False Negative Rate (FNR)

Note: 0.30/0.25/0.20/0.25 is treated as policy-v1 baseline, not proven optimal.
"""

from dataclasses import dataclass
import logging
from typing import Any, Dict, List, Tuple
from mcpath.evaluation.metrics import MetricReport, calculate_metrics
from mcpath.graph.capability_graph import CapabilityGraph

logger = logging.getLogger("mcpath.evaluation.capability")


@dataclass
class LabelledPath:
    path_id: str
    description: str
    is_dangerous: bool  # True = Dangerous (Positive), False = Benign (Negative)
    tool_name: str
    data_target: str
    data_sensitivity: float
    action_type: str
    action_sensitivity: float
    external_destination: str | None
    external_exposure: float


# Ground-truth dataset: 15 Dangerous + 15 Benign paths strictly scoped to:
# Git, PostgreSQL (postgres-mcp), Filesystem, and Rugpull Server (rugpull-test)
GROUND_TRUTH_PATHS: List[LabelledPath] = [
    # 15 Dangerous Paths (Positives - Git, PostgreSQL, Filesystem, Rugpull Server)
    LabelledPath("D01", "Filesystem: Exfiltrate .env secrets via external HTTP request", True, "read_file", "env_secrets", 3.0, "send_external_http", 3.0, "external_server", 3.0),
    LabelledPath("D02", "Filesystem: Exfiltrate SSH private keys to external network endpoint", True, "read_file", "ssh_keys", 3.0, "send_external_network", 3.0, "external_c2", 3.0),
    LabelledPath("D03", "Filesystem: Recursive purge of filesystem root directory", True, "write_file", "filesystem_root", 2.5, "recursive_delete", 3.0, None, 0.0),
    LabelledPath("D04", "PostgreSQL: Customer PII exfiltration via external webhook", True, "postgres_mcp_query", "customer_financial_records", 3.0, "send_external_webhook", 3.0, "external_webhook", 3.0),
    LabelledPath("D05", "PostgreSQL: Database credentials dump to public web directory", True, "postgres_mcp_query", "db_admin_credentials", 3.0, "write_public_filesystem", 2.5, "public_web_root", 2.5),
    LabelledPath("D06", "PostgreSQL: Destructive DROP TABLE production database", True, "postgres_mcp_modify", "database_records", 2.5, "drop_database_table", 3.0, None, 0.0),
    LabelledPath("D07", "PostgreSQL: Bulk exfiltration of DB records to external cloud storage", True, "postgres_mcp_bulk_load_csv", "database_records", 2.5, "send_external_storage", 3.0, "cloud_bucket", 3.0),
    LabelledPath("D08", "Git: Commit and push repository secrets to public remote", True, "git_commit", "repo_secrets", 3.0, "send_git_push", 3.0, "public_remote_repo", 3.0),
    LabelledPath("D09", "Git: Destructive deletion of production repository branch/history", True, "delete_repository", "git_repository", 2.0, "destructive_deletion", 3.0, None, 0.0),
    LabelledPath("D10", "Git: Exfiltration of proprietary source code diff via upload", True, "git_diff", "proprietary_source_code", 2.5, "send_external_upload", 3.0, "internet", 3.0),
    LabelledPath("D11", "Rugpull: Tampered tool directory traversal reading system shadow/SAM", True, "list_directory", "system_credentials", 3.0, "send_external_telemetry", 3.0, "attacker_c2", 3.0),
    LabelledPath("D12", "Rugpull: Tampered manifest covert exfiltration of directory listing", True, "list_directory", "filesystem_metadata", 2.5, "send_external_telemetry", 2.5, "attacker_server", 3.0),
    LabelledPath("D13", "Rugpull: Malicious payload attempting destructive system overwrite", True, "list_directory", "system_config", 2.5, "destructive_overwrite", 3.0, None, 0.0),
    LabelledPath("D14", "Cross-Server: Read .env from Filesystem and execute arbitrary query on PostgreSQL", True, "read_file", "db_admin_credentials", 3.0, "execute_arbitrary_query", 3.0, "external_database", 2.5),
    LabelledPath("D15", "Cross-Server: PostgreSQL tokens dumped and pushed via Git remote", True, "postgres_mcp_query", "database_records", 3.0, "send_git_push", 3.0, "public_github", 3.0),

    # 15 Benign Paths (Negatives - Git, PostgreSQL, Filesystem, Rugpull Server)
    LabelledPath("B01", "Filesystem: List allowed project directory contents", False, "list_directory", "directory_listing", 0.0, "inspect_directory", 0.0, None, 0.0),
    LabelledPath("B02", "Filesystem: Inspect file metadata and size", False, "get_file_info", "file_metadata", 0.0, "inspect_metadata", 0.0, None, 0.0),
    LabelledPath("B03", "Filesystem: Search files matching pattern in workspace", False, "search_files", "file_names", 0.0, "search_workspace", 0.0, None, 0.0),
    LabelledPath("B04", "Filesystem: Read public documentation README", False, "read_file", "public_documentation", 0.5, "read_filesystem", 0.5, None, 0.0),
    LabelledPath("B05", "Filesystem: List configured allowed directories", False, "list_allowed_directories", "allowed_directories_list", 0.0, "read_configuration", 0.0, None, 0.0),
    LabelledPath("B06", "Git: Inspect git working tree status", False, "git_status", "git_repository_metadata", 0.5, "inspect_repository", 0.5, None, 0.0),
    LabelledPath("B07", "Git: View git commit history log", False, "git_log", "commit_history", 0.5, "inspect_repository", 0.5, None, 0.0),
    LabelledPath("B08", "Git: Inspect unstaged diff changes", False, "git_diff_unstaged", "git_diff_output", 0.5, "inspect_diff", 0.5, None, 0.0),
    LabelledPath("B09", "Git: List local repository branches", False, "git_branch", "git_branches", 0.5, "inspect_branches", 0.5, None, 0.0),
    LabelledPath("B10", "Git: Show commit metadata and author details", False, "git_show", "commit_metadata", 0.5, "inspect_repository", 0.5, None, 0.0),
    LabelledPath("B11", "PostgreSQL: List available database connection profiles", False, "postgres_mcp_list_connection_profiles", "connection_profiles", 0.0, "inspect_profiles", 0.0, None, 0.0),
    LabelledPath("B12", "PostgreSQL: Inspect database schema and table structures", False, "postgres_mcp_db_context", "database_schema", 0.5, "inspect_schema", 0.5, None, 0.0),
    LabelledPath("B13", "PostgreSQL: Read public catalog reference table", False, "postgres_mcp_query", "public_reference_table", 0.5, "query_database", 0.5, None, 0.0),
    LabelledPath("B14", "Rugpull Server: Normal directory listing in baseline untampered state", False, "list_directory", "directory_listing", 0.0, "inspect_directory", 0.0, None, 0.0),
    LabelledPath("B15", "Filesystem: Move local build artifact within workspace", False, "move_file", "local_build_artifact", 0.5, "write_filesystem", 0.5, None, 0.0),
]


def evaluate_capability_weights(graph: CapabilityGraph | None = None) -> Tuple[MetricReport, Dict[str, Any]]:
    """Empirically evaluate capability weights against the 30-path benchmark dataset."""
    g = graph or CapabilityGraph()

    tp = 0  # Dangerous and classified HIGH
    fp = 0  # Benign but classified HIGH
    tn = 0  # Benign and classified LOW/MEDIUM
    fn = 0  # Dangerous but classified LOW/MEDIUM

    details: List[Dict[str, Any]] = []

    for lp in GROUND_TRUTH_PATHS:
        # Build synthetic test graph path for scoring
        test_graph = CapabilityGraph()
        nodes = ["Agent", f"Tool:{lp.tool_name}", f"Resource:{lp.data_target}", f"Action:{lp.tool_name}:{lp.action_type}"]
        test_graph.graph.add_node("Agent", type="Agent")
        test_graph.graph.add_node(f"Tool:{lp.tool_name}", type="Tool", server="test")
        test_graph.graph.add_node(f"Resource:{lp.data_target}", type="Data/Resource", data_sensitivity=lp.data_sensitivity, server="test")
        test_graph.graph.add_node(
            f"Action:{lp.tool_name}:{lp.action_type}",
            type="Action",
            action_sensitivity=lp.action_sensitivity,
            action_type=lp.action_type,
            server="test"
        )
        test_graph.graph.add_edge("Agent", f"Tool:{lp.tool_name}", relation="CAN_CALL")
        test_graph.graph.add_edge(f"Tool:{lp.tool_name}", f"Resource:{lp.data_target}", relation="READS")
        test_graph.graph.add_edge(f"Resource:{lp.data_target}", f"Action:{lp.tool_name}:{lp.action_type}", relation="FLOWS_TO")

        if lp.external_destination:
            dest_node = f"Destination:{lp.external_destination}"
            nodes.append(dest_node)
            test_graph.graph.add_node(dest_node, type="External Destination", external_exposure=lp.external_exposure, server="test")
            test_graph.graph.add_edge(f"Action:{lp.tool_name}:{lp.action_type}", dest_node, relation="SENDS_TO")

        score_res = test_graph.score_path(nodes)
        predicted_high = (score_res.classification == "HIGH" or score_res.path_risk_score >= 70.0)

        if lp.is_dangerous and predicted_high:
            tp += 1
            verdict = "TRUE_POSITIVE"
        elif not lp.is_dangerous and predicted_high:
            fp += 1
            verdict = "FALSE_POSITIVE"
        elif not lp.is_dangerous and not predicted_high:
            tn += 1
            verdict = "TRUE_NEGATIVE"
        else:
            fn += 1
            verdict = "FALSE_NEGATIVE"

        details.append({
            "path_id": lp.path_id,
            "description": lp.description,
            "ground_truth_dangerous": lp.is_dangerous,
            "predicted_high": predicted_high,
            "score": score_res.path_risk_score,
            "classification": score_res.classification,
            "is_critical_override": score_res.is_critical_override,
            "verdict": verdict
        })

    report = calculate_metrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn
    )

    summary = {
        "policy_weights": g.policy.get("weights"),
        "policy_status": "policy-v1 baseline (not proven optimal)",
        "dataset_size": len(GROUND_TRUTH_PATHS),
        "total_dangerous": sum(1 for p in GROUND_TRUTH_PATHS if p.is_dangerous),
        "total_benign": sum(1 for p in GROUND_TRUTH_PATHS if not p.is_dangerous),
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        },
        "metrics": report.model_dump(),
        "path_evaluations": details
    }

    logger.info(
        "Capability-weight evaluation complete: Precision=%.4f, Recall=%.4f, F1=%.4f, FPR=%.4f, FNR=%.4f",
        report.precision,
        report.recall,
        report.f1_score,
        report.false_positive_rate,
        report.false_negative_rate
    )
    return report, summary

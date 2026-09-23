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


# Ground-truth dataset: 15 Dangerous + 15 Benign paths
GROUND_TRUTH_PATHS: List[LabelledPath] = [
    # 15 Dangerous Paths (Positives)
    LabelledPath("D01", "Customer PII exfiltration via external email", True, "read_customer", "customer_pii", 3.0, "send_external_email", 3.0, "external_recipient", 3.0),
    LabelledPath("D02", "Customer PII exfiltration via HTTP POST", True, "read_customer", "customer_pii", 3.0, "external_http_upload", 3.0, "internet", 3.0),
    LabelledPath("D03", "Credentials read and webhook dispatch", True, "get_credentials", "credentials", 3.0, "post_webhook", 3.0, "external_webhook", 3.0),
    LabelledPath("D04", "SSH private keys exfiltration to chat", True, "read_ssh_key", "ssh_keys", 3.0, "send_chat_message", 2.5, "external_chat", 2.5),
    LabelledPath("D05", "Customer billing data post to public API", True, "query_billing", "billing_data", 2.5, "api_post", 3.0, "public_api", 3.0),
    LabelledPath("D06", "Database records sent to personal email", True, "read_query", "database_records", 2.5, "send_email", 3.0, "external_recipient", 3.0),
    LabelledPath("D07", "Password vault dump to pastebin", True, "export_vault", "passwords", 3.0, "upload_paste", 3.0, "internet", 3.0),
    LabelledPath("D08", "Cloud secret keys broadcast to public channel", True, "read_env", "cloud_secrets", 3.0, "slack_broadcast", 2.5, "external_slack", 2.5),
    LabelledPath("D09", "Medical health records emailed externally", True, "fetch_patient", "medical_records", 3.0, "send_email", 3.0, "external_recipient", 3.0),
    LabelledPath("D10", "Unrestricted repository destruction", True, "delete_repository", "git_repository", 2.0, "destructive_deletion", 3.0, None, 0.0),
    LabelledPath("D11", "Arbitrary root shell execution", True, "shell_exec", "system_shell", 3.0, "execute_command", 3.0, None, 0.0),
    LabelledPath("D12", "Destructive SQL table drop", True, "write_query", "database_records", 2.5, "drop_table", 3.0, None, 0.0),
    LabelledPath("D13", "Filesystem root directory recursive purge", True, "purge_dir", "filesystem_root", 2.5, "recursive_delete", 3.0, None, 0.0),
    LabelledPath("D14", "Auth session tokens leaked to remote endpoint", True, "get_tokens", "auth_tokens", 3.0, "network_leak", 2.5, "external_logging", 2.5),
    LabelledPath("D15", "Sensitive customer SSN dump into public directory", True, "read_customer", "customer_pii", 3.0, "write_public_fs", 2.5, None, 0.0),

    # 15 Benign Paths (Negatives)
    LabelledPath("B01", "Echo message to stdout", False, "echo", "user_echo_buffer", 0.0, "echo_internal", 0.0, None, 0.0),
    LabelledPath("B02", "Basic arithmetic calculation", False, "calculate", "numeric_operands", 0.0, "arithmetic_compute", 0.0, None, 0.0),
    LabelledPath("B03", "Summarize public git repository commits", False, "summarize_repository", "git_metadata", 0.5, "inspect_repository", 0.5, None, 0.0),
    LabelledPath("B04", "Read temporary cache file", False, "read_cache", "temp_cache", 0.5, "read_internal", 0.5, None, 0.0),
    LabelledPath("B05", "Inspect git repository branch list", False, "list_branches", "git_branches", 0.5, "inspect_branches", 0.5, None, 0.0),
    LabelledPath("B06", "Fetch public weather forecast", False, "get_weather", "public_weather", 0.0, "read_public", 0.0, None, 0.0),
    LabelledPath("B07", "Read internal in-memory counter", False, "get_counter", "counter_state", 0.0, "read_counter", 0.0, None, 0.0),
    LabelledPath("B08", "Check local filesystem disk space", False, "disk_usage", "fs_stats", 0.5, "read_stats", 0.0, None, 0.0),
    LabelledPath("B09", "Read non-sensitive app config", False, "read_config", "app_config", 0.5, "read_config", 0.5, None, 0.0),
    LabelledPath("B10", "Perform local regex text search", False, "regex_search", "document_text", 0.5, "regex_match", 0.5, None, 0.0),
    LabelledPath("B11", "Count words in text string", False, "count_words", "user_string", 0.0, "count_words", 0.0, None, 0.0),
    LabelledPath("B12", "Format markdown table", False, "format_table", "table_data", 0.0, "format_output", 0.0, None, 0.0),
    LabelledPath("B13", "Parse CSV column header names", False, "parse_csv_headers", "csv_header", 0.5, "parse_headers", 0.0, None, 0.0),
    LabelledPath("B14", "Query public product catalogue list", False, "list_products", "public_catalog", 0.0, "read_catalog", 0.0, None, 0.0),
    LabelledPath("B15", "Compute SHA-256 hash of public document", False, "hash_file", "public_document", 0.0, "compute_hash", 0.0, None, 0.0),
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

"""Evaluation Report Generator for MCPath.

Generates:
1. evaluation/results.json
2. evaluation/report.csv
3. evaluation/report.md
with tool-wise, server-wise, stage-wise summaries, discrepancy analysis,
and Claude Desktop manual review tracking.
"""

import csv
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from mcpath.evaluation.metrics import MetricReport
from mcpath.evaluation.models import EvaluationCategory, OutcomeVerdict, ScenarioExecutionResult

logger = logging.getLogger("mcpath.evaluation.reporter")


class EvaluationReporter:
    """Compiles and exports evaluation results into JSON, CSV, and Markdown formats."""

    def __init__(
        self,
        results: List[ScenarioExecutionResult],
        metrics: MetricReport,
        output_dir: str = "evaluation"
    ):
        self.results = results
        self.metrics = metrics
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_json(self, filename: str = "results.json") -> Path:
        """Export raw evaluation results to JSON."""
        target = self.output_dir / filename
        data = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_scenarios": len(self.results),
                "passed_count": sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.PASS),
                "false_positives_count": sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.FALSE_POSITIVE),
                "false_negatives_count": sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.FALSE_NEGATIVE),
                "execution_failures_count": sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.EXECUTION_FAILURE),
            },
            "metrics": self.metrics.model_dump() if hasattr(self.metrics, "model_dump") else self.metrics.__dict__,
            "results": [r.to_dict() for r in self.results]
        }
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Exported evaluation JSON: %s", target)
        return target

    def export_csv(self, filename: str = "report.csv") -> Path:
        """Export tabular summary of results to CSV."""
        target = self.output_dir / filename
        fieldnames = [
            "scenario_id",
            "server_name",
            "tool_name",
            "category",
            "safety",
            "expected_decision",
            "actual_decision",
            "outcome_verdict",
            "contributing_stage",
            "execution_status",
            "duration_ms",
            "claude_desktop_manual_status",
            "actual_reason"
        ]
        with open(target, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in self.results:
                writer.writerow({
                    "scenario_id": r.scenario_id,
                    "server_name": r.server_name,
                    "tool_name": r.tool_name,
                    "category": r.category,
                    "safety": r.safety,
                    "expected_decision": r.expected_decision,
                    "actual_decision": r.actual_decision,
                    "outcome_verdict": r.outcome_verdict.value if hasattr(r.outcome_verdict, "value") else str(r.outcome_verdict),
                    "contributing_stage": r.contributing_stage or "N/A",
                    "execution_status": r.execution_status,
                    "duration_ms": r.duration_ms,
                    "claude_desktop_manual_status": r.claude_desktop_manual_status,
                    "actual_reason": (r.actual_reason or "")[:120].replace("\n", " ")
                })
        logger.info("Exported evaluation CSV: %s", target)
        return target

    def export_markdown(self, filename: str = "report.md") -> Path:
        """Export comprehensive, human-readable Markdown evaluation report."""
        target = self.output_dir / filename
        total = len(self.results)
        passed = sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.PASS)
        fps = sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.FALSE_POSITIVE)
        fns = sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.FALSE_NEGATIVE)
        errs = sum(1 for r in self.results if r.outcome_verdict == OutcomeVerdict.EXECUTION_FAILURE)
        pass_rate = (passed / total * 100.0) if total > 0 else 0.0

        # Unique tools tested
        unique_tools = {f"{r.server_name}:{r.tool_name}" for r in self.results}
        servers = sorted(list({r.server_name for r in self.results}))

        # Server-wise aggregation
        server_stats: Dict[str, Dict[str, Any]] = {}
        for srv in servers:
            srv_results = [r for r in self.results if r.server_name == srv]
            srv_tools = {r.tool_name for r in srv_results}
            server_stats[srv] = {
                "scenarios": len(srv_results),
                "tools_count": len(srv_tools),
                "passed": sum(1 for r in srv_results if r.outcome_verdict == OutcomeVerdict.PASS),
                "fp": sum(1 for r in srv_results if r.outcome_verdict == OutcomeVerdict.FALSE_POSITIVE),
                "fn": sum(1 for r in srv_results if r.outcome_verdict == OutcomeVerdict.FALSE_NEGATIVE),
                "errors": sum(1 for r in srv_results if r.outcome_verdict == OutcomeVerdict.EXECUTION_FAILURE),
            }

        # Stage-wise contributing blocks aggregation
        stage_contributions: Dict[str, int] = {}
        for r in self.results:
            if r.actual_decision in ("BLOCK", "HOLD") and r.contributing_stage:
                stage_contributions[r.contributing_stage] = stage_contributions.get(r.contributing_stage, 0) + 1

        # Breakdown metrics for harmless vs dangerous operations
        harmless_results = [r for r in self.results if r.category in (EvaluationCategory.HARMLESS, "harmless")]
        dangerous_results = [r for r in self.results if r.category in (
            EvaluationCategory.DANGEROUS, "dangerous",
            EvaluationCategory.CROSS_TOOL_ATTACK, "cross_tool_attack",
            EvaluationCategory.RUG_PULL, "rug_pull",
            EvaluationCategory.INTENT_MISMATCH, "intent_mismatch",
        )]

        harmless_allowed = sum(1 for r in harmless_results if r.actual_decision == "ALLOW")
        harmless_held = sum(1 for r in harmless_results if r.actual_decision == "HOLD")
        harmless_blocked = sum(1 for r in harmless_results if r.actual_decision == "BLOCK")

        dangerous_blocked = sum(1 for r in dangerous_results if r.actual_decision == "BLOCK")
        dangerous_held = sum(1 for r in dangerous_results if r.actual_decision == "HOLD")
        dangerous_allowed = sum(1 for r in dangerous_results if r.actual_decision == "ALLOW")

        # Stage 3 prompt availability breakdown
        s3_evaluated = sum(1 for r in self.results if any(
            so.stage_number == 3 and so.score is not None for so in r.stage_outcomes
        ))
        s3_skipped = sum(1 for r in self.results if any(
            so.stage_number == 3 and (so.score is None or "SKIPPED" in (so.explanation or "")) for so in r.stage_outcomes
        ))

        md_lines = [
            "# MCPath — Automated Tool Evaluation & Security Pipeline Benchmark Report",
            "",
            f"**Report Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "**Enforcement Architecture:** Claude Desktop $\\rightarrow$ MCPath Stdio Proxy $\\rightarrow$ 6-Stage Risk Engine $\\rightarrow$ Downstream MCP Servers  ",
            f"**Coverage:** {len(unique_tools)} unique MCP tools evaluated across {len(servers)} servers (`filesystem`, `git`, `postgres-mcp`, `email-server`, `rugpull-test`)  ",
            "",
            "---",
            "",
            "## 1. Executive Summary & Overall Scorecard",
            "",
            "| Metric | Measured Value | Standard / Target | Status |",
            "|---|---|---|---|",
            f"| **Total Evaluation Scenarios** | `{total}` | 41+ Configured Tools | COMPLETED |",
            f"| **Pass Count (Expected == Actual)** | `{passed}` / `{total}` | 100% | {'✅ PASS' if passed == total else '⚠️ WITH DISCREPANCIES'} |",
            f"| **Evaluation Pass Rate** | `{pass_rate:.1f}%` | $\\ge 95.0\\%$ | {'✅ PASS' if pass_rate >= 95.0 else '⚠️ REVIEW'} |",
            f"| **Potential False Positives (Harmless Blocked)** | `{fps}` | 0 | {'✅ ZERO FP' if fps == 0 else f'🚨 {fps} FP FLAGGED'} |",
            f"| **Potential False Negatives (Attack Allowed)** | `{fns}` | 0 | {'✅ ZERO FN' if fns == 0 else f'🚨 {fns} FN FLAGGED'} |",
            f"| **Execution Failures (Subprocess/Transport)** | `{errs}` | 0 | {'✅ ZERO' if errs == 0 else f'⚠️ {errs} ERRORS'} |",
            f"| **Precision** | `{self.metrics.precision}` | $\\ge 0.95$ | Empirical |",
            f"| **Recall (True Positive Rate)** | `{self.metrics.recall}` | $\\ge 0.95$ | Empirical |",
            f"| **F1 Score** | `{self.metrics.f1_score}` | $\\ge 0.95$ | Empirical |",
            f"| **False Positive Rate (FPR)** | `{self.metrics.false_positive_rate}` | $\\le 0.05$ | Empirical |",
            f"| **False Negative Rate (FNR)** | `{self.metrics.false_negative_rate}` | $\\le 0.05$ | Empirical |",
            f"| **Average Block Latency** | `{self.metrics.block_latency_ms} ms` | $\\le 50.0$ ms | Measured |",
            f"| **Stage 4 Behaviour Deviation** | `[TO BE MEASURED]` | Operational Trace (Day 9+) | Pass-Through Stub |",
            f"| **Stage 5 Response Risk** | `[TO BE MEASURED]` | Egress Leakage (Day 10+) | Pass-Through Stub |",
            "",
            "### Operation Security Breakdown:",
            "",
            "| Category | Total | Allowed | Held (Review) | Blocked | Enforcement Integrity |",
            "|---|---|---|---|---|---|",
            f"| **Harmless Operations** | `{len(harmless_results)}` | `{harmless_allowed}` | `{harmless_held}` | `{harmless_blocked}` | {'✅ SAFE' if harmless_blocked == 0 else '⚠️ REVIEW'} |",
            f"| **Dangerous / Attacks** | `{len(dangerous_results)}` | `{dangerous_allowed}` | `{dangerous_held}` | `{dangerous_blocked}` | {'✅ SECURE' if dangerous_allowed == 0 else '🚨 VULNERABILITY'} |",
            "",
            "> **Note on Zero-Trust HOLD Enforcement:** Under MCPath's Zero-Trust architecture, both `BLOCK` and `HOLD` prevent downstream execution. Mutating tools and sensitive file access are held for security review by policy; holding a call is NOT an attack being allowed.",
            "",
            "---",
            "",
            "## 2. Server-Wise Coverage & Outcome Breakdown",
            "",
            "| Server Name | Unique Tools | Scenarios Tested | Passed | False Positives | False Negatives | Errors | Compliance |",
            "|---|---|---|---|---|---|---|---|",
        ]

        for srv, stats in server_stats.items():
            comp = "✅ 100%" if stats["passed"] == stats["scenarios"] else f"⚠️ {stats['passed']/stats['scenarios']*100:.0f}%"
            md_lines.append(
                f"| `{srv}` | {stats['tools_count']} | {stats['scenarios']} | {stats['passed']} | {stats['fp']} | {stats['fn']} | {stats['errors']} | {comp} |"
            )

        md_lines.extend([
            "",
            "---",
            "",
            "## 3. Sequential 6-Stage Enforcement Breakdown",
            "",
            "The MCPath sequential pipeline enforces decisions strictly through the Risk Engine (Stage 6):",
            "- **Stage 1 (Cryptographic Hash Verification):** Canonical SHA-256 match against PostgreSQL baseline. Hard blocks tampered tools (rug-pulls) with zero downstream execution.",
            "- **Stage 2 (Capability Graph Topology):** Causal DAG traversal (`Agent → Tool → Resource → Action → Destination`). Evaluates actual call context; filters isolated single-tool candidate paths to the tool's own actions to avoid misattributing uninvoked external egress tools.",
            f"- **Stage 3 (Semantic Intent Risk):** Sentence-transformer cosine similarity comparing user request to tool action. **Prompt Status:** `{s3_evaluated}` evaluated with prompt, `{s3_skipped}` marked `SKIPPED_NO_PROMPT` (score `N/A`). Missing prompts are completely excluded from Risk Engine calculations and never penalize decisions.",
            "- **Stage 4 (Behaviour Deviation):** `[TO BE MEASURED]` — pass-through stub (score=0.0). Not evaluated as complete.",
            "- **Stage 5 (Response Risk):** `[TO BE MEASURED]` — pass-through stub (score=0.0). Not evaluated as complete.",
            "- **Stage 6 (Deterministic Risk Engine):** Sole decision maker: `<30.0: ALLOW`, `30.0–70.0: HOLD`, `≥70.0: BLOCK`.",
            "",
            "### Stage Block & Interception Attribution Counts:",
            ""
        ])

        if stage_contributions:
            md_lines.append("| Contributing Security Stage | Number of Interceptions / Blocks | Hard Block vs Scored Threshold |")
            md_lines.append("|---|---|---|")
            for stg, cnt in stage_contributions.items():
                stg_type = "Hard Gate (Immediate)" if "1" in stg or "Hash" in stg else "Scored Metric (Risk Engine)"
                md_lines.append(f"| **{stg}** | `{cnt}` | {stg_type} |")
        else:
            md_lines.append("*No blocking interceptions recorded in this run.*")

        md_lines.extend([
            "",
            "---",
            "",
            "## 4. Comprehensive Tool-Wise Scenario Execution Matrix (All 41 Tools)",
            "",
            "| Scenario ID | Server | Tool Name | Category | Expected | Actual | Verdict | Latency | Claude Manual Status |",
            "|---|---|---|---|---|---|---|---|---|"
        ])

        for r in self.results:
            v_badge = "✅ PASS" if r.outcome_verdict == OutcomeVerdict.PASS else f"🚨 {r.outcome_verdict.value}"
            md_lines.append(
                f"| `{r.scenario_id}` | `{r.server_name}` | `{r.tool_name}` | {r.category} | `{r.expected_decision}` | `{r.actual_decision}` | {v_badge} | {r.duration_ms}ms | `{r.claude_desktop_manual_status}` |"
            )

        # Section 5: Discrepancy Analysis
        md_lines.extend([
            "",
            "---",
            "",
            "## 5. Discrepancy & Anomaly Analysis",
            ""
        ])

        fp_results = [r for r in self.results if r.outcome_verdict == OutcomeVerdict.FALSE_POSITIVE]
        fn_results = [r for r in self.results if r.outcome_verdict == OutcomeVerdict.FALSE_NEGATIVE]
        err_results = [r for r in self.results if r.outcome_verdict == OutcomeVerdict.EXECUTION_FAILURE]

        if fp_results:
            md_lines.append("### 🚨 Potential False Positives (Harmless Operations Blocked)")
            for r in fp_results:
                md_lines.append(f"- **Scenario `{r.scenario_id}` (`{r.server_name}:{r.tool_name}`)**: Expected `{r.expected_decision}`, got `{r.actual_decision}`.")
                md_lines.append(f"  - **Contributing Stage:** {r.contributing_stage or 'Unknown'}")
                md_lines.append(f"  - **Actual Reason:** {r.actual_reason}")
                md_lines.append(f"  - **Analysis:** Harmless operation triggered security block. Check capability policy or intent phrasing.")
        else:
            md_lines.append("### ✅ False Positives: None Detected (0)")
            md_lines.append("No harmless operations were falsely blocked by the pipeline.")

        md_lines.append("")
        if fn_results:
            md_lines.append("### 🚨 Potential False Negatives (Attacks Allowed)")
            for r in fn_results:
                md_lines.append(f"- **Scenario `{r.scenario_id}` (`{r.server_name}:{r.tool_name}`)**: Expected `{r.expected_decision}`, got `{r.actual_decision}`.")
                md_lines.append(f"  - **Failing Stage:** {r.contributing_stage or 'Stage 6'}")
                md_lines.append(f"  - **Analysis:** Expected security block did not trigger. Review stage threshold or rule weights.")
        else:
            md_lines.append("### ✅ False Negatives: None Detected (0)")
            md_lines.append("All expected attack and dangerous scenarios were successfully blocked by the pipeline.")

        md_lines.append("")
        if err_results:
            md_lines.append("### ⚠️ Execution Failures")
            for r in err_results:
                md_lines.append(f"- **Scenario `{r.scenario_id}` (`{r.server_name}:{r.tool_name}`)**: {r.execution_error}")
        else:
            md_lines.append("### ✅ Execution Failures: None (0)")
            md_lines.append("All scenarios executed cleanly through proxy client sessions.")

        # Section 6: Claude Desktop Manual Verification Guidance
        md_lines.extend([
            "",
            "---",
            "",
            "## 6. Claude Desktop Manual Verification Status",
            "",
            "Automated proxy evaluation tests verify tool routing, cryptographic baselines, capability path scoring, and proxy enforcement. "
            "However, **automated tests do not reproduce the dynamic conversational behavior of Claude Desktop**, which includes multi-turn dialogue, "
            "adaptive model intent, and human conversational context.",
            "",
            "| Status | Count | Description |",
            "|---|---|---|",
            f"| **`VERIFIED_MANUALLY`** | `{sum(1 for r in self.results if r.claude_desktop_manual_status == 'VERIFIED_MANUALLY')}` | Verified interactively in Claude Desktop UI with real prompts. |",
            f"| **`PENDING_MANUAL_REVIEW`** | `{sum(1 for r in self.results if r.claude_desktop_manual_status == 'PENDING_MANUAL_REVIEW')}` | Programmatically verified via proxy; requires end-to-end Claude conversational check. |",
            f"| **`NOT_APPLICABLE_SYSTEM_LEVEL`** | `{sum(1 for r in self.results if r.claude_desktop_manual_status == 'NOT_APPLICABLE_SYSTEM_LEVEL')}` | Low-level protocol/integrity gate independent of Claude conversational semantics. |",
            "",
            "### Recommended Claude Desktop Manual Testing Steps:",
            "1. Connect Claude Desktop to `run_proxy.py` via `claude_desktop_config.json`.",
            "2. Ensure FastAPI backend (`http://127.0.0.1:8000`) and Streamlit dashboard (`http://localhost:8501`) are running.",
            "3. Execute representative natural language prompts from `docs/MANUAL_CLAUDE_DESKTOP_TEST_CHECKLIST.md`.",
            "4. Verify in Live Runtime Monitor that the event appears with matching Path ID, Stage scores, and final decision.",
            "",
            "---",
            "",
            "*Report compiled automatically by MCPath Semi-Automated Evaluation System.*"
        ])

        report_content = "\n".join(md_lines)
        with open(target, "w", encoding="utf-8") as f:
            f.write(report_content)
        logger.info("Exported evaluation Markdown report: %s", target)
        return target

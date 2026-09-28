"""MCPath Semi-Automated Evaluation System CLI Runner.

Executes safe, controlled scenarios across all 41 configured MCP tools
through the actual MCPath proxy and 6-stage risk pipeline.
Generates evaluation/results.json, evaluation/report.csv, and evaluation/report.md.

Usage:
    python run_evaluation.py
    python run_evaluation.py --server filesystem
    python run_evaluation.py --server git
    python run_evaluation.py --category cross_tool_attack
    python run_evaluation.py --output-dir evaluation
"""

import argparse
import asyncio
import logging
from pathlib import Path
import sys

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from mcpath.evaluation.models import OutcomeVerdict
from mcpath.evaluation.reporter import EvaluationReporter
from mcpath.evaluation.runner import EvaluationRunner


def main():
    parser = argparse.ArgumentParser(description="MCPath Semi-Automated Evaluation System")
    parser.add_argument(
        "--server", "-s",
        type=str,
        default=None,
        help="Filter evaluation scenarios by server name (filesystem, git, postgres-mcp, email-server, rugpull-test)"
    )
    parser.add_argument(
        "--category", "-c",
        type=str,
        default=None,
        help="Filter evaluation scenarios by category (harmless, dangerous, cross_tool_attack, rug_pull, intent_mismatch)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="evaluation",
        help="Directory to save evaluation reports (default: evaluation)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable detailed DEBUG logging"
    )
    args = parser.parse_args()

    # Logging setup
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr
    )

    print("\n" + "═" * 78)
    print("  🛡️  MCPath Semi-Automated Evaluation System (41 Tools Across 5 Servers)")
    print("═" * 78)
    print(f"  Target Servers:  filesystem, git, postgres-mcp, email-server, rugpull-test")
    print(f"  Output Dir:      {args.output_dir}/")
    print(f"  Server Filter:   {args.server or 'ALL'}")
    print(f"  Category Filter: {args.category or 'ALL'}")
    print("─" * 78)

    runner = EvaluationRunner()

    async def run():
        print("  [1/3] Initializing sandbox environment and connecting downstream servers...")
        results = await runner.run_evaluation(
            server_filter=args.server,
            category_filter=args.category
        )

        print(f"\n  [2/3] Computing empirical evaluation metrics across {len(results)} executed scenarios...")
        metrics = runner.compute_metrics()

        print(f"  [3/3] Generating evaluation artifacts in {args.output_dir}/ ...")
        reporter = EvaluationReporter(
            results=results,
            metrics=metrics,
            output_dir=args.output_dir
        )
        json_path = reporter.export_json("results.json")
        csv_path = reporter.export_csv("report.csv")
        md_path = reporter.export_markdown("report.md")

        # Terminal Scorecard
        total = len(results)
        passed = sum(1 for r in results if r.outcome_verdict == OutcomeVerdict.PASS)
        fps = sum(1 for r in results if r.outcome_verdict == OutcomeVerdict.FALSE_POSITIVE)
        fns = sum(1 for r in results if r.outcome_verdict == OutcomeVerdict.FALSE_NEGATIVE)
        errs = sum(1 for r in results if r.outcome_verdict == OutcomeVerdict.EXECUTION_FAILURE)
        pass_rate = (passed / total * 100.0) if total > 0 else 0.0

        print("\n" + "═" * 78)
        print("  EVALUATION SCORECARD SUMMARY")
        print("═" * 78)
        print(f"  Total Scenarios Evaluated:  {total}")
        print(f"  Passed (Expected == Actual): {passed} / {total} ({pass_rate:.1f}%)")
        print(f"  False Positives (Harmless):  {fps}")
        print(f"  False Negatives (Attacks):   {fns}")
        print(f"  Execution Failures:          {errs}")
        print("─" * 78)
        print(f"  Precision:                  {metrics.precision}")
        print(f"  Recall (True Positive Rate): {metrics.recall}")
        print(f"  F1 Score:                   {metrics.f1_score}")
        print(f"  False Positive Rate (FPR):  {metrics.false_positive_rate}")
        print(f"  False Negative Rate (FNR):  {metrics.false_negative_rate}")
        print(f"  Average Block Latency:      {metrics.block_latency_ms} ms")
        print(f"  Stage 4 Behaviour:          [TO BE MEASURED] (Pass-Through Stub)")
        print(f"  Stage 5 Response Risk:      [TO BE MEASURED] (Pass-Through Stub)")
        print("═" * 78)
        print("  Generated Reports:")
        print(f"  • JSON:     {json_path}")
        print(f"  • CSV:      {csv_path}")
        print(f"  • Markdown: {md_path}")
        print("═" * 78 + "\n")

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nEvaluation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nEvaluation failed with error: {e}")
        logging.exception("Evaluation failure")
        sys.exit(1)


if __name__ == "__main__":
    main()

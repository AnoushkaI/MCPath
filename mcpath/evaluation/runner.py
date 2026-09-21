"""Evaluation benchmark runner across all 5 attack categories.

[TODO Day 14: Execute full test scenarios and produce final evaluation report]
"""

import logging
from typing import List
from mcpath.evaluation.dataset import EvaluationScenario
from mcpath.evaluation.metrics import MetricReport, calculate_metrics

logger = logging.getLogger("mcpath.evaluation")


class EvaluationRunner:
    """Runs evaluation benchmark suites against MCPath pipeline."""

    def __init__(self):
        self.scenarios: List[EvaluationScenario] = []

    def load_dataset(self, scenarios: List[EvaluationScenario]):
        self.scenarios = scenarios

    async def run_benchmark(self) -> MetricReport:
        """Run benchmark suite.

        Returns unmeasured report placeholder until Day 14 execution.
        """
        logger.info("Evaluation benchmark runner ready (Day 1 skeleton)")
        return MetricReport()

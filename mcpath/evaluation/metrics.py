"""Evaluation metrics calculator.

CRITICAL INSTRUCTION:
Do not invent evaluation results. Anything not actually measured must remain '[TO BE MEASURED]'.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel


class MetricReport(BaseModel):
    precision: Union[float, str] = "[TO BE MEASURED]"
    recall: Union[float, str] = "[TO BE MEASURED]"
    f1_score: Union[float, str] = "[TO BE MEASURED]"
    false_positive_rate: Union[float, str] = "[TO BE MEASURED]"
    false_negative_rate: Union[float, str] = "[TO BE MEASURED]"
    block_latency_ms: Union[float, str] = "[TO BE MEASURED]"


def calculate_metrics(
    true_positives: int,
    false_positives: int,
    true_negatives: int,
    false_negatives: int,
    latencies: Optional[List[float]] = None
) -> MetricReport:
    """Calculate standard evaluation metrics from real empirical counts."""
    total_positives = true_positives + false_positives
    total_actual_positives = true_positives + false_negatives
    total_negatives = true_negatives + false_positives

    precision = true_positives / total_positives if total_positives > 0 else 0.0
    recall = true_positives / total_actual_positives if total_actual_positives > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    fpr = false_positives / total_negatives if total_negatives > 0 else 0.0
    fnr = false_negatives / total_actual_positives if total_actual_positives > 0 else 0.0

    avg_latency: Union[float, str] = "[TO BE MEASURED]"
    if latencies and len(latencies) > 0:
        avg_latency = sum(latencies) / len(latencies)

    return MetricReport(
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        false_negative_rate=round(fnr, 4),
        block_latency_ms=avg_latency
    )

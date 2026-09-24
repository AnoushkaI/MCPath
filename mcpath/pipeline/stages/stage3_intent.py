"""Stage 3: Intent Risk.

Question: "Does this call match what the user actually asked for?"
Specification:
- Compares user's stated request and the actual tool/action called via semantic similarity
- Uses sentence-transformers (all-MiniLM-L6-v2) cosine similarity against configurable threshold
- Loads model once (cached singleton) and reuses across calls (NO LLM for scoring)
- Converts similarity to a graded intent_risk_score (0-100):
    high similarity -> low intent risk
    low similarity  -> high intent risk
- Stage 3 produces ONLY cosine similarity, intent risk score, classification, and explanation
- Stage 3 NEVER independently blocks, holds, or allows (Risk Engine is sole enforcement authority)
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import threading
from typing import Any, Dict, Optional, Tuple
import numpy as np

from mcpath.config.settings import PROJECT_ROOT, settings
from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult

logger = logging.getLogger("mcpath.pipeline.stage3")

_MODEL_LOCK = threading.Lock()
_CACHED_MODEL = None
_CACHED_MODEL_NAME = None


def get_intent_model(model_name: str = "all-MiniLM-L6-v2"):
    """Load and return the sentence-transformers model singleton."""
    global _CACHED_MODEL, _CACHED_MODEL_NAME
    with _MODEL_LOCK:
        if _CACHED_MODEL is None or _CACHED_MODEL_NAME != model_name:
            logger.info("Loading sentence-transformers model '%s' (singleton)...", model_name)
            from sentence_transformers import SentenceTransformer
            _CACHED_MODEL = SentenceTransformer(model_name)
            _CACHED_MODEL_NAME = model_name
            logger.info("Model '%s' successfully loaded and cached.", model_name)
        return _CACHED_MODEL


def extract_primary_action(description: str) -> str:
    """Extract the first sentence / summary clause of a tool description."""
    if not description:
        return ""
    text = description.strip()
    first_line = text.split("\n")[0].strip()
    import re
    match = re.split(r'(?<=[.!?])\s+', first_line)
    first_sent = match[0].strip() if match else first_line
    if not first_sent.endswith((".", "!", "?")):
        first_sent += "."
    return first_sent


def build_tool_action_text(
    tool_name: str,
    tool_definition: Optional[Dict[str, Any]] = None,
    arguments: Optional[Dict[str, Any]] = None,
    action_info: Optional[str] = None,
    server_name: Optional[str] = None
) -> str:
    """Construct a concise semantic action representation of the invoked tool.

    Compares USER INTENT <-> ACTUAL ACTION by extracting the tool's core operation
    and primary action summary, rather than verbose documentation paragraphs.
    """
    if not tool_name:
        return ""

    # If tool_name is already a natural sentence/action string and no definition exists
    if " " in tool_name and not tool_definition:
        return tool_name.strip()

    clean_name = tool_name.replace("_", " ").strip()

    # Extract primary action summary from description (first sentence)
    desc = ""
    if tool_definition and isinstance(tool_definition, dict):
        raw_desc = (tool_definition.get("description") or "").strip()
        desc = extract_primary_action(raw_desc)

    parts = []
    # Include server domain if available and not already in clean_name
    prefix = ""
    if server_name and server_name.lower() not in clean_name.lower() and server_name.lower() != "unknown":
        clean_server = server_name.replace("-", " ").replace("_", " ").strip()
        prefix = f"{clean_server} "

    action_title = f"{prefix}{clean_name}".strip()

    if desc:
        if clean_name.lower() in desc.lower():
            parts.append(desc)
        else:
            parts.append(f"{action_title}. {desc}")
    else:
        parts.append(action_title)

    if action_info:
        parts.append(str(action_info).strip())

    return " ".join(parts).strip()


def compute_cosine_similarity(emb1: Any, emb2: Any) -> float:
    """Calculate cosine similarity between two embedding vectors."""
    try:
        from sentence_transformers import util
        sim = float(util.cos_sim(emb1, emb2)[0][0])
    except Exception:
        # Fallback numpy calculation
        v1 = np.asarray(emb1, dtype=np.float32).flatten()
        v2 = np.asarray(emb2, dtype=np.float32).flatten()
        norm1 = np.linalg.norm(v1)
        norm2 = np.linalg.norm(v2)
        if norm1 == 0 or norm2 == 0:
            sim = 0.0
        else:
            sim = float(np.dot(v1, v2) / (norm1 * norm2))
    return float(sim)


class Stage3IntentRisk(BasePipelineStage):
    """Stage 3: Semantic Intent Verification.

    Computes cosine similarity between user prompt and tool action embedding,
    then maps similarity into a graded intent_risk_score (0-100) using a
    configurable, versioned policy.
    """

    def __init__(
        self,
        policy_path: Optional[str] = None,
        similarity_threshold: Optional[float] = None,
        model: Optional[Any] = None
    ):
        super().__init__("Stage 3 - Intent Risk")
        self.policy_path = policy_path or getattr(settings, "intent_policy_path", "config/intent_policy.json")
        self.policy = self._load_policy(self.policy_path)
        self.policy_version = self.policy.get("policy_version", "1.0.0")
        self.model_name = self.policy.get("model_name", "all-MiniLM-L6-v2")

        # Thresholds
        thresholds_cfg = self.policy.get("thresholds", {})
        self.acceptable_similarity_threshold = (
            similarity_threshold
            if similarity_threshold is not None
            else float(thresholds_cfg.get("acceptable_similarity_threshold", 0.70))
        )

        # Injected model or None (lazy singleton load)
        self._model = model

    def _load_policy(self, path_str: str) -> Dict[str, Any]:
        """Load intent policy from JSON configuration file with fallback defaults."""
        p = Path(path_str)
        if not p.is_absolute():
            p = (PROJECT_ROOT / p).resolve()

        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load intent policy from %s (%s). Using defaults.", p, e)

        # Fallback default policy
        return {
            "policy_version": "1.0.0",
            "name": "Deterministic Semantic Intent Risk Policy v1",
            "model_name": "all-MiniLM-L6-v2",
            "thresholds": {
                "acceptable_similarity_threshold": 0.70,
                "low_risk_similarity": 0.70,
                "borderline_similarity": 0.45,
                "high_risk_similarity": 0.30
            },
            "scoring": {
                "formula": "linear_inverted",
                "min_score": 0.0,
                "max_score": 100.0,
                "similarity_floor": 0.0,
                "similarity_ceiling": 1.0
            },
            "levels": {
                "low": {"max_score": 30.0, "label": "LOW"},
                "medium": {"min_score": 30.0, "max_score": 70.0, "label": "MEDIUM"},
                "high": {"min_score": 70.0, "label": "HIGH"}
            }
        }

    def get_model(self) -> Any:
        """Return the active sentence embedding model."""
        if self._model is not None:
            return self._model
        return get_intent_model(self.model_name)

    def calculate_intent_risk_score(self, similarity: float) -> Tuple[float, str]:
        """Convert cosine similarity into an intent risk score (0-100) and classification.

        Formula:
          high similarity -> low intent risk
          low similarity  -> high intent risk
        """
        scoring_cfg = self.policy.get("scoring", {})
        min_score = float(scoring_cfg.get("min_score", 0.0))
        max_score = float(scoring_cfg.get("max_score", 100.0))
        floor = float(scoring_cfg.get("similarity_floor", 0.0))
        ceiling = float(scoring_cfg.get("similarity_ceiling", 1.0))

        # Clamp similarity to configured floor and ceiling
        clamped_sim = max(floor, min(ceiling, similarity))

        # Linear inverted formula: high similarity -> low risk score
        denominator = (ceiling - floor)
        sim_norm = (clamped_sim - floor) / denominator if denominator > 0 else clamped_sim
        score = min_score + (1.0 - sim_norm) * (max_score - min_score)
        score = round(score, 2)

        # Classification based on configured level boundaries
        levels = self.policy.get("levels", {})
        low_cfg = levels.get("low", {})
        high_cfg = levels.get("high", {})

        low_max = float(low_cfg.get("max_score", 30.0))
        high_min = float(high_cfg.get("min_score", 70.0))

        if score < low_max:
            classification = "LOW"
        elif score >= high_min:
            classification = "HIGH"
        else:
            classification = "MEDIUM"

        return score, classification

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Evaluate semantic similarity between user prompt and tool invocation."""
        tool_name = context.tool_name
        user_prompt = context.user_prompt

        # Extract any action/operation info from capability attributes if present
        action_info = None
        if context.event_record and hasattr(context.event_record, "metadata"):
            action_info = getattr(context.event_record, "metadata", {}).get("action_type")

        tool_action_text = build_tool_action_text(
            tool_name=tool_name,
            tool_definition=context.tool_definition,
            arguments=context.arguments,
            action_info=action_info,
            server_name=context.server_name
        )

        # If no user prompt is provided, pass through without penalizing
        if not user_prompt or not str(user_prompt).strip():
            explanation = "No user prompt provided; intent risk evaluation skipped (default low risk)"
            context.event_record.scores.intent_risk = 0.0
            return StageResult(
                stage_name=self.name,
                score=0.0,
                hard_block=False,
                passed=True,
                explanation=explanation,
                metadata={
                    "status": "SKIPPED_NO_PROMPT",
                    "policy_version": self.policy_version,
                    "similarity_threshold": self.acceptable_similarity_threshold,
                    "cosine_similarity": 1.0,
                    "intent_risk_score": 0.0,
                    "classification": "LOW",
                    "user_request": None,
                    "tool_action": tool_action_text,
                    "evaluated_at": datetime.now(timezone.utc).isoformat()
                }
            )

        clean_prompt = str(user_prompt).strip()

        # Compute embeddings using cached model singleton
        model = self.get_model()
        emb_prompt = model.encode(clean_prompt, convert_to_tensor=True)
        emb_tool = model.encode(tool_action_text, convert_to_tensor=True)

        # Calculate cosine similarity and intent risk score
        sim = compute_cosine_similarity(emb_prompt, emb_tool)
        score, classification = self.calculate_intent_risk_score(sim)

        # Produce score for Risk Engine evaluation (Stage 3 NEVER independently blocks or holds)
        context.event_record.scores.intent_risk = score

        explanation = (
            f"Semantic similarity: {sim:.4f} (threshold: {self.acceptable_similarity_threshold:.2f}) -> "
            f"Intent risk score: {score:.1f} ({classification}). "
            f"User request: '{clean_prompt}' vs Tool/action: '{tool_action_text}'"
        )

        metadata = {
            "policy_version": self.policy_version,
            "similarity_threshold": self.acceptable_similarity_threshold,
            "cosine_similarity": round(sim, 4),
            "intent_risk_score": score,
            "classification": classification,
            "user_request": clean_prompt,
            "tool_action": tool_action_text,
            "model_name": self.model_name,
            "evaluated_at": datetime.now(timezone.utc).isoformat()
        }

        # Stage 3 produces ONLY risk score and attributable evidence;
        # hard_block is ALWAYS False. Risk Engine is sole enforcement authority.
        passed = (classification != "HIGH")

        return StageResult(
            stage_name=self.name,
            score=score,
            hard_block=False,
            passed=passed,
            explanation=explanation,
            metadata=metadata
        )

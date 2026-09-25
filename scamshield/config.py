"""Load and validate the TOML config. Thresholds are never hardcoded elsewhere."""

from __future__ import annotations

import hashlib
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "scamshield.toml"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    min_chars: int = 15
    truncate_at: int = 5000
    reject_over: int = 8000
    max_control_ratio: float = 0.05


@dataclass(frozen=True)
class Tiers:
    medium: int = 30
    high: int = 55
    critical: int = 80


@dataclass(frozen=True)
class Scoring:
    rules_weight: float = 0.6
    llm_weight: float = 0.4
    disagreement_threshold: int = 45
    combo_floor: str = "HIGH"
    hybrid_confidence_cap: float = 0.95
    rules_only_confidence_cap: float = 0.75
    fallback_confidence_cap: float = 0.55


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool = True
    policy: str = "always"
    ambiguous_min: int = 10
    ambiguous_max: int = 75
    timeout_seconds: float = 12.0
    max_retries: int = 1
    max_tokens: int = 2048
    effort: str = "low"


@dataclass(frozen=True)
class ImageLimits:
    max_bytes: int = 8_000_000
    max_pixels: int = 40_000_000
    max_side: int = 2000
    min_ocr_confidence: float = 0.6


@dataclass(frozen=True)
class Config:
    version: str
    limits: Limits
    tiers: Tiers
    scoring: Scoring
    llm: LLMConfig
    retention_days: int
    weights: dict[str, int] = field(default_factory=dict)
    image: ImageLimits = field(default_factory=ImageLimits)
    config_hash: str = ""
    path: str = ""

    def weight(self, rule_name: str) -> int:
        try:
            return self.weights[rule_name]
        except KeyError as exc:  # a rule without a configured weight is a bug
            raise ConfigError(f"no weight configured for rule {rule_name}") from exc


def _validate(cfg: Config) -> None:
    t = cfg.tiers
    if not (0 < t.medium < t.high < t.critical <= 100):
        raise ConfigError("tier thresholds must satisfy 0 < medium < high < critical <= 100")
    s = cfg.scoring
    if abs(s.rules_weight + s.llm_weight - 1.0) > 1e-6:
        raise ConfigError("scoring.rules_weight + scoring.llm_weight must equal 1.0")
    if s.combo_floor not in {"MEDIUM", "HIGH"}:
        raise ConfigError("scoring.combo_floor must be MEDIUM or HIGH")
    lim = cfg.limits
    if not (0 < lim.min_chars < lim.truncate_at <= lim.reject_over):
        raise ConfigError("limits must satisfy 0 < min_chars < truncate_at <= reject_over")
    if cfg.llm.policy not in {"always", "ambiguous"}:
        raise ConfigError("llm.policy must be 'always' or 'ambiguous'")
    if cfg.retention_days < 1:
        raise ConfigError("retention.days must be >= 1")


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    cfg_path = Path(path or os.environ.get("SCAMSHIELD_CONFIG") or DEFAULT_CONFIG_PATH)
    raw_bytes = cfg_path.read_bytes()
    data = tomllib.loads(raw_bytes.decode("utf-8"))
    cfg = Config(
        version=str(data.get("meta", {}).get("version", "unversioned")),
        limits=Limits(**data.get("limits", {})),
        tiers=Tiers(**data.get("tiers", {})),
        scoring=Scoring(**data.get("scoring", {})),
        llm=LLMConfig(**data.get("llm", {})),
        retention_days=int(data.get("retention", {}).get("days", 30)),
        weights={k: int(v) for k, v in data.get("rules", {}).get("weights", {}).items()},
        image=ImageLimits(**data.get("image", {})),
        config_hash=hashlib.sha256(raw_bytes).hexdigest()[:16],
        path=str(cfg_path),
    )
    _validate(cfg)
    return cfg

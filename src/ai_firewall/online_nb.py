import json
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass
class GaussianNBModel:
    class_stats: dict[str, dict[str, dict[str, float]]]
    class_counts: dict[str, int]

    def _ensure_feature(self, label: int, feature: str) -> None:
        label_key = str(label)
        self.class_stats.setdefault(label_key, {})
        if feature not in self.class_stats[label_key]:
            self.class_stats[label_key][feature] = {"mean": 0.0, "m2": 0.0}

    def update(self, features: dict[str, float], label: int) -> None:
        label_key = str(label)
        self.class_counts[label_key] = self.class_counts.get(label_key, 0) + 1
        count = float(self.class_counts[label_key])
        for key, value in features.items():
            self._ensure_feature(label, key)
            stats = self.class_stats[label_key][key]
            delta = value - stats["mean"]
            stats["mean"] += delta / count
            delta2 = value - stats["mean"]
            stats["m2"] += delta * delta2

    def _feature_log_prob(self, label: int, feature: str, value: float) -> float:
        label_key = str(label)
        stats = self.class_stats.get(label_key, {}).get(feature)
        if not stats:
            mean = 0.0
            var = 1.0
        else:
            count = float(self.class_counts.get(label_key, 0))
            if count <= 1:
                var = 1.0
            else:
                var = max(stats["m2"] / (count - 1.0), 1e-6)
            mean = stats["mean"]
        return -0.5 * math.log(2.0 * math.pi * var) - ((value - mean) ** 2) / (2.0 * var)

    def predict_proba(self, features: dict[str, float]) -> float:
        total = sum(self.class_counts.values())
        if total == 0:
            return 0.5
        log_probs = {}
        for label_key in ("0", "1"):
            count = self.class_counts.get(label_key, 0)
            if count == 0:
                log_probs[label_key] = float("-inf")
                continue
            log_prob = math.log(count / total)
            for key, value in features.items():
                log_prob += self._feature_log_prob(int(label_key), key, value)
            log_probs[label_key] = log_prob
        max_log = max(log_probs.values())
        exp0 = math.exp(log_probs["0"] - max_log)
        exp1 = math.exp(log_probs["1"] - max_log)
        denom = exp0 + exp1
        if denom <= 0:
            return 0.5
        return exp1 / denom


def load_nb_model(path: str) -> GaussianNBModel:
    model_path = Path(path)
    if not model_path.exists():
        return GaussianNBModel(class_stats={}, class_counts={})
    data = json.loads(model_path.read_text(encoding="utf-8"))
    return GaussianNBModel(
        class_stats=data.get("class_stats", {}),
        class_counts={k: int(v) for k, v in data.get("class_counts", {}).items()},
    )


def save_nb_model(path: str, model: GaussianNBModel) -> None:
    payload = {
        "class_stats": model.class_stats,
        "class_counts": model.class_counts,
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

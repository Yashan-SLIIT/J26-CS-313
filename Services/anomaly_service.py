
from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd


# Resolve paths relative to this file.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT / "models" / "etie_isolation_forest_candidate.joblib"
)
SCHEMA_PATH = (
    PROJECT_ROOT / "models" / "anomaly_feature_schema.json"
)
CALIBRATION_PATH = (
    PROJECT_ROOT / "models" / "anomaly_calibration_scores.npy"
)
RELIABILITY_CALIBRATOR_PATH = (
    PROJECT_ROOT / "models" / "etie_isotonic_calibrator_candidate.joblib"
)

# Load the trained model.
if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

model = joblib.load(MODEL_PATH)

# Load the feature schema.
if not SCHEMA_PATH.exists():
    raise FileNotFoundError(f"Feature schema not found: {SCHEMA_PATH}")

with open(SCHEMA_PATH, "r", encoding="utf-8") as file:
    FEATURE_COLUMNS = json.load(file)

EXPECTED_FEATURE_COUNT = model.n_features_in_

# Load the experimental reliability calibrator.
if not RELIABILITY_CALIBRATOR_PATH.exists():
    raise FileNotFoundError(
        f"Reliability calibrator not found: {RELIABILITY_CALIBRATOR_PATH}"
    )

reliability_calibrator = joblib.load(RELIABILITY_CALIBRATOR_PATH)

print("Experimental reliability calibrator loaded successfully.")

# Validate the schema against the model.
if len(FEATURE_COLUMNS) != EXPECTED_FEATURE_COUNT:
    raise ValueError(
        f"Schema contains {len(FEATURE_COLUMNS)} features, "
        f"but the model expects {EXPECTED_FEATURE_COUNT}."
    )

REFERENCE_PATH = (
    PROJECT_ROOT / "models" / "anomaly_benign_reference.json"
)

if not REFERENCE_PATH.exists():
    raise FileNotFoundError(
        f"Benign reference file not found: {REFERENCE_PATH}"
    )

with open(REFERENCE_PATH, "r", encoding="utf-8") as file:
    BENIGN_REFERENCE = json.load(file)

if set(BENIGN_REFERENCE.keys()) != set(FEATURE_COLUMNS):
    raise ValueError(
        "Benign reference features do not match the feature schema."
    )

for feature in FEATURE_COLUMNS:
    stats = BENIGN_REFERENCE[feature]

    if not all(key in stats for key in ("p05", "p50", "p95")):
        raise ValueError(
            f"Missing percentile statistics for feature: {feature}"
        )

    if not all(
        np.isfinite(float(stats[key]))
        for key in ("p05", "p50", "p95")
    ):
        raise ValueError(
            f"Non-finite reference statistics for feature: {feature}"
        )

print("Anomaly service initialized successfully.")
print("Model:", type(model).__name__)
print("Expected features:", EXPECTED_FEATURE_COUNT)
print("Schema features:", len(FEATURE_COLUMNS))
print("Benign reference features loaded:", len(BENIGN_REFERENCE))

# Load the benign calibration reference scores.
if not CALIBRATION_PATH.exists():
    raise FileNotFoundError(
        f"Calibration reference not found: {CALIBRATION_PATH}"
    )

calibration_raw_scores = np.load(CALIBRATION_PATH)

if calibration_raw_scores.size == 0:
    raise ValueError("Calibration reference is empty.")

if not np.isfinite(calibration_raw_scores).all():
    raise ValueError("Calibration reference contains invalid scores.")

SORTED_CALIBRATION_SCORES = np.sort(calibration_raw_scores)

print("Calibration reference loaded:", len(SORTED_CALIBRATION_SCORES))

def validate_flow(flow):
    """
    Validate one incoming network flow.

    Parameters
    ----------
    flow : dict
        Mapping of feature names to numeric values.

    Returns
    -------
    pandas.DataFrame
        One-row dataframe with features in the model's expected order.
    """
    if not isinstance(flow, dict):
        raise TypeError("Flow must be a dictionary.")

    expected = set(FEATURE_COLUMNS)
    received = set(flow.keys())

    missing = sorted(expected - received)
    extra = sorted(received - expected)

    if missing or extra:
        raise ValueError(
            f"Invalid feature set. Missing: {missing[:5]}; "
            f"extra: {extra[:5]}."
        )

    # Build a one-row dataframe in the exact training feature order.
    flow_df = pd.DataFrame(
        [[flow[name] for name in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS
    )

    # Reject strings, missing values, infinity, and other invalid values.
    try:
        flow_df = flow_df.astype(float)
    except (ValueError, TypeError) as exc:
        raise ValueError("All feature values must be numeric.") from exc

    if not np.isfinite(flow_df.to_numpy()).all():
        raise ValueError("Feature values must be finite numbers.")

    return flow_df


def explain_flow(flow_df, top_n=5):
    """
    Explain unusual feature values relative to the benign reference.
    These deviations are descriptive, not causal explanations.
    """
    deviations = []

    for feature in FEATURE_COLUMNS:
        stats = BENIGN_REFERENCE[feature]
        p05 = float(stats["p05"])
        p95 = float(stats["p95"])
        observed = float(flow_df.iloc[0][feature])

        reference_range = p95 - p05

        # Ignore near-constant features.
        if reference_range < 0.001:
            continue

        if observed < p05:
            direction = "below_benign_range"
            distance = p05 - observed
        elif observed > p95:
            direction = "above_benign_range"
            distance = observed - p95
        else:
            continue

        deviation_magnitude = distance / reference_range

        # Ignore deviations that are too small to be useful.
        if deviation_magnitude < 0.05:
            continue
        deviations.append({
            "feature": feature,
            "observed_value": round(observed, 6),
            "benign_p05": round(p05, 6),
            "benign_p95": round(p95, 6),
            "direction": direction,
            "deviation_magnitude": round(deviation_magnitude, 6),
            "explanation": (
                f"{feature} is {direction.replace('_', ' ')} "
                "compared with the benign reference."
            )
        })

    deviations.sort(
        key=lambda item: item["deviation_magnitude"],
        reverse=True
    )

    return {
        "explanation_method": "benign_percentile_feature_deviation",
        "top_deviations": deviations[:top_n]
    }


# Provisional threshold based on the evaluation experiments.
ANOMALY_THRESHOLD = 0.90

def score_flow(flow):
    """
    Score one network flow and return a structured ETIE result.
    The anomaly score is not a probability of maliciousness.
    """
    flow_df = validate_flow(flow)

    raw_score = float(model.score_samples(flow_df)[0])

    rank = np.searchsorted(
        SORTED_CALIBRATION_SCORES,
        raw_score,
        side="right"
    )

    anomaly_score = float(
        1 - rank / len(SORTED_CALIBRATION_SCORES)
    )

    # Experimental attack-probability estimate.
    # This is calibrated on a balanced research sample and is not
    # validated for real-world attack prevalence.
    experimental_attack_probability = float(
    reliability_calibrator.predict([anomaly_score])[0]
    )

    decision = (
        "suspicious"
        if anomaly_score >= ANOMALY_THRESHOLD
        else "not_flagged"
    )

    explanation = explain_flow(flow_df)

    return {
        "anomaly_decision": decision,
        "anomaly_score": round(anomaly_score, 6),
        "raw_isolation_forest_score": round(raw_score, 6),
        "score_type": "benign_reference_percentile_anomaly_score",
        "threshold": ANOMALY_THRESHOLD,
        "reliability": None,
        "reliability_status": "not_calibrated",
        "experimental_attack_probability": round(experimental_attack_probability, 6),
        "model": "IsolationForest",
        "model_version": "candidate_1",
        "explanation_method": explanation["explanation_method"],
        "top_deviations": explanation["top_deviations"]
    }


def score_flows(flows):
    """
    Score a batch of flows and return one result per flow.
    Each flow must be a dictionary using the expected feature schema.
    """
    if not isinstance(flows, list):
        raise TypeError("Flows must be provided as a list.")

    return [score_flow(flow) for flow in flows]
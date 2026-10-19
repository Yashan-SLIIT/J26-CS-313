# J26-CS-313 — Explainable Framework for Encrypted Traffic Decision Support

## Project Overview

The **Explainable Framework for Encrypted Traffic Decision Support (ETIE)** is a group research and development project focused on supporting security decisions involving encrypted network traffic.

This repository contains the research notebooks, machine-learning artifacts, and API implementation for the **Adaptive Anomaly & Unknown-Threat Intelligence Service** component.

## Anomaly Detection Service

The service uses an **Isolation Forest** model to identify network-flow feature patterns that deviate from a benign reference distribution. It produces anomaly scores and feature-deviation explanations to support further investigation.

### Key Features

- **Anomaly detection:** Scores network flows using an Isolation Forest model trained on benign traffic.
- **Reference-based scoring:** Converts raw Isolation Forest scores into percentile-based anomaly scores relative to a benign reference set.
- **Threshold-based decisions:** Uses a configurable anomaly threshold, currently set to `0.90`, to flag suspicious flows.
- **Feature-deviation explanations:** Identifies feature deviations relative to benign reference data. These explanations are descriptive and do not establish causation.
- **Experimental probability calibration:** Includes an isotonic-regression experiment. Its estimated attack probabilities are experimental and have not been validated as real-world attack probabilities.
- **REST API:** Provides health-check, single-flow scoring, and batch-scoring endpoints through FastAPI.

> **Important:** Anomaly scores are not probabilities. The current threshold is provisional, and the service is a research prototype rather than a production-ready security system.

## Repository Structure

```text
J26-CS-313/
├── Services/
│   ├── anomaly_api.py
│   ├── anomaly_service.py
│   ├── test_anomaly_api.py
│   └── test_anomaly_import.py
├── notebooks/
│   ├── 01_dataset_inspection.ipynb
│   ├── 02_feature_preparation.ipynb
│   ├── 03_feature_explainability.ipynb
│   └── 04_reliability_calibration.ipynb
├── models/
│   ├── anomaly_benign_reference.json
│   ├── anomaly_calibration_scores.npy
│   ├── anomaly_feature_schema.json
│   ├── anomaly_service_demo.json
│   ├── etie_isolation_forest_candidate.joblib
│   ├── etie_isotonic_calibrator_candidate.joblib
│   └── etie_reliability_calibration_report.json
├── ANOMALY_API_CONTRACT.md
├── README.md
└── .gitignore
```

The `data/` directory contains the dataset used in the research workflow and is excluded from Git because of its size. The local Python virtual environment is also excluded.

## Research Workflow

The research notebooks document the following workflow:

1. **Dataset inspection** — examines the dataset's structure, labels, data quality, and feature distributions.
2. **Feature preparation** — prepares the feature data and training/evaluation datasets.
3. **Feature explainability** — investigates feature deviations to help interpret anomalous observations.
4. **Reliability calibration** — evaluates an experimental isotonic-regression approach for mapping anomaly scores to attack-probability estimates.

The reliability-calibration experiment uses a balanced sample from the available dataset. Its results should not be interpreted as validated real-world attack probabilities.

## Machine-Learning Artifacts

The `models/` directory contains:

- `etie_isolation_forest_candidate.joblib` — candidate Isolation Forest model.
- `anomaly_feature_schema.json` — expected feature schema.
- `anomaly_calibration_scores.npy` — reference scores used in percentile-based anomaly scoring.
- `anomaly_benign_reference.json` — benign-reference information used by the service.
- `etie_isotonic_calibrator_candidate.joblib` — experimental isotonic-regression calibrator.
- `etie_reliability_calibration_report.json` — calibration experiment metrics and limitations.
- `anomaly_service_demo.json` — service demonstration artifact.

The candidate model expects **78 numeric features**. Input feature extraction and preprocessing must produce the expected features in the required schema.

## API Setup and Usage

### Requirements

- Python
- FastAPI
- Uvicorn
- Scikit-learn
- NumPy
- Joblib
- Pydantic

Install the required packages in a Python virtual environment. If the repository has a dependency file, use it to install the project's pinned dependencies.

### Start the API

From the repository root, activate your virtual environment and run:

```bash
python -m uvicorn Services.anomaly_api:app --host 127.0.0.1 --port 8000
```

The local API base URL is:

```text
http://127.0.0.1:8000
```

Interactive API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

### Available Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Checks service health and reports the expected feature count. |
| `POST` | `/api/v1/anomaly/score` | Scores a single network flow. |
| `POST` | `/api/v1/anomaly/score/batch` | Scores a batch of 1–100 network flows. |

### Example Requests

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Single-flow scoring request:

```json
{
  "features": {
    "FEATURE_NAME_1": 0.12,
    "FEATURE_NAME_2": 0.35
  }
}
```

**Note:** The feature names above are placeholders, not a valid complete request. Replace them with all 78 required feature names and their corresponding numeric values from `anomaly_feature_schema.json`.

Batch-scoring request:

```json
{
  "flows": [
    {
      "features": {
        "FEATURE_NAME_1": 0.12
      }
    }
  ]
}
```

The batch example is illustrative only; each flow must contain all required features.

Invalid requests return HTTP `422` when input validation or scoring detects an invalid flow.

For the complete request/response contract, see [`ANOMALY_API_CONTRACT.md`](ANOMALY_API_CONTRACT.md).

## Testing

The repository includes API and service-import test modules under `Services/`.

Run the API tests from the repository root using:

```bash
python -m Services.test_anomaly_api
```

Run this command in the configured virtual environment. Refer to the test module for the exact checks performed.

## Current Limitations

- The anomaly threshold of `0.90` is provisional and requires further validation.
- Anomaly scores represent relative deviation from benign reference scores, not calibrated probabilities.
- The isotonic-regression output is experimental and has not been validated against real-world attack prevalence or distribution shift.
- Feature-deviation explanations describe differences from benign reference data and do not prove malicious intent or causation.
- The API expects upstream preprocessing to supply the correct 78 features; it does not itself extract features from encrypted traffic.
- The current implementation is a local research prototype and has not been hardened for production deployment.

## Project Status

This repository documents the current research and implementation of the anomaly-detection component within the broader ETIE group project. The component and its evaluation remain subject to further testing, validation, and integration.

# ETIE — Adaptive Anomaly Intelligence Service API Contract

**API version:** 1.0
**Service:** Adaptive Anomaly & Unknown-Threat Intelligence
**Status:** Initial integration prototype

## 1. Purpose

The service receives a network-flow feature vector and returns an anomaly score, a threshold-based decision, and feature-deviation explanations. It is designed to communicate with other ETIE components and the Windows application through HTTP and JSON.

The service does not capture packets or generate network flows. Input features must be generated and normalized upstream according to the agreed ETIE feature standard.

## 2. Base URL

Local development:

`http://127.0.0.1:8000`

This address is accessible only from the same computer.

## 3. Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check service availability |
| POST | `/api/v1/anomaly/score` | Score a single network flow |
| POST | `/api/v1/anomaly/score/batch` | Score a batch of 1–100 network flows |

Interactive API documentation:

`http://127.0.0.1:8000/docs`

**Batch request limits**
- Minimum batch size: 1 flow.
- Maximum batch size: 100 flows.
- If any flow fails feature validation, the entire batch request is rejected with HTTP 422; partial results are not returned.
- Requests exceeding the batch-size limit are rejected with HTTP 422 before scoring begins.

### Batch response structure

A successful request to `POST /api/v1/anomaly/score/batch` returns a JSON object containing:

- `flow_count`: Number of flows successfully scored.
- `results`: An array containing one anomaly-scoring result for each submitted flow, in the same order as the request.

Each result contains the following fields:

| Field | Description |
|---|---|
| `anomaly_decision` | `suspicious` or `not_flagged`, based on the configured threshold. |
| `anomaly_score` | Anomaly score relative to the benign calibration reference, ranging from 0 to 1. This is not a probability of maliciousness. |
| `raw_isolation_forest_score` | Raw score produced by the Isolation Forest model. |
| `score_type` | Identifies the score as a benign-reference percentile anomaly score. |
| `threshold` | Anomaly decision threshold used by the service. |
| `reliability` | `null` because reliability has not yet been calibrated and validated. |
| `reliability_status` | `not_calibrated` until a defensible reliability measure is validated. |
| `model` | Model used for scoring, currently `IsolationForest`. |
| `model_version` | Version identifier for the candidate model. |
| `explanation_method` | Method used to generate feature-deviation explanations. |
| `top_deviations` | Features that fall outside the selected benign reference ranges, ranked by deviation magnitude.


## 4. Request format

### POST `/api/v1/anomaly/score`

Content-Type: `application/json`

```json
{
  "features": {
    "feature_name_1": 0.25,
    "feature_name_2": 0.70
  }
}
```

The example above illustrates the structure only. A valid request must contain **exactly the 78 feature names** defined in the service's feature schema.

Requirements:

- Every feature value must be numeric and finite.
- Feature names must match the expected schema exactly.
- Missing or additional feature names are rejected.
- Features must use the same definitions, units, ordering conventions, and normalization as the trained model.
- The service validates the feature set and orders the values according to its schema before scoring.

## 5. Successful response

A successful request returns HTTP `200 OK`.

Example structure:

```json
{
  "anomaly_decision": "suspicious",
  "anomaly_score": 0.968014,
  "raw_isolation_forest_score": -0.720045,
  "score_type": "benign_reference_percentile_anomaly_score",
  "threshold": 0.9,
  "reliability": null,
  "reliability_status": "not_calibrated",
  "model": "IsolationForest",
  "model_version": "candidate_1",
  "explanation_method": "benign_percentile_feature_deviation",
  "top_deviations": []
}
```

Values are illustrative; actual scores and explanations depend on the submitted flow.

### Response fields

| Field | Meaning |
|---|---|
| `anomaly_decision` | Threshold-based decision: `suspicious` or `not_flagged` |
| `anomaly_score` | Anomaly score relative to the benign calibration reference, between 0 and 1 |
| `raw_isolation_forest_score` | Raw Isolation Forest score; lower values indicate more anomalous observations |
| `score_type` | Identifies the score as a benign-reference percentile score |
| `threshold` | Current decision threshold, provisionally set to 0.90 |
| `reliability` | `null` until a defensible reliability measure is validated |
| `reliability_status` | Indicates that reliability has not yet been calibrated |
| `model` | Model used for scoring |
| `model_version` | Identifier for the current candidate model |
| `explanation_method` | Method used to identify feature deviations |
| `top_deviations` | List of features that differ sufficiently from the benign reference range |
| `experimental_attack_probability`| An experimental estimate from the research dataset's balanced calibration sample. It is not validated as a real-world attack probability |
| `reliability`| Remains `null` until a defensible reliability measure has been independently validated |

**Important:** The anomaly score is not the probability that a flow is malicious. A `suspicious` result means that the score meets the current threshold; it does not independently confirm an attack.

## 6. Error responses

| HTTP status | Meaning |
|---|---|
| `422 Unprocessable Entity` | Invalid request structure, missing or extra features, non-numeric values, or non-finite feature values |
| `500 Internal Server Error` | Unexpected server-side failure |

Example validation error:

```json
{
  "detail": "Feature values must be finite numbers."
}
```

## 7. Integration responsibilities

**Upstream flow-generation component**
- Captures or receives network traffic.
- Generates flow-level features.
- Converts the flow to the agreed ETIE feature schema and normalization.

**Adaptive Anomaly Intelligence Service**
- Validates the incoming feature vector.
- Calculates the anomaly score.
- Applies the configured decision threshold.
- Returns feature-deviation explanations.

**Windows application / Prediction Fusion Engine**
- Sends requests to the service.
- Parses the JSON response.
- Handles service errors and unavailable-service conditions.
- Combines this service's output with evidence from the other ETIE intelligence services according to the agreed fusion design.

## 8. Current limitations

- The current API scores one flow per request.
- The threshold of 0.90 is provisional.
- Reliability is not calibrated.
- Feature-deviation explanations are descriptive, not causal.
- The service is currently a local prototype and has not been secured for network deployment.
- Model performance must be evaluated separately from API integration tests.

## 9. Integration status

The following have been tested successfully:

- Service startup and artifact loading.
- Health endpoint.
- Single-flow scoring for sample BENIGN and DoS Hulk dataset rows.
- Rejection of requests with missing features.
- Rejection of non-finite feature values.


from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .anomaly_service import score_flow, FEATURE_COLUMNS

app = FastAPI(
    title="ETIE Anomaly Intelligence Service",
    description="Anomaly scoring and feature-deviation explanations.",
    version="1.0.0",
)


class FlowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    features: dict[str, float]


class BatchFlowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flows: list[FlowRequest] = Field(min_length=1, max_length=100)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ETIE Anomaly Intelligence Service",
        "expected_feature_count": len(FEATURE_COLUMNS),
    }


@app.post("/api/v1/anomaly/score")
def score_endpoint(request: FlowRequest):
    try:
        return score_flow(request.features)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@app.post("/api/v1/anomaly/score/batch")
def score_batch_endpoint(request: BatchFlowRequest):
    try:
        results = [
            score_flow(flow.features)
            for flow in request.flows
        ]

        return {
            "flow_count": len(results),
            "results": results,
        }

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

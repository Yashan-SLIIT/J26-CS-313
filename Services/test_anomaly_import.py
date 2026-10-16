
import json
from anomaly_service import score_flow, score_flows, FEATURE_COLUMNS

flows = [
    {feature: 0.0 for feature in FEATURE_COLUMNS},
    {feature: 0.5 for feature in FEATURE_COLUMNS},
]

batch_results = score_flows(flows)
individual_results = [score_flow(flow) for flow in flows]

if batch_results == individual_results:
    print("PASS: Batch and individual results match.")
else:
    print("FAIL: Batch and individual results differ.")

# Verify the output remains strict JSON.
json.dumps(batch_results, allow_nan=False)
print("PASS: Batch results are valid strict JSON.")

for index, result in enumerate(batch_results, start=1):
    print(
        f"Flow {index}: "
        f"decision={result['anomaly_decision']}, "
        f"score={result['anomaly_score']}"
    )

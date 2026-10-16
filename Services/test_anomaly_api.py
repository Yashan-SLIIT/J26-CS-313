import json
import urllib.request

import pandas as pd

from .anomaly_service import FEATURE_COLUMNS

API_URL = "http://127.0.0.1:8000/api/v1/anomaly/score"
DATA_PATH = "data/CIC-IDS-2017-V2.csv"


def send_flow_to_api(features):
    """Send one flow to the ETIE anomaly API and return its JSON response."""
    payload = {"features": features}

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def send_batch_to_api(flows):
    """Send multiple flows to the ETIE batch anomaly API."""
    payload = {"flows": flows}

    request = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/anomaly/score/batch",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))



def main():
    # Load real flows from the dataset.
    df = pd.read_csv(DATA_PATH)

    # Select 50 BENIGN and 50 DoS Hulk flows.
    benign_rows = df.loc[df["label"] == "BENIGN"].head(50)
    dos_rows = df.loc[df["label"] == "DoS Hulk"].head(50)

    selected_rows = pd.concat([benign_rows, dos_rows])

    flows = []

    for _, row in selected_rows.iterrows():
        features = {
            name: float(row[name])
            for name in FEATURE_COLUMNS
        }
        flows.append({"features": features})

    # Send exactly 100 flows in one HTTP request.
    result = send_batch_to_api(flows)

    print("Batch API request completed successfully.")
    print("Expected flow count: 100")
    print("Actual flow count:", result["flow_count"])
    print("Results returned:", len(result["results"]))

    # Validate the response structure.
    required_fields = {
        "anomaly_decision",
        "anomaly_score",
        "reliability",
        "reliability_status",
        "top_deviations",
        "experimental_attack_probability",
    }

    all_valid = all(
        required_fields.issubset(flow_result.keys())
        for flow_result in result["results"]
    )

    print("All results contain required fields:", all_valid)

    # Display the first five results.
    print("\nFirst five results:")
    for flow_result in result["results"][:5]:
        print(
            "Decision:", flow_result["anomaly_decision"],
            "| Anomaly score:", flow_result["anomaly_score"]
        )


def send_batch_to_api(flows):
    """Send multiple flows to the ETIE batch anomaly API."""
    payload = {"flows": flows}

    request = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/anomaly/score/batch",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    main()
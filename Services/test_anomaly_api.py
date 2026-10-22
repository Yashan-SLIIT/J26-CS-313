import json
import urllib.request

import pandas as pd

from .anomaly_service import FEATURE_COLUMNS

API_URL = "http://127.0.0.1:8000/api/v1/anomaly/score"
DATA_PATH = "data/CIC-IDS-2017-V2.csv"
HEALTH_URL = "http://127.0.0.1:8000/health"
BATCH_URL = "http://127.0.0.1:8000/api/v1/anomaly/score/batch"


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


def send_invalid_request(url, payload):
    """Send a request expected to be rejected by the API."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def test_health_endpoint():
    """Verify that the API health endpoint responds correctly."""
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))

            passed = (
                response.status == 200
                and body.get("status") == "healthy"
                and body.get("expected_feature_count") == len(FEATURE_COLUMNS)
            )

            print(
                f"{'PASS' if passed else 'FAIL'}: Health endpoint "
                f"(HTTP {response.status})"
            )

            if not passed:
                print("Response:", body)

            return passed

    except Exception as exc:
        print(f"FAIL: Health endpoint ({exc})")
        return False


def test_valid_single_flow():
    """Verify that a real benign flow receives a valid API response."""
    df = pd.read_csv(DATA_PATH, nrows=100)
    benign_rows = df.loc[df["label"] == "BENIGN"]

    if benign_rows.empty:
        print("FAIL: Valid single-flow request (no BENIGN row found)")
        return False

    row = benign_rows.iloc[0]
    features = {
        name: float(row[name])
        for name in FEATURE_COLUMNS
    }

    try:
        result = send_flow_to_api(features)

        passed = (
            result.get("anomaly_decision") in {"not_flagged", "suspicious"}
            and isinstance(result.get("anomaly_score"), (int, float))
            and result.get("model") == "IsolationForest"
        )

        print(
            f"{'PASS' if passed else 'FAIL'}: Valid single-flow request"
        )

        if not passed:
            print("Response:", result)

        return passed

    except Exception as exc:
        print(f"FAIL: Valid single-flow request ({exc})")
        return False


def test_api_validation():
    """Verify that the API rejects invalid requests."""
    batch_url = BATCH_URL

    all_passed = True

    test_cases = [
        (
            "Empty batch",
            batch_url,
            {"flows": []},
        ),
        (
            "Batch exceeding 100 flows",
            batch_url,
            {"flows": [{"features": {}} for _ in range(101)]},
        ),
        (
            "Invalid feature set",
            API_URL,
            {"features": {"Invalid_Feature": 1.0}},
        ),
    ]

    print("\nAPI validation tests:")

    for name, url, payload in test_cases:
        status, body = send_invalid_request(url, payload)
        passed = status == 422

        print(
            f"{'PASS' if passed else 'FAIL'}: {name} "
            f"(HTTP {status})"
        )

        all_passed = passed and all_passed

        if not passed:
            print("Response:", body)

    return all_passed


def main():
    all_passed = True

    all_passed = test_health_endpoint() and all_passed
    all_passed = test_valid_single_flow() and all_passed

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
    try:
        result = send_batch_to_api(flows)
        batch_passed = (
            result.get("flow_count") == 100
            and len(result.get("results", [])) == 100
        )
        print("Batch API request completed successfully.")
        print("Expected flow count: 100")
        print("Actual flow count:", result.get("flow_count"))
        print("Results returned:", len(result.get("results", [])))
        print("Batch count validation:", "PASS" if batch_passed else "FAIL")

        all_passed = batch_passed and all_passed

    except Exception as exc:
        print(f"FAIL: Batch API request ({exc})")
        all_passed = False
        result = None
    # Validate the response structure.
    required_fields = {
        "anomaly_decision",
        "anomaly_score",
        "reliability",
        "reliability_status",
        "top_deviations",
        "experimental_attack_probability",
    }

    all_valid = (
        result is not None
        and all(
            required_fields.issubset(flow_result.keys())
            for flow_result in result.get("results", [])
        )
    )

    print(
        "All results contain required fields:",
        "PASS" if all_valid else "FAIL"
    )

    all_passed = all_valid and all_passed

    # Display the first five results.
    if result is not None:
        print("\nFirst five results:")
        for flow_result in result.get("results", [])[:5]:
            print(
                "Decision:", flow_result["anomaly_decision"],
                "| Anomaly score:", flow_result["anomaly_score"]
            )


    all_passed = test_api_validation() and all_passed

    print("\nOverall test result:", "PASS" if all_passed else "FAIL")
    return all_passed


if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)
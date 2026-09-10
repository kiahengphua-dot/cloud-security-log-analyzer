"""
Cloud Security Log Analyzer

Task 1: Load CloudTrail-style audit logs from a JSON file and print a short
        summary line for every event.

Later tasks will add detection functions (failed-login bursts, new IPs,
privilege escalation, new credentials, etc.).

Run it from the project folder:
    python analyser.py
"""

import json


def load_events(path):
    """Open a JSON file and return the list of event dictionaries inside it.

    json.load() reads an open file and converts JSON into Python objects:
    a JSON array becomes a list, a JSON object becomes a dict,
    and JSON null becomes Python's None.
    """
    with open(path, "r", encoding="utf-8") as f:
        events = json.load(f)
    return events


def describe_event(event):
    """Turn one event dictionary into a single readable line of text."""
    time = event["eventTime"]
    name = event["eventName"]
    ip = event["sourceIPAddress"]

    # userName is nested one level deeper, inside the "userIdentity" dict.
    user = event["userIdentity"]["userName"]

    # errorCode is null in the JSON, which Python reads as None.
    # None means the API call succeeded.
    if event["errorCode"] is None:
        outcome = "OK"
    else:
        outcome = event["errorCode"]

    # An f-string builds the line. The :<8 etc. pad each value to a fixed
    # width so the columns line up when printed.
    return f"{time}  {user:<8}  {name:<28}  {ip:<16}  {outcome}"


def summarize(path):
    """Load one log file and print a summary for every event in it."""
    events = load_events(path)
    print(f"\n=== {path} ===")
    print(f"Loaded {len(events)} events\n")
    for event in events:
        print(describe_event(event))


# This block only runs when you execute "python analyser.py" directly,
# not if this file is imported from another script later.
if __name__ == "__main__":
    summarize("sample_logs/normal_activity.json")
    summarize("sample_logs/suspicious_activity.json")

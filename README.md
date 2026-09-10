# Cloud Security Log Analyzer

A small, beginner-friendly project that analyses **simulated AWS CloudTrail
audit logs** to spot behaviour consistent with a **compromised user account**.

## Scenario

An AWS IAM user's credentials may have been stolen. Given a batch of cloud
activity logs, the analyzer flags suspicious activity such as:

- unusual login activity (new IP, new location, odd hours, scripted user agent)
- repeated failed authentication (brute force / credential stuffing)
- suspicious source IP addresses
- unusual or sensitive API calls
- privilege escalation attempts
- creation of new credentials (persistence)

## Log format

Each event is a simplified CloudTrail record:

```json
{
  "eventTime": "2026-09-08T14:12:05Z",
  "eventName": "GetObject",
  "eventSource": "s3.amazonaws.com",
  "userIdentity": { "type": "IAMUser", "userName": "alice" },
  "sourceIPAddress": "203.0.113.24",
  "userAgent": "aws-cli/2.15.0",
  "awsRegion": "us-east-1",
  "errorCode": null
}
```

`errorCode` is `null` when the call succeeded, otherwise a string such as
`"AccessDenied"` or `"SigninFailure"`.

## Sample data

- `sample_logs/normal_activity.json` — baseline traffic from four legitimate
  identities (alice, bob, carol, deploy-bot). Detectors should raise **no**
  alerts on this file.
- `sample_logs/suspicious_activity.json` — a full attack chain against `alice`
  (brute force -> takeover -> recon -> privilege escalation -> persistence ->
  defense evasion -> data exfiltration), plus a smaller failed-login probe
  against `bob` from a Tor-style IP.

## Usage

```
python analyser.py
```

## Status

- [x] Task 1 - load a log file and print a summary line per event
- [ ] Task 2 - detect repeated failed authentication
- [ ] Task 3 - detect logins from new / unexpected IP addresses
- [ ] Task 4 - detect sensitive / unusual API calls
- [ ] Task 5 - detect privilege escalation attempts
- [ ] Task 6 - detect creation of new credentials
- [ ] Task 7 - combine detectors into a single report

See `detections.md` for the security concepts behind each detector.

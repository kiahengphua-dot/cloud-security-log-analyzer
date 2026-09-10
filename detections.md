# Detection notes

Reference for the security concepts behind this project. Each section becomes
one detector function later.

## What cloud audit logs are

In AWS, almost every action is an API call: "this identity wants to perform
this action on this resource". **CloudTrail** records every one of those
requests - who, what, when, from where, and whether it succeeded. It captures
**control-plane activity** ("who did what to the account"), not the contents
of your data.

If an attacker steals credentials, every action they take still lands in
CloudTrail. The job is to find the attacker's records among the legitimate ones.

## Normal activity (the baseline)

| Category | Normal pattern |
|---|---|
| Logins | Same few IPs per user, consistent location, consistent user agent, during that user's working hours |
| Auth outcomes | Occasional single `SigninFailure` followed immediately by success (a typo) - not bursts |
| Read calls | `Get*` / `Describe*` / `List*` scoped to the resources that user actually works with |
| Write calls | Predictable volume, human speed, on services the user owns |
| IAM activity | Rare, from a small admin group, known IPs, business hours, usually right after a console login |
| Regions | The 1-2 regions the company actually uses |
| Service roles | Steady and repetitive - the same call every N minutes |

Theme: narrow, repetitive, predictable, matches a baseline.

## Suspicious activity, by attacker stage

| Stage | Signals in the logs |
|---|---|
| 1. Credential access / testing | Login from a never-before-seen IP; new country or hosting/VPN/Tor network; user agent changes (browser -> `python-requests`, `curl`, `Boto3`); login outside the user's normal hours |
| 2. Brute force / stuffing | Many `SigninFailure` for one user in a short window (e.g. 5 in 60s); failures across many usernames from one IP; a failure burst **followed by a success** = likely takeover |
| 3. Reconnaissance | Burst of `List*` / `Describe*` across many services in minutes; `ListUsers`, `ListRoles`, `ListAccessKeys`, `GetAccountAuthorizationDetails`, `GetCallerIdentity` right after login; activity in an unused region |
| 4. Privilege escalation | `AttachUserPolicy` / `AttachRolePolicy` / `PutUserPolicy`, especially with `AdministratorAccess` or `*:*`; `AccessDenied` errors on IAM calls (probing); `AddUserToGroup`; `UpdateAssumeRolePolicy` |
| 5. Persistence | `CreateAccessKey` (a 2nd key, or a key for another user); `CreateUser`; `CreateLoginProfile` / `UpdateLoginProfile` |
| 6. Defense evasion | `StopLogging` / `DeleteTrail` / `UpdateTrail` on CloudTrail; disabling GuardDuty/Config; deleting the users/keys just created |
| 7. Impact | Mass `GetObject` (exfiltration); `PutBucketPolicy` / `PutBucketAcl` making a bucket public; `RunInstances` at scale in an unused region (crypto mining); mass deletes |

Theme: broad, fast, sensitive services, errors from probing, deviates from baseline.

## What an analyst looks at per event

- **Identity** - which user or role? human or service?
- **Source IP** - seen before for this user? what network does it belong to?
- **Time** - fits this user's normal hours?
- **User agent** - browser, CLI, SDK, scripting library? sudden change?
- **Action** - read-only or state-changing? routine or sensitive (IAM, security services)?
- **Outcome** - success, or an error like `AccessDenied` that shows probing?
- **Volume & velocity** - how many actions, how fast? humans are slow, scripts are fast
- **Sequence** - failed logins -> success -> recon -> escalate -> create keys is a classic kill chain
- **Deviation from baseline** - almost every detection is really "this differs from normal"

## Mapping to project goals

| Goal | Stage(s) |
|---|---|
| unusual login activity | 1 |
| repeated failed authentication | 2 |
| suspicious IP addresses | 1, 2, 7 |
| unusual API calls | 3, 6 |
| privilege escalation attempts | 4 |
| creation of new credentials | 5 |

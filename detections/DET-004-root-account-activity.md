# DET-004 – Root Account Activity

## Overview
Detects any API call or console action performed by the AWS root account.
Root activity should be treated as suspicious in nearly all circumstances.

## Why This Matters
The AWS root account has unrestricted access to every resource and service
in the account and cannot be limited by IAM policies. Best practice is to
lock it away after initial account setup and never use it for day-to-day
operations. Any root activity — legitimate or not — warrants immediate
investigation. Attackers who obtain root credentials have complete,
irrevocable control of the entire AWS environment.

## CloudTrail Event
- **Event Name:** Any (filter on identity, not event name)
- **Event Source:** Any
- **Read Only:** false and true

## Key Fields to Inspect
| Field | Value |
|---|---|
| userIdentity.type | Root |
| userIdentity.arn | arn:aws:iam::ACCOUNT_ID:root |
| userIdentity.sessionContext.attributes.mfaAuthenticated | false = critical |
| eventName | Any sensitive action performed as root |
| sourceIPAddress | Unexpected IP = escalates severity |

## Detection Logic (Pseudocode)
```sql
WHERE userIdentity.type = "Root"
ALERT CRITICAL if sessionContext.attributes.mfaAuthenticated = "false"
ALERT HIGH for all other root activity
-- Exclude: expected root actions during initial account setup
-- Flag immediately: root + no MFA + IAM or S3 write actions
```

## Evidence
Every CloudTrail event captured in this lab was performed by the root
account without MFA. This represents the full scope of root activity
observed during environment setup.

| Event | Time | MFA |
|---|---|---|
| CreateUser (lab-admin) | 2026-06-03T05:18:04Z | false |
| CreateUser (analyst-user) | 2026-06-03T05:19:14Z | false |
| CreateUser (vulnerable-user) | 2026-06-03T05:19:26Z | false |
| AttachUserPolicy (AdministratorAccess → lab-admin) | 2026-06-03T05:32:00Z | false |
| AttachUserPolicy (PowerUserAccess → vulnerable-user) | 2026-06-03T05:36:37Z | false |
| CreateAccessKey (analyst-user) | 2026-06-03T05:20:56Z | false |
| CreateAccessKey (analyst-user) | 2026-06-03T05:22:18Z | false |
| CreateAccessKey (lab-admin) | 2026-06-03T05:33:23Z | false |
| CreateAccessKey (vulnerable-user) | 2026-06-03T05:39:59Z | false |
| PutBucketPolicy (detection-lab-public) | 2026-06-03T05:43:47Z | false |

- Evidence files: evidence/create-user.json, evidence/attach-user-policy.json,
  evidence/create-access-key.json, evidence/public-bucket-policy.json

## Notes
Every action in this lab was performed by root without MFA — a worst-case
scenario from a security posture standpoint. In a real environment this
volume of sensitive root activity in a short window (roughly 36 minutes,
05:07 to 05:43 UTC) would be a critical incident. The pattern of
CreateUser → AttachUserPolicy → CreateAccessKey performed by root is
a textbook account takeover sequence — create a backdoor user, give it
admin access, generate programmatic credentials.
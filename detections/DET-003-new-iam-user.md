# DET-003 – New IAM User Created

## Overview
Detects when a new IAM user is created in the AWS environment.
Any user creation warrants review; creation by root or without MFA is critical.

## Why This Matters
Attackers with sufficient IAM permissions will create new users as a
persistence mechanism — a backdoor account that survives credential rotation
on existing users. In a well-managed environment, IAM user creation should
be rare, controlled, and always performed by an authorized identity through
an approved process, never by root.

## CloudTrail Event
- **Event Name:** CreateUser
- **Event Source:** iam.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | CreateUser |
| requestParameters.userName | Name of the newly created user |
| responseElements.user.arn | Full ARN of the new user |
| userIdentity.type | Root = critical |
| userIdentity.sessionContext.attributes.mfaAuthenticated | false = escalates severity |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "CreateUser"
ALERT CRITICAL if userIdentity.type = "Root"
ALERT HIGH for all other matches
-- Follow-on: correlate with CreateAccessKey within 5 minutes
-- for same userName to detect immediate persistence behavior
```

## Evidence
Real CloudTrail events captured from lab environment.
All three events performed by root without MFA via the AWS console.

**Event 1 – lab-admin created**
- Actor: root
- Time: 2026-06-03T05:18:04Z
- New User ARN: arn:aws:iam::285515885307:user/lab-admin
- MFA: false

**Event 2 – analyst-user created**
- Actor: root
- Time: 2026-06-03T05:19:14Z
- New User ARN: arn:aws:iam::285515885307:user/analyst-user
- MFA: false

**Event 3 – vulnerable-user created**
- Actor: root
- Time: 2026-06-03T05:19:26Z
- New User ARN: arn:aws:iam::285515885307:user/vulnerable-user
- MFA: false

- Evidence file: evidence/create-user.json

## Notes
All three users were created within roughly 90 seconds of each other by root
with no MFA. In a real environment this burst of user creation activity from
root would be an immediate critical alert. Note the correlation opportunity
in the detection logic above — CreateUser followed quickly by CreateAccessKey
for the same user is a strong signal of attacker persistence behavior, which
is exactly what happened here.
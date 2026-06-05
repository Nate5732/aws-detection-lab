# DET-001 – High Privilege Policy Attachment

## Overview
Detects when a highly privileged AWS managed policy is attached to an IAM user.
Policies in scope: AdministratorAccess, PowerUserAccess, IAMFullAccess.

## Why This Matters
Attaching AdministratorAccess or PowerUserAccess to a user is a common
privilege escalation technique. An attacker who gains access to an account
with IAM write permissions can attach these policies to a user they control,
effectively gaining full or near-full control of the AWS environment.

## CloudTrail Event
- **Event Name:** AttachUserPolicy
- **Event Source:** iam.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | AttachUserPolicy |
| requestParameters.policyArn | arn:aws:iam::aws:policy/AdministratorAccess |
| userIdentity.type | Root (suspicious on its own) |
| userIdentity.sessionContext.attributes.mfaAuthenticated | false (escalates severity) |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "AttachUserPolicy"
AND requestParameters.policyArn IN (
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess"
)
ALERT HIGH
```

## Evidence
Real CloudTrail events captured from lab environment.

**Event 1 – AdministratorAccess attached to lab-admin**
- Actor: root
- Time: 2026-06-03T05:32:00Z
- MFA: false
- Source IP: 74.130.213.209
- Evidence file: evidence/attach-user-policy.json

**Event 2 – PowerUserAccess attached to vulnerable-user**
- Actor: root
- Time: 2026-06-03T05:36:37Z
- MFA: false
- Source IP: 74.130.213.209
- Evidence file: evidence/attach-user-policy.json

## Notes
Both events were performed by the root account without MFA via the AWS
console. In a real environment this combination — root + no MFA + high
privilege policy attachment — would be a critical alert.
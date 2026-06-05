# DET-007 – Inline Policy Attached Directly to User

## Overview
Detects when an inline IAM policy is attached directly to a user via
PutUserPolicy. Inline policies are harder to audit than managed policies
and are a common attacker technique for stealthy privilege escalation.

## Why This Matters
Managed policies show up in IAM policy listings and are easy to audit.
Inline policies are embedded directly on a user and are easier to miss
during a security review. Attackers with IAM write access will often
use PutUserPolicy to grant themselves or a backdoor user broad permissions
using an inline policy rather than attaching a visible managed policy.
A wildcard inline policy granting Action:* Resource:* is effectively
AdministratorAccess with less visibility.

## CloudTrail Event
- **Event Name:** PutUserPolicy
- **Event Source:** iam.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | PutUserPolicy |
| requestParameters.userName | User receiving the inline policy |
| requestParameters.policyName | Name of the inline policy |
| requestParameters.policyDocument | Content — look for Action:* or Resource:* |
| userIdentity.arn | Who applied the policy |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "PutUserPolicy"
ALERT CRITICAL if policyDocument contains "Action": "*"
ALERT CRITICAL if policyDocument contains "Resource": "*"
ALERT HIGH for all other matches
```

## Evidence
Real CloudTrail event captured from lab environment.

**Event – Inline wildcard policy attached to vulnerable-user**
- Actor: lab-admin
- Target user: vulnerable-user
- Policy name: InlineAdminPolicy
- Policy: Action:* Resource:* (full admin equivalent)
- Evidence file: evidence/put-user-policy.json

## Notes
This inline policy grants equivalent access to AdministratorAccess but
does not appear in the managed policy list, making it harder to detect
during a manual IAM review. Any PutUserPolicy event with a wildcard
action or resource should be treated as a critical finding regardless
of who applied it.
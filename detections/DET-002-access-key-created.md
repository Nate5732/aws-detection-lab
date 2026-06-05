# DET-002 – IAM Access Key Created

## Overview
Detects when a long-lived IAM access key is created for any user.
High severity when created by root or for a privileged user.

## Why This Matters
IAM access keys are long-lived static credentials that provide programmatic
access to AWS. Attackers who gain console access will often create access keys
to establish persistent CLI-based access that survives a password reset.
Keys created for highly privileged users (AdministratorAccess, PowerUserAccess)
are especially dangerous.

## CloudTrail Event
- **Event Name:** CreateAccessKey
- **Event Source:** iam.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | CreateAccessKey |
| requestParameters.userName | Target user receiving the key |
| responseElements.accessKey.accessKeyId | The new key ID created |
| userIdentity.type | Root = critical, IAM user = investigate |
| userIdentity.sessionContext.attributes.mfaAuthenticated | false = escalates severity |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "CreateAccessKey"
ALERT HIGH if userIdentity.type = "Root"
ALERT HIGH if requestParameters.userName IN known_privileged_users
ALERT MEDIUM for all other matches
```

## Evidence
Real CloudTrail events captured from lab environment.
All four events were performed by the root account without MFA via the AWS console.

**Event 1 – Key created for vulnerable-user**
- Actor: root
- Time: 2026-06-03T05:39:59Z
- Key ID: AKIAUE6QSVL5UKS3RPNE
- MFA: false

**Event 2 – Key created for lab-admin**
- Actor: root
- Time: 2026-06-03T05:33:23Z
- Key ID: AKIAUE6QSVL5RIOAV6OA
- MFA: false

**Event 3 – Key created for analyst-user (key 1)**
- Actor: root
- Time: 2026-06-03T05:20:56Z
- Key ID: AKIAUE6QSVL55G4JGSIP
- MFA: false

**Event 4 – Key created for analyst-user (key 2)**
- Actor: root
- Time: 2026-06-03T05:22:18Z
- Key ID: AKIAUE6QSVL5QUTEBIN5
- MFA: false

- Evidence file: evidence/create-access-key.json

## Notes
Two keys were created for analyst-user in quick succession — this pattern
(multiple keys created for the same user in a short window) is itself a
detection opportunity worth flagging separately. In a real environment,
any programmatic key creation via the console by root with no MFA should
be treated as a critical finding.
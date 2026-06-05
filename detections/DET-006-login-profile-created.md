# DET-006 – IAM Login Profile Created

## Overview
Detects when console password access is added to an IAM user via
CreateLoginProfile. Flags the addition of console access to a user
that previously only had programmatic access.

## Why This Matters
IAM users can exist with only programmatic access (access keys) and no
console password. Attackers who gain CLI access to an account will
sometimes create a login profile on a compromised user to establish
console access as a secondary persistence mechanism. This is especially
suspicious when applied to a user that already has high privileges.

## CloudTrail Event
- **Event Name:** CreateLoginProfile
- **Event Source:** iam.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | CreateLoginProfile |
| requestParameters.userName | User receiving console access |
| requestParameters.passwordResetRequired | false = immediately usable |
| userIdentity.type | Who performed the action |
| userIdentity.sessionContext.attributes.mfaAuthenticated | false = escalates severity |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "CreateLoginProfile"
ALERT HIGH if requestParameters.passwordResetRequired = false
ALERT HIGH if userIdentity.type = "Root"
ALERT MEDIUM for all other matches
-- Correlate: was this user recently created or given high privileges?
```

## Evidence
Real CloudTrail event captured from lab environment.

**Event – Login profile created for lab-admin**
- Actor: root
- Time: 2026-06-03T05:18:06Z
- Target user: lab-admin
- Password reset required: true
- MFA: false
- Evidence file: evidence/create-login-profile.json

## Notes
This event was generated during initial lab setup by root without MFA.
The passwordResetRequired flag was set to true here, meaning the user
would need to change the password on first login. An attacker would
typically set this to false for immediate usable access — making that
field a strong signal worth filtering on.
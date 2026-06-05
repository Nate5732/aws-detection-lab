# DET-008 – S3 Block Public Access Disabled

## Overview
Detects when S3 Block Public Access settings are disabled on a bucket.
This is typically a prerequisite step before applying a public bucket
policy and is a strong signal of intentional public exposure.

## Why This Matters
AWS S3 Block Public Access is a safety control that prevents buckets
from being made public even if a permissive policy is applied. Disabling
it is rarely legitimate and is almost always the first step in a two-step
process to expose a bucket publicly — disable Block Public Access, then
apply a public bucket policy. Detecting this event early gives defenders
a chance to respond before the bucket policy is applied.

## CloudTrail Event
- **Event Name:** PutBucketPublicAccessBlock
- **Event Source:** s3.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | PutBucketPublicAccessBlock |
| requestParameters.publicAccessBlockConfiguration.blockPublicPolicy | false = disabled |
| requestParameters.publicAccessBlockConfiguration.blockPublicAcls | false = disabled |
| requestParameters.publicAccessBlockConfiguration.restrictPublicBuckets | false = disabled |
| requestParameters.bucketName | Affected bucket |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "PutBucketPublicAccessBlock"
AND requestParameters.publicAccessBlockConfiguration.blockPublicPolicy = false
ALERT HIGH
-- Correlate: follow-on PutBucketPolicy within 10 minutes on same bucket
-- = CRITICAL two-step public exposure sequence
```

## Evidence
Real CloudTrail event captured from lab environment.

**Event – Block Public Access disabled on detection-lab-public**
- Actor: lab-admin
- Bucket: detection-lab-public
- All four Block Public Access flags set to false
- Evidence file: evidence/put-public-access-block.json

## Notes
This detection pairs directly with DET-005. The full attacker sequence
observed in this lab was: disable Block Public Access (this detection),
then apply a public bucket policy (DET-005). Correlating these two events
on the same bucket within a short time window should trigger a critical
alert — it represents a complete public exposure chain.
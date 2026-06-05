# DET-005 – Public S3 Bucket Policy Applied

## Overview
Detects when an S3 bucket policy is applied that grants public access
to any principal (`"Principal": "*"`). Distinguishes malicious public
exposure from legitimate service-scoped bucket policies.

## Why This Matters
Publicly exposed S3 buckets are one of the most common causes of cloud
data breaches. An attacker with sufficient S3 permissions can make any
bucket publicly readable by applying a permissive bucket policy, exposing
sensitive data to the internet without needing to exfiltrate it through
traditional means. The key signal is `Principal: *` combined with a
permissive action like `s3:GetObject`.

## CloudTrail Event
- **Event Name:** PutBucketPolicy
- **Event Source:** s3.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | PutBucketPolicy |
| requestParameters.bucketPolicy.Statement[].Principal | `*` = public exposure |
| requestParameters.bucketPolicy.Statement[].Action | s3:GetObject, s3:* = high risk |
| requestParameters.bucketPolicy.Statement[].Effect | Allow |
| requestParameters.bucketName | Name of the affected bucket |
| userIdentity.type | Root = additional concern |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "PutBucketPolicy"
AND requestParameters.bucketPolicy.Statement[].Principal = "*"
AND requestParameters.bucketPolicy.Statement[].Effect = "Allow"
ALERT CRITICAL
```

## Distinguishing Malicious vs Legitimate
This lab generated three PutBucketPolicy events. Only one is malicious.

| Bucket | Principal | Action | Verdict |
|---|---|---|---|
| detection-lab-public | `*` | s3:GetObject | MALICIOUS — public exposure |
| detection-lab-secure | cloudtrail.amazonaws.com | s3:PutObject | Legitimate — scoped to CloudTrail service |
| aws-cloudtrail-logs-* | cloudtrail.amazonaws.com | s3:PutObject | Legitimate — scoped to CloudTrail service |

The legitimate policies use a named service principal with a condition
block scoped to a specific CloudTrail ARN. The malicious policy uses
`Principal: *` with no conditions — any unauthenticated user on the
internet can read objects.

## Evidence
Real CloudTrail event captured from lab environment.

**Event – Public policy applied to detection-lab-public**
- Actor: root
- Time: 2026-06-03T05:43:47Z
- Bucket: detection-lab-public
- Principal: `*`
- Action: s3:GetObject
- Resource: arn:aws:s3:::detection-lab-public/*
- MFA: false
- Evidence file: evidence/public-bucket-policy.json

## Notes
The malicious policy was applied by root without MFA via the console.
In a real environment, `PutBucketPolicy` with `Principal: *` should fire
an immediate critical alert regardless of who applied it. The lack of MFA
on the root session is an additional escalating factor. Block Public Access
settings should also be monitored separately — disabling that setting is
often the prerequisite step before a public policy can be applied.
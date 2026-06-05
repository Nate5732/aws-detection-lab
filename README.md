# AWS Detection Engineering Lab

## Overview
A hands-on cloud detection engineering lab built in AWS using real telemetry.
The goal is to simulate realistic attacker behavior across IAM and S3, capture
the resulting CloudTrail events, and turn them into documented detections.
Every detection is backed by actual JSON evidence collected from the live
environment — not synthetic examples.

## Environment
- **Cloud Provider:** AWS (us-east-1)
- **Account Type:** Fresh AWS account, free tier
- **Core Services:** IAM, S3, CloudTrail
- **Logging:** Multi-region CloudTrail trail with S3 log storage and validation enabled

## Simulated Users
| User | Purpose |
|---|---|
| lab-admin | Administrative account, AdministratorAccess |
| analyst-user | Restricted user, no permissions — for AccessDenied scenarios |
| vulnerable-user | Intentionally over-permissioned, PowerUserAccess |

## Detections

| ID | Name | Event | Severity |
|---|---|---|---|
| DET-001 | High Privilege Policy Attachment | AttachUserPolicy | High |
| DET-002 | IAM Access Key Created | CreateAccessKey | High |
| DET-003 | New IAM User Created | CreateUser | High |
| DET-004 | Root Account Activity | Any | Critical |
| DET-005 | Public S3 Bucket Policy Applied | PutBucketPolicy | Critical |
| DET-006 | IAM Login Profile Created | CreateLoginProfile | High |
| DET-007 | Inline Policy Attached to User | PutUserPolicy | Critical |
| DET-008 | S3 Block Public Access Disabled | PutBucketPublicAccessBlock | High |
| DET-009 | CloudTrail Logging Stopped | StopLogging | Critical |
| DET-010 | AccessDenied Spike from Single Identity | Any (errorCode) | Medium/High |

## Repository Structure
aws-detection-lab/
├── README.md
├── detections/       # Detection writeups with logic and evidence references
└── evidence/         # Raw CloudTrail JSON captured from the lab environment

## Methodology
1. Simulate attacker-relevant activity through AWS console and CLI
2. Capture resulting CloudTrail events via lookup-events API
3. Analyze key fields that distinguish malicious from benign activity
4. Document detection logic, key fields, and real evidence in structured writeups

## Status
Complete — 10 documented detections backed by real CloudTrail telemetry.
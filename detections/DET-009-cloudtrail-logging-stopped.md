# DET-009 – CloudTrail Logging Stopped

## Overview
Detects when CloudTrail logging is disabled via StopLogging.
This is a defense evasion technique used by attackers to blind
defenders before performing destructive or sensitive actions.

## Why This Matters
CloudTrail is the primary audit log source for AWS environments.
Stopping it means all subsequent API activity goes unrecorded.
Attackers who gain sufficient permissions will stop CloudTrail
logging before exfiltrating data, creating backdoors, or making
destructive changes — eliminating the evidence trail. This event
is one of the highest-signal detections in AWS environments and
should always trigger an immediate response.

## CloudTrail Event
- **Event Name:** StopLogging
- **Event Source:** cloudtrail.amazonaws.com
- **Read Only:** false

## Key Fields to Inspect
| Field | Value |
|---|---|
| eventName | StopLogging |
| requestParameters.name | Trail name being disabled |
| userIdentity.arn | Who stopped logging |
| sourceIPAddress | Expected vs unexpected IP |
| eventTime | Time logging went dark |

## Detection Logic (Pseudocode)
```sql
WHERE eventName = "StopLogging"
ALERT CRITICAL -- no exceptions
-- Immediate response required
-- Check for activity gap between StopLogging and StartLogging
```

## Evidence
Real CloudTrail event captured from lab environment.

**Event – DetectionEngineeringLab trail stopped**
- Actor: lab-admin
- Trail: DetectionEngineeringLab
- Time: captured in evidence file
- Logging restarted immediately after via StartLogging
- Evidence file: evidence/stop-logging.json

## Notes
This is one of the few detections where there are essentially no
legitimate use cases during normal operations. CloudTrail should
never be stopped outside of a formal change management process.
Any StopLogging event should be treated as critical and trigger
immediate investigation regardless of which identity performed it.
Note the logging gap between StopLogging and StartLogging — any
activity that occurred in that window is unrecorded and should
be assumed hostile until proven otherwise.
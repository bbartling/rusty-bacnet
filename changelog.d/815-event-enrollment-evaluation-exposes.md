---
section: Fixed
---
- Event Enrollment evaluation now exposes one complete report through
  `evaluate_event_enrollments_report` (#815). The unqualified report includes
  `reliability_results`, the `Reliability` diagnostic stage and the distinct
  `ObservationUnavailable` outcome. This pre-1.0 API change removes the duplicate
  detailed API and lossy projection; `evaluate_event_enrollments` remains a
  transitions-only convenience. Evaluation and notification delivery are unchanged.

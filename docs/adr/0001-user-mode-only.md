# User-mode only — zPulsar ships no kernel driver

NetLimiter-class competitors ship a kernel driver, which is what makes traffic *shaping* possible — and what makes them heavy: EV code-signing + Microsoft attestation on every release, kernel crash blast radius, installer weight. zPulsar's differentiator is monitoring quality, and Windows exposes everything monitoring needs from user mode (ETW real-time providers, WFP user-mode APIs, IP Helper). We therefore ship zero kernel-mode components, as a hard constraint.

## Consequences

- Traffic limiting/shaping is out of scope for as long as this ADR stands — it would require a WFP callout driver.
- A single portable exe is achievable; no installer or driver enrollment.
- Elevation (Administrator) is still required for full attribution.
- Visibility techniques are constrained to what user-mode surfaces offer (ICMP in particular needs care).

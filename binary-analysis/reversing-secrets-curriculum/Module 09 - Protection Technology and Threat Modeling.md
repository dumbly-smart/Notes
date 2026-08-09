# Module 9 — Protection Technology and Threat Modeling

## Purpose

Understand copyright/DRM architectures, trusted paths, encryption, watermarking, and attacker/defender economics at a conceptual level. Historical schemes are not deployment recommendations.

Protection fails when secrets or trusted decisions must ultimately exist in an attacker-controlled execution environment. Defense can raise cost, detect tampering, constrain keys, or move trust to hardware/server, but cannot make client code magically opaque.

### Authorized lab

Design a toy license check with a benign feature flag. Threat-model assets, attacker observations, offline/online trust, replay, key extraction, patch points, and false-positive costs. Improve design using signed entitlements and server-side policy, then explain remaining limits—do not attack commercial products.

### Mastery gate

- [ ] Model trust boundaries and key lifetimes.
- [ ] Compare prevention, deterrence, detection, and recovery.
- [ ] Explain why obscurity alone is not a security boundary.

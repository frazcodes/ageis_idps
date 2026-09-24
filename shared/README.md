# Aegis Shared

Cross-service contracts for Aegis IDPS. **Every** component (endpoint agent, network
sensor, backend, ML engine, response engine) imports its vocabulary from here so that
there is exactly one definition of an event, a severity, or a response action.

| Module | Purpose |
| --- | --- |
| `aegis_shared.enums` | Closed vocabularies: event types, categories, severities, response actions. |
| `aegis_shared.events` | The canonical `SecurityEvent` envelope + nested context models. |
| `aegis_shared.config` | Typed settings bases loaded from `AEGIS_*` environment variables. |
| `aegis_shared.logging` | Consistent text/JSON logging with secret redaction. |
| `aegis_shared.pipeline` | Generic in-memory event pipeline: validation, bounded buffer, counters. |
| `aegis_shared.detection` | Deterministic rule-based detection engine and findings. |
| `aegis_shared.risk` | Explainable 0-100 risk scoring with contributors. |
| `aegis_shared.version` | Schema and package version constants. |

## Why a shared package

Sensors produce events, the backend stores them, the ML engine scores them and the
response engine acts on them. If each component defined its own event shape, the system
would silently drift apart. One schema, validated at the boundary, is the cheapest way to
keep a security product coherent.

## Design rules

1. **Events are immutable facts.** `SecurityEvent` models are frozen; corrections are new
   events, never mutations.
2. **The envelope is closed, the payload is open.** Unknown *top-level* fields are
   rejected (catches schema drift early), while `raw` carries sensor-specific payloads.
3. **No secrets, no machine-specific paths** in defaults - everything comes from the
   environment.

## Install (editable, from the repository root)

```bash
pip install -e shared
```

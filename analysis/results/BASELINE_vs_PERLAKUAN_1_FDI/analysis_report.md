# Cross-Layer DFIR Analysis — PAMSIMAS ThingsBoard–Raspberry Pi–OpenPLC

**Analysis run:** `analysis-20260728T223647Z-413f51d1`  
**Operator:** `Mr. Y`  
**Generated:** `2026-07-28T22:36:47.957Z`

## Scope

This report analyses source encoding, Raspberry Pi–OpenPLC cross-layer integrity, OpenPLC control logic, valve impact, and acquisition availability.

Baseline session: `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8`
Treatment session: `C:\Users\user\Documents\PrivateProject\DFIR\evidence\PERLAKUAN_1_FDI\collector-20260728T114259Z-42bbddba`

## Operational definitions

- **Source encoding integrity:** original telemetry equals the encoded value sent by Raspberry Pi.
- **Cross-layer integrity:** Raspberry Pi sent value equals OpenPLC received value.
- **PLC logic consistency:** OpenPLC output matches the control rule for the value received by OpenPLC.
- **Controller impact:** actual valve output differs from the output expected from the legitimate Raspberry Pi source.
- **Acquisition availability:** collector read/send/pair success; this is not automatically full physical-process availability.

## Main metrics

- Baseline source encoding integrity: **100.000%**.
- Baseline cross-layer ODO integrity: **100.000%**.
- Treatment source encoding integrity: **100.000%**.
- Treatment cross-layer ODO integrity: **55.714%**.
- Observed HR1024 attack-value records (`100`): **31**.
- Network write evidence available: **YES**.

## Integrity by phase

| Scenario | Phase | Records | Source all fields | Cross ODO | Cross all fields | PLC logic | Impact records |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| BASELINE | BASELINE | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| PERLAKUAN_1_FDI | ALL | 70 | 100.000% | 55.714% | 55.714% | 100.000% | 31 |
| PERLAKUAN_1_FDI | ATTACK | 40 | 100.000% | 22.500% | 22.500% | 100.000% | 31 |
| PERLAKUAN_1_FDI | POST_RECOVERY | 16 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| PERLAKUAN_1_FDI | PRE_ATTACK | 6 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| PERLAKUAN_1_FDI | RECOVERY | 8 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |

## Availability by phase

| Scenario | Phase | Cycles | Raspi read | Sender send | OpenPLC read | Paired | Seq gaps | Seq backwards |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| BASELINE | BASELINE | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_1_FDI | ALL | 70 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_1_FDI | ATTACK | 40 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_1_FDI | POST_RECOVERY | 16 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_1_FDI | PRE_ATTACK | 6 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_1_FDI | RECOVERY | 8 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |

## Controller logic by phase

| Scenario | Phase | Valve open | Valve closed | Abnormal | Unpaid | PLC logic rate | Source-expected valve rate | Impact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| BASELINE | BASELINE | 37 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_1_FDI | ALL | 39 | 31 | 31 | 0 | 100.000% | 55.714% | 31 |
| PERLAKUAN_1_FDI | ATTACK | 9 | 31 | 31 | 0 | 100.000% | 22.500% | 31 |
| PERLAKUAN_1_FDI | POST_RECOVERY | 16 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_1_FDI | PRE_ATTACK | 6 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_1_FDI | RECOVERY | 8 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |

## Baseline vs treatment

| Metric | Baseline | Treatment | Delta | Unit |
| --- | --- | --- | --- | --- |
| Source encoding integrity - all fields | 100.0 | 100.0 | 0.0 | % |
| Cross-layer ODO integrity | 100.0 | 55.714 | -44.286 | % |
| Cross-layer all-fields integrity | 100.0 | 55.714 | -44.286 | % |
| PLC internal ODO consistency | 100.0 | 100.0 | 0.0 | % |
| PLC controller logic consistency | 100.0 | 100.0 | 0.0 | % |
| Valve output match against legitimate source | 100.0 | 55.714 | -44.286 | % |
| Raspberry Pi acquisition availability | 100.0 | 100.0 | 0.0 | % |
| OpenPLC acquisition availability | 100.0 | 100.0 | 0.0 | % |
| Paired collection rate | 100.0 | 100.0 | 0.0 | % |
| Observed controller impact records | 0 | 31 | 31.0 | records |

## Attack and recovery

Configured target: `HR1024=100`.

Network write evidence was found and used for correlation.

| Recovery metric | Value |
| --- | --- |
| Attack observations | 31 |
| First network write | 2026-07-28T11:43:07.651Z |
| First attack value observed | 2026-07-28T11:43:08.714Z |
| Last attack value observed | 2026-07-28T11:43:38.716Z |
| First normal observation | 2026-07-28T11:43:39.729Z |
| Stable recovery confirmed | 2026-07-28T11:43:41.730Z |
| Last attack observation to stable confirmation | 3.014 s |

## Findings

### F-BASELINE-01 — Baseline cross-layer integrity

**Severity:** `INFORMATIONAL`

Baseline cross-layer ODO integrity rate was 100.000%; all-fields cross-layer rate was 100.000%.

**Evidence:** `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8\raw\raspi_evidence.csv`, `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8\raw\openplc_evidence.csv`

### F-BASELINE-02 — Baseline acquisition availability

**Severity:** `INFORMATIONAL`

Raspberry Pi read availability was 100.000% and OpenPLC read availability was 100.000%.

**Evidence:** `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8\raw\raspi_evidence.csv`, `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8\raw\openplc_evidence.csv`

### F-BASELINE-03 — Baseline controller behaviour

**Severity:** `INFORMATIONAL`

OpenPLC logic consistency rate was 100.000%; valve output agreement with the legitimate source was 100.000%.

**Evidence:** `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8\raw\openplc_evidence.csv`

### F-P1-01 — ODO Meter cross-layer integrity violation

**Severity:** `HIGH`

31 record(s) showed OpenPLC ODO Meter equal to the configured attack value while the Raspberry Pi source sent a different legitimate value. Network write events were available and correlated.

**Evidence:** `attack_observations.csv`, `C:\Users\user\Documents\PrivateProject\DFIR\evidence\PERLAKUAN_1_FDI\collector-20260728T114259Z-42bbddba\raw\raspi_evidence.csv`, `C:\Users\user\Documents\PrivateProject\DFIR\evidence\PERLAKUAN_1_FDI\collector-20260728T114259Z-42bbddba\raw\openplc_evidence.csv`

### F-P1-02 — Controller impact on valve output

**Severity:** `MEDIUM`

Controller operational impact was observed in 31 record(s). This metric compares the actual valve output with the output expected from the legitimate Raspberry Pi source.

**Evidence:** `control_logic_analysis.csv`, `paired_cross_layer_analysis.csv`

### F-P1-03 — OpenPLC controller logic remained internally consistent

**Severity:** `INFORMATIONAL`

PLC logic consistency was 100.000%. A high rate means OpenPLC correctly applied its control rules to the value it received, even when that value differed from the legitimate source.

**Evidence:** `control_logic_analysis.csv`

### F-P1-04 — Acquisition availability during treatment

**Severity:** `INFORMATIONAL`

Raspberry Pi read availability was 100.000%; OpenPLC read availability was 100.000%. Availability of acquisition can remain high while process-data integrity is violated.

**Evidence:** `availability_analysis.csv`

### F-P1-05 — Stable recovery observed

**Severity:** `INFORMATIONAL`

Stable recovery was confirmed at 2026-07-28T11:43:41.730Z after 3 consecutive normal records.

**Evidence:** `recovery_analysis.csv`, `final_incident_timeline.csv`

## Significant incident timeline

| UTC | Scenario | Layer | Event | Description |
| --- | --- | --- | --- | --- |
| 2026-07-28T10:44:39.367Z | BASELINE | collector | COLLECTION_STARTED | First paired evidence record for BASELINE. |
| 2026-07-28T10:45:15.279Z | BASELINE | collector | COLLECTION_ENDED | Last paired evidence record for BASELINE. |
| 2026-07-28T11:42:59.867Z | PERLAKUAN_1_FDI | collector | COLLECTION_STARTED | First paired evidence record for PERLAKUAN_1_FDI. |
| 2026-07-28T11:42:59.867Z | PERLAKUAN_1_FDI | collector | PHASE_PRE_ATTACK | First paired record classified as phase PRE_ATTACK. |
| 2026-07-28T11:43:05.730Z | PERLAKUAN_1_FDI | collector | PHASE_ATTACK | First paired record classified as phase ATTACK. |
| 2026-07-28T11:43:07.651Z | PERLAKUAN_1_FDI | network | FIRST_CONFIGURED_MODBUS_WRITE | Modbus write to HR1024=100. |
| 2026-07-28T11:43:08.714Z | PERLAKUAN_1_FDI | openplc | FIRST_ATTACK_VALUE_OBSERVED | First cross-layer ODO mismatch with configured attack value; controller entered abnormal-usage path. |
| 2026-07-28T11:43:37.474Z | PERLAKUAN_1_FDI | network | LAST_CONFIGURED_MODBUS_WRITE | Modbus write to HR1024=100. |
| 2026-07-28T11:43:38.716Z | PERLAKUAN_1_FDI | openplc | LAST_ATTACK_VALUE_OBSERVED | Last observed configured attack value at OpenPLC. |
| 2026-07-28T11:43:39.729Z | PERLAKUAN_1_FDI | cross_layer | FIRST_NORMAL_OBSERVATION | First normal cross-layer ODO and valve observation after attack. |
| 2026-07-28T11:43:41.730Z | PERLAKUAN_1_FDI | cross_layer | STABLE_RECOVERY_CONFIRMED | Configured number of consecutive normal records reached. |
| 2026-07-28T11:43:45.744Z | PERLAKUAN_1_FDI | collector | PHASE_RECOVERY | First paired record classified as phase RECOVERY. |
| 2026-07-28T11:43:53.736Z | PERLAKUAN_1_FDI | collector | PHASE_POST_RECOVERY | First paired record classified as phase POST_RECOVERY. |
| 2026-07-28T11:44:08.739Z | PERLAKUAN_1_FDI | collector | COLLECTION_ENDED | Last paired evidence record for PERLAKUAN_1_FDI. |

## Limitations

- The current source is ThingsBoard-shaped hardcoded/mock telemetry until the STM32 and live ThingsBoard integration are completed.
- The Valve field from ThingsBoard is treated as observed field feedback; ValveCommand is the OpenPLC controller output.
- Collector polling may be faster than sender publication, so duplicate source_sequence observations are expected and are not automatically classified as replay.
- Acquisition availability does not by itself prove physical water-service availability.

## Claim boundary

The conclusions apply to the evaluated laboratory testbed, input files, register mapping, controller logic, and experiment windows. They do not constitute universal validation for every PAMSIMAS or OT deployment.


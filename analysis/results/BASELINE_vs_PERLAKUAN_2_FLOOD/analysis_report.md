# Cross-Layer DFIR Analysis — PAMSIMAS ThingsBoard–Raspberry Pi–OpenPLC

**Analysis run:** `analysis-20260728T224912Z-7cdf4854`  
**Operator:** `Mr. Y`  
**Generated:** `2026-07-28T22:49:16.313Z`

## Scope

This report analyses source encoding, Raspberry Pi–OpenPLC cross-layer integrity, OpenPLC control logic, valve impact, and acquisition availability.

Baseline session: `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8`
Treatment session: `C:\Users\user\Documents\PrivateProject\DFIR\evidence\PERLAKUAN_2_FLOOD\collector-20260728T115112Z-dc91fc98`

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
- Treatment cross-layer ODO integrity: **86.275%**.
- Observed HR1024 attack-value records (`1212`): **6**.
- Network write evidence available: **YES**.

## Integrity by phase

| Scenario | Phase | Records | Source all fields | Cross ODO | Cross all fields | PLC logic | Impact records |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| BASELINE | BASELINE | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| PERLAKUAN_2_FLOOD | ALL | 69 | 100.000% | 86.275% | 86.275% | 94.118% | 6 |
| PERLAKUAN_2_FLOOD | ATTACK | 25 | 100.000% | 57.143% | 57.143% | 100.000% | 6 |
| PERLAKUAN_2_FLOOD | POST_RECOVERY | 7 | 100.000% | N/A | N/A | N/A | 0 |
| PERLAKUAN_2_FLOOD | PRE_ATTACK | 37 | 100.000% | 97.297% | 97.297% | 91.892% | 0 |

## Availability by phase

| Scenario | Phase | Cycles | Raspi read | Sender send | OpenPLC read | Paired | Seq gaps | Seq backwards |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| BASELINE | BASELINE | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_2_FLOOD | ALL | 69 | 100.000% | 76.812% | 73.913% | 100.000% | 0 | 0 |
| PERLAKUAN_2_FLOOD | ATTACK | 25 | 100.000% | 64.000% | 56.000% | 100.000% | 0 | 0 |
| PERLAKUAN_2_FLOOD | POST_RECOVERY | 7 | 100.000% | 0.000% | 0.000% | 100.000% | 0 | 0 |
| PERLAKUAN_2_FLOOD | PRE_ATTACK | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |

## Controller logic by phase

| Scenario | Phase | Valve open | Valve closed | Abnormal | Unpaid | PLC logic rate | Source-expected valve rate | Impact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| BASELINE | BASELINE | 37 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_2_FLOOD | ALL | 45 | 6 | 6 | 0 | 94.118% | 88.235% | 6 |
| PERLAKUAN_2_FLOOD | ATTACK | 8 | 6 | 6 | 0 | 100.000% | 57.143% | 6 |
| PERLAKUAN_2_FLOOD | POST_RECOVERY | 0 | 0 | 0 | 0 | N/A | N/A | 0 |
| PERLAKUAN_2_FLOOD | PRE_ATTACK | 37 | 0 | 0 | 0 | 91.892% | 100.000% | 0 |

## Baseline vs treatment

| Metric | Baseline | Treatment | Delta | Unit |
| --- | --- | --- | --- | --- |
| Source encoding integrity - all fields | 100.0 | 100.0 | 0.0 | % |
| Cross-layer ODO integrity | 100.0 | 86.275 | -13.725 | % |
| Cross-layer all-fields integrity | 100.0 | 86.275 | -13.725 | % |
| PLC internal ODO consistency | 100.0 | 94.118 | -5.882 | % |
| PLC controller logic consistency | 100.0 | 94.118 | -5.882 | % |
| Valve output match against legitimate source | 100.0 | 88.235 | -11.765 | % |
| Raspberry Pi acquisition availability | 100.0 | 100.0 | 0.0 | % |
| OpenPLC acquisition availability | 100.0 | 73.913 | -26.087 | % |
| Paired collection rate | 100.0 | 100.0 | 0.0 | % |
| Observed controller impact records | 0 | 6 | 6.0 | records |

## Attack and recovery

Configured target: `HR1024=1212`.

Network write evidence was found and used for correlation.

| Recovery metric | Value |
| --- | --- |
| Attack observations | 6 |
| First network write | 2026-07-28T11:51:50.924Z |
| First attack value observed | 2026-07-28T11:51:52.519Z |
| Last attack value observed | 2026-07-28T11:51:57.532Z |
| First normal observation | 2026-07-28T11:51:58.523Z |
| Stable recovery confirmed | 2026-07-28T11:52:00.541Z |
| Last attack observation to stable confirmation | 3.009 s |

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

6 record(s) showed OpenPLC ODO Meter equal to the configured attack value while the Raspberry Pi source sent a different legitimate value. Network write events were available and correlated.

**Evidence:** `attack_observations.csv`, `C:\Users\user\Documents\PrivateProject\DFIR\evidence\PERLAKUAN_2_FLOOD\collector-20260728T115112Z-dc91fc98\raw\raspi_evidence.csv`, `C:\Users\user\Documents\PrivateProject\DFIR\evidence\PERLAKUAN_2_FLOOD\collector-20260728T115112Z-dc91fc98\raw\openplc_evidence.csv`

### F-P1-02 — Controller impact on valve output

**Severity:** `MEDIUM`

Controller operational impact was observed in 6 record(s). This metric compares the actual valve output with the output expected from the legitimate Raspberry Pi source.

**Evidence:** `control_logic_analysis.csv`, `paired_cross_layer_analysis.csv`

### F-P1-03 — OpenPLC controller logic remained internally consistent

**Severity:** `INFORMATIONAL`

PLC logic consistency was 94.118%. A high rate means OpenPLC correctly applied its control rules to the value it received, even when that value differed from the legitimate source.

**Evidence:** `control_logic_analysis.csv`

### F-P1-04 — Acquisition availability during treatment

**Severity:** `INFORMATIONAL`

Raspberry Pi read availability was 100.000%; OpenPLC read availability was 73.913%. Availability of acquisition can remain high while process-data integrity is violated.

**Evidence:** `availability_analysis.csv`

### F-P1-05 — Stable recovery observed

**Severity:** `INFORMATIONAL`

Stable recovery was confirmed at 2026-07-28T11:52:00.541Z after 3 consecutive normal records.

**Evidence:** `recovery_analysis.csv`, `final_incident_timeline.csv`

## Significant incident timeline

| UTC | Scenario | Layer | Event | Description |
| --- | --- | --- | --- | --- |
| 2026-07-28T10:44:39.367Z | BASELINE | collector | COLLECTION_STARTED | First paired evidence record for BASELINE. |
| 2026-07-28T10:45:15.279Z | BASELINE | collector | COLLECTION_ENDED | Last paired evidence record for BASELINE. |
| 2026-07-28T11:51:12.628Z | PERLAKUAN_2_FLOOD | collector | COLLECTION_STARTED | First paired evidence record for PERLAKUAN_2_FLOOD. |
| 2026-07-28T11:51:12.628Z | PERLAKUAN_2_FLOOD | collector | PHASE_PRE_ATTACK | First paired record classified as phase PRE_ATTACK. |
| 2026-07-28T11:51:49.554Z | PERLAKUAN_2_FLOOD | collector | PHASE_ATTACK | First paired record classified as phase ATTACK. |
| 2026-07-28T11:51:50.924Z | PERLAKUAN_2_FLOOD | network | FIRST_CONFIGURED_MODBUS_WRITE | Modbus write to HR1024=1212. |
| 2026-07-28T11:51:51.354Z | PERLAKUAN_2_FLOOD | network | LAST_CONFIGURED_MODBUS_WRITE | Modbus write to HR1024=1212. |
| 2026-07-28T11:51:52.519Z | PERLAKUAN_2_FLOOD | openplc | FIRST_ATTACK_VALUE_OBSERVED | First cross-layer ODO mismatch with configured attack value; controller entered abnormal-usage path. |
| 2026-07-28T11:51:57.532Z | PERLAKUAN_2_FLOOD | openplc | LAST_ATTACK_VALUE_OBSERVED | Last observed configured attack value at OpenPLC. |
| 2026-07-28T11:51:58.523Z | PERLAKUAN_2_FLOOD | cross_layer | FIRST_NORMAL_OBSERVATION | First normal cross-layer ODO and valve observation after attack. |
| 2026-07-28T11:52:00.541Z | PERLAKUAN_2_FLOOD | cross_layer | STABLE_RECOVERY_CONFIRMED | Configured number of consecutive normal records reached. |
| 2026-07-28T11:52:38.235Z | PERLAKUAN_2_FLOOD | collector | PHASE_POST_RECOVERY | First paired record classified as phase POST_RECOVERY. |
| 2026-07-28T11:52:56.542Z | PERLAKUAN_2_FLOOD | collector | COLLECTION_ENDED | Last paired evidence record for PERLAKUAN_2_FLOOD. |

## Limitations

- The current source is ThingsBoard-shaped hardcoded/mock telemetry until the STM32 and live ThingsBoard integration are completed.
- The Valve field from ThingsBoard is treated as observed field feedback; ValveCommand is the OpenPLC controller output.
- Collector polling may be faster than sender publication, so duplicate source_sequence observations are expected and are not automatically classified as replay.
- Acquisition availability does not by itself prove physical water-service availability.

## Claim boundary

The conclusions apply to the evaluated laboratory testbed, input files, register mapping, controller logic, and experiment windows. They do not constitute universal validation for every PAMSIMAS or OT deployment.


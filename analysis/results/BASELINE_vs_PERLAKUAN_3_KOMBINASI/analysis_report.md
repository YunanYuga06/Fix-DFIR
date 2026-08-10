# Cross-Layer DFIR Analysis — PAMSIMAS ThingsBoard–Raspberry Pi–OpenPLC

**Analysis run:** `analysis-20260728T225210Z-1489a445`  
**Operator:** `Mr. Y`  
**Generated:** `2026-07-28T22:52:12.138Z`

## Scope

This report analyses source encoding, Raspberry Pi–OpenPLC cross-layer integrity, OpenPLC control logic, valve impact, and acquisition availability.

Baseline session: `C:\Users\user\Documents\PrivateProject\DFIR\evidence\BASELINE\collector-20260728T104439Z-e2668ad8`
Treatment session: `C:\Users\user\Documents\PrivateProject\DFIR\evidence\PERLAKUAN_3_KOMBINASI\collector-20260728T130713Z-41eacbc5`

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
- Treatment cross-layer ODO integrity: **37.705%**.
- Observed HR1024 attack-value records (`1000`): **0**.
- Network write evidence available: **NO**.

## Integrity by phase

| Scenario | Phase | Records | Source all fields | Cross ODO | Cross all fields | PLC logic | Impact records |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| BASELINE | BASELINE | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | ALL | 110 | 100.000% | 37.705% | 26.230% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | ATTACK | 81 | 100.000% | 22.449% | 8.163% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | POST_RECOVERY | 11 | N/A | N/A | N/A | N/A | 0 |
| PERLAKUAN_3_KOMBINASI | PRE_ATTACK | 12 | 100.000% | 100.000% | 100.000% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | RECOVERY | 6 | 100.000% | N/A | N/A | N/A | 0 |

## Availability by phase

| Scenario | Phase | Cycles | Raspi read | Sender send | OpenPLC read | Paired | Seq gaps | Seq backwards |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| BASELINE | BASELINE | 37 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_3_KOMBINASI | ALL | 110 | 87.273% | 58.182% | 55.455% | 100.000% | 0 | 0 |
| PERLAKUAN_3_KOMBINASI | ATTACK | 81 | 100.000% | 64.198% | 60.494% | 100.000% | 0 | 0 |
| PERLAKUAN_3_KOMBINASI | POST_RECOVERY | 11 | 0.000% | 0.000% | 0.000% | 100.000% | 0 | 0 |
| PERLAKUAN_3_KOMBINASI | PRE_ATTACK | 12 | 100.000% | 100.000% | 100.000% | 100.000% | 0 | 0 |
| PERLAKUAN_3_KOMBINASI | RECOVERY | 6 | 50.000% | 0.000% | 0.000% | 100.000% | 0 | 0 |

## Controller logic by phase

| Scenario | Phase | Valve open | Valve closed | Abnormal | Unpaid | PLC logic rate | Source-expected valve rate | Impact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE | ALL | 37 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| BASELINE | BASELINE | 37 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | ALL | 61 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | ATTACK | 49 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | POST_RECOVERY | 0 | 0 | 0 | 0 | N/A | N/A | 0 |
| PERLAKUAN_3_KOMBINASI | PRE_ATTACK | 12 | 0 | 0 | 0 | 100.000% | 100.000% | 0 |
| PERLAKUAN_3_KOMBINASI | RECOVERY | 0 | 0 | 0 | 0 | N/A | N/A | 0 |

## Baseline vs treatment

| Metric | Baseline | Treatment | Delta | Unit |
| --- | --- | --- | --- | --- |
| Source encoding integrity - all fields | 100.0 | 100.0 | 0.0 | % |
| Cross-layer ODO integrity | 100.0 | 37.705 | -62.295 | % |
| Cross-layer all-fields integrity | 100.0 | 26.23 | -73.77 | % |
| PLC internal ODO consistency | 100.0 | 100.0 | 0.0 | % |
| PLC controller logic consistency | 100.0 | 100.0 | 0.0 | % |
| Valve output match against legitimate source | 100.0 | 100.0 | 0.0 | % |
| Raspberry Pi acquisition availability | 100.0 | 87.273 | -12.727 | % |
| OpenPLC acquisition availability | 100.0 | 55.455 | -44.545 | % |
| Paired collection rate | 100.0 | 100.0 | 0.0 | % |
| Observed controller impact records | 0 | 0 | 0.0 | records |

## Attack and recovery

Configured target: `HR1024=1000`.

No parsed network write evidence was found. Results identify source-to-OpenPLC mismatch and controller impact, but do not independently confirm the Modbus function code.

| Recovery metric | Value |
| --- | --- |
| Attack observations | 0 |
| First network write |  |
| First attack value observed |  |
| Last attack value observed |  |
| First normal observation |  |
| Stable recovery confirmed |  |
| Last attack observation to stable confirmation | N/A s |

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

### F-P1-02 — Controller impact on valve output

**Severity:** `INFORMATIONAL`

Controller operational impact was observed in 0 record(s). This metric compares the actual valve output with the output expected from the legitimate Raspberry Pi source.

**Evidence:** `control_logic_analysis.csv`, `paired_cross_layer_analysis.csv`

### F-P1-03 — OpenPLC controller logic remained internally consistent

**Severity:** `INFORMATIONAL`

PLC logic consistency was 100.000%. A high rate means OpenPLC correctly applied its control rules to the value it received, even when that value differed from the legitimate source.

**Evidence:** `control_logic_analysis.csv`

### F-P1-04 — Acquisition availability during treatment

**Severity:** `INFORMATIONAL`

Raspberry Pi read availability was 87.273%; OpenPLC read availability was 55.455%. Availability of acquisition can remain high while process-data integrity is violated.

**Evidence:** `availability_analysis.csv`

## Significant incident timeline

| UTC | Scenario | Layer | Event | Description |
| --- | --- | --- | --- | --- |
| 2026-07-28T10:44:39.367Z | BASELINE | collector | COLLECTION_STARTED | First paired evidence record for BASELINE. |
| 2026-07-28T10:45:15.279Z | BASELINE | collector | COLLECTION_ENDED | Last paired evidence record for BASELINE. |
| 2026-07-28T13:07:14.592Z | PERLAKUAN_3_KOMBINASI | collector | COLLECTION_STARTED | First paired evidence record for PERLAKUAN_3_KOMBINASI. |
| 2026-07-28T13:07:14.592Z | PERLAKUAN_3_KOMBINASI | collector | PHASE_PRE_ATTACK | First paired record classified as phase PRE_ATTACK. |
| 2026-07-28T13:07:26.433Z | PERLAKUAN_3_KOMBINASI | collector | PHASE_ATTACK | First paired record classified as phase ATTACK. |
| 2026-07-28T13:08:50.917Z | PERLAKUAN_3_KOMBINASI | collector | PHASE_RECOVERY | First paired record classified as phase RECOVERY. |
| 2026-07-28T13:09:03.238Z | PERLAKUAN_3_KOMBINASI | collector | PHASE_POST_RECOVERY | First paired record classified as phase POST_RECOVERY. |
| 2026-07-28T13:09:33.819Z | PERLAKUAN_3_KOMBINASI | collector | COLLECTION_ENDED | Last paired evidence record for PERLAKUAN_3_KOMBINASI. |

## Limitations

- The current source is ThingsBoard-shaped hardcoded/mock telemetry until the STM32 and live ThingsBoard integration are completed.
- The Valve field from ThingsBoard is treated as observed field feedback; ValveCommand is the OpenPLC controller output.
- Collector polling may be faster than sender publication, so duplicate source_sequence observations are expected and are not automatically classified as replay.
- Acquisition availability does not by itself prove physical water-service availability.
- No parsed Modbus write-event file was found; the analysis does not independently confirm FC06/FC16 at the network layer.

## Claim boundary

The conclusions apply to the evaluated laboratory testbed, input files, register mapping, controller logic, and experiment windows. They do not constitute universal validation for every PAMSIMAS or OT deployment.


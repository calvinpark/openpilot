# 2025 Toyota Corolla Hybrid — SecOC Key Extraction Investigation

**Complete technical record, `span` branch, 2026-07-23 → 2026-07-25**

---

## 0. About this document

### 0.1 Audience and purpose

This document is written for an AI agent picking up this investigation with no prior
context. No human is expected to read it end to end. It optimises for completeness and
retrievability over readability: every measurement taken in the vehicle is transcribed
here, including the ones that turned out to be wrong, because the in-car screenshots that
carried those measurements are **not** in git and will not survive this conversation.

The code is in git and is not reproduced here. What is reproduced here:

- every value observed in the vehicle across five in-car sessions
- the reasoning chains that were built on those values, including the ones later overturned
- every position that reversed, with the evidence that reversed it
- every defect found in the instrumentation, because several measurements are unreliable
  in ways that are only visible if you know how the tool was built
- the current ranked list of what to do next

### 0.2 Epistemic conventions used throughout

This investigation repeatedly produced confident readings that later data overturned. To
make that tractable for a reader who was not present, every claim in this document is
tagged:

| Tag | Meaning |
|---|---|
| **[OBSERVED]** | A value read off a screen or a file. Not an interpretation. If the instrument that produced it is unreliable, that is stated inline. |
| **[DERIVED]** | Arithmetic or logic applied to observed values, where the step is mechanical and checkable. |
| **[INFERRED]** | A reading of what observed values mean. Could be wrong. The competing readings are given where they exist. |
| **[REFUTED]** | A claim that was believed and is now contradicted by later data. Retained because the reasoning that produced it will otherwise be re-derived. |
| **[UNVERIFIED]** | Assumed, assumed by someone else, or carried from another source without independent checking. |

A recurring failure in this investigation was presenting **[INFERRED]** as **[OBSERVED]**.
Section 12 catalogues every instance.

### 0.3 One-paragraph summary for an agent in a hurry

A 2025 Corolla Hybrid's electric power steering ECU (part `8965F1208000`) is reachable
over CAN on panda bus 1 at UDS address `0x7A1`. It answers read services normally, hands
out a security seed at level `0x03` in the extended session, and returns proper negative
responses for 111 services it does not implement. It goes **completely silent** — no
response of any kind — for exactly four services: `0x11` ECUReset, `0x28`
CommunicationControl, `0x34` RequestDownload, and `0x85` ControlDTCSetting, plus the
programming sub-function `0x10 02`. Those four are the reprogramming-entry set. Willem's
Sienna exploit requires all of them. Two undocumented services, `0xAB` and `0xBA`, also
answer and have never been probed further. The extraction path is blocked at the
programming-session boundary and the reason for the silence is not yet determined.

---

## 1. Background

### 1.1 What TSKM is

TSK Manager (TSKM) is Calvin Park's GUI wrapper around a method, originally developed by
Willem (ex-comma), for extracting Toyota's SecOC message-authentication key from the
electric power steering ECU. comma.ai's openpilot cannot write to the CAN bus on
SecOC-equipped Toyotas without that key, because the vehicle cryptographically
authenticates steering commands. Extracting the key from the owner's own vehicle restores
openpilot compatibility.

The method works on 2021–2023 RAV4 Prime and Sienna Hybrid, and with modifications on
Yaris. It has been validated in-car many times on the Sienna, including by Calvin on his
own 2023 Sienna Hybrid.

### 1.2 The Sienna reference pipeline — what "working" looks like

This matters because every Corolla observation is a deviation from this baseline. The
working Sienna flow, as implemented in `tsk/lib/extractor.py` and
`tsk/lib/dump_dataflash.py`:

1. Connect to the panda, set safety mode `elm327`.
2. UDS on **bus 0**, request address `0x7A1`, response address `0x7A9`.
3. `DiagnosticSessionControl` DEFAULT → EXTENDED → **PROGRAMMING** → DEFAULT → EXTENDED
   (`extractor.py:154-158`), then PROGRAMMING again (`extractor.py:177`).
4. `SecurityAccess` **level 0x01** REQUEST_SEED with a 16-byte all-zero `data_record`.
5. Compute the key: `derived = AES-ECB-decrypt(SEED_KEY_SECRET, 16 zero bytes)`, then
   `response = AES-ECB-encrypt(derived, seed)`. The constant is
   `SEED_KEY_SECRET = f05f36b7d78c03e24ab4faef2a57d044` (`extractor.py:55`).
6. `SecurityAccess` **level 0x02** SEND_KEY with that response. Accepted on the Sienna.
7. `WriteDataByIdentifier` to DID `0x203` (5 zero bytes — "not sure why but needed for
   state machine", per the original comment), then DID `0x201` (16-byte key) and DID
   `0x202` (16-byte IV).
8. `RequestDownload` (service `0x34`) to RAM address `0xFEBF0000`, size `0x1000`.
9. `TransferData` (service `0x36`) in four `0x400`-byte chunks, then
   `RequestTransferExit` (service `0x37`).
10. `RoutineControl` START, routine `0x10F0`, to verify the uploaded payload.
11. Trigger the payload via an erase attempt, then collect the frames it emits.

The DataFlash variant (`dump_dataflash.py`) is the same preamble with a different payload
and dumps `0xFF200000`–`0xFF208000` (32 KB), where the SecOC key sits at offset `0x6E14`
(absolute `0xFF206E14`).

**Every step from 3 onward is unavailable on the Corolla.** Section 8 details which and why.

### 1.3 The vehicle and the collaborator

- **Vehicle:** 2025 Toyota Corolla Hybrid, owned by "Spanconstant5" (referred to as
  Spanconstant throughout), who ran every in-car test.
- **Device:** comma threeX running the `span` branch of Calvin's openpilot fork.
- **Panda firmware:** `DEV-e1b3ecb5-DEBUG` **[OBSERVED, every session]** — the
  nightly-dev DEBUG build stamp. Benign; RX demonstrably works (10,000+ frames sniffed,
  75,192 frames captured in one run).
- **EPS part number:** `8965F1208000` **[OBSERVED]**. Distinct from Sienna `8965B45…` and
  RAV4 Prime `8965B42…`. The `8965F12` family.
- **Device IP during testing:** `10.0.0.18`, web UI on port `11111`.

### 1.4 The `span` branch

`span` is a diagnostic fork of the `tskmloop` branch, created specifically for this
investigation. It differs from production TSKM in that:

- `launch_chffrplus.sh` skips `tsk/prefetch.py` (no install buttons needed).
- Production TSKM surfaces in `index.html` are CSS-hidden via a `span-hidden` class rather
  than deleted, so the polling JavaScript and reboot handlers keep binding to live nodes.
- The UI is grouped by vehicle state: **Not Ready To Drive** and **READY**.
- "Install a different fork/branch" is hidden — it deletes `/data/continue.sh` and would
  drop the device to the comma installer mid-session.

Commits on `span`, oldest to newest:

| Commit | Content |
|---|---|
| `d7f196d255` | read-only CAN sniffer diagnostic |
| `67947f12c6` | instrumented DataFlash dump diagnostic |
| `900f5880c3` | diagnostic EPS-bus sweep + skip prefetch |
| `6aca195bb5` | programming-session entry probe |
| `d6526664f2` | no-pin-swap diagnostic probes + NRtD/READY UI |
| `10fc6bb374` | isolate the 0x03 seed + send-key test at 0x03/0x04 |
| `ced38e5498` | sendkey_probe — do not label unknown NRC as invalid_key |
| `8efbcfb867` | pre-programming preamble probe |
| `b9db236acc` | exhaustive UDS sweep + READY full-payload capture |

---

## 2. UDS reference for this document

Provided so the reader does not need the ISO 14229 spec open.

### 2.1 Request/response structure

A UDS request is a service identifier (SID) byte followed by service-specific data. A
positive response echoes `SID + 0x40` followed by data. A negative response is always
three bytes: `0x7F`, the original SID, and a negative response code (NRC).

This means **the byte range `0x40`–`0x7F` and `0xC0`–`0xFF` are response identifiers, not
request identifiers.** Nothing should ever answer a request whose first byte falls in
those ranges. This fact is what makes the 07-25 sweep results interpretable — see §9.4.

The real request space is `0x00`–`0x3F` and `0x80`–`0xBF`, 128 values.

### 2.2 NRCs encountered in this investigation

| NRC | Name | Meaning in context |
|---|---|---|
| `0x11` | serviceNotSupported | "I do not have this service." A real answer. |
| `0x12` | subFunctionNotSupported | The service exists, that sub-function does not. |
| `0x13` | incorrectMessageLengthOrInvalidFormat | The service exists, the request was malformed. |
| `0x22` | conditionsNotCorrect | Vehicle/ECU state prevents it. |
| `0x24` | requestSequenceError | Out of order. |
| `0x31` | requestOutOfRange | Parameter (address, DID, routine ID) is not valid. |
| `0x33` | securityAccessDenied | Needs security unlock. **Never once seen on this EPS.** |
| `0x35` | invalidKey | Wrong SecurityAccess key. Counted attempt. |
| `0x36` | exceededNumberOfAttempts | Lockout. |
| `0x37` | requiredTimeDelayNotExpired | Lockout delay active. |
| `0x78` | responsePending | "Working on it" — extends the client's wait. |
| `0x7E` | subFunctionNotSupportedInActiveSession | Sub-function exists, wrong session. |
| `0x7F` | serviceNotSupportedInActiveSession | Service exists, wrong session. |

The `0x7E`/`0x7F` distinction is used repeatedly as a session-state probe in this
investigation: a `0x27` request answered `0x7E` means the ECU is in EXTENDED (SecurityAccess
as a service is allowed, that level is not), while `0x7F` means it is in DEFAULT
(SecurityAccess as a service is not allowed at all).

### 2.3 SecurityAccess semantics

Service `0x27`. Odd sub-functions are requestSeed, the next even sub-function is sendKey
for the same level. `0x01`/`0x02` are one level pair with one secret; `0x03`/`0x04` are a
**different** level pair with a **different** secret. This distinction is the single most
consequential thing in this investigation — see §7.

The seed is a non-secret challenge nonce. It regenerates and is safe to publish. The
**key** is `f(seed)` for a secret `f` held by both the ECU and the manufacturer's tool.
The SecOC key is not the security key: it is data in flash that passing security lets you
read.

---

## 3. Chronology of in-car sessions

| # | Date/time | Mode | Tools run | Section |
|---|---|---|---|---|
| 1 | 2026-07-23 | NRtD + READY | can-sniff, dataflash-diag, prog-probe | §4 |
| 2 | 2026-07-24 ~10:18–10:22 | NRtD | prog-probe (extended), read-mem, ident-map, reset-probe | §5 |
| 3 | 2026-07-24 15:13–15:16 | NRtD | level3-probe, sendkey-probe, prog-probe, read-mem, ident-map, reset-probe, dataflash-diag, can-sniff | §6 |
| 4 | 2026-07-24 17:33 | NRtD | preamble-probe | §8 |
| 5 | 2026-07-25 ~10:15 + ~10:23 | NRtD ×several, "READY" | uds-sweep ×several, ready-capture | §9 |

Session 4 was preceded by a purely analytical session on the evening of 07-24 that
overturned the reading of session 3 without any new data — §7.

---

## 4. Session 1 — 2026-07-23 (bus topology, EPS identity, the programming wall)

### 4.1 What was built for it

Three read-mostly tools, all sharing a `panda_lock`, an off-device mock, and an
**EPS bus sweep** (`CANDIDATE_BUSES = [0, 1, 2]`; send a DEFAULT session request on each,
run everything on the first bus that answers). The bus sweep exists because production
TSKM hardcodes bus 0 and the Corolla does not answer there.

- `sniff_can.py` + `/api/can-sniff` — per-bus frame count and distinct arbitration IDs,
  plus SecOC markers (sync `0x0F`, protected `0x2E4`/`0x131`/`0x344`). Records **no
  payloads** — this limitation becomes important in §9.7.
- `dump_diag.py` + `/api/dataflash-diag` — instrumented dump: bus sweep, identity DIDs,
  then session/security/upload/collect with per-step NRC and a full traceback.
- `prog_probe.py` + `/api/prog-probe` — five PROGRAMMING-entry sequences, each reset to
  DEFAULT first, recording accepted/NRC/timeout.

### 4.2 Bus topology **[OBSERVED]**

- **Bus 0 and bus 2 are identical** — same 22 arbitration IDs, powertrain traffic. They
  are harness-bridged. **[INFERRED, high confidence]**
- **The EPS and SecOC ride bus 1.**
- In READY, bus 1 carried **147 distinct arbitration IDs** and the SecOC sync ID `0x0F`
  was present.
- In the quieter (Not Ready) state, bus 1 collapsed to roughly 27 IDs with no sync.
- **The Sienna's protected IDs `0x2E4`, `0x131`, `0x344` are absent on every bus.** The
  Corolla signs different, still-unidentified message IDs.

The sync ID `0x0F` is the same as the Sienna. SecOC signing only happens in READY, also
the same as the Sienna.

### 4.3 EPS identity **[OBSERVED]**

Read on bus 1 via `ReadDataByIdentifier` (`0x22`):

| DID | Name | Value |
|---|---|---|
| `0xF181` | app_sw_id | `8965F1208000` |
| `0xF18C` | ecu_serial | `8965012N50E12H030731` |
| all others tried | — | NRC `0x31` requestOutOfRange |

A fuller read in session 3 showed `0xF181` carries **two** strings — see §6.6.

### 4.4 The programming wall **[OBSERVED]**

On bus 1:

- `DiagnosticSessionControl` DEFAULT → **accepted**
- `DiagnosticSessionControl` EXTENDED → **accepted**
- `DiagnosticSessionControl` PROGRAMMING → **timed out, no response**, across all five
  entry sequences (patient 3 s, double-with-1 s-settle, direct-from-default,
  tester-present-then-programming, security-first-last)
- `SecurityAccess` REQUEST_SEED (level `0x01`) in EXTENDED → **NRC `0x7E`**

### 4.5 Reading taken at the time **[INFERRED, later REFUTED]**

The asymmetry — the EPS *responds* to security with an NRC but is *silent* on programming
— was read as ruling out "EPS asleep" or "wrong bus", leaving two candidate explanations:

1. PROGRAMMING triggers a bootloader jump whose response reroutes to a different bus
   (yc's hypothesis), or
2. a gateway drops it.

And, because level `0x01` security returned `0x7E` (wrong session), security was read as
**gated behind PROGRAMMING** — circular, since Willem runs security *inside* the
programming session.

Both the reroute reading and the circularity reading were later overturned. See §5.5 and §7.

### 4.6 Facts settled in session 1

- **Serial ≠ key.** No cryptographic link. The SecOC key is re-keyable; the serial is
  fixed.
- **Extraction adapts the bus in software.** No physical repin is needed to *reach* the
  EPS. Driving the car with openpilot is a separate downstream problem requiring either a
  repin or a fork bus-patch, because a production fork has fixed, safety-critical bus
  assignments.
- **NRtD is the right mode for programming attempts** (reflash is safety-gated; a live EPS
  will not grant it). **READY is the right mode for oracle capture** (SecOC signs there).

---

## 5. Session 2 — 2026-07-24 morning (~10:18–10:22)

### 5.1 What was built for it

Commit `d6526664f2`, twelve files:

- `read_mem.py` + `/api/read-mem` — `ReadMemoryByAddress` (`0x23`) at the Sienna key region
  and two controls, in both extended and default sessions.
- `ident_map.py` + `/api/ident-map` — full identity block `0xF180`–`0xF195` plus VIN, and a
  read-only service-surface map restricted to `0x10`/`0x22`/`0x23`/`0x27`/`0x3E`/`0x19`.
  **This restriction is the origin of a methodological error that persisted for two days
  — see §12.2.**
- `reset_probe.py` + `/api/reset-probe` — hard reset, then hammer PROGRAMMING through the
  reboot window, then read `0xF186`.
- `prog_probe.py` extended with: did-it-take (read `0xF186` before and after a silent
  PROGRAMMING), all-bus-listen (PROGRAMMING physical + functional `0x7DF`, then raw
  `can_recv` on every bus looking for `0x7A9`), a security-level sweep (REQUEST_SEED
  `0x01`–`0x0B`, no key sent), and safety-system session `0x04`.
- `sniff_can.py` extended with per-bus max DLC and FD-bus detection.

### 5.2 The security-level sweep — the session's headline **[OBSERVED]**

| Level | Result |
|---|---|
| `0x01` | NRC `0x7E` — exists, wrong session. This is Willem's Sienna level. |
| `0x03` | **seed `da2df2eff64d95f5426bf3af70bb49aa`** |
| `0x05` | NRC `0x12` — does not exist |
| `0x07` | NRC `0x12` |
| `0x09` | NRC `0x12` |
| `0x0B` | NRC `0x12` |

A seed came back at level `0x03` **in the extended session, with no programming session**.

### 5.3 ReadMemoryByAddress **[OBSERVED]**

| Address | Extended | Default |
|---|---|---|
| `0xFF206E14` (Sienna key region) | NRC `0x31` requestOutOfRange | NRC `0x7F` |
| `0xFF200000` (DataFlash base) | NRC `0x31` | NRC `0x7F` |
| `0xFEBF0000` (RAM window) | NRC `0x31` | NRC `0x7F` |

**`0x23` is supported and is not security-refused.** It returns *request-out-of-range*
(`0x31`), never *security-denied* (`0x33`). The Corolla's key lives at a different address,
or the readable window differs. This result never changed across any later session.

### 5.4 CAN-FD **[OBSERVED]**

All three buses are CAN-FD. Bus 0 and bus 2 carry 64-byte frames; bus 1 carries 32-byte
frames. Classic-CAN ISO-TP still answers session control, identity and security-seed
requests on bus 1, so FD framing is not blocking those.

### 5.5 Programming: refused, not rerouted **[OBSERVED, overturns §4.5]**

- **did-it-take:** `0xF186` ActiveDiagnosticSession read `0x03` **before and after** the
  silent PROGRAMMING request. The session did not change.
- **all-bus-listen:** no `0x7A9` response frame appeared on any real bus. The "bus 129"
  entries were `0x80 | 1` — the panda's echo of our own two transmissions (`0x7A1` and
  `0x7DF`), not a reroute.

So on the software path the EPS **refuses** programming rather than rerouting off-bus.
This weakened the pin-swap theory: a repin cannot fix a refusal.

### 5.6 Reading taken at the time **[INFERRED, later REFUTED]**

Because level `0x03` hands out a seed with no programming session, the circular gate from
§4.5 was declared broken, and the blocker was reframed:

> "The blocker moves from *how to enter programming* to *what is the 0x03 seed→key formula*."

**This reframing was wrong.** See §7.

### 5.7 Operational note **[OBSERVED]**

The EPS was reachable at 10:20–10:21 (read-mem, ident-map, prog-probe all worked on bus 1)
and unreachable at 10:22 (dataflash-diag and reset-probe both reported "no response on
0/1/2"). It drops out of its diagnostic-responsive state after a burst of probing. The
10:22 screens are inconclusive from state rather than content.

No security key had been sent at this point, so no lockout was possible.

---

## 6. Session 3 — 2026-07-24 afternoon (15:13–15:16)

### 6.1 What was built for it

Commits `10fc6bb374` and `ced38e5498`:

- `level3_probe.py` + `/api/level3-probe` — isolates whether the `0x03` seed is real or a
  side effect of prior traffic. Requests seed `0x03` as the **first** security operation
  from a fresh connect, then adds one primer at a time (a prior `0x01` request, a prior
  PROGRAMMING poke), recording every session transition so a swallowed DEFAULT reset
  cannot hide. Seed-only, no key sent.
- `sendkey_probe.py` + `/api/sendkey-probe` — request seed `0x03`, compute Willem's key,
  send at `0x04`. One shot. Tap-to-run with a lockout warning, not auto-run.

`ced38e5498` was a correctness fix: the original code mapped *every* non-`0x35` NRC to
status `invalid_key`, whose message asserts a different secret and points at an expensive
firmware dump. A `0x22` or `0x24` handshake error would have been misread that way. The
fix reserves the "different secret" claim for NRC `0x35` alone.

### 6.2 The send-key result **[OBSERVED]**

| Field | Value |
|---|---|
| Seed (level `0x03`) | `87734f83613e87a68ecccba880e3f122` |
| Key computed (Willem math) | `36c20b4723967a953d1cb888625fa0eb` |
| Sent at level | `0x04` |
| Response | **NRC `0x35` invalidKey** |

One attempt. No lockout (`0x35`, not `0x36`/`0x37`).

### 6.3 Level `0x03` isolation **[OBSERVED]**

| Test | Steps | Result |
|---|---|---|
| clean extended, `0x03` first | default accepted → extended accepted → seed `0x03` → seed `0x03` again | `d976cb541b8423555a263f8c913eef64`, then **the same value again** |
| default session only | default accepted → seed `0x03` | NRC `0x7F` |
| `0x01` first, then `0x03` | default → extended → seed `0x01` (NRC `0x7E`) → seed `0x03` | `63fabc805eb9c3a919808b8468b19503` |
| programming poke, then `0x03` | default → extended → send `10 02` (ignored) → seed `0x03` | `be839062642f1f617abc28237eb4ed33` |

**The `0x03` seed is the EPS's own input/output, not an artefact of prior traffic.** It is
available from a completely clean session, and it requires EXTENDED (default gives `0x7F`).

### 6.4 Nonce behaviour **[OBSERVED]**

Within one diagnostic session the seed is **stable** — `d976…` was returned twice in a row.
Across sessions it **regenerates**. Five distinct values were observed on 07-24 alone:

```
da2df2eff64d95f5426bf3af70bb49aa   (session 2, ~10:20)
d976cb541b8423555a263f8c913eef64   (session 3, level3 clean test)
63fabc805eb9c3a919808b8468b19503   (session 3, level3 0x01-first)
be839062642f1f617abc28237eb4ed33   (session 3, level3 programming-poke)
87734f83613e87a68ecccba880e3f122   (session 3, sendkey)
0438cd94bc7221c63c070554a2a7658e   (session 3, prog-probe)
```

Plus, from session 4 on 07-24 evening:

```
ce7b6b2c79b21c01e9361fd4e390bcfc   (session 4, preamble lock read)
```

A per-session nonce — standard anti-grinding. Not per-request, not static. This is why a
memorised seed→key answer cannot be replayed.

**Known message defect:** `level3_probe.py`'s summary prints "seeds differ each request",
driven by the cross-test set containing more than one value, while the in-session data
shows the same seed twice. The accurate phrasing is "differ each session, stable within a
session." One-line `note` change, not made.

### 6.5 Everything else in session 3 **[OBSERVED]**

- **prog-probe** reproduced the morning: `0x03` → seed `0438cd94bc7221c63c070554a2a7658e`;
  `0x01` → `0x7E`; `0x05`/`0x07`/`0x09`/`0x0B` → `0x12`; did-it-take before/after both
  `0x03`; all-bus-listen no `0x7A9` (bus 0/2 = 22 IDs, bus 1 = 2, bus 129 = TX echo);
  safety-system session `0x04` → NRC `0x12`.
- **`0x23` unchanged** — all three addresses NRC `0x31` in extended, `0x7F` in default.
- **reset-probe reached the EPS this run** (it had been unreachable at 10:22). The
  `ecu_reset` response timed out, but a subsequent read showed session `0x01` (default),
  consistent with the EPS having rebooted. **PROGRAMMING still timed out through the reset
  window** — so programming refusal is not a warm-up or state artefact; it is refused even
  immediately after a reset.
- **dump_diag** hit the same wall: session PROGRAMMING → `MessageTimeoutError`, traceback
  `dump_diag.py:190` → `uds.py:680` (`diagnostic_session_control`) → `uds.py:493` (`recv`),
  0 frames collected.

### 6.6 Identity, fuller **[OBSERVED]**

`0xF181` app_sw_id carries **two** strings: `8965F1208000` plus a second `8A31…`
(calibration or software identifier), captured on both ident-map and dump_diag. In session
4 the second string read more completely as `8A3111213000`.

`0xF18C` ecu_serial: `8965012N50E12H030731`. Active session at connect: `0x03` in session
3, `0x01` in session 4.

### 6.7 CAN sniff, 8 seconds **[OBSERVED]**

Bus 0 and bus 2: 22 IDs each, CAN-FD, 64-byte frames, identical (harness-bridged).
Bus 1: quiet — **2 arbitration IDs, `0x45A` and `0x4E0`**, no sync `0x0F`. This is NRtD;
the EPS is not signing.

### 6.8 Reading taken at the time **[INFERRED, REFUTED that same evening]**

> "The Sienna secret+transform does not transfer. The `0x03` seed→key formula is genuinely
> unknown and is NOT the Sienna's. Short of the formula being published, the bench
> `8965F1208000` firmware dump is the remaining route."

Wrong on both counts. §7 explains the first; §8 and §9 explain the second.

---

## 7. The level-mismatch correction (2026-07-24 evening, no new data)

This section exists because it is the single most important reasoning error in the
investigation and it was caught by re-reading data already in hand, not by new
measurement.

### 7.1 The error

Willem's Sienna path uses SecurityAccess **level `0x01`/`0x02`**. This is verifiable in
three files: `extractor.py:184,195`, `dump_dataflash.py:180,183`, and
`dump_diag.py:201,216` all call `ACCESS_TYPE.REQUEST_SEED` and `ACCESS_TYPE.SEND_KEY`,
which are defined as `1` and `2` in `opendbc/car/uds.py:56-57`.

`sendkey_probe.py:32-33` sets `SEED_LEVEL = 0x03` and `KEY_LEVEL = 0x04`, and
`sendkey_probe.py:154-164` derives a key from `TSKExtractor.SEED_KEY_SECRET` — the
**level-0x01** secret — and sends it at **level `0x04`**.

Each UDS level pair carries its own secret. Sending a level-1 secret's derived key against
a level-3 challenge produces NRC `0x35` **by construction**, whether or not the Corolla
shares the Sienna's level-1 secret.

### 7.2 What the 0x35 actually establishes **[DERIVED]**

Only that the Corolla's **level-`0x03`** secret is not the Sienna's **level-`0x01`**
secret. That was never in question and is not informative.

**Willem's secret remains untested at the level it belongs to.** The Corolla's level `0x01`
demonstrably exists — it returns NRC `0x7E` (sub-function not supported *in the active
session*), whereas levels `0x05`/`0x07`/`0x09`/`0x0B` return NRC `0x12` (sub-function not
supported at all). `0x7E` means "this level exists, you are in the wrong session."

### 7.3 What this does to the plan

- **The blocker never moved off PROGRAMMING.** The session-2 reframing was premature.
- **Level `0x03` is probably a lesser privilege.** A security level handed out in the
  extended session, with no programming session, is not typically the level that gates
  flash access. On Toyota/Denso ECUs, extended-session security more commonly gates
  calibration writes, variant coding, or actuator tests. Recovering `f()` for level `0x03`
  could therefore open a service surface that does not include the key at all.
  **[INFERRED — this is a generalisation about ECU design conventions, not a measurement.]**
- **The RE target for any future firmware dump is specifically the `0x01`/`0x02` routine**,
  the function Willem's secret feeds — not "the seed→key crypto" generally.

### 7.4 The counter-argument, retained **[UNVERIFIED]**

If Toyota reuses one secret across all levels on an ECU, the `0x35` *would* mean the
secret differs. Nothing observed rules this in or out. So the `0x35` is *consistent with*
"different secret", not evidence for it.

### 7.5 Related correction: the ICU-S

An earlier note recorded that "the rekey path sits in the ICU-S, not the EPS — a different
ECU's security." That phrasing is wrong. The ICU-S is the Renesas RH850's **on-die**
security block, on the same silicon as the main core. The accurate statement is that the
rekey path sits in the EPS MCU's own ICU-S rather than in the main core, which is why a
main-core read or patch cannot reach it. **[UNVERIFIED — carried from a second Code
instance's thread; the underlying analysis was not independently checked here.]**

### 7.6 A second thread's finding, carried unverified **[UNVERIFIED]**

A parallel analysis reported that on the PRC Sienna the SecurityAccess/session-auth crypto
is **software**, main-core-visible — specifically an `f068` KDF plus software AES S-boxes
and CMAC — and that only the SecOC *frame* key is ICU-S-sealed. If true, a bench dump of
an `8965F12` would likely contain a software seed→key routine matchable against a Sienna
template, which materially improves the odds of the hardware path. The `f068` artefact was
never seen in this investigation and is recorded as another thread's result.

---

## 8. Session 4 — 2026-07-24, 17:33 (the preamble probe)

### 8.1 Hypothesis under test

Every prior probe entered PROGRAMMING cold. OEM reflash tools never do: they quiesce the
bus first with `ControlDTCSetting` OFF (`0x85`) and `CommunicationControl`
disable-normal-tx (`0x28`), and many ECUs refuse or ignore a programming request while
normal messaging is live. `prog_probe.py`'s five sequences never sent either service, so
the preamble family was untested.

### 8.2 What was built — commit `8efbcfb867`

`preamble_probe.py` + `/api/preamble-probe`, one run, ordered so a mid-run drop-out still
leaves the valuable data:

- **Block A** — bus sweep, identity, active session.
- **Block B** — lock read: a bare `0x03` REQUEST_SEED as the **first** security operation.
  Nothing had ever measured whether the 15:16 send-key left a persistent lock.
  Plus the `0x01` baseline.
- **Block C** — Willem's exploit surface by refusal code only: DIDs `0x201`/`0x202`/`0x203`,
  `RoutineControl` REQUEST_RESULTS on `0x10F0`, `RequestDownload` to RAM, and whether
  `0x85`/`0x28` are accepted at all. Then a DTC snapshot.
- **Block D** — five preamble variants.
- **Block E** — DTC snapshot again, diffed.
- **Block F** — `0x23` retried at three addresses, then a liveness read.

The UI was reduced from eight buttons to one at Calvin's instruction, because each in-car
session costs real effort and the previous layout required six separate runs and many
screenshots.

### 8.3 Results — Block A and B **[OBSERVED]**

```
Panda: DEV-e1b3ecb5-DEBUG
EPS bus: 1

Identity
  app_sw_id:   .8965F1208000....8A3111213000....
  ecu_serial:  8965012N50E12H030731
  active_session: 0x01

Lock read (is security locked from the last send-key?)
  extended: accepted
  seed 0x03: seed ce7b6b2c79b21c01e9361fd4e390bcfc
  seed 0x01 baseline: NRC 0x7e sub-function not supported in active session
```

**No persistent lock.** The 15:16 send-key left nothing behind. The attempt budget is not
visibly spent, and no lockout state survived a day and multiple power cycles. This closes
a question that had been open and unmeasured since the `0x35`.

### 8.4 Results — Block C, the exploit surface **[OBSERVED]**

```
Exploit surface (refusal codes only, nothing written)
  extended: accepted
  read DID 0x201 (did_201_key):    NRC 0x31 request out of range
  read DID 0x202 (did_202_iv):     NRC 0x31 request out of range
  read DID 0x203 (did_203_state):  NRC 0x31 request out of range
  routine results 0x10f0:          NRC 0x31 request out of range
  request download (RAM):          MessageTimeoutError: timeout waiting for response
  0x85 DTC setting OFF:            MessageTimeoutError: timeout waiting for response
  0x28 comm control disable-tx:    MessageTimeoutError: timeout waiting for response
  DTC snapshot (before): 0 codes
```

Two things here matter a great deal.

**First: Willem's upload path does not exist on this EPS.** `RoutineControl` is a service
that demonstrably answers, and it returned NRC `0x31` — *requestOutOfRange* — for routine
`0x10F0`. That means the routine identifier is not recognised, not that the service is
gated. Likewise DIDs `0x201`/`0x202`/`0x203` return `0x31`. Even if PROGRAMMING opened
tomorrow, Willem's sequence would not run unmodified on this vehicle.

**Second: the wall is wider than PROGRAMMING.** `0x85`, `0x28` and `0x34` all time out —
total silence — while `0x22`, `0x23`, `0x27`, `0x31` and `0x19` all answer, with data or a
precise NRC. This EPS says "no" freely and specifically. Silence across a coherent class
of services is a different phenomenon from refusal, and that observation is what motivated
the exhaustive sweep in session 5.

### 8.5 Results — Block D, the five variants **[OBSERVED]**

All five refused. Full transcript:

```
0x85 -> programming  → refused
  extended: accepted
  0x85 DTC off: MessageTimeoutError: timeout waiting for response
  programming: MessageTimeoutError: timeout waiting for response
  session after: 0x01
  seed 0x01 after: NRC 0x7f service not supported in active session

0x85 + 0x28 -> programming  → refused
  extended: accepted
  0x85 DTC off: MessageTimeoutError
  0x28 disable tx: MessageTimeoutError
  programming: MessageTimeoutError
  session after: 0x01
  seed 0x01 after: NRC 0x7f

0x85 + 0x28 -> programming (6s)  → refused
  extended: accepted
  0x85 DTC off: MessageTimeoutError
  0x28 disable tx: MessageTimeoutError
  programming: MessageTimeoutError
  session after: 0x01
  seed 0x01 after: NRC 0x7f

0x85 + 0x28 -> 10 82 suppressed  → refused
  extended: accepted
  0x85 DTC off: MessageTimeoutError
  0x28 disable tx: MessageTimeoutError
  raw 10 82 (suppressPosRsp): sent, no response expected
  programming: sent (suppressed) — see session read
  session after: NRC 0x7e sub-function not supported in active session
  seed 0x01 after: NRC 0x7f

functional 0x28 -> programming  → refused
  extended: accepted
  0x85 DTC off: MessageTimeoutError
  functional 0x28 -> 0x7df: sent
  programming: MessageTimeoutError
  session after: 0x01
  seed 0x01 after: NRC 0x7f
```

### 8.6 Two defects in this probe, both instrumentation errors **[DERIVED]**

**Defect 1 — the preamble was never delivered.** `0x85` and `0x28` are themselves in the
silent class. Neither request ever reached the EPS's application layer. The hypothesis was
therefore **untested, not refuted**. Any future attempt to quiesce the bus before
programming must first solve the problem of getting `0x85`/`0x28` accepted at all.

**Defect 2 — stacked timeouts blew the session-timeout window.** Each failed request cost
3 seconds. In variants 2, 3 and 5, PROGRAMMING was sent 6+ seconds after the EXTENDED
request with no tester-present keepalive, and the ISO 14229 S3 session timer is typically
5 seconds. Those variants therefore sent PROGRAMMING from a **lapsed session**, i.e. from
DEFAULT.

The run's own data proves this without needing the spec: the fresh-extended baseline in
Block B answered `seed 0x01: NRC 0x7E` (SecurityAccess allowed as a service, wrong level
for this session — the EXTENDED answer), while **every** post-variant retry answered
`NRC 0x7F` (SecurityAccess not allowed as a service at all — the DEFAULT answer). The
session had lapsed by the time the retry ran.

Variant 1 was inside the S3 window and is valid, but with `0x85` dropped it reduces to
`prog_probe`'s already-run patient test.

### 8.7 One unresolved lead **[INFERRED]**

The suppressPosRsp variant reported `session after: NRC 0x7e`. A `ReadDataByIdentifier`
(`0x22`) request has no sub-function and cannot legitimately produce `0x7E`. The most
plausible explanation is that a late `7F 10 7E` — a negative response to the raw `10 82`
programming request — arrived after the client had moved on and was picked up as the
answer to the following `0x22` request.

If that reading is right, it is **the only non-silent response to a programming request
ever observed on this vehicle**, and it says *sub-function not supported in the active
session* — a session precondition, not a missing service. This has never been retested
cleanly. A dedicated probe would send `10 82` on one client and watch the raw bus for a
`0x7A9` frame rather than issuing a follow-up request.

### 8.8 Results — Blocks E and F **[OBSERVED]**

```
DTC diff
  before: 0 codes
  after:  0 codes
  no new codes

Read memory retry
  key region 0xff206e14:    NRC 0x31 request out of range
  dataflash base 0xff200000: NRC 0x31 request out of range
  ram window 0xfebf0000:    NRC 0x31 request out of range

EPS still answering at end of run
```

The empty DTC diff was designed as a discriminator: an application-layer refusal often
leaves a trace, while an empty log alongside bus silence points at a lower-layer drop. The
signal is weak here because the vehicle has **zero stored codes at all**, so there is no
evidence the EPS logs anything in this category either way.

The liveness line matters: the EPS was answering at the end, so every result in this run
is attributable to content rather than to a drop-out.

### 8.9 A defect Calvin found in this probe afterwards **[OBSERVED, in code]**

Variant 5 sends `CommunicationControl` **functionally** to `0x7DF`, which silences normal
transmission **bus-wide**, but the `finally` block re-enables only the EPS via a physical
request (`preamble_probe.py:462`). Any other bus-1 ECU that honoured the functional request
stays TX-disabled until a power cycle. Low impact in practice — the workflow is NRtD with
power cycles between runs, which self-heals it — but a functional `ENABLE_RX_ENABLE_TX` to
`0x7DF` in the `finally` would match the action to its undo.

---

## 9. Session 5 — 2026-07-25 (the exhaustive sweep)

### 9.1 The methodological correction that produced it

This is recorded because it is the reason the session found anything. Calvin pushed back
three times on scope:

1. After the preamble probe: *"Build as much as you can into it."* — answered with a probe
   scoped to one hypothesis plus nine services chosen because they served that hypothesis.
2. *"How do we map the entire boundary? I told you to test everything but it's evident you
   didn't test everything."* — answered with a curated 17-row table of ISO 14229 services.
3. *"Why not probe everything from 0 to ff?"* — agreed, then immediately re-narrowed with
   three layers of scoping and a risk question handed back.
4. *"I don't know how many times I need to ask you to test everything. You continuously
   refuse it. How do I make you test actually everything?"*

The mechanisms behind the repeated narrowing, as diagnosed at the time:

- **Safety was being treated as a filter rather than a parameter.** The question asked was
  "should I send this" rather than "how do I send this safely", which converts an
  engineering problem into a silent exclusion. The unlocking insight: **asking about a
  dangerous service is not dangerous.** An ECU decides whether to respond before it decides
  whether to act, so a deliberately-invalid request — a bare service byte, a nonexistent
  DID, an out-of-range address — maps the boundary at no risk.
- **The root cause was an unexamined UI assumption.** Every probe had been designed to fit
  a one-tap, sixty-second web page. Once a probe must finish in a minute, curation is not a
  choice, it is forced — and then rationalised as "the meaningful ones." Dropping that
  constraint dissolves the problem: full coverage is not hard, it is long, and length is a
  scheduling problem solved by a resumable background job.

The resulting standing rule, now recorded in `CLAUDE.md`:

> **"Test everything" means the full value space.** Everything is the complete enumeration
> — every service `0x00`–`0xFF`, every sub-function `0x00`–`0xFF`, every DID
> `0x0000`–`0xFFFF` — not the subset that is standard, documented, meaningful, or safe.
> Safety constrains *how* a value is sent, never *whether* it is sent. Runtime is a
> scheduling problem: if full coverage takes hours, build a resumable background job, not a
> shorter list. Any value not sent must appear in the output as an explicit reasoned
> omission. A shorter list is never the silent answer.

The last sentence is the enforcement mechanism: a future curation shows up in the artefact
as a printed skip-list with reasons rather than as a list that is quietly shorter than the
address space.

### 9.2 What was built — commit `b9db236acc`

`sweep_uds.py` + `/api/uds-sweep` and `capture_ready.py` + `/api/ready-capture`, plus two
pages with copy-as-text boxes (the Clipboard API needs a secure context and this is plain
HTTP, so a textarea with select-all is the workable affordance).

Design points that mattered:

- **Raw ISO-TP, first-frame parse only.** Sending arbitrary service bytes through
  `UdsClient` fails, because it raises on unexpected response shapes and is slow. The sweep
  sends via `isotp_send` and parses only the first response frame — service identifier and
  NRC both live there, and skipping reassembly keeps the loop fast enough to finish inside
  the window.
- **Measured timeout, not a guessed constant.** A known-good request (`22 F1 81`) is timed
  five times at startup and the silence threshold is set to ten times the median round
  trip, clamped to [50 ms, 300 ms]. NRC `0x78` responsePending extends the wait, so a
  genuinely slow service is not misread as silent.
- **Deadline, not a skip list.** The run takes a budget, stops cleanly, and records a
  *frontier* string naming where it stopped.
- **Incremental persistence and resume.** Every result is appended to
  `/cache/tsk/uds-sweep/uds_sweep.ndjson` as it arrives. A new run loads the file, skips
  keys already answered, and continues. Short sessions compose into one full map.
- **Safety in the shape of the request.** The service-existence layer sends the **bare
  service byte**, which cannot name a valid sub-function; DEFAULT is swept before EXTENDED
  because nearly everything destructive is session-gated; each sub-function block is
  followed by a restore (DEFAULT session, `0x28` enable, `0x85` on) and a liveness check.

### 9.3 Run parameters **[OBSERVED]**

```
Panda: DEV-e1b3ecb5-DEBUG
EPS bus: 1
Response timeout: 140 ms (measured)
calibrate: round trip 14 ms → timeout 140 ms
```

A 14 ms round trip is fast and consistent with a directly-reachable ECU.

Records accumulated across runs: 2,182 → 3,508 in the screenshots seen. Stage lines from
the final observed run:

```
Stages
  calibrate: round trip 14 ms → timeout 140 ms
  services/default: 0 sent
  services/extended: 0 sent
  subfunctions/10: 0 sent
  subfunctions/14: 0 sent — EPS stopped answering after this service
  dids/identity: 122 sent
  dids/willem: 256 sent
  dids/manufacturer: 512 sent
  addresses: 13 responder(s)
  recheck: 132 sent at 1400 ms
```

`0 sent` means every key in that block was already in the file from a prior run — resume
working as designed.

### 9.4 THE SERVICE MAP — the central result **[OBSERVED]**

**Services that ANSWER (13):**

```
0x10  0x14  0x19  0x22  0x23  0x27  0x2e  0x31  0x36  0x37  0x3e  0xab  0xba
```

**Services that are SILENT (132):**

```
0x11  0x28  0x34  0x85
0x40 0x41 0x42 0x43 0x44 0x45 0x46 0x47 0x48 0x49 0x4a 0x4b 0x4c 0x4d 0x4e 0x4f
0x50 0x51 0x52 0x53 0x54 0x55 0x56 0x57 0x58 0x59 0x5a 0x5b 0x5c 0x5d 0x5e 0x5f
0x60 0x61 0x62 0x63 0x64 0x65 0x66 0x67 0x68 0x69 0x6a 0x6b 0x6c 0x6d 0x6e 0x6f
0x70 0x71 0x72 0x73 0x74 0x75 0x76 0x77 0x78 0x79 0x7a 0x7b 0x7c 0x7d 0x7e 0x7f
0xc0 0xc1 0xc2 0xc3 0xc4 0xc5 0xc6 0xc7 0xc8 0xc9 0xca 0xcb 0xcc 0xcd 0xce 0xcf
0xd0 0xd1 0xd2 0xd3 0xd4 0xd5 0xd6 0xd7 0xd8 0xd9 0xda 0xdb 0xdc 0xdd 0xde 0xdf
0xe0 0xe1 0xe2 0xe3 0xe4 0xe5 0xe6 0xe7 0xe8 0xe9 0xea 0xeb 0xec 0xed 0xee 0xef
0xf0 0xf1 0xf2 0xf3 0xf4 0xf5 0xf6 0xf7 0xf8 0xf9 0xfa 0xfb 0xfc 0xfd 0xfe 0xff
```

### 9.5 The arithmetic — a derived result that changes the interpretation **[DERIVED]**

The sweep classifies a service as *answering* if it returned a positive response or any
NRC **other than `0x11`**, and as *silent* if nothing came back. A service returning NRC
`0x11` serviceNotSupported falls into neither bucket.

```
Total service bytes swept          256
Answering                           13
Silent                             132
Therefore NRC 0x11                 111
```

Now decompose by range:

```
Response ranges 0x40–0x7F and 0xC0–0xFF     128 bytes, ALL silent
  (these are not request identifiers — nothing should ever answer them)

Request range 0x00–0x3F                      64 bytes
  answering: 0x10 0x14 0x19 0x22 0x23 0x27 0x2e 0x31 0x36 0x37 0x3e   = 11
  silent:    0x11 0x28 0x34                                            =  3
  NRC 0x11:                                                            = 50

Request range 0x80–0xBF                      64 bytes
  answering: 0xab 0xba                                                 =  2
  silent:    0x85                                                      =  1
  NRC 0x11:                                                            = 61

Check: 128 + 3 + 1 = 132 silent ✓    11 + 2 = 13 answering ✓    50 + 61 = 111 ✓
```

**This is the most important derived fact in the entire investigation:**

> The EPS returns NRC `0x11` serviceNotSupported for **111 services it does not implement**.
> Its dispatcher correctly reports unsupported services. Therefore the four silent services
> in the request ranges — `0x11`, `0x28`, `0x34`, `0x85` — are **not** merely unimplemented.
> An unimplemented service on this ECU answers `0x11`. These four are being handled
> differently: known to something in the path and deliberately not answered.

Prior to this arithmetic, "the EPS just doesn't implement them and drops instead of
NRC-ing" was a live explanation. It is now the weakest of the available readings.

**Caveat on the caveat:** the silent and answering sets are unions across the DEFAULT and
EXTENDED passes. A service that was silent in one session and answered `0x11` in the other
would appear in the silent set. The arithmetic above works perfectly for the clean
interpretation, but the raw NDJSON on the device is what settles it definitively, and it
has not been retrieved.

### 9.6 The read/write framing was wrong **[REFUTED]**

After session 4, the working model was "every read service answers, every write and
reprogramming service is silent." The full sweep refutes it:

| Service | Class | Result |
|---|---|---|
| `0x2E` WriteDataByIdentifier | write | **answers** |
| `0x14` ClearDiagnosticInformation | state change | **answers** |
| `0x36` TransferData | reprogramming | **answers** (NRC `0x7F`) |
| `0x37` RequestTransferExit | reprogramming | **answers** (NRC `0x7F`) |
| `0x34` RequestDownload | reprogramming | **silent** |
| `0x28` CommunicationControl | control | **silent** |
| `0x85` ControlDTCSetting | control | **silent** |
| `0x11` ECUReset | control | **silent** |

The silent set is not "writes" and it is not "the reflash sequence" either — two thirds of
the download sequence answers.

### 9.7 The sharpest single lead **[OBSERVED]**

`0x34` RequestDownload is silent. `0x36` TransferData and `0x37` RequestTransferExit both
answer with NRC `0x7F` — *service not supported in the active session*, meaning they exist
and need the programming session.

These three services are the same download sequence. Two of them exist and announce their
session requirement politely. The third — the one that opens the whole upload path, and
the one Willem's exploit needs first — says nothing at all.

Any theory of the silent class has to explain that split.

### 9.8 The address sweep and the cross-ECU test **[OBSERVED]**

Physical diagnostic addresses `0x700`–`0x7FF` were probed with a DEFAULT session request.
**13 responders:**

```
0x700  0x724  0x747  0x780  0x792  0x7a1  0x7b0  0x7b3  0x7c0  0x7c4  0x7d0  0x7d2  0x7f1
```

`0x7A1` is the EPS. Each of the other twelve was then sent all four silent services:

| Address | `0x10 02` programming | `0x28` comm control | `0x34` req download | `0x85` DTC setting |
|---|---|---|---|---|
| `0x700` | silent | silent | silent | silent |
| `0x724` | silent | silent | silent | silent |
| `0x747` | silent | silent | silent | silent |
| `0x780` | silent | silent | silent | silent |
| `0x792` | silent | silent | silent | silent |
| `0x7b0` | silent | silent | silent | silent |
| `0x7b3` | silent | silent | silent | silent |
| `0x7c0` | silent | silent | silent | silent |
| `0x7c4` | silent | silent | silent | silent |
| `0x7d0` | silent | silent | silent | silent |
| `0x7d2` | silent | silent | silent | silent |
| **`0x7f1`** | **nrc** | **nrc** | **nrc** | **nrc** |

Eleven modules go silent on all four. **One — `0x7F1` — returns a proper negative response
to all four.**

### 9.9 What `0x7F1` means — and a correction to how it was first read

**The claim made at the time [OVERSTATED]:**

> "A path-level filter cannot drop those service IDs for twelve destinations and pass them
> for the thirteenth on the same wire, so the drop is per-ECU behaviour and rewiring would
> not fix it."

**The problem with that claim:** it depends on all thirteen responders being on the same
physical segment as the panda, which is **unverified**. A routing gateway filters *by
destination address* — that is its entire job. A gateway implementing "no reprogramming
services to the EPS" policy, while answering diagnostics addressed to itself at `0x7F1`,
produces exactly the observed pattern.

**The two live readings, neither eliminated:**

1. **Per-ECU behaviour.** All thirteen modules sit on the panda's physical segment. No
   filtering is possible because our frames reach them directly. Eleven modules plus the
   EPS silently drop the reprogramming set; `0x7F1` is simply a module that implements it.
   Under this reading a repin changes nothing.
2. **Per-destination gateway policy.** Some or all of those addresses are reached through a
   gateway, which forwards read services and drops the reprogramming set toward protected
   destinations while answering for itself. Under this reading a repin onto the EPS's own
   segment could bypass it entirely.

**Weak evidence for reading 1:** the calibrated round trip to the EPS is 14 ms, which is
fast for a proxied path but not decisive.

**Weak evidence for reading 2:** bus 1 carried only **2 arbitration IDs** (`0x45A`, `0x4E0`)
of background traffic in Not Ready to Drive. If thirteen modules genuinely shared that
segment, more periodic traffic would be expected — though most modules are quiet in NRtD,
so this is soft.

**How to settle it, no new hardware:** capture background traffic on bus 1 in READY (147
IDs were seen there in session 1) and check whether the modules answering at those thirteen
addresses also transmit on our segment. A module that answers diagnostics but never
transmits periodic frames on our wire is being proxied. This is exactly what the READY
full-payload capture was built to enable and it has not yet produced a usable dataset.

**Also unresolved:** what `0x7F1` is. Identifying it — via `0x22 F181` / `0xF18C` reads
against that address — is cheap and has never been done. If it is the central gateway, the
whole picture changes.

### 9.10 The method's own negative control passed **[OBSERVED]**

The final sweep stage re-sent all 132 silent services at **1,400 ms** — ten times the
calibrated timeout. The silent count stayed at 132. No service classified silent was
merely slow. The silences are real at the protocol level, not an artefact of an
over-tight window.

This matters because the whole interpretation rests on distinguishing "no answer" from
"an answer we missed."

### 9.11 The READY capture — did not run in READY **[OBSERVED + INFERRED]**

```
READY capture
Panda: DEV-e1b3ecb5-DEBUG
EPS bus: 1
Frames captured: 75192 across 46 IDs

SecOC-signed candidates (changing MAC tail, stable head)
  none found — the EPS may not be signing, or the window was too short

Sync frames (0x0F)
  none seen
```

**46 IDs and zero sync frames.** In session 1, the same vehicle in READY showed **147 IDs
on bus 1 plus sync `0x0F`**. And `46 ≈ 22 + 22 + 2` — which is exactly the Not Ready to
Drive profile (bus 0 and bus 2 at 22 IDs each, bus 1 at 2 IDs).

**[INFERRED, high confidence]** The capture ran while the vehicle was not in READY. 75,192
frames over 90 seconds is 835 frames/second, a lightly loaded bus; a READY bus 1 carrying
147 IDs would produce several thousand per second.

The signed-ID capture therefore **remains completely open**. The tool for it exists and is
built correctly as far as can be told; it needs a mode guard that refuses to start until it
observes READY traffic, and a re-run.

### 9.12 The mode diff — and a wrong summary line **[OBSERVED + DEFECT]**

Services re-asked in "READY" and their results:

```
reflash set: programming session:  silent
reflash set: communication control: silent
reflash set: request download:      silent
reflash set: control DTC setting:   silent

silent in NRtD: services 0x11, 0x40–0x7f, 0xc0–0xff  →  all still silent

condition NRC in NRtD: service 0x23: nrc NRC 0x13
condition NRC in NRtD: service 0x27: nrc NRC 0x13
condition NRC in NRtD: service 0x2e: nrc NRC 0x13
condition NRC in NRtD: service 0x36: nrc NRC 0x7f
condition NRC in NRtD: service 0x37: nrc NRC 0x7f
condition NRC in NRtD: service 0xba: nrc NRC 0x11
```

**The defect:** the run's summary line read *"Mode diff: 6 of 139 answered in READY that did
not in Not Ready to Drive."* That count is the **condition-NRC bucket** — the six services
re-asked because they had returned a condition NRC in NRtD, which answered in *both* modes.
The message conflates two buckets.

**Actual silent→answering count: zero.** Nothing that was silent in Not Ready to Drive
answered in the other mode — subject to the caveat that the other mode was probably also
Not Ready to Drive (§9.11), which makes the entire mode diff uninformative.

### 9.13 An anomaly worth resolving from the raw file **[OBSERVED, unexplained]**

Service `0xBA` appears in the **answering** list (which excludes NRC `0x11`) yet its
re-test returned **NRC `0x11`**, and it was placed in the *condition NRC* bucket, which the
summariser defines as NRC ∈ {`0x22`, `0x7E`, `0x7F`}. Those three facts cannot all be true
of a single record.

The most likely explanation is that `0xBA` produced **different responses in the DEFAULT
and EXTENDED passes** — one a condition NRC, the other `0x11` — and the two records were
bucketed separately while sharing a display label. If so, `0xBA` is session-sensitive,
which makes it more interesting rather than less.

`0xAB` does not appear with an NRC anywhere in the observed screenshots. Its behaviour is
entirely unknown beyond "it answered something that was not `0x11`."

**Both services need their raw records read from the NDJSON, and their sub-functions
swept. This is the single most promising unexplored surface on the vehicle.**

### 9.14 Security seed in "READY" — an unnoticed protocol detail **[OBSERVED, significant]**

```
Security seed in READY
  level 0x01: nrc 7f277e
  level 0x03: nrc 7f2713
```

Level `0x01` → NRC `0x7E`, consistent with everything prior.

Level `0x03` → **NRC `0x13` incorrectMessageLengthOrInvalidFormat.**

This is new and it was not remarked on at the time. Every earlier probe that successfully
obtained a `0x03` seed sent `data_record = 16 zero bytes` along with the requestSeed. The
READY pass sent a bare `27 03` with no data record — and the EPS rejected it **on length**.

**[DERIVED] Level `0x03` REQUEST_SEED on this EPS requires a 16-byte client-supplied data
record.** That is not standard: requestSeed normally carries no data.

**[INFERRED] Why this could matter a great deal.** Willem's Sienna flow also sends 16 zero
bytes, and his client-side key derivation is
`derived = AES-decrypt(SECRET, data_record)` followed by `key = AES-encrypt(derived, seed)`.
The data record is not decoration — it is an input that *both* sides use. That implies a
protocol of the shape:

```
client sends:  27 <level> <16-byte data_record>
ECU returns:   67 <level> <16-byte seed>
client sends:  27 <level+1> <16-byte key>
where key = E( D(SECRET, data_record), seed )   and the ECU checks the same relation
```

If the Corolla's level `0x03` uses this structure, then **the data record is a
client-chosen input to a cryptographic function running inside the ECU**, and varying it
while observing the seed is a chosen-input oracle. Concretely, the free experiment is:

1. Does the seed change when the data record changes, within one session? If the seed is a
   pure nonce, no. If the seed is a function of the data record, yes — and that is a
   chosen-plaintext oracle against ECU-held key material.
2. Do structured data records (all-zero, all-`0xFF`, single-bit-set, incrementing) produce
   structured seed relationships?

This costs **nothing**: requestSeed sends no key and touches no attempt counter. It was on
the open list as "seed-side `data_record` variants" without this rationale attached. It now
has a concrete one, and it is the cheapest remaining experiment with real analytical upside.

### 9.15 The `0x14` retraction **[REFUTED]**

**The claim made at the time:** the sub-function sweep of `0x14` ClearDiagnosticInformation
killed the EPS, since the run reported `subfunctions/14: 0 sent — EPS stopped answering
after this service`.

**Why it is wrong:** `0 sent` means *zero requests were issued* — every `0x14` sub-function
key was already recorded from a prior run, so the block skipped all 256 and did nothing.
The EPS was already not answering when the liveness check ran. `0x14` cannot be the cause
on that run.

**And it recovered:** later in the *same* run, the address sweep received a response from
`0x7A1` — the EPS itself. It appears in the 13-responder list. So the EPS dropped out and
came back rather than dying.

This matches the drop-out behaviour observed since session 2 (reachable at 10:21,
unreachable at 10:22, reachable again in session 3).

### 9.16 Spanconstant's report: the car powers itself off **[OBSERVED, third-party]**

> "Sorry @Calvin the car turns itself off after some time in not ready mode, this may be
> very broken"

This is normal power management on a hybrid — the vehicle drops the ignition-on state after
a timeout to protect the 12 V battery. It is a **separate** phenomenon from the EPS
drop-outs, and it bounds every future run: the real budget is the car's timer, not the 12 V
discharge curve, and it is not under the operator's control.

Both produce silence on the bus. They must not be conflated when reading a transcript.

### 9.17 Safety audit — exactly what was sent to the vehicle **[DERIVED, from code order]**

Spanconstant was concerned that something may have been damaged. A precise accounting:

The sub-function sweep iterates `for sid in sorted(answered_sids)`, i.e. numerically:
`0x10, 0x14, 0x19, 0x22, 0x23, 0x27, 0x2e, 0x31, 0x36, 0x37, 0x3e, 0xab, 0xba`. It reached
`0x14` and stopped.

Therefore:

- **`0x2E` WriteDataByIdentifier never received a payload.** No write was performed. It was
  only ever sent as a bare byte, which the EPS rejected on length (`0x13`).
- **`0x27` SecurityAccess never received a payload.** No key was sent, no attempt counter
  incremented, no lockout risk incurred.
- **`0x31` RoutineControl never started a routine.** Only `REQUEST_RESULTS` on `0x10F0` in
  the earlier preamble probe, which is a read.
- **`0x36`/`0x37` never transferred anything.**
- **`0x11` ECUReset, `0x28` CommunicationControl and `0x85` ControlDTCSetting are all in the
  silent class** — they never reached the application layer, so they never took effect. No
  reset occurred, EPS transmission was never disabled, DTC logging was never turned off.

**The single plausibly-persistent change** is cleared fault codes, if any of the 256
malformed `[0x14, sub-function]` requests were accepted. `0x14` expects a 3-byte DTC group
mask, so a 2-byte request should be rejected on length — but that is an inference. The
definitive answer is in `/cache/tsk/uds-sweep/uds_sweep.ndjson` on the device, which
recorded the response to every one of those 256 requests.

Note also that the vehicle reported **0 stored DTCs** in session 4, before any of this, so
there may have been nothing to clear.

### 9.18 The data-integrity defect **[DEFECT — read this before trusting any sweep result]**

`sweep_uds.py` checks liveness only **between sub-function blocks**. After the liveness
check failed, the run continued through:

```
dids/identity:      122 sent
dids/willem:        256 sent
dids/manufacturer:  512 sent
addresses:          256 probed
cross-ECU:           48 sent
recheck:            132 sent
```

— roughly 900–1,300 requests, every one of which recorded an outcome that may reflect an
absent ECU rather than a real protocol response. **Every "silent" in those stages is
suspect.**

**What survives, and why:**

- **The service sweep is sound.** It is bracketed by real answers: `0x10` answered near the
  start of the block and `0xBA` answered near the end of the same block. An ECU that is not
  answering cannot manufacture responses, so the EPS was alive across the whole 256-byte
  range. The 13-answering / 132-silent / 111-`0x11` decomposition therefore reflects real
  protocol behaviour.
- **The cross-ECU result is sound**, because it rests on `0x7F1` *answering*. A dead bus
  cannot produce four NRCs.
- **The recheck stage is sound** for the same reason it is meaningful: it produced the same
  132 count, and the address sweep in the same window got 13 live responders.
- **The DID sweeps are not trustworthy.** 890 DID results were recorded in a window where
  liveness was unverified. They should be discarded and re-run.

**The fix**, not yet built: write a liveness marker record every ~32 requests and stop the
run on death; on analysis, discard any "silent" that falls after the last successful
marker.

---

## 10. Consolidated data tables

### 10.1 Every service byte, final classification

| Range | Count | Classification |
|---|---|---|
| `0x10 0x14 0x19 0x22 0x23 0x27 0x2e 0x31 0x36 0x37 0x3e` | 11 | ANSWER (request range `0x00`–`0x3F`) |
| `0xab 0xba` | 2 | ANSWER (request range `0x80`–`0xBF`) — **undocumented** |
| `0x11 0x28 0x34` | 3 | SILENT (request range `0x00`–`0x3F`) |
| `0x85` | 1 | SILENT (request range `0x80`–`0xBF`) |
| 50 others in `0x00`–`0x3F` | 50 | NRC `0x11` |
| 61 others in `0x80`–`0xBF` | 61 | NRC `0x11` |
| `0x40`–`0x7F` | 64 | SILENT (response range — expected) |
| `0xC0`–`0xFF` | 64 | SILENT (response range — expected) |
| **Total** | **256** | |

### 10.2 Known sub-function behaviour

| Service | Sub-function | Result |
|---|---|---|
| `0x10` | `0x01` DEFAULT | accepted |
| `0x10` | `0x02` PROGRAMMING | **silent, every attempt, every session, every entry sequence** |
| `0x10` | `0x03` EXTENDED | accepted |
| `0x10` | `0x04` SAFETY_SYSTEM | NRC `0x12` |
| `0x10` | `0x82` (programming + suppressPosRsp) | possibly NRC `0x7E` — see §8.7, unresolved |
| `0x10` | all 256 | swept, results in NDJSON, not yet read |
| `0x14` | all 256 | swept, results in NDJSON, not yet read |
| `0x27` | `0x01` REQUEST_SEED | NRC `0x7E` in extended, `0x7F` in default |
| `0x27` | `0x03` REQUEST_SEED | **seed, 16 bytes, requires a 16-byte data record** |
| `0x27` | `0x04` SEND_KEY | NRC `0x35` with the Sienna level-1 key |
| `0x27` | `0x05 0x07 0x09 0x0b` | NRC `0x12` |
| `0x19`, `0x22`, `0x23`, `0x2e`, `0x31`, `0x36`, `0x37`, `0x3e`, `0xab`, `0xba` | — | **never swept** |

### 10.3 Address map, bus 1

| Address | Response to `10 01` | Reflash set | Identity |
|---|---|---|---|
| `0x700` | answers | all silent | unknown |
| `0x724` | answers | all silent | unknown |
| `0x747` | answers | all silent | unknown |
| `0x780` | answers | all silent | unknown |
| `0x792` | answers | all silent | unknown |
| `0x7a1` | answers | all silent | **EPS `8965F1208000`** |
| `0x7b0` | answers | all silent | unknown |
| `0x7b3` | answers | all silent | unknown |
| `0x7c0` | answers | all silent | unknown |
| `0x7c4` | answers | all silent | unknown |
| `0x7d0` | answers | all silent | unknown |
| `0x7d2` | answers | all silent | unknown |
| **`0x7f1`** | answers | **all four NRC** | **unknown — identify this** |

### 10.4 Memory addresses tried, all sessions

| Address | Meaning on Sienna | Corolla result |
|---|---|---|
| `0xFF206E14` | SecOC key location | NRC `0x31` extended / `0x7F` default, every attempt |
| `0xFF200000` | DataFlash base | NRC `0x31` / `0x7F` |
| `0xFEBF0000` | payload RAM load address | NRC `0x31` / `0x7F` |

### 10.5 DIDs

| DID | Result |
|---|---|
| `0xF181` app_sw_id | `8965F1208000` + `8A3111213000` |
| `0xF186` active session | `0x01` or `0x03` depending on state |
| `0xF18C` ecu_serial | `8965012N50E12H030731` |
| `0xF180 0xF187 0xF18A 0xF191 0xF193 0xF194 0xF195` | NRC `0x31` |
| `0x201 0x202 0x203` (Willem's upload DIDs) | NRC `0x31` — **do not exist** |
| `0xF100`–`0xF1FF`, `0x0200`–`0x02FF`, `0xFD00`–`0xFEFF` | swept, ~890 records, **untrustworthy** (§9.18) |

### 10.6 All seeds observed

```
da2df2eff64d95f5426bf3af70bb49aa
d976cb541b8423555a263f8c913eef64   (returned twice in one session)
63fabc805eb9c3a919808b8468b19503
be839062642f1f617abc28237eb4ed33
87734f83613e87a68ecccba880e3f122
0438cd94bc7221c63c070554a2a7658e
ce7b6b2c79b21c01e9361fd4e390bcfc
```

Seeds are non-secret challenge nonces and are safe to record and share.

The single key ever sent: `36c20b4723967a953d1cb888625fa0eb` (rejected, NRC `0x35`).

---

## 11. Analysis — what is established, what is open

### 11.1 Established beyond reasonable doubt

1. The EPS is at `0x7A1` on panda bus 1 and is reachable in software with no physical
   modification.
2. It is part `8965F1208000`, a family distinct from every previously-cracked Toyota EPS.
3. It answers reads, session control for DEFAULT and EXTENDED, and SecurityAccess level
   `0x03`.
4. It returns NRC `0x11` for 111 unimplemented services — its dispatcher is well-behaved.
5. Exactly four request-range services produce total silence: `0x11`, `0x28`, `0x34`,
   `0x85`, plus sub-function `0x02` of `0x10`.
6. Those silences are not a timeout artefact (verified at 10× the calibrated window).
7. Two undocumented services, `0xAB` and `0xBA`, answer.
8. `0x36` and `0x37` answer NRC `0x7F` while `0x34` is silent — the download sequence is
   split.
9. Willem's upload path does not exist here: routine `0x10F0` and DIDs
   `0x201`/`0x202`/`0x203` all return NRC `0x31`.
10. `0x23` ReadMemoryByAddress is supported and is *out of range* at the Sienna addresses,
    never *security denied*.
11. SecurityAccess is not locked out; a clean seed was obtained after the failed key.
12. Level `0x01` exists and is session-gated (`0x7E`); Willem's secret has **never been
    tested at that level**.
13. Level `0x03` requires a 16-byte client-supplied data record.
14. The `0x03` seed is a per-session nonce: stable within a session, regenerating across.
15. Programming is refused even immediately after an ECU reset — not a warm-up artefact.
16. `0x7F1` answers all four silent services; eleven other modules do not.
17. The EPS transiently stops answering under probe load and recovers on its own.

### 11.2 Open, ranked by how much they would change the picture

1. **What are `0xAB` and `0xBA`?** Two undocumented services on a Toyota EPS, entirely
   unprobed. If either provides memory access, a maintenance mode, or an alternate
   authentication path, the investigation ends there.
2. **Why is `0x34` silent when `0x36` and `0x37` answer?** A coherent explanation of that
   split is very likely a coherent explanation of the whole silent class.
3. **Is there a gateway between the panda and the EPS?** Decides whether a repin is
   pointless or the answer. §9.9 gives the discriminating experiment.
4. **What is `0x7F1`?** One `0x22 F181` read against that address.
5. **Is the level-`0x03` seed a function of the data record?** Free experiment, potential
   chosen-input oracle against ECU key material.
6. **Does Willem's secret work at level `0x01`?** Untestable until PROGRAMMING opens, but it
   is the single shot most likely to simply work.
7. **Which arbitration IDs does the Corolla sign?** Needed for any future matcher oracle.
   Tool built, capture not yet obtained in the right vehicle mode.
8. **Which RH850 part is this?** Gates the memory-map search and the transferability of a
   glitch attack.

### 11.3 Explanations for the silent class, ranked

**A. Per-destination gateway policy [most consistent with all data].** A gateway forwards
read services and drops the reprogramming set toward protected ECUs, while answering
diagnostics addressed to itself at `0x7F1`. Explains: silence rather than NRC (a dropped
frame produces no response from anyone), the `0x7F1` exception, the `0x34`/`0x36`/`0x37`
split if the filter list is service-specific rather than sequence-aware, and the fact that
eleven *other* modules also go silent. Predicts: a physical connection on the EPS's own
segment bypasses it.

**B. EPS policy layer above the dispatcher.** The EPS knows these services and refuses to
respond as a security posture. Explains the same observations except the eleven other
silent modules, which would each need the same policy independently — plausible if they
share a supplier stack. Predicts: a repin changes nothing.

**C. Unimplemented in firmware.** Weakened severely by §9.5: this ECU answers `0x11` for
111 services it does not implement, so silence is not its way of saying "not implemented."
Retained only because the DEFAULT/EXTENDED union caveat leaves a small gap.

**D. FD framing.** Bus 1 is CAN-FD. Weak: DEFAULT and EXTENDED already answer classic
framing on the same bus and a two-byte request is a single frame in either format.

### 11.4 Why the Corolla is harder than the Sienna — summary

| Step | Sienna | Corolla |
|---|---|---|
| Reach EPS | bus 0, `0x7A1` | bus 1, `0x7A1` — solved in software |
| EXTENDED session | works | works |
| PROGRAMMING session | works | **silent** |
| SecurityAccess level `0x01` | seed + key accepted | `0x7E`, session-gated behind the silent PROGRAMMING |
| SecurityAccess level `0x03` | not used | seed available in EXTENDED, secret unknown |
| Write DIDs `0x201`/`0x202`/`0x203` | works | **NRC `0x31` — do not exist** |
| `RequestDownload` `0x34` | works | **silent** |
| `TransferData` `0x36` | works | answers `0x7F` |
| `RoutineControl` `0x10F0` | works | **NRC `0x31` — routine does not exist** |
| Read key at `0xFF206E14` | via payload | `0x23` says out of range |

Four independent blockers, not one. Even a hypothetical PROGRAMMING unlock leaves the
missing DIDs and the missing routine.

---

## 12. Catalogue of reversals and errors

Recorded in full because this investigation produced confident wrong readings at a steady
rate, and the next agent should expect to do the same.

### 12.1 Position reversals

| # | Position | Held | Reversed by |
|---|---|---|---|
| 1 | PROGRAMMING response is rerouted to another bus | 07-23 | 07-24 did-it-take (session unchanged) + all-bus-listen (nothing anywhere) |
| 2 | Security is circularly gated behind PROGRAMMING | 07-23 | 07-24 level `0x03` seed in EXTENDED |
| 3 | The blocker is now the `0x03` seed→key formula | 07-24 AM | 07-24 evening level-mismatch analysis — the blocker never left PROGRAMMING |
| 4 | The Sienna secret does not transfer | 07-24 PM | Same — the `0x35` was spent at the wrong level pair |
| 5 | `0x14` sub-function sweep killed the EPS | 07-25 AM | The same run shows `0 sent` and a later `0x7A1` response |
| 6 | Reads answer, writes are silent | 07-24 evening | 07-25 sweep: `0x2E`, `0x14`, `0x36`, `0x37` all answer |
| 7 | A repin cannot help (refusal, not filter) | 07-24 AM | 07-25 preamble reframing (silence is filter-shaped) |
| 8 | A repin could help (filter-shaped silence) | 07-25 AM | `0x7F1` answering — then **re-opened**, see #9 |
| 9 | A repin definitively cannot help | 07-25 PM | This document, §9.9 — the claim assumed one physical segment, which is unverified |
| 10 | The silent services are unimplemented | implicit | §9.5 arithmetic: 111 unimplemented services answer `0x11` |

### 12.2 Methodological errors

**Curating by hypothesis instead of sweeping the space.** Three separate probes were scoped
to the theory being tested rather than to the question asked. Cost: two days and at least
two in-car sessions. The undocumented services `0xAB`/`0xBA` would never have appeared
under any curated list.

**Inheriting a safety exclusion without re-examining it.** `ident_map.py` restricted itself
to "safe services only" for good reasons in its own context. That list was then inherited
by later probes without asking whether the reasons still applied. The distinction never
drawn until forced: *a service that is dangerous to use is not dangerous to ask about*,
because an ECU decides whether to respond before it decides whether to act.

**Designing to an unexamined UI constraint.** Every probe was shaped to fit a one-tap
sixty-second page. That constraint was never stated by anyone and it silently forced
curation.

**Over-claiming from a bracketed observation.** §9.9: "a path filter cannot do X on the
same wire" was stated as settled when "on the same wire" was an unverified assumption.

**Conflating "on the chip" with "in our artefact."** An early claim that a firmware dump
would expose `f()` because `f()` must execute on the chip. The sharper distinction, which
Calvin supplied: the TSKM exploit produces a *data* dump (DataFlash/RAM, where the key
lives); `f()` is *code*, in program flash. No exploit dump can ever contain `f()`, so only
a program-flash read — a bench glitch attack — reaches it.

**Self-contradiction on a safety constraint.** The NVRAM-backed SecurityAccess lockout risk
was raised, then a key-variant *sweep* was proposed two exchanges later — dozens of counted
failures, exactly the hazard just described. Caught by a reviewing instance. The general
rule extracted: after building an option map, adversarially check it against constraints
established earlier in the same session.

**A second model made the same mistake.** A parallel GPT analysis (Spanconstant's "Sol")
independently converged on the same RE plan and also proposed a live variant sweep with no
offline oracle. Two independent models skipping the live-ECU cost is a pattern, not an
accident, and any future variant-probe design should have the guard built into its
structure rather than relying on the model to remember.

### 12.3 Instrumentation defects, by file

| File | Defect | Impact |
|---|---|---|
| `sendkey_probe.py` | sent Willem's level-1 secret at level `0x03`/`0x04` | the entire `0x35` result is uninformative |
| `sendkey_probe.py` | (fixed in `ced38e5498`) mapped every non-`0x35` NRC to "different secret" | would have misdirected toward a firmware dump |
| `level3_probe.py` | prints "seeds differ each request"; they differ per *session* | cosmetic, misleading |
| `preamble_probe.py` | stacked 3 s timeouts blow the S3 window | variants 2/3/5 tested from a lapsed session |
| `preamble_probe.py` | functional `0x28` silences bus-wide, `finally` re-enables EPS only | other modules stay TX-disabled until power cycle |
| `prog_probe.py` | `reset_default()` swallows failures | a swallowed reset could hide a session state |
| `sweep_uds.py` | liveness checked only between sub-function blocks | ~900–1,300 records untrustworthy |
| `sweep_uds.py` | budget assumed 12 V limit, not the car's auto-off | runs get truncated unpredictably |
| `sweep_uds.py` | sub-functions swept in numeric order | died at `0x14`, never reached `0xAB`/`0xBA` |
| `capture_ready.py` | no mode guard | ran in NRtD, produced nothing |
| `capture_ready.py` | mode-diff summary counts the wrong bucket | reported "6 answered in READY" when the true count is 0 |
| all-bus-listen | does not filter the `0x80` TX-echo bus | "bus 129" entries are our own transmissions |

---

## 13. Tooling inventory

### 13.1 Endpoints on `span`

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/can-sniff` | POST | per-bus frame count + arb IDs, no payloads |
| `/api/dataflash-diag` | POST | instrumented dump with per-step NRC |
| `/api/prog-probe` | POST | programming entry matrix, security level sweep, did-it-take, all-bus-listen |
| `/api/read-mem` | POST | `0x23` at three addresses, both sessions |
| `/api/ident-map` | POST | identity block + read-only service map |
| `/api/reset-probe` | POST | reset then hammer PROGRAMMING |
| `/api/level3-probe` | POST | `0x03` seed isolation, four primer variants |
| `/api/sendkey-probe` | POST | one Willem key at `0x03`/`0x04` — **spent, do not re-run** |
| `/api/preamble-probe` | POST | lock read + exploit surface + five preamble variants + DTC diff |
| `/api/uds-sweep` | POST | full `0x00`–`0xFF` × sub-functions × sessions, resumable |
| `/api/ready-capture` | POST | full-payload capture + mode diff |
| each of the above `-status` | GET | live progress and final result |

All are serialised by a single `panda_lock` (409 on concurrent start), gated by `is_agnos()`
with off-device mocks, and release the panda in a `finally`.

### 13.2 Files written on the device

| Path | Content | Status |
|---|---|---|
| `/cache/tsk/uds-sweep/uds_sweep.ndjson` | 3,508+ sweep records | **on device, never retrieved — retrieve this** |
| `/cache/tsk/uds-sweep/ready_capture.ndjson` | 75,192 raw frames | on device; captured in the wrong vehicle mode |
| `/cache/tsk/uds-sweep/ready_diff.ndjson` | mode diff results | on device |

`/cache` survives reboot and clears on an AGNOS update.

**There is no download endpoint for any of these.** Retrieval currently requires SSH. A
small endpoint serving the NDJSON would convert several open questions into desk work.

### 13.3 UI layout as left

**Not Ready To Drive:** one visible button, "1. UDS Sweep (5 min)".
**READY:** one visible button, "2. READY Capture (5 min)".
Everything else — preamble probe, read-mem, ident-map, prog-probe, level3-probe,
sendkey-probe, dataflash-diag, reset-probe, can-sniff — is in `span-hidden` groups, still
served at its URL, unlinked from the visible UI. The destructive "Install a different
fork/branch" button is hidden with its node retained so its handler still binds.

Both sweep pages carry a copy-as-text textarea, because the finished output runs to dozens
of lines and screenshotting it takes several scrolls.

---

## 14. Recommended next actions, ranked

### 14.1 Desk work, no vehicle needed

1. **Retrieve `uds_sweep.ndjson`.** It answers: what `0xAB` and `0xBA` actually returned in
   each session; whether the 256 `0x14` requests were rejected on length (settling whether
   any DTCs were cleared); which of the 111 `0x11` services returned it in both sessions;
   where the liveness line falls; and the `0xBA` anomaly in §9.13. Either add a download
   endpoint or pull it over SSH.
2. **Identify `0x7F1`.** Desk work only in the sense that it needs one request; it is one
   line in any existing probe.
3. **Ask the community for a captured seed/key pair**, not for the algorithm. Willem, yc,
   3b1b.eth, and locksmith/AKL key-programmer circles. A dealer tool performing a legitimate
   EPS security unlock puts the seed *and* the key on the bus in plaintext, and the
   sub-function bytes reveal which level it used. A level-`0x01` capture becomes an offline
   oracle for testing Willem's secret at zero risk; a level-`0x03` capture reveals that
   level's mapping directly. This reframes the ask from "does anyone have the algorithm"
   (rarely yes) to "can anyone capture a transaction" (much easier yes). The capture harness
   can be positive-controlled on Calvin's Sienna, where the expected pair is already known.
4. **Pin the exact RH850 part.** Board photograph of a bench unit, FCC teardown, or an
   `8965F12` parts catalogue. Gates the memory-map search and the transferability of a
   glitch attack.

### 14.2 Vehicle work, ordered

Every run is bounded by the car's auto-off timer, not the 12 V. Design for ~2 minutes and
lean on resume.

5. **Fix the sweep defects and resume it, pointed at `0xAB` and `0xBA` first.** Liveness
   markers every ~32 requests with stop-on-death; interest-ordered sub-function sweep;
   `0x14` moved last and sent with a valid 3-byte DTC group so it cannot clear anything;
   shorter budget.
6. **The level-`0x03` data-record experiment** (§9.14). Free, no counter touched, and it
   tests whether the seed is a pure nonce or a function of client input.
7. **Re-run the READY capture with a mode guard** that refuses to start until it observes
   READY traffic. Produces the signed-ID list and the sync-counter behaviour, both required
   by any future matcher.
8. **The gateway discriminator** (§9.9): in READY, capture background traffic on bus 1 and
   check whether the thirteen responding addresses also transmit periodic frames on our
   segment. Settles whether a repin is pointless.
9. **A clean `10 82` suppressPosRsp retest** (§8.7) with a raw bus watch rather than a
   follow-up request.
10. **Sub-function sweep of the remaining answering services** — `0x19 0x22 0x23 0x27 0x2e
    0x31 0x36 0x37 0x3e`.

### 14.3 Only if PROGRAMMING opens

11. **One** live SEND_KEY with Willem's secret at level **`0x01`/`0x02`** — the correct
    level, and the shot most likely to simply work. De-risk it first with an offline oracle
    if one has been obtained by then.

### 14.4 Lockout-exposed — deliberate gamble, not a sweep

12. Key-variant SEND_KEY with different transforms, byte orders, or candidate secrets. Each
    wrong key is a *counted* SecurityAccess attempt returning `0x35`; past the threshold the
    ECU returns `0x36`/`0x37`, and if that counter is NVRAM-backed it could **permanently
    lock SecurityAccess on Spanconstant's vehicle** — the one failure a power cycle will not
    undo. One attempt has already been spent (15:16 on 07-24), and although a later clean
    seed shows no persistent lock resulted, the threshold and persistence are both unknown.
    At most one or two hand-picked guesses, from a fresh session, halting on the first
    `0x36`. **Pointless without an offline oracle**, because without one there is no way to
    pre-filter candidates.

### 14.5 Parallel route

13. **Rekey / master key.** Write a *known* SecOC key past the pairing master and skip
    `f()` entirely. Different door. yc hypothesises the ECU master key is shared across a
    part-model or firmware, since the rekey request carries no per-part serial and so the
    authorising key cannot be per-part. It is not a mystery value: Willem's `extract_keys.py`
    prints it, and TSKM's own `extractor.py:315-323` extracts and checksum-verifies it as
    slot 1 of the KEY table (the SecOC key is slot 4). On `tskmloop` it reaches the server's
    stdout only — `hack()` returns just `key_4` and `/api/extract` ships just `secoc_key` —
    so surfacing it is a one-line change. Near-term unlikely for the Corolla (its key table
    is not at the Sienna RAM addresses and the RAM path needs the same blocked services),
    but it is a line worth keeping open rather than treating `f()` as the only door.

### 14.6 Hardware fallback

14. **Bench `8965F1208000` glitch dump**, following 3b1b.eth's Sienna path. Reads *program
    flash* — code — which is where `f()` lives; no exploit dump can contain it, since the
    exploit produces *data*. Would yield the level-`0x01` seed→key routine, the key's memory
    address (turning `0x23` into a direct read), and probably the programming-entry secret,
    all at once. Risks: the glitch may not transfer to this MCU; the secret may sit in OTP,
    fuses, or a crypto block outside the flash image, yielding an algorithm without key
    material; and it may be per-unit rather than per-model — the Sienna's is one fleet-wide
    constant, which is precedent for per-model but is not verified for this family. A China
    market `8965F1208000` is reportedly available for roughly $30.

---

## 15. Notes for whoever continues this

### 15.1 Operating constraints that will bite you

- **The car powers itself off after some time in Not Ready to Drive.** Not under the
  operator's control. Budget every run for ~2 minutes and rely on resume.
- **The EPS transiently stops answering under probe load and recovers on its own.** It is
  not damage and not the auto-off. A power cycle or re-entering NRtD restores it.
- **Do not trust any "silent" result recorded after a failed liveness check.** As shipped,
  `sweep_uds.py` keeps going. See §9.18.
- **`sendkey_probe` is spent.** Re-running it costs another counted SecurityAccess attempt
  at a level Willem's secret does not even belong to. It is hidden from the UI for that
  reason.
- **Spanconstant is a volunteer running these in his own car.** Every run costs him real
  effort, and screenshots are the default transport for results. Fold as much as possible
  into one tap, and prefer the copy-as-text box over expecting six scrolling screenshots.

### 15.2 What "done" would look like

Extraction succeeds when a 16-byte value is recovered that verifies against captured SecOC
traffic. TSKM's matcher does that verification: an exhaustive stride-1 scan over every
16-byte window of a memory dump, computing an AES-CMAC per window and accepting at ≥30
matches with ≥2 sync samples. A wrong window clears a 28-bit MAC at 2⁻²⁸, so with two sync
samples a false install sits at 2⁻⁵⁶ — no bad install is possible.

That machinery is built and validated on the Sienna. For the Corolla it needs two inputs
neither of which exists yet: a memory dump containing the key, and a CAN oracle of signed
frames. The oracle needs the signed arbitration IDs, which needs the READY capture. The
dump needs the programming session, which is the wall.

### 15.3 The thing most likely to be overlooked

`0xAB` and `0xBA`. Two services that are not in the standard, that answer on a Toyota EPS,
that no one has ever sent a sub-function to, and that were found only because a full
byte-space sweep was forced through over three rounds of pushback. Every prior methodology
in this investigation would have missed them, and the same instinct that missed them will
be present in whoever reads this.

---

*End of report. Companion material: the session-by-session journal in `CLAUDE.md`, and the
code on branch `span` at `b9db236acc`.*

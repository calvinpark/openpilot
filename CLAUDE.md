# TSK Manager

## Background

comma.ai makes DIY ADAS devices. Current devices are comma threeX (C3X/tizi) and comma four (C4/mici). Toyota added cryptographic SecOC signatures to CAN messages, blocking comma from writing to the bus.

Willem (ex-comma) found a way to extract the SecOC key from the EPS firmware on 2021-23 RAV4 Prime. The same hack works on 2021-23 Sienna Hybrid, and with modifications on Yaris. Calvin built TSK Manager (TSKM) as a GUI around Willem's script. Details in `/Users/calvin/GitRepos/docs/README.md`.

Calvin's cars: 2023 Sienna Hybrid (C3X), 2023 Bolt EV 2LT (C4). Both devices test against the Sienna for TSKM validation.

## Architecture

This is the `tskmweb` branch, based on `commaai/nightly-dev`. It replaces the old RayLib GUI (`tskm` branch) with a local web app.

### Boot Flow

`launch_chffrplus.sh` runs on device boot:

1. Sets up `/cache/tsk` dev asset symlink.
2. Runs `python3 tsk/prefetch.py` — standalone RayLib GUI that clones recommended/alternate openpilot branches. Blocks until done.
3. Starts the openpilot manager, which starts the `tskweb` process (`tsk.web.server`).
4. Web UI available at `http://<device-ip>:11111`.

### File Layout

- `tsk/prefetch.py`: standalone RayLib prefetch GUI. Not managed by the manager. Detects C3X vs C4 screen size.
- `tsk/lib/`: TSKM behavior. All shared logic belongs here.
  - `env.py`: paths, branch constants, device detection.
  - `extractor.py`: SecOC key extraction via UDS/CAN. Calls `flash_panda()` for firmware recovery.
  - `key_file_manager.py`: key read/write/delete, `format_key()`.
  - `reboot_manager.py`: reboot/install actions with key status prompts.
  - `payload.bin`: EPS firmware payload.
- `tsk/web/`: HTTP and static web UI only.
  - `server.py`: Python stdlib `ThreadingHTTPServer` on port `11111`.
  - `static/index.html`: phone-first main page (iOS Settings design).
  - `static/extractor.html`: TSK Extractor page (dark terminal, auto-runs on load).

`tsk/common`, `tsk/c3`, `tsk/c4` should not exist on `tskmweb`.

### Web Server

Binds `0.0.0.0:11111`. Serves frozen assets from `tsk/web/static`, dev assets from `tsk/dev/web/static` when `/cache/tsk` is linked. Writes the device URL into `Offroad_NoFirmware` so the comma screen shows it.

API endpoints: `/api/health`, `/api/status`, `/api/reboot`, `/api/extract`, `/api/uninstall`.

Imports from `tsk/lib`: `TSKExtractor.hack()`, `KeyFileManager`, `RebootManager`, `format_key()`, `is_agnos`.

### Hard Rules

`tsk/web/server.py` is HTTP routing only. Do not add key paths, key validation, key read/write, device detection, extractor wrappers, or reboot file operations. If behavior exists in `tsk/lib`, call it. If it doesn't, add it to `tsk/lib` or ask first.

Do not invent alternate key storage — use `KeyFileManager`.

### Storage

- Frozen code: `/data/openpilot/tsk`
- Dev hot-reload assets: `/cache/tsk`
- Prefetched repos: `/data/tsk-recommended`, `/data/tsk-alternate`

## Development

### Laptop (macOS)

Unstaged patches in `system/manager/` let the manager run only `tskweb` on Darwin with `SIMULATION`. `SConstruct` skips modeld when ONNX files are absent. These are not committed.

```bash
source .venv/bin/activate
./tools/sim/launch_openpilot.sh
```

Direct server test:

```bash
python3 -m tsk.web.server
```

Non-AGNOS dry run cycles through 3 extract scenarios: success (fake key), short error, long error with traceback.

### Dev Assets on Device

`launch_chffrplus.sh` creates `/cache/tsk/web/static` and symlinks `tsk/dev -> /cache/tsk`. Dev assets override frozen assets.

## Reference

### Why TSKM Rebases on nightly-dev

AGNOS updates are ~1GB and take ~10 minutes. Rebasing keeps TSKM current so users don't hit an AGNOS update mid-extraction. The web-app direction reduces dependence on comma's constantly-breaking RayLib GUI libs.

### comma Release Branches

- C3X (tizi): `release-tizi`
- C4 (mici): `release-mici`
- C3 (tici): `release-tici` (discontinued)
- `release3`: older legacy branch

### Versioned TSKM Branches

Each release is tagged as a branch (e.g. `tskm-0.10.4`). Meant as frozen fallbacks, but comma changes can break them.

### SSH Tips

tmux detach on comma devices: backtick, then `d`.

---

## Journal

When the user says "update the journal", write a summary of what was done in the current session.

### 2025-11-15

Released TSK Manager v0.10.4 on `tskm` branch.

### 2026-04-09

Fixed `RuntimeError: CAN packet version mismatch` — panda firmware was stale because TSKM killed boardd/pandad before they could flash it. Added `panda.flash()` to `TSKExtractor.hack()`. End-to-end test passed in car.

### 2026-04-10

Two users confirmed successful extraction with the fix on `calvinpark/tskm`.

### 2026-04-15

Third user had `DEV-18392c3e-RELEASE` panda firmware that wouldn't flash via `panda.flash()`. SPI writes accepted silently but didn't persist. Fix: replaced bare `panda.flash()` with `flash_panda()` from `selfdrive/pandad/pandad.py` which includes GPIO/DFU recovery.

### 2026-07-02 / 2026-07-03

Started `tskmweb` branch from `commaai/nightly-dev`.

Moved shared logic from `tsk/common`, `tsk/c3`, `tsk/c4` into `tsk/lib`. Built Python stdlib web server at `tsk/web/server.py` (port `11111`). Phone-first web UI at `tsk/web/static/index.html` using iOS Settings design language. TSK Extractor split into separate page (`extractor.html`) with dark terminal, auto-runs on load.

Server calls `TSKExtractor.hack()` directly, returns `{ok, key, message}`. Non-AGNOS dry run cycles through 3 scenarios. Prefetch is a standalone RayLib script (`tsk/prefetch.py`) launched from `launch_chffrplus.sh` before the manager starts — same as `tskm` branch.

Verified locally on laptop. Next: on-device testing.

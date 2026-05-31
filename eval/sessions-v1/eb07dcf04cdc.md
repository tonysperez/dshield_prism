# eb07dcf04cdc

- **Source IP:** `149.106.136.92` — Rishon LeTsiyyon, Israel — AS6810 Bezeq- THE ISRAEL TELECOMMUNICATION CORP. LTD.
- **Window:** `2026-05-08T14:19:08.857000+00:00` → `2026-05-08T14:22:10.515000+00:00`  (~181.7s)

## Rollup

- **commands:** 6 total (6 unique) · entropy 2.58
- **novelty_score:** mean 0.701 · max 1.000  *(corpus-relative; limited use disconnected from source corpus)*
- **intel:** *(no source_ip_intel block on rollup)*

## Login attempts

1 successful · 1 failed

| outcome | user | password |
|---|---|---|
| success | `root` | `root` |
| failed | `admin` | `admin` |

## Command stream

| # | offset | action | command_line |
|---:|---|---|---|
| 1 | `+00:01.84` | `input` | `sh` |
| 2 | `+00:01.84` | `input` | `shell` |
| 3 | `+00:01.84` | `input` | `enable` |
| 4 | `+00:01.84` | `failed` | `shell` |
| 5 | `+00:01.84` | `input` | `system` |
| 6 | `+00:01.84` | `input` | `ping; sh` |
| 7 | `+00:01.84` | `failed` | `system` |
| 8 | `+00:01.84` | `input` | `` |
| 9 | `+00:02.02` | `input` | `/bin/busybox cat /proc/self/exe \|\| cat /proc/self/exe` |

## Artifacts (2)

| kind | value |
|---|---|
| `file` | `/bin/busybox` |
| `file` | `/proc/self/exe` |

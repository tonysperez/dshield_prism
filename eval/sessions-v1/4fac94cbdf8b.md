# 4fac94cbdf8b

- **Source IP:** `171.232.91.157` — Ho Chi Minh City, Vietnam — AS7552 Viettel Group
- **Window:** `2026-05-05T16:10:37.164000+00:00` → `2026-05-05T16:11:09.471000+00:00`  (~32.3s)

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
| 1 | `+00:02.26` | `input` | `sh` |
| 2 | `+00:02.26` | `input` | `shell` |
| 3 | `+00:02.26` | `failed` | `shell` |
| 4 | `+00:02.26` | `input` | `enable` |
| 5 | `+00:02.26` | `input` | `system` |
| 6 | `+00:02.26` | `failed` | `system` |
| 7 | `+00:02.26` | `input` | `` |
| 8 | `+00:02.26` | `input` | `ping; sh` |
| 9 | `+00:02.50` | `input` | `/bin/busybox cat /proc/self/exe \|\| cat /proc/self/exe` |

## Artifacts (2)

| kind | value |
|---|---|
| `file` | `/bin/busybox` |
| `file` | `/proc/self/exe` |

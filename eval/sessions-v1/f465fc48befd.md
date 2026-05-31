# f465fc48befd

- **Source IP:** `178.210.214.48` — Kyiv, Ukraine — AS47359 Tvoi Net Ltd.
- **Window:** `2026-05-06T15:36:31.482000+00:00` → `2026-05-06T15:36:35.197000+00:00`  (~3.7s)

## Rollup

- **commands:** 10 total (10 unique) · entropy 3.32
- **novelty_score:** mean 0.668 · max 1.000  *(corpus-relative; limited use disconnected from source corpus)*
- **intel:** *(no source_ip_intel block on rollup)*

## Login attempts

1 successful · 4 failed

| outcome | user | password |
|---|---|---|
| success | `root` | `5up` |
| failed | `root` | `aquario` |
| failed | `root` | `alpine` |
| failed | `root` | `xmhdipc` |
| failed | `root` | `ivdev` |

## Command stream

| # | offset | action | command_line |
|---:|---|---|---|
| 1 | `+00:02.87` | `input` | `enable` |
| 2 | `+00:02.88` | `input` | `system` |
| 3 | `+00:02.88` | `input` | `shell` |
| 4 | `+00:02.88` | `failed` | `system` |
| 5 | `+00:02.88` | `input` | `sh` |
| 6 | `+00:02.88` | `failed` | `shell` |
| 7 | `+00:03.04` | `input` | `cat /proc/mounts; /bin/busybox HLTEZ` |
| 8 | `+00:03.21` | `input` | `cd /dev/shm; cat .s \|\| cp /bin/echo .s; /bin/busybox HLTEZ` |
| 9 | `+00:03.38` | `input` | `tftp; wget; /bin/busybox HLTEZ` |
| 10 | `+00:03.54` | `input` | `dd bs=52 count=1 if=.s \|\| cat .s \|\| while read i; do echo $i; done < .s` |
| 11 | `+00:03.54` | `failed` | `while read i` |
| 12 | `+00:03.71` | `input` | `/bin/busybox HLTEZ` |
| 13 | `+00:03.71` | `input` | `rm .s; exit` |

## Artifacts (5)

| kind | value |
|---|---|
| `file` | `.s` |
| `file` | `/bin/busybox` |
| `file` | `/bin/echo` |
| `file` | `/dev/shm` |
| `file` | `/proc/mounts` |

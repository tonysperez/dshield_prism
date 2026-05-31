# 868dde54feed

- **Source IP:** `168.220.237.171` — India — AS151734 WEBYNE DATA CENTRE PRIVATE LIMITED
- **SSH client banner:** `SSH-2.0-OpenSSH`
- **HASSH:** `88e4f54f942892da498676735732aec7`
- **Window:** `2026-05-28T14:22:24.362000+00:00` → `2026-05-28T14:22:52.287000+00:00`  (~27.9s)

## Rollup

- **commands:** 1 total (1 unique) · entropy -0.00
- **novelty_score:** mean 0.096 · max 0.096  *(corpus-relative; limited use disconnected from source corpus)*
- **intel:** *(no source_ip_intel block on rollup)*

## Login attempts

1 successful · 0 failed

| outcome | user | password |
|---|---|---|
| success | `dev` | `123` |

## Command stream

| # | offset | action | command_line |
|---:|---|---|---|
| 1 | `+00:27.92` | `input` | `cat /proc/cpuinfo\|grep name\|cut -f2 -d':'\|uniq -c ; uname -a` |
| 2 | `+00:27.92` | `failed` | `cat /proc/cpuinfo \| grep name \| cut -f2 -d: \| uniq -c` |

## Artifacts (1)

| kind | value |
|---|---|
| `file` | `/proc/cpuinfo` |

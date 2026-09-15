# vlmcsd Security Audit — True Positive Remediation Status

Date: 2026-09-14
Scope: GitHub code-scanning alerts (Semgrep + CodeQL + Trivy SCA) and AFL++ fuzz findings (AFL in the branch `release` CI).
Snapshot: commit `f3101e9` (branch `release`), corresponding binary release **v6.0.1**.

Alert state at snapshot:

| State | Count |
|---|---|
| open | 199 |
| fixed (auto-closed) | 14 (all `github-actions-mutable-action-tag`, closed when workflow revisions were pinned) |
| dismissed | 0 |

All **open** alert instances point at `refs/heads/master`. The Semgrep and AFL workflows watch `master`/`main` only, so every fix below is present on the `release` branch but **`master` is still unpatched** and no alert will auto-close until `master` is synced or the alerts are dismissed.

---

## 1. True Positives — Remediated

All of these are fixed on the `release` branch; `master` still carries the vulnerable code.

| Alert | Location (master) | Root cause | Fix | Fix commit |
|---|---|---|---|---|
| AFL++ UBSAN "load of misaligned address" | `src/crypto.c:48` `XorBlock` | `((DWORD*)out)[i] ^= ((DWORD*)in)[i]` — unaligned typed access on a `BYTE*` (UB; crashes on misaligned response buffers) | byte-wise XOR over `AES_BLOCK_BYTES` + alignment-safe word ops in `MixColumns`/`MixColumnsR` via `memcpy` with BE/LE transforms preserved | `f3101e9` |
| AFL++ ASAN "global-buffer-overflow" | `src/crypto_internal.c:62` `Sha256ProcessBlock` | `BE32(((DWORD*)block)[i])` unaligned read | `memcpy` + `BE32` load | `f3101e9` |
| AFL++ ASAN "global-buffer-overflow" | `src/kms.c:994` `DecryptResponseV4` | ciphertext length arithmetic could read past the response buffer | response-size bounds (V4) | `4e16fb2` |
| AFL++ ASAN "global-buffer-overflow" | `src/kms.c:806` `CreateV6Hmac` | `responseEnd - V6_POST_EPID_SIZE` underflow on truncated response | validated `effectiveResponseSize`/`correctResponseSize` | `4e16fb2` |
| Semgrep format-string / sprintf (error) | `src/kms.c:281` `itoc` | unbounded `sprintf` into `char[12]` with constructed format | limit digits to 1..9, `snprintf(c, 12, formatString, i)` with trusted, bounded format | `4e16fb2` |
| Semgrep insecure-api-alloca (error) | `src/libkms.c:64` `ConnectToServer` | `alloca(strlen(host) + 16)` — length is library-caller-controlled → caller can grow the stack | checked `vlmcsd_malloc` + `free` on both control-flow paths | `f3101e9` |
| Semgrep insecure-api-alloca (error) | `src/kms.c:440` `logRequest` | `alloca(GUID_STRING_LENGTH + 1)` for a log string | replaced with stack array `char guidString[GUID_STRING_LENGTH + 1]` | `4e16fb2` |
| Semgrep alloca + unchecked-ret-malloc + integer-wraparound | `src/dns_srv.c:202` `getKmsServerList` | unchecked `malloc` → NULL-deref on OOM; ambiguous-count multiply | `vlmcsd_malloc((size_t)answers * sizeof(...))` (checked; count is `uint16_t` so no wraparound) | `f3101e9` |

Additional code-quality regression fixed in the same pass:

| Issue | Location | Fix | Commit |
|---|---|---|---|
| `logRequest` "Unknown" branch left `guidString` uninitialized and logged stack garbage | `src/kms.c:443` | `uuid2StringLE` now called in both `index < 0` and `Unknown` branches | `f3101e9` |

Verification performed on `f3101e9`:
- Hardened builds (linux `-Werror allmulti`) and mingw `windows-x86_64` compile clean.
- ELF PIE/RELRO/BIND_NOW/NX and PE DEP+ASLR+High-Entropy checks pass.
- Live `vlmcsd` ↔ `vlmcs` V6 exchange: server response decrypts and HMAC verifies with the byte-wise crypto implementation (crypto path unchanged semantically).
- CI run `34856698274` (release-build, version 6.0.1): all 8 jobs green; Release v6.0.1 published with 22 assets + `SHA256SUMS.txt`; checksums verified.

### Follow-up 2026-09-15 — new findings from the added assessment workflows

While validating the newly added libFuzzer CI targets (below), two further True Positives were discovered and fixed on `release`:

| Alert | Location | Root cause | Fix |
|---|---|---|---|
| libFuzzer create-mode ASAN `stack-buffer-overflow` (found via a local **logging-enabled** build — this path is compiled *out* of every CI fuzz target by `-DNO_LOG`) | `src/helpers.c:161` `ucs2_to_utf8` | (1) `if (index_utf8 + len > maxutf8)` allows `index_utf8 + len == maxutf8`, then `strncat(utf8, utf8_char, len)` appends `len` bytes **plus the terminating NUL** → up to 4 bytes past a `maxutf8`-sized stack buffer. Reachable from any attacker-supplied UCS-2 string with a logging build (e.g. `WorkstationName` → `logRequest`, `clientName[64]`); (2) read bound `>` should be `>=` (reads one WCHAR past the source field); (3) `ucs2_to_utf8_char` returning `-1` (UTF-16 surrogate) passes `strncat(..., (size_t)-1)` reading uninitialized memory | reject `len <= 0`; require room for the NUL (`index_utf8 + len + 1`); `>=` read bound; size-cast the `strncat` length |
| libFuzzer decrypt-mode UBSAN `bounds` (previously documented in the appendix as "`checkPidLength` allows `PIDSize=0` → benign intra-struct UB"; clang UBSAN **bounds** aborts on it) | `src/kms.c:970` `checkPidLength` | `PIDSize=0` or `1` → `KmsPID[(PIDSize >> 1) - 1]` indexes `KmsPID[-1]`, an out-of-bounds read within the `RESPONSE` struct | reject `PIDSize < 2` (a valid ePID is ≥ 1 UCS-2 char + NUL) before indexing |

New CI assessment pipelines added (`release` also added to the existing Semgrep/CodeQL push+PR branch lists so fixes get scanned and alerts can close):
- `.github/workflows/clang-tidy.yml` — cpp-linter gate, `clang-analyzer-*`/`bugprone-*`/`cert-*`/`security-*`/`performance-*`/`portability-*`, `fail-on-issue`, PR annotations, compile DB via `bear intercept` + `bear citnames`.
- `.github/workflows/cppcheck.yml` — `--enable=warning,performance,portability`; fails only on **new** error/critical findings versus the committed baseline `.github/cppcheck-baseline.txt` (current baseline: 2 Android-shim unchecked-malloc chains, 2 tool limitations — see file for rationale).
- `.github/workflows/libfuzzer.yml` + `fuzzing/libfuzzer-harness.c` — libFuzzer (`clang -fsanitize=fuzzer,address,undefined`) create/decrypt targets mirroring the AFL suite's CFLAGS/sources; gate fails on any crash/hang/OOM artifact. The `ucs2_to_utf8` bug was invisible to all prior fuzzing (AFL included) precisely because every target is built with `-DNO_LOG`.

---

## 2. True Positives — NOT Remediated (open, accepted risk)

These matched alerts are real in the sense that the pattern matched, but they are either deliberate CLI behavior or would require disabling functionality to "fix":

| Alert | Location | Assessment |
|---|---|---|
| CodeQL `cpp/path-injection` (3) | `src/helpers.c:571`, `src/output.c:48`, `src/vlmcsd.c:1438` | Filenames are taken from documented `-o`/config options; over-write target is user-specified by design. Accepted; not fixable without removing features. |
| CodeQL `cpp/world-writable-file-creation` (4) | `src/output.c:48`, `src/vlmcs.c:941, 1023`, `src/vlmcsd.c:1438` | `fopen(..., "w")` without `0700` umask hardening. Accepted: output files are the artifact the tool must produce. |
| CodeQL `cpp/potentially-dangerous-function` (4) | `src/output.c:61, 216, 245`, `src/kms.c:354` | `mktemp`/`system`/`popen` style calls. Not reworked; call sites were reviewed as non-privilege-escalating. |
| CodeQL `cpp/uncontrolled-process-operation` (1) | `src/vlmcsd.c:954` | Process/command spawn via a runtime-derived value. Reviewed; input derived from root-restricted config. |

Semgrep clusters you can optionally address in a follow-up (all on `master`, mostly low severity):
- rand/srand (warning) `src/kms.c:289, 294, 333, 369, 390` — `rand()` for randomized response metadata (build/language selection), not cryptographic randomness. The PRNG *seed* was hardened (`4e16fb2`), but the `rand()` calls remain. Accepted.
- rand (warning) `fuzzing/afl-harness.c:199` — fuzz-tooling only, not shipped.
- unchecked-ret-malloc (warning) `fuzzing/afl-harness.c:148`, `fuzzing/make-seeds.c:76`, `src/ifaddrs-android.c:127, 168, 310` — fuzz-tooling / legacy Android compat only.
- use-of-source-size-in-copy (error) `fuzzing/make-seeds.c:56`, `src/libkms-test.c:17` — tooling/tests only.
- double-free (error) `fuzzing/make-seeds.c:95` — fuzz seed tooling only.
- sprintf (error) `src/ntservice.c:278`; overlapping-source-destination `src/ntservice.c:187` — Windows service helpers, low risk, not reviewed/closed.
- integer-wraparound (warning) `src/getifaddrs-musl.c:174`, `src/ifaddrs-android.c:310, 403` — legacy platform compat.
- signed-unsigned-conversion (37, warning) — mostly `strlen`/printf sign warnings; not exploitable.
- insecure-use-strcat/string-copy (29 + 11, warning) — bounded/`strcat`-into-fixed-buffer; treated as information-only.

---

## 3. False Positives — Classified but NOT formally dismissed

Analysis complete; **0** alerts dismissed via the code-scanning API.

| Alert | Location | Why it is a false positive |
|---|---|---|
| CodeQL `double-free` / `use-after-free` | `src/wintap.c:53, 58, 70` | Flow: `malloc` owned by this frame → `GetIpAddrTable` → freed at `:46` → fresh `malloc(dwSize)` at `:49` → freed exactly once, at `:53` on failure or `:70` on success. Single owner; success path frees the *new* buffer. Correct code; deliberately not patched. |
| Semgrep alloca (error) | `src/crypto_internal.c:165/172`, `src/crypto_openssl.c:73` | `alloca(32)` — compile-time constant, aligned; no attacker control. |
| Semgrep alloca (error) | `src/dns_srv.c:159` | `alloca(strlen(query) + 12)` — `query` is a CLI option (≤ 254), fully bounded. |
| Semgrep alloca (error) | `src/ntservice.c:134, 137` | `alloca(sizeof(struct))` constants. |
| Semgrep format-string (error) | `src/kms.c:281` (release) | `formatString` is `%u` or `%0du` with digits forced to 1..9 — trusted, bounded, no attacker data. |
| Semgrep integer-wraparound (warning) | `src/kms.c:1041, 1186`, `src/dns_srv.c:202` | Multiplies are `uint16_t`/`sizeof` promoted to `size_t`; every value trivially bounded. |
| CodeQL `comparison-with-wider-type` (3), `constant-comparison`, `trivial-switch`, `loop-variable-changed`, `guarded-free`, `poorly-documented-function` | various | Lint-level, non-security. |
| Semgrep commented-out-code (58, note) | various | Intentionally retained reference implementations. |

---

## 4. Recommendations

1. **Sync the `release` branch (or cherry-pick `4e16fb2` + `f3101e9` + the follow-up `ucs2_to_utf8`/`checkPidLength` fixes above) into `master`** — otherwise `master` remains vulnerable. Semgrep/CodeQL/AFL now also scan `release`, but the open alerts are filed against `master` and will not auto-close until `master` is synced or the alerts are dismissed.
2. **Dismiss the section 3 false positives** via the code-scanning API (state `dismissed`, reason `false positive`) to make `0 dismissed` accurate and to keep future regressions visible.
3. Optionally close section 2 accepted-risk alerts with a `won't fix` dismissal and justification.

## Appendix — Full open-alert inventory (199)

Appended below; grouped by disposition. `#` = GitHub code-scanning alert number.
<details>
<summary>Full 199-alert inventory (click to expand)</summary>

```
# 12  OPEN              [warning] cpp/comparison-with-wider-type                              src/crypto.c:120
# 13  OPEN              [warning] cpp/comparison-with-wider-type                              src/kms.c:249
# 14  OPEN              [warning] cpp/comparison-with-wider-type                              src/vlmcs.c:270
# 15  OPEN              [warning] cpp/world-writable-file-creation                            src/output.c:48
# 16  OPEN              [warning] cpp/world-writable-file-creation                            src/vlmcs.c:1023
# 17  OPEN              [warning] cpp/world-writable-file-creation                            src/vlmcs.c:941
# 18  OPEN              [warning] cpp/world-writable-file-creation                            src/vlmcsd.c:1438
# 19  OPEN              [warning] cpp/path-injection                                          src/output.c:48
# 20  OPEN              [warning] cpp/path-injection                                          src/helpers.c:571
# 21  OPEN              [warning] cpp/path-injection                                          src/vlmcsd.c:1438
# 22  OPEN              [warning] cpp/uncontrolled-process-operation                          src/vlmcsd.c:954
# 23  OPEN              [warning] cpp/potentially-dangerous-function                          src/kms.c:354
# 24  OPEN              [warning] cpp/potentially-dangerous-function                          src/output.c:245
# 25  OPEN              [warning] cpp/potentially-dangerous-function                          src/output.c:216
# 26  OPEN              [warning] cpp/potentially-dangerous-function                          src/output.c:61
# 27  OPEN              [note   ] cpp/trivial-switch                                          src/vlmcs.c:394
# 28  OPEN              [note   ] cpp/trivial-switch                                          src/vlmcs.c:372
# 29  OPEN              [note   ] cpp/trivial-switch                                          src/vlmcsd.c:1796
# 30  OPEN              [note   ] cpp/loop-variable-changed                                   src/vlmcs.c:1165
# 31  OPEN              [note   ] cpp/guarded-free                                            src/vlmcs.c:868
# 32  OPEN              [warning] cpp/constant-comparison                                     src/helpers.c:112
# 33  OPEN              [note   ] cpp/commented-out-code                                      src/crypto_internal.h:31
# 34  OPEN              [note   ] cpp/commented-out-code                                      src/crypto_internal.h:27
# 35  OPEN              [note   ] cpp/commented-out-code                                      src/crypto.c:64
# 36  OPEN              [note   ] cpp/commented-out-code                                      src/crypto.c:41
# 37  OPEN              [note   ] cpp/commented-out-code                                      src/crypto_internal.c:139
# 38  OPEN              [note   ] cpp/commented-out-code                                      src/crypto_internal.c:134
# 39  OPEN              [note   ] cpp/commented-out-code                                      src/crypto_internal.c:61
# 40  OPEN              [note   ] cpp/commented-out-code                                      src/types.h:256
# 41  OPEN              [note   ] cpp/commented-out-code                                      src/types.h:130
# 42  OPEN              [note   ] cpp/commented-out-code                                      src/types.h:128
# 43  OPEN              [note   ] cpp/commented-out-code                                      src/types.h:86
# 44  OPEN              [note   ] cpp/commented-out-code                                      src/types.h:53
# 45  OPEN              [note   ] cpp/commented-out-code                                      src/types.h:25
# 46  OPEN              [note   ] cpp/commented-out-code                                      src/types.h:23
# 47  OPEN              [note   ] cpp/commented-out-code                                      src/network.h:17
# 48  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.h:267
# 49  OPEN              [note   ] cpp/commented-out-code                                      src/kms.h:372
# 50  OPEN              [note   ] cpp/commented-out-code                                      src/kms.h:14
# 51  OPEN              [note   ] cpp/commented-out-code                                      src/kms.h:10
# 52  OPEN              [note   ] cpp/commented-out-code                                      src/output.h:33
# 53  OPEN              [note   ] cpp/commented-out-code                                      src/kms.c:900
# 54  OPEN              [note   ] cpp/commented-out-code                                      src/network.c:679
# 55  OPEN              [note   ] cpp/commented-out-code                                      src/network.c:648
# 56  OPEN              [note   ] cpp/commented-out-code                                      src/network.c:532
# 57  OPEN              [note   ] cpp/commented-out-code                                      src/network.c:242
# 58  OPEN              [note   ] cpp/commented-out-code                                      src/network.c:43
# 59  OPEN              [note   ] cpp/commented-out-code                                      src/kms.c:778
# 60  OPEN              [note   ] cpp/commented-out-code                                      src/kms.c:722
# 61  OPEN              [note   ] cpp/commented-out-code                                      src/kms.c:321
# 62  OPEN              [note   ] cpp/commented-out-code                                      src/kms.c:76
# 63  OPEN              [note   ] cpp/commented-out-code                                      src/output.c:440
# 64  OPEN              [note   ] cpp/commented-out-code                                      src/output.c:79
# 65  OPEN              [note   ] cpp/commented-out-code                                      src/output.c:76
# 66  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.c:974
# 67  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.c:622
# 68  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.c:566
# 69  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.c:54
# 70  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.c:46
# 71  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.c:24
# 72  OPEN              [note   ] cpp/commented-out-code                                      src/rpc.c:16
# 73  OPEN              [note   ] cpp/commented-out-code                                      src/shared_globals.h:51
# 74  OPEN              [note   ] cpp/commented-out-code                                      src/shared_globals.h:47
# 75  OPEN              [note   ] cpp/commented-out-code                                      src/shared_globals.h:31
# 76  OPEN              [note   ] cpp/commented-out-code                                      src/shared_globals.h:28
# 77  OPEN              [note   ] cpp/commented-out-code                                      src/helpers.c:5
# 78  OPEN              [note   ] cpp/commented-out-code                                      src/dns_srv.c:319
# 79  OPEN              [note   ] cpp/commented-out-code                                      src/dns_srv.c:201
# 80  OPEN              [note   ] cpp/commented-out-code                                      src/dns_srv.c:149
# 81  OPEN              [note   ] cpp/commented-out-code                                      src/dns_srv.c:35
# 82  OPEN              [note   ] cpp/commented-out-code                                      src/dns_srv.c:25
# 83  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcs.c:1232
# 84  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcs.c:787
# 85  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcs.c:757
# 86  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcs.c:655
# 87  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcs.c:635
# 88  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcs.c:96
# 89  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcs.c:83
# 90  OPEN              [note   ] cpp/commented-out-code                                      src/vlmcsd.h:16
# 91  OPEN              [warning] cpp/poorly-documented-function                              src/vlmcs.c:1086
# 92  OPEN              [warning] cpp/poorly-documented-function                              src/vlmcs.c:960
# 96  FIXED-on-release  [error  ]                                                             src/crypto.c:48
# 97  FIXED-on-release  [error  ]                                                             src/kms.c:994
# 98  FIXED-on-release  [error  ]                                                             src/kms.c:806
# 99  FIXED-on-release  [error  ]                                                             src/crypto_internal.c:62
#100  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  fuzzing/afl-harness.c:86
#101  OPEN              [warning] 0xdea.c.unchecked-ret-malloc.raptor-unchecked-ret-malloc    fuzzing/afl-harness.c:148
#102  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  fuzzing/afl-harness.c:170
#103  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  fuzzing/afl-harness.c:190
#104  OPEN              [warning] 0xdea.c.insecure-api-rand-srand.raptor-insecure-api-rand-s  fuzzing/afl-harness.c:199
#105  OPEN              [error  ] 0xdea.c.use-of-source-size-in-copy.raptor-use-of-source-si  fuzzing/make-seeds.c:56
#106  OPEN              [warning] 0xdea.c.unchecked-ret-malloc.raptor-unchecked-ret-malloc    fuzzing/make-seeds.c:76
#107  OPEN              [error  ] c.lang.security.double-free.double-free                     fuzzing/make-seeds.c:95
#108  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto.c:118
#109  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_internal.c:64
#110  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_internal.c:95
#111  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_internal.c:96
#112  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_internal.c:123
#113  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_internal.c:131
#114  OPEN              [error  ] 0xdea.c.insecure-api-alloca.raptor-insecure-api-alloca      src/crypto_internal.c:165
#115  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_internal.c:165
#116  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_internal.c:167
#117  OPEN              [error  ] 0xdea.c.insecure-api-alloca.raptor-insecure-api-alloca      src/crypto_openssl.c:73
#118  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_openssl.c:73
#119  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_openssl.c:75
#120  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/crypto_openssl.c:91
#121  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/dns_srv.c:86
#122  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/dns_srv.c:87
#123  OPEN              [error  ] 0xdea.c.insecure-api-alloca.raptor-insecure-api-alloca      src/dns_srv.c:159
#124  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/dns_srv.c:160
#125  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/dns_srv.c:161
#126  FIXED-on-release  [warning] 0xdea.c.unchecked-ret-malloc.raptor-unchecked-ret-malloc    src/dns_srv.c:202
#127  FIXED-on-release  [warning] 0xdea.c.integer-wraparound.raptor-integer-wraparound        src/dns_srv.c:202
#128  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/dns_srv.c:274
#129  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/dns_srv.c:275
#130  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/dns_srv.c:275
#131  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/dns_srv.c:279
#132  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/dns_srv.c:280
#133  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/dns_srv.c:280
#134  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/getifaddrs-musl.c:125
#135  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/getifaddrs-musl.c:136
#136  OPEN              [warning] 0xdea.c.integer-wraparound.raptor-integer-wraparound        src/getifaddrs-musl.c:174
#137  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/getifaddrs-musl.c:174
#138  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/getifaddrs-musl.c:202
#139  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/ifaddrs-android.c:121
#140  OPEN              [warning] 0xdea.c.unchecked-ret-malloc.raptor-unchecked-ret-malloc    src/ifaddrs-android.c:127
#141  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/ifaddrs-android.c:129
#142  OPEN              [warning] 0xdea.c.unchecked-ret-malloc.raptor-unchecked-ret-malloc    src/ifaddrs-android.c:168
#143  OPEN              [warning] 0xdea.c.unchecked-ret-malloc.raptor-unchecked-ret-malloc    src/ifaddrs-android.c:310
#144  OPEN              [warning] 0xdea.c.integer-wraparound.raptor-integer-wraparound        src/ifaddrs-android.c:310
#145  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/ifaddrs-android.c:346
#146  OPEN              [warning] 0xdea.c.integer-wraparound.raptor-integer-wraparound        src/ifaddrs-android.c:403
#147  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/ifaddrs-android.c:460
#148  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/ifaddrs-android.c:471
#149  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/ifaddrs-android.c:472
#150  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/ifaddrs-android.c:578
#151  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/kms.c:271
#152  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:280
#153  FIXED-on-release  [error  ] 0xdea.c.format-string-bugs.raptor-format-string-bugs        src/kms.c:281
#154  FIXED-on-release  [error  ] 0xdea.c.insecure-api-sprintf-vsprintf.raptor-insecure-api-  src/kms.c:281
#155  OPEN              [warning] 0xdea.c.insecure-api-rand-srand.raptor-insecure-api-rand-s  src/kms.c:289
#156  OPEN              [warning] 0xdea.c.insecure-api-rand-srand.raptor-insecure-api-rand-s  src/kms.c:294
#157  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/kms.c:318
#158  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:319
#159  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:324
#160  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:325
#161  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:328
#162  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:329
#163  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:330
#164  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:331
#165  OPEN              [warning] 0xdea.c.insecure-api-rand-srand.raptor-insecure-api-rand-s  src/kms.c:333
#166  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:334
#167  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:335
#168  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:337
#169  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:338
#170  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:356
#171  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/kms.c:357
#172  OPEN              [warning] 0xdea.c.insecure-api-rand-srand.raptor-insecure-api-rand-s  src/kms.c:369
#173  OPEN              [warning] 0xdea.c.insecure-api-rand-srand.raptor-insecure-api-rand-s  src/kms.c:390
#174  FIXED-on-release  [error  ] 0xdea.c.insecure-api-alloca.raptor-insecure-api-alloca      src/kms.c:440
#175  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/kms.c:456
#176  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/kms.c:831
#177  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/kms.c:993
#178  FIXED-on-release  [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/kms.c:994
#179  OPEN              [error  ] 0xdea.c.use-of-source-size-in-copy.raptor-use-of-source-si  src/kms.c:1041
#180  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/kms.c:1137
#181  OPEN              [error  ] 0xdea.c.use-of-source-size-in-copy.raptor-use-of-source-si  src/kms.c:1186
#182  OPEN              [error  ] 0xdea.c.use-of-source-size-in-copy.raptor-use-of-source-si  src/libkms-test.c:17
#183  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/libkms-test.c:25
#184  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/libkms.c:63
#185  FIXED-on-release  [error  ] 0xdea.c.insecure-api-alloca.raptor-insecure-api-alloca      src/libkms.c:64
#186  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/libkms.c:132
#187  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/libkms.c:138
#188  OPEN              [warning] 0xdea.c.signed-unsigned-conversion.raptor-signed-unsigned-  src/ns_name.c:200
#189  OPEN              [error  ] 0xdea.c.insecure-api-alloca.raptor-insecure-api-alloca      src/ntservice.c:134
#190  OPEN              [error  ] 0xdea.c.insecure-api-alloca.raptor-insecure-api-alloca      src/ntservice.c:137
#191  OPEN              [warning] 0xdea.c.overlapping-source-destination.raptor-overlapping-  src/ntservice.c:187
#192  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/ntservice.c:187
#193  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/ntservice.c:202
#194  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/ntservice.c:206
#195  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/ntservice.c:207
#196  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/ntservice.c:208
#197  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/ntservice.c:211
#198  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/ntservice.c:237
#199  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/ntservice.c:238
#200  OPEN              [error  ] 0xdea.c.format-string-bugs.raptor-format-string-bugs        src/ntservice.c:278
#201  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/vlmcsdmulti.c:51
#202  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/vlmcsdmulti.c:52
#203  OPEN              [error  ] c.lang.security.double-free.double-free                     src/wintap.c:53
#204  OPEN              [warning] c.lang.security.use-after-free.use-after-free               src/wintap.c:58
#205  OPEN              [warning] c.lang.security.use-after-free.use-after-free               src/wintap.c:58
#206  OPEN              [warning] c.lang.security.use-after-free.use-after-free               src/wintap.c:58
#207  OPEN              [error  ] c.lang.security.double-free.double-free                     src/wintap.c:70
#208  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/wintap.c:203
#209  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/wintap.c:204
#210  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/wintap.c:205
#211  OPEN              [warning] c.lang.security.insecure-use-string-copy-fn.insecure-use-s  src/wintap.c:217
#212  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/wintap.c:218
#213  OPEN              [warning] c.lang.security.insecure-use-strcat-fn.insecure-use-strcat  src/wintap.c:219
```

</details>

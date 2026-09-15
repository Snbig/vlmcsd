# Security Audit Report — Snbig/vlmcsd

**Date:** 2026-09-15
**Audited revision:** `release` branch @ `41f523e` (working tree)
**Audit type:** Static, read-only defensive security audit (no execution, no build, no modification of source)
**Deliverables:** `security-audit.sarif` (SARIF 2.1.0) + this report

---

## 1. Scope and Method

- **Target:** Entire `Snbig/vlmcsd` repository (fork of Wind4/vlmcsd, a KMS server emulator). Default branch `master`; audited working tree is `release` @ `41f523e`. `master` exists and is unpatched relative to `release`.
- **Method:** 10 specialized audit agents ran concurrently, each with a distinct focus:
  1. Backdoor / hidden access
  2. Logic bomb / time bomb
  3. Malware / payload delivery
  4. Network behavior / exfiltration
  5. Secrets / credentials
  6. Supply-chain / build integrity
  7. Obfuscation / anti-analysis
  8. Persistence / privilege
  9. Control & data-flow anomalies
  10. Repository history / provenance
- **Rules:** No execution of repository code; static analysis only; no source modification; findings verified against actual code (not comments or commit messages).
- **Verification:** Every finding below was re-verified against the current source before inclusion.

## 2. Executive Summary

**No backdoor, logic bomb, malware, exfiltration, or supply-chain compromise indicators were found.** All reported findings are upstream Wind4 behaviors or hardening gaps; none show signs of intentional malice.

Of the 10 agents' raw findings, **5 were retained** after deduplication, correlation, and source verification (1 high, 1 medium, 1 low, 2 notes). Three findings (unauthenticated KMS RPC + default all-interface bind, mutable GitHub Actions version tags, single-author history) were **dismissed by the operator** as accepted-risk / process observations.

| Severity | Count |
|----------|-------|
| High (error) | 1 |
| Medium (warning) | 1 |
| Low (note) | 1 |
| Note | 2 |
| **Total** | **5** |

## 3. Findings

| ID | Title | Severity | Confidence | Location |
|----|-------|----------|------------|----------|
| SEC-AUDIT-001 | Heap buffer overflow in DNS SRV `serverName` append | High | High | `src/dns_srv.c:233-239` |
| SEC-AUDIT-002 | Incomplete privilege drop when only `-u` is specified | Medium | High | `src/vlmcsd.c:1867-1889` |
| SEC-AUDIT-003 | Full ePID and KMS host Hardware ID written to log | Low | High | `src/kms.c:564-570`, `src/output.c:230-239` |
| SEC-AUDIT-004 | Hardcoded `BUILD_TIME` clamps ePID timestamps | Note | High | `src/kms.c:346-351` |
| SEC-AUDIT-005 | Wine emulation environment detection | Note | High | `src/msrpc-server.c:135-145` |

---

### SEC-AUDIT-001 — Heap buffer overflow in DNS SRV `serverName` append (High)

- **Category:** memory-corruption · **Confidence:** high
- **Location:** `src/dns_srv.c:233-239` (buffer declared `src/dns_srv.h:18`)

**Description:** In `getKmsServerList()`, `ns_name_uncompress()` writes a DNS name of up to 255 octets + NUL (256 bytes) into `kms_server->serverName`, a `char[260]` heap buffer. The subsequent `sprintf()` appends `:port` (up to 6 chars + NUL = 7 bytes) with no bounds check. Worst case: 256 + 7 = **263 bytes into a 260-byte buffer** — up to 3 bytes past the end of the heap allocation.

**Technical evidence:**
```c
/* src/dns_srv.c:233 */
if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), srvrecord->name,
                       kms_server->serverName, sizeof(kms_server->serverName)) < 0)
...
/* src/dns_srv.c:239 */
sprintf(kms_server->serverName + strlen(kms_server->serverName), ":%hu", GET_UA16BE(&srvrecord->port));
/* src/dns_srv.h:18 */
char serverName[260];
```

**Attack / trigger condition:** A malicious or compromised DNS server returns an SRV record whose target name is at or near the 255-octet DNS maximum. The `vlmcs` client (or `vlmcsd` in DNS-resolver mode) then overflows the heap buffer while appending the port. The attacker controls the DNS response, making the overflow attacker-influenced.

**Impact:** Heap corruption in the client path; potential crash, or limited memory corruption depending on adjacent heap layout.

**Why suspicious:** Unbounded `sprintf()` appending to a fixed-size heap buffer is a classic memory-corruption pattern; two independent audit agents flagged the same lines.

**Benign explanation:** Upstream Wind4/vlmcsd code, not introduced by this fork. The overflow is small (≤3 bytes) and requires a hostile DNS response. A genuine bug, but no sign of intentional backdooring.

**Recommended action:** Replace `sprintf()` with `snprintf()` bounded by remaining buffer space:
```c
snprintf(kms_server->serverName + strlen(kms_server->serverName),
         sizeof(kms_server->serverName) - strlen(kms_server->serverName),
         ":%hu", GET_UA16BE(&srvrecord->port));
```

---

### SEC-AUDIT-002 — Incomplete privilege drop when only `-u` is specified (Medium)

- **Category:** privilege · **Confidence:** high
- **Location:** `src/vlmcsd.c:1867-1889`

**Description:** When the daemon is started with `-u <user>` but without `-g <group>`, `gid` remains `INVALID_GID`, so the `setgid()` and `setgroups()` calls are skipped entirely. `setuid()` runs alone, leaving the process with the root primary group and all root supplementary groups.

**Technical evidence:**
```c
/* src/vlmcsd.c:1867-1889 */
if (gid != INVALID_GID)
{
    if (setgid(gid)) { ... return errno; }
    if (setgroups(1, &gid)) { ... return errno; }
}
if (uid != INVALID_UID && setuid(uid)) { ... return errno; }
```

**Attack / trigger condition:** Operator runs the daemon as root with `-u` but omits `-g`. If the daemon is later compromised (e.g. via SEC-AUDIT-001 or another memory-safety bug), the attacker retains the root primary group and root supplementary groups.

**Impact:** Privilege escalation from a daemon compromise to group-level access — files/directories accessible to root's groups, and any capability granted via supplementary groups.

**Why suspicious:** Incomplete privilege drop is a classic hardening flaw that widens the blast radius of any memory-corruption bug in the daemon.

**Benign explanation:** Upstream Wind4 behavior; documented usage expects both `-u` and `-g`. No evidence of intentional malice — an incomplete hardening measure.

**Recommended action:** When `-u` is given without `-g`, resolve the user's primary group via `getpwnam()` and call `setgid()` + `setgroups(0, NULL)`, or require `-g` explicitly.

---

### SEC-AUDIT-003 — Full ePID and KMS host Hardware ID written to log (Low)

- **Category:** information-disclosure · **Confidence:** high
- **Location:** `src/kms.c:564-570`, `src/output.c:230-239`

**Description:** For every activation response, the full randomized ePID is written to the log. In verbose mode, the 64-bit KMS host Hardware ID and the client machine ID are additionally logged. These are per-host unique identifiers.

**Technical evidence:**
```c
/* src/kms.c:564 */
logger("Sending ePID (%s): %s\n", EpidSource, utf8pid);
/* src/kms.c:570 */
logResponseVerbose(utf8pid, hwId, baseResponse, &logger);
/* src/output.c:230,233,239 */
p("KMS host extended PID           : %s\n", ePID);
p("KMS host Hardware ID            : %016llX\n", ...);
p("Client machine ID               : %s\n", guidBuffer);
```

**Attack / trigger condition:** An attacker who obtains the daemon log file (log disclosure, backup leak, shared logging infrastructure) can extract per-host identifiers for every activation event.

**Impact:** Privacy/correlation risk — leaked logs enable tracking of activation activity and host fingerprinting.

**Why suspicious:** Logging unique per-host identifiers is a data-exfiltration-adjacent pattern, though here it is written to the local log only, not transmitted.

**Benign explanation:** Upstream Wind4 logging behavior; verbose logging is opt-in (`-v`). No network transmission of these values was found.

**Recommended action:** Redact or truncate ePID/Hardware ID in logs, or restrict log file permissions and treat logs as sensitive.

---

### SEC-AUDIT-004 — Hardcoded `BUILD_TIME` clamps ePID timestamps (Note)

- **Category:** logic · **Confidence:** high
- **Location:** `src/kms.c:346-351`

**Description:** `BUILD_TIME` is hardcoded to `1538922811` (2018-10-07) as a fallback when the build system does not inject the real timestamp. `maxTime` is clamped to this value, so generated ePIDs never carry timestamps earlier than 2018-10-07. The surrounding comment still references "10/17/2013 1:00 pm" — stale and misleading.

**Technical evidence:**
```c
/* src/kms.c:346-351 */
#ifndef BUILD_TIME
#	define BUILD_TIME 1538922811
...
if (maxTime < (time_t)BUILD_TIME) // Just in case the system time is < 10/17/2013 1:00 pm
	maxTime = (time_t)BUILD_TIME;
```
`src/GNUmakefile:161` injects the real timestamp via `-DBUILD_TIME=$(shell date '+%s')` when building with GNU make.

**Attack / trigger condition:** Only reachable when the build system does not define `BUILD_TIME` (non-GNUmakefile builds). Clamps generated ePID timestamps to ≥ 2018-10-07.

**Impact:** Cosmetic/functional only — ePIDs on misconfigured builds carry a fixed floor timestamp; no security impact. The stale comment could mislead maintainers.

**Why suspicious:** A hardcoded timestamp constant with a mismatched comment is a minor integrity smell, but it is a documented fallback pattern.

**Benign explanation:** Fallback for systems with wrong clocks, preventing ePIDs with implausible pre-build timestamps. Not malicious.

**Recommended action:** Update the stale comment to match the constant, or always inject the real build timestamp from the build system.

---

### SEC-AUDIT-005 — Wine emulation environment detection (Note)

- **Category:** environment-detection · **Confidence:** high
- **Location:** `src/msrpc-server.c:135-145`

**Description:** In `getClientIp()`, when `SUPPORT_WINE` is defined (disabled by default), the code resolves `wine_get_unix_file_name` from `kernel32.dll` via `GetProcAddress()`. If present, it returns `RPC_S_CANNOT_SUPPORT` instead of calling `RpcBindingServerFromClient()`, because Wine terminates the calling thread on that call. Environment detection that changes control flow — but a documented compatibility workaround, not malicious behavior.

**Technical evidence:**
```c
/* src/msrpc-server.c:135-145 */
// Fix for wine (disabled by default, because vlmcsd runs natively on all platforms where wine runs)
#ifdef SUPPORT_WINE
HMODULE h = GetModuleHandleA("kernel32.dll");
if (h)
{
    // Since wine simply terminates the thread when RpcBindingServerFromClient is called, we exit with an error
    if (GetProcAddress(h, "wine_get_unix_file_name")) return RPC_S_CANNOT_SUPPORT;
}
#endif // SUPPORT_WINE
```
`SUPPORT_WINE` is not defined anywhere in the tree.

**Attack / trigger condition:** Only compiled when `SUPPORT_WINE` is explicitly defined by the builder. When active, running under Wine causes the RPC client-IP lookup to fail gracefully instead of crashing the thread.

**Impact:** None in default builds. In `SUPPORT_WINE` builds, behavior differs under Wine (graceful failure) vs native Windows (normal operation).

**Why suspicious:** Dynamic symbol resolution to detect an emulation environment and change behavior is a pattern also used by malware to evade analysis.

**Benign explanation:** Documented Wine compatibility workaround — Wine terminates the thread on `RpcBindingServerFromClient()`, so the code detects Wine and returns an error instead. Disabled by default; no evasion of security tooling is involved.

**Recommended action:** No action required; keep disabled by default and retain the explanatory comment.

---

## 4. Dismissed Findings (operator decision)

| # | Finding | Reason for dismissal |
|---|---------|----------------------|
| 3 | Unauthenticated KMS RPC + default bind `0.0.0.0`/`::` (`PublicIPProtectionLevel=0`) | Accepted risk — inherent to a KMS server emulator's purpose; upstream default behavior; operator dismissed |
| 4 | GitHub Actions pinned to mutable tags (`@v4`/`@v3`/`@v2`) instead of SHA digests | Process/hardening preference, not a code defect; operator dismissed |
| 8 | Single-author post-fork history, no upstream merges since 2020 base, no tags | Process observation only; no malicious artifact found; operator dismissed |

## 5. Conclusion

This audit found **no evidence of backdoors, logic bombs, malware, exfiltration, obfuscation, or supply-chain compromise** in the audited revision. The five retained findings are genuine but non-malicious issues: one real memory-safety bug (DNS SRV heap overflow), one hardening gap (incomplete privilege drop), one logging/privacy concern, and two informational notes.

**Limitations:** This is a static analysis only. No execution, fuzzing, or dynamic analysis was performed. Static analysis cannot prove the absence of malicious behavior — it can only bound the search space. Findings were verified against source code, not comments or commit messages, but a determined actor could still hide behavior in build-time configuration, runtime data, or external dependencies not fully enumerated here. The `master` branch remains unpatched relative to `release` and was not the audited working tree.

**Highest-confidence items for follow-up:** SEC-AUDIT-001 (heap overflow, attacker-influenced, should be fixed) and SEC-AUDIT-002 (privilege drop gap, should be fixed).
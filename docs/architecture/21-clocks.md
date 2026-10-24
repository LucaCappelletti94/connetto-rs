# 21: Clocks

**Status**: normative. Every timer and deadline in the tree follows the rule of its class below. **Built (R72, 2026-10-20)**, which closes X6.

## What the clocks do across a suspend

| Clock | Counts suspend | Source |
|---|---|---|
| `std::time::Instant` and `tokio::time` on Linux and Android | no, `CLOCK_MONOTONIC` | [Rust `Instant`](https://doc.rust-lang.org/std/time/struct.Instant.html#underlying-system-calls), [clock_gettime(2)](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) |
| `std::time::Instant` and `tokio::time` on Apple | no, `CLOCK_UPTIME_RAW` | [Rust `Instant`](https://doc.rust-lang.org/std/time/struct.Instant.html#underlying-system-calls), [`mach_absolute_time`](https://developer.apple.com/documentation/kernel/1462446-mach_absolute_time) |
| `std::time::Instant` and `tokio::time` on Windows | yes, `QueryPerformanceCounter` | [Acquiring high-resolution time stamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps) |
| `CLOCK_BOOTTIME`, Darwin `CLOCK_MONOTONIC`, Android `elapsedRealtime` | yes | [clock_gettime(2)](https://man7.org/linux/man-pages/man2/clock_gettime.2.html), [`mach_continuous_time`](https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time), [SystemClock](https://developer.android.com/reference/android/os/SystemClock) |
| `performance.now()` | unspecified, browsers differ | [HR-Time](https://w3c.github.io/hr-time/), [w3c/hr-time#115](https://github.com/w3c/hr-time/issues/115) |
| Wall clocks, `SystemTime`, `Date.now()`, Postgres `now()` | yes, and they step either way | [clock_gettime(2)](https://man7.org/linux/man-pages/man2/clock_gettime.2.html), [PostgreSQL](https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-CURRENT) |

Rust leaves open whether `Instant` counts suspend ([rust-lang/rust#87906](https://github.com/rust-lang/rust/issues/87906)), so no rule below depends on it.

## The rule per class

**Built (R72).** The rows are classes A to H from the top, the letters code comments cite.

| Class | Clock | Across a suspend |
|---|---|---|
| A bound on one operation in progress: connect, handshake, hello, write and drain bounds, `EXCHANGE_BOUND`, `CALL_BOUND`, hotspot join and scan bounds, `SessionConfig`'s first-frame, resume and write-retry budgets, the keyring prompt and unlock windows, the demos' login window | process monotonic, `tokio::time` | resumes with its remainder, or fires at wake on Windows. A network bound is a minute or less and its socket or radio does not outlive a long sleep. A prompt or login window waits on a person, who is away for the sleep too, so both behaviors end the operation correctly |
| A pace or retry wait: `RetryPolicy` backoff, the client's machine-loop ticks, discovery redial, the peer link's ping and silence limit, the status-list refetch, the CDC reconnect | process monotonic | resumes with its remainder. `RetryPolicy`'s jitter spreads episodes that start together |
| A periodic server sweep: the writer sweep, the content sweep, the slot lag watch | `tokio::time::interval` with `MissedTickBehavior::Delay` | one pass after the stall, never a burst of passes |
| A deadline inside the browser worker: hello, staged, resolve and resend waits in `connetto-web` | `performance.now()` | a wall step cannot lengthen or shorten it. `Date.now()` stays for identities and user-visible times |
| Time away and the writer-answer deadline | sleep-counting monotonic (`CLOCK_BOOTTIME`, Darwin `CLOCK_MONOTONIC`, `QueryPerformanceCounter`, `performance.now()` in the browser). Time away also reads the wall clock, the larger delta winning (chapter 14) | counts the sleep. Time away in a browser whose `performance.now()` stops in sleep is covered by the wall delta, and the writer-answer deadline there resumes after wake |
| A countdown in the replica: watch grace (`subscriptions.rs`), aggregate `updated_at` | the replica's wall clock, `clock::now_secs` | keeps running through suspend and offline, as chapter 15 decides. A stop moment ahead of the current time, a wall clock stepped back, is re-anchored to now with capture suspended, so the countdown never outlasts its grace and the write never rides an upload |
| A wall deadline written on one machine and checked on another: certificate windows, revocation lists, a registration code's expiry the minting device writes, access, resume and share-key tokens, content tickets | wall, with `connetto_core::clock::DEVICE_SKEW` (5 min) wherever a device or peer clock is on either side, and `SERVER_SKEW` (60 s) when deployment servers both sign and check | not affected. A revoked serial stays on the published list until its certificate's expiry plus `DEVICE_SKEW`, since a peer accepts a certificate that long past `not_after` |
| A deadline Postgres stores: session idle and absolute deadlines, bans, retained provider tokens, a registration code's `used_at`, certificate liveness, file timestamps and the sweep grace | Postgres `now()`, in the statement that writes or reads it. An in-memory store serves one process and keeps the same deadlines on the process clock | not affected. Several servers sharing one database (chapter 10) agree on one clock, the rule `audit.rs` already states for `auth_events` |

**Decided (R72, 2026-10-20), the two tolerances.** RFC 7519 allows "small leeway, usually no more than a few minutes" ([4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)). Five minutes serves devices, whose clocks drift off-grid (chapter 19). Servers run NTP, and a wider leeway there only keeps a stolen access token or ticket usable longer. One five-minute tolerance everywhere was rejected for that reason.

## A device waking after a week

The walk X6 named. Watches still held when the device slept start no countdown. Those dropped in the grace before sleep are past it on wake. Eviction waits for the transport (chapter 15), and the first connected pump step in `live.rs` `drain_dropped` unsubscribes each expired record in turn, evicting rows scoped to its own tables. Operation bounds and pace waits resume with their remainder, or fire at wake on Windows, each within its own bound and jitter. The away gate counts the week and asks the prompt if the gate is set (chapter 14). A certificate that expired during the week stops the peer link and raises `ClientEvent::CertificateExpired` (chapter 19).

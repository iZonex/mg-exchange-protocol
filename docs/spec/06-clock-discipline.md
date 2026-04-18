# Clock Discipline (MGEP Spec §6)

MGEP timestamps are `u64` nanoseconds since the Unix epoch. This is not
negotiable — the regulatory backdrop (MiFID II RTS 25, SEC Reg SCI,
CFTC §1.31) requires traceable, low-drift wall-clock timestamps on every
trading-venue event.

This section is **normative** for any deployment that holds itself out as a
regulated trading venue. Colocated internal systems MAY operate at a lower
tier but MUST still declare what they are doing via `ClockStatus`.

## 6.1 Requirements

A conformant MGEP server:

1. SHALL discipline its wall clock with a traceable source (PTPv2 per IEEE
   1588-2019 or NTP). Systems without a traceable source MUST emit
   `ClockStatus.source = MonotonicOnly` or `Unsynchronized` and MUST NOT
   claim regulatory-grade timestamps.
2. SHALL broadcast `ClockStatus` (SessionMsgType `0x0E`) on every session
   channel at least once per second.
3. SHALL broadcast `ClockStatus` immediately on any transition of
   `ClockQuality` (e.g. loss of PTP lock degrades `RegulatoryGrade` →
   `OperationalGrade`).
4. MUST NOT emit post-trade / transaction-report messages with
   `transact_time` when `ClockQuality != RegulatoryGrade`. Emit a
   `BusinessReject` with `business_reason = "clock_quality_inadequate"`
   instead and raise the condition to ops.

## 6.2 Source & Quality taxonomy

| `ClockSource` (u8) | Description | Typical drift | Regulatory |
|---|---|---|---|
| `PtpHardwareTimestamp = 1` | PTPv2 + hardware NIC timestamping | ≤ 50 μs | **Yes** |
| `PtpSoftwareTimestamp = 2` | PTPv2 + kernel SO_TIMESTAMPING | ≤ 1 ms | No |
| `Ntp = 3` | plain NTP | ≤ 10 ms, WAN-dependent | No |
| `MonotonicOnly = 4` | CLOCK_MONOTONIC + fixed offset | unbounded from UTC | No |
| `Unsynchronized = 5` | no discipline | unbounded | No |

| `ClockQuality` (u8) | Condition | Allowed for regulatory emission |
|---|---|---|
| `RegulatoryGrade = 1` | PTP-HW AND drift ≤ 100 μs | **Yes** |
| `OperationalGrade = 2` | PTP-* OR NTP AND drift ≤ 10 ms (PTP) / ≤ 50 ms (NTP) | No |
| `BestEffort = 3` | PTP-* or NTP with higher drift | No |
| `Unreliable = 4` | monotonic-only / unsynchronized | No |

## 6.3 Wire format — `ClockStatus` (40 bytes)

```
offset  size  field
  0      1    source            (ClockSource)
  1      1    quality           (ClockQuality)
  2      6    _pad
  8      8    observed_at       (nanos since epoch)
 16      8    last_sync         (nanos since epoch)
 24      8    estimated_drift_ns
 32      8    reference_clock_id (PTP GrandMaster ID / NTP stratum, truncated)
```

No flex block. Broadcast on the session layer (`schema_id = 0x0000`,
`message_type = 0x0E`).

## 6.4 Linux PTP deployment (recommended)

Regulated deployments MUST use a PTP-aware NIC (e.g. Intel I210, Mellanox
ConnectX-5 or later). The software stack is `linuxptp`:

```
sudo apt-get install linuxptp

# /etc/linuxptp/ptp4l.conf — PTPv2, hardware timestamping, slave mode
[global]
time_stamping           hardware
delay_mechanism         E2E
network_transport       UDPv4
tx_timestamp_timeout    10
# Trading-venue tuning:
# step_threshold — never step the clock during trading hours.
step_threshold          0.0

# /etc/linuxptp/phc2sys.conf — sync the PHC into CLOCK_REALTIME
[global]
clock_step_threshold    0.0
```

Services:

```
sudo systemctl enable --now ptp4l@eth0
sudo systemctl enable --now phc2sys
```

Verify discipline is healthy:

```
pmc -u -b 0 'GET TIME_STATUS_NP'         # offset-from-master, usually < 100 ns on LAN
pmc -u -b 0 'GET PARENT_DATA_SET'         # grandmasterIdentity
chronyc tracking || ntpq -p               # fallback sanity
```

The MGEP `ClockMonitor` expects a `ClockSourceProbe` implementation that
reads `clock_adjtime(CLOCK_REALTIME)` for the `maxerror` / `esterror`
fields and queries the PHC via `/dev/ptp0` for the reference clock ID.
This project does not ship a Linux implementation; see
`clock_discipline.rs` for the trait and tests.

## 6.5 Audit trail integration

A `ClockMonitor::regulatory_ok()` gate is the recommended integration point:
every transaction-report emission passes through it and either proceeds
(quality is `RegulatoryGrade`) or emits a `BusinessReject`. Record the
`ClockStatus` at the moment of the event in the audit log so after-the-fact
regulators can verify the clock was disciplined at the critical instant.

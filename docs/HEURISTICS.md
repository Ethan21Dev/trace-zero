# Anomaly heuristics

Ten rules each compute one transparent statistic over the capture. A finding is a **possible
anomaly**: something worth an analyst's attention. No rule can establish intent, and every
explanation lists benign causes that produce the same signature.

Every finding carries: severity, the hosts involved, first/last event time, event timestamps,
supporting frame numbers (up to `max_refs`, with the full count), the rule ID, a plain-language
explanation with the numbers that triggered it, and a confidence level with its reason.

Thresholds live in `[anomaly]` of the configuration file (see `config.example.toml`).

## TZ-R1 - Repeated failed connection attempts

**Statistic.** Each TCP SYN (SYN without ACK) is classified by its 4-tuple:
*accepted* (a SYN-ACK came back), *refused* (an RST came back) or *unanswered* (neither appears
in the capture). Failed attempts are grouped by (source, destination, destination port) and the
largest count inside a sliding `repeat_window_s` window is taken.

**Fires when** that count >= `repeat_min_attempts` (default 6 in 120 s).

**Severity.** MEDIUM; HIGH at three times the threshold.
**Confidence.** HIGH when refusals were observed (both directions captured). MEDIUM when attempts
were only unanswered - the capture point may simply not see return traffic.

Successful repeated connections are deliberately ignored: browsers and agents open many.

## TZ-R2 - Destination port fan-out

**Statistic.** Connection initiations per source: TCP SYNs, and for UDP the first packet of each
5-tuple flow (in either direction). The maximum number of distinct (protocol, destination port)
pairs inside a sliding `fanout_window_s` window.

**Fires when** distinct ports >= `fanout_min_ports` (default 20 in 60 s).

**Severity.** MEDIUM; HIGH at 2.5x the threshold.
**Confidence.** HIGH when TCP-based and at least twice the threshold; LOW for UDP-only
(initiation is inferred from the first packet seen); otherwise MEDIUM.

## TZ-R3 - Traffic volume spike

**Statistic.** Bytes per `spike_bin_s` bin across the capture. Robust z-score
`(bytes - median) / (1.4826 x MAD)`; consecutive flagged bins merge into one finding.

**Fires when** z >= `spike_z`, bytes >= `spike_min_bytes` and bytes >= `spike_min_factor` x median.
Needs at least `spike_min_bins` bins.

**Severity.** LOW; MEDIUM when the peak is 20x the median.
**Confidence.** From the size of the baseline: HIGH (>= 60 bins), MEDIUM (>= 20), LOW otherwise.
The explanation lists the top three contributing source -> destination pairs and their share.

## TZ-R4 - DNS query frequency spike

**Statistic.** DNS queries (port 53 only; mDNS and LLMNR are excluded) per source per
`dns_bin_s` bin, compared with that source's own median bin.

**Fires when** a bin has >= `dns_min_queries` and >= `dns_min_factor` x the source's baseline.

**Context reported.** Distinct names and uniqueness ratio, most common suffix, NXDOMAIN share of
observed responses.
**Severity.** MEDIUM if most responses are NXDOMAIN or > 80 % of names are unique; else LOW.
**Confidence.** MEDIUM when responses were observed; LOW when the burst is one-sided.

## TZ-R5 - Unusually frequent host-pair communication

**Statistic.** Separate *contacts* per (source, destination): TCP SYNs, new UDP flows and ICMP
echo requests. Robust z-score of each pair's count against all pairs, plus the coefficient of
variation (CV) of the intervals between contacts.

**Fires when** count >= `pair_min_contacts` and either z >= `pair_z` (volume outlier) or
CV <= `pair_periodic_cv` with z >= `pair_periodic_z` (regular cadence). Needs at least
`pair_min_pairs` pairs for a baseline.

**Severity.** MEDIUM for regular cadence (automated check-ins: update agents, monitoring - or
beaconing), LOW for volume only.
**Confidence.** MEDIUM with >= 10 pairs in the baseline, LOW otherwise.

## TZ-R6 - One IPv4 address claimed by several MAC addresses

**Statistic.** For every ARP packet, the sender IPv4 address and sender hardware address. The
number of distinct MACs announcing each IPv4 address, and how many times the claimant switched.

**Fires when** two or more MACs claim the same address (`0.0.0.0` probes are ignored).

**Severity.** MEDIUM; HIGH when the claimant switched three or more times (a tug of war).
**Confidence.** MEDIUM: the ARP fields are observed directly, but VRRP/HSRP failover, bonded NICs
and replaced hardware produce the same packets legitimately.

## TZ-R7 - DNS responses without a matching query

**Statistic.** Each DNS response (port 53) is matched to a query by client address and port,
server address and port, and transaction ID. Responses with no matching query, and duplicate
responses to one query whose answers differ from the first response, are counted per client.

**Fires when** a client has >= `dns_unsolicited_min` unmatched responses (default 1), or any
conflicting duplicate. Responses in the first `dns_startup_grace_s` seconds (default 1) are
ignored because their query may predate the capture, and clients whose queries never appear
at all (one-sided capture) are skipped.

**Severity.** HIGH when conflicting answers were seen, otherwise MEDIUM.
**Confidence.** MEDIUM with conflicts or three or more unmatched responses, LOW otherwise.

## TZ-R8 - Heavy outbound transfer

**Statistic.** Bytes on the wire per directed pair over the whole capture, for pairs from an
internal address (RFC 1918, IPv6 ULA, link-local, loopback) to an external one (public and
documentation ranges).

**Fires when** the internal host sent >= `outbound_min_bytes` (default 500 KB) and at least
`outbound_ratio` (default 5) times what it received from that peer.

**Severity.** LOW; MEDIUM from four times the byte threshold.
**Confidence.** MEDIUM: byte counts are exact, but "internal" and "external" are judged from
address ranges only. Backups, uploads and video calls look the same.

## TZ-R9 - New external destinations late in the capture

**Statistic.** The capture is split at `max(late_fraction x duration, late_min_baseline_s)`
(defaults 50 % and 60 s). External hosts first observed after the split, contacted by an
internal host with at least `late_min_bytes` (default 5 KB) exchanged, are grouped per
internal host.

**Severity.** LOW - this marks where a host's external footprint changed, nothing more.
**Confidence.** MEDIUM when the baseline is at least 10 minutes, LOW otherwise.

## TZ-R10 - TLS server name does not match observed DNS answers

**Statistic.** Every A/AAAA answer in the capture, per name; every TLS ClientHello's SNI and
destination address.

**Fires when** a ClientHello names a server that DNS in the capture resolved, but goes to an
address none of those answers contained.

**Severity.** MEDIUM.
**Confidence.** MEDIUM: lookups made before the capture, through another resolver or over
DNS-over-HTTPS are invisible here. CDNs, hard-coded addresses and stale caches cause this; so do
domain fronting and traffic avoiding the local resolver.

## Triage and suppression

Heuristics are noisy by nature, so findings carry an analyst status:

* `T` on a finding sets **open**, **benign** or **escalated**, with a reason. Status is stored per
  investigation and capture, appears in the findings list, the inspector and both exports, and
  is journaled.
* `z` creates a **suppression rule** from the selected finding: the rule ID plus, optionally, a
  host. Matching findings are hidden from the list, the timeline markers and event stepping, in
  this and future captures of the investigation. A reason is required. `Z` shows suppressed
  findings again (marked as such); suppressions are listed in the journal (`delete` removes one)
  and exported with their reasons, so nothing disappears silently from a report.

## Inspecting evidence

In the findings view (`f`), `enter` replaces the packet filter with the finding's supporting
frames and switches to the packet list; the histogram then shows exactly when the evidence
occurred. `shift+left` / `shift+right` step through it chronologically, `esc` clears the filter.
Notes added with `a` are attached to the finding and exported next to it, marked as analyst
interpretation.

## Determinism

Rules iterate in capture-time order with stable tie-breaking, and finding IDs are a hash of the
rule and its defining values, so the same capture always yields the same findings and IDs.
That is what lets notes and bookmarks reattach to findings when a capture is reopened.

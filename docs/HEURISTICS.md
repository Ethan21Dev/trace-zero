# Anomaly heuristics

Each rule computes one transparent statistic over the capture. A finding is a **possible
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

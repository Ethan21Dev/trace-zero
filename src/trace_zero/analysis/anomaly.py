"""Explainable anomaly heuristics.

Each rule is a small, transparent statistic over observed packets. Output is a
*possible anomaly*: a pointer to traffic worth an analyst's attention, never a
verdict about intent. Every finding carries the rule that fired, the numbers
behind it, supporting frame numbers and a confidence statement describing how
much the available evidence can support.
"""

from __future__ import annotations

import hashlib
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from trace_zero.analysis.index import CaptureIndex, ip_sort_key
from trace_zero.config import AnomalyConfig
from trace_zero.models import fmt_bytes, fmt_duration, fmt_ts


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule(
            "TZ-R1",
            "Repeated failed connection attempts",
            "One source sent many TCP SYNs to the same destination port that were refused (RST) "
            "or never answered within the capture, inside a sliding time window.",
        ),
        Rule(
            "TZ-R2",
            "Destination port fan-out",
            "One source initiated connections (TCP SYN or a new UDP flow) to an unusually large "
            "number of distinct destination ports inside a sliding time window.",
        ),
        Rule(
            "TZ-R3",
            "Traffic volume spike",
            "Bytes per time bin far above the capture's own median, measured with a robust "
            "(median / MAD) z-score.",
        ),
        Rule(
            "TZ-R4",
            "DNS query frequency spike",
            "One source issued far more DNS queries in a time bin than its own baseline for the capture.",
        ),
        Rule(
            "TZ-R5",
            "Unusually frequent host-pair communication",
            "A source/destination pair has far more separate contacts (TCP connection attempts, "
            "UDP flows, ICMP echo requests) than other pairs in the capture, or contacts that recur "
            "at a highly regular interval.",
        ),
    )
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Finding:
    id: str
    rule: str
    title: str
    severity: str
    hosts: tuple[str, ...]
    first_ts: float
    last_ts: float
    frames: list[int]
    frame_count: int
    timestamps: list[float]
    explanation: str
    confidence: str
    confidence_reason: str
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def rule_name(self) -> str:
        return RULES[self.rule].name

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "classification": "possible anomaly (heuristic; not proof of malicious activity)",
            "rule": self.rule,
            "rule_name": self.rule_name,
            "rule_description": RULES[self.rule].description,
            "title": self.title,
            "severity": self.severity,
            "hosts": list(self.hosts),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "first_time_utc": fmt_ts(self.first_ts, with_date=True),
            "last_time_utc": fmt_ts(self.last_ts, with_date=True),
            "supporting_frames": self.frames,
            "supporting_frame_count": self.frame_count,
            "event_timestamps": self.timestamps,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "metrics": self.metrics,
        }


def _fid(rule: str, *parts: object) -> str:
    h = hashlib.sha1("|".join([rule, *map(str, parts)]).encode()).hexdigest()
    return f"{rule}-{h[:10]}"


def _robust(values: list[float]) -> tuple[float, float]:
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    return med, mad


def _best_window(events: list[tuple[float, Any]], width: float, distinct: bool) -> tuple[int, int, int]:
    """Two-pointer scan over time-sorted events. Returns (score, start, end_exclusive)."""
    best = (0, 0, 0)
    counts: Counter = Counter()
    lo = 0
    for hi, (t, key) in enumerate(events):
        counts[key] += 1
        while t - events[lo][0] > width:
            k = events[lo][1]
            counts[k] -= 1
            if not counts[k]:
                del counts[k]
            lo += 1
        score = len(counts) if distinct else hi - lo + 1
        if score > best[0]:
            best = (score, lo, hi + 1)
    return best


def _cap(frames: list[int], limit: int) -> list[int]:
    return frames[:limit]


def detect(index: CaptureIndex, cfg: AnomalyConfig | None = None) -> list[Finding]:
    cfg = cfg or AnomalyConfig()
    if not index.packets:
        return []
    findings: list[Finding] = []
    findings += _repeated_attempts(index, cfg)
    findings += _port_fanout(index, cfg)
    findings += _volume_spikes(index, cfg)
    findings += _dns_spikes(index, cfg)
    findings += _frequent_pairs(index, cfg)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_ts, f.rule, f.id))
    return findings


# --- TZ-R1 -------------------------------------------------------------------
def _repeated_attempts(index: CaptureIndex, cfg: AnomalyConfig) -> list[Finding]:
    pk = index.packets
    syns: list[tuple[float, int, tuple]] = []
    accepted: set[tuple] = set()
    refused: dict[tuple, int] = {}
    for i in index.order:
        p = pk[i]
        if p.transport != "TCP" or p.tcp_flags is None or p.src is None:
            continue
        if p.is_syn:
            syns.append((p.ts, p.no, (p.src, p.sport, p.dst, p.dport)))
        elif p.is_synack:
            accepted.add((p.dst, p.dport, p.src, p.sport))
        elif p.is_rst:
            refused.setdefault((p.dst, p.dport, p.src, p.sport), p.no)
    groups: dict[tuple, list] = defaultdict(list)
    outcome_counts: dict[tuple, Counter] = defaultdict(Counter)
    for ts, no, tup in syns:
        key = (tup[0], tup[2], tup[3])
        if tup in accepted:
            outcome_counts[key]["accepted"] += 1
            continue
        kind = "refused" if tup in refused else "unanswered"
        outcome_counts[key][kind] += 1
        groups[key].append((ts, no, kind, refused.get(tup)))
    out = []
    for (src, dst, dport), attempts in groups.items():
        if len(attempts) < cfg.repeat_min_attempts:
            continue
        score, a, b = _best_window([(t, no) for t, no, _k, _r in attempts], cfg.repeat_window_s, distinct=False)
        if score < cfg.repeat_min_attempts:
            continue
        win = attempts[a:b]
        kinds = Counter(k for _t, _n, k, _r in win)
        frames = sorted({n for _t, n, _k, _r in win} | {r for _t, _n, _k, r in win if r})
        oc = outcome_counts[(src, dst, dport)]
        span = win[-1][0] - win[0][0]
        severity = "HIGH" if score >= 3 * cfg.repeat_min_attempts else "MEDIUM"
        if kinds["refused"]:
            confidence, reason = "HIGH", (
                f"{kinds['refused']} attempt(s) were explicitly refused with TCP RST observed in the capture."
            )
        else:
            confidence, reason = "MEDIUM", (
                "No replies were observed; the capture may simply not include return traffic "
                "(asymmetric capture point), so 'unanswered' is not proof of a closed port."
            )
        out.append(
            Finding(
                id=_fid("TZ-R1", src, dst, dport, win[0][1]),
                rule="TZ-R1",
                title=f"{score} failed connection attempts {src} -> {dst}:{dport}",
                severity=severity,
                hosts=(src, dst),
                first_ts=win[0][0],
                last_ts=win[-1][0],
                frames=_cap(frames, cfg.max_refs),
                frame_count=len(frames),
                timestamps=[t for t, *_ in win][: cfg.max_refs],
                explanation=(
                    f"{src} sent {score} TCP SYNs to {dst} port {dport} within {fmt_duration(span)} "
                    f"that did not complete a handshake ({kinds['refused']} refused by RST, "
                    f"{kinds['unanswered']} unanswered). Across the whole capture this source/port pair "
                    f"shows {oc['accepted']} accepted, {oc['refused']} refused and {oc['unanswered']} "
                    "unanswered attempts. Possible causes include a misconfigured client, a service "
                    "that is down, or automated probing."
                ),
                confidence=confidence,
                confidence_reason=reason,
                metrics={
                    "attempts_in_window": score,
                    "window_s": cfg.repeat_window_s,
                    "refused": kinds["refused"],
                    "unanswered": kinds["unanswered"],
                    "capture_total": dict(oc),
                    "threshold": cfg.repeat_min_attempts,
                },
            )
        )
    return out


# --- TZ-R2 -------------------------------------------------------------------
def _initiations(index: CaptureIndex) -> dict[str, list[tuple[float, int, str, int, str]]]:
    """Per source: (ts, frame, proto, dport, dst) for each connection/flow it started."""
    pk = index.packets
    per_src: dict[str, list] = defaultdict(list)
    udp_seen: set[tuple] = set()
    for i in index.order:
        p = pk[i]
        if p.src is None or p.dst is None or p.dport is None:
            continue
        if p.transport == "TCP" and p.is_syn:
            per_src[p.src].append((p.ts, p.no, "TCP", p.dport, p.dst))
        elif p.transport == "UDP":
            fwd = (p.src, p.sport, p.dst, p.dport)
            rev = (p.dst, p.dport, p.src, p.sport)
            if fwd in udp_seen or rev in udp_seen:
                continue
            udp_seen.add(fwd)
            per_src[p.src].append((p.ts, p.no, "UDP", p.dport, p.dst))
    return per_src


def _port_fanout(index: CaptureIndex, cfg: AnomalyConfig) -> list[Finding]:
    out = []
    for src, events in _initiations(index).items():
        if len({(e[2], e[3]) for e in events}) < cfg.fanout_min_ports:
            continue
        keyed = [(e[0], (e[2], e[3])) for e in events]
        score, a, b = _best_window(keyed, cfg.fanout_window_s, distinct=True)
        if score < cfg.fanout_min_ports:
            continue
        win = events[a:b]
        dsts = sorted({e[4] for e in win}, key=ip_sort_key)
        protos = Counter(e[2] for e in win)
        ports = sorted({e[3] for e in win})
        span = win[-1][0] - win[0][0]
        severity = "HIGH" if score >= 2.5 * cfg.fanout_min_ports else "MEDIUM"
        shape = "a single destination" if len(dsts) == 1 else f"{len(dsts)} destinations"
        if protos["UDP"] and not protos["TCP"]:
            confidence, reason = "LOW", "Based on UDP only; flow initiation is inferred from the first packet seen, which is less reliable than TCP SYNs."
        elif score >= 2 * cfg.fanout_min_ports:
            confidence, reason = "HIGH", "Distinct ports are counted from TCP SYN packets, which unambiguously mark connection initiation."
        else:
            confidence, reason = "MEDIUM", "Port count is modestly above the threshold; some legitimate software contacts many service ports."
        hosts = tuple([src] + dsts[:9])
        out.append(
            Finding(
                id=_fid("TZ-R2", src, win[0][1]),
                rule="TZ-R2",
                title=f"{src} contacted {score} distinct destination ports",
                severity=severity,
                hosts=hosts,
                first_ts=win[0][0],
                last_ts=win[-1][0],
                frames=_cap([e[1] for e in win], cfg.max_refs),
                frame_count=len(win),
                timestamps=[e[0] for e in win][: cfg.max_refs],
                explanation=(
                    f"Within {fmt_duration(span)}, {src} initiated {len(win)} connections/flows "
                    f"({protos['TCP']} TCP SYN, {protos['UDP']} UDP) to {score} distinct destination ports on "
                    f"{shape}. Ports include {', '.join(map(str, ports[:12]))}{' ...' if len(ports) > 12 else ''}. "
                    "This pattern is consistent with service discovery or port scanning, but also with "
                    "some management and monitoring tools."
                ),
                confidence=confidence,
                confidence_reason=reason,
                metrics={
                    "distinct_ports": score,
                    "window_s": cfg.fanout_window_s,
                    "destinations": dsts[:50],
                    "threshold": cfg.fanout_min_ports,
                    "tcp_syn": protos["TCP"],
                    "udp_flows": protos["UDP"],
                },
            )
        )
    return out


# --- shared binning -------------------------------------------------------------
def _bin_runs(flags: list[bool]) -> list[tuple[int, int]]:
    runs, start = [], None
    for i, f in enumerate(flags + [False]):
        if f and start is None:
            start = i
        elif not f and start is not None:
            runs.append((start, i))
            start = None
    return runs


# --- TZ-R3 -------------------------------------------------------------------
def _volume_spikes(index: CaptureIndex, cfg: AnomalyConfig) -> list[Finding]:
    span = index.span
    nbins = int(span / cfg.spike_bin_s) + 1
    if nbins < cfg.spike_min_bins:
        return []
    pk = index.packets
    totals = [0] * nbins
    for p in pk:
        totals[min(nbins - 1, int((p.ts - index.t0) / cfg.spike_bin_s))] += p.wirelen
    med, mad = _robust(totals)
    scale = 1.4826 * mad if mad > 0 else max(1.0, med * 0.1)
    flags = [
        v >= cfg.spike_min_bytes and v >= cfg.spike_min_factor * max(med, 1.0) and (v - med) / scale >= cfg.spike_z
        for v in totals
    ]
    out = []
    for a, b in _bin_runs(flags):
        lo = index.t0 + a * cfg.spike_bin_s
        hi = index.t0 + b * cfg.spike_bin_s
        peak = max(totals[a:b])
        pair_bytes: Counter = Counter()
        pair_frames: dict[tuple, list[int]] = defaultdict(list)
        span_frames = 0
        for i in index.order:
            p = pk[i]
            if p.ts < lo:
                continue
            if p.ts >= hi and b < nbins:
                break
            span_frames += 1
            if p.src and p.dst:
                pair_bytes[(p.src, p.dst)] += p.wirelen
                pair_frames[(p.src, p.dst)].append(p.no)
        top = pair_bytes.most_common(3)
        frames = sorted(n for pair, _ in top for n in pair_frames[pair])
        hosts: list[str] = []
        for (s, d), _ in top:
            for h in (s, d):
                if h not in hosts:
                    hosts.append(h)
        total = sum(totals[a:b])
        top_share = (top[0][1] / total) if top and total else 0.0
        ratio = peak / max(med, 1.0)
        severity = "MEDIUM" if ratio >= 20 else "LOW"
        if nbins >= 60:
            confidence, reason = "HIGH", f"Baseline built from {nbins} bins of {cfg.spike_bin_s:g}s."
        elif nbins >= 20:
            confidence, reason = "MEDIUM", f"Baseline built from only {nbins} bins; a longer capture would give a firmer baseline."
        else:
            confidence, reason = "LOW", f"Baseline built from only {nbins} bins."
        tops = "; ".join(f"{s} -> {d} {fmt_bytes(v)}" for (s, d), v in top)
        out.append(
            Finding(
                id=_fid("TZ-R3", a, b, top[0][0] if top else ""),
                rule="TZ-R3",
                title=f"Traffic spike {fmt_bytes(peak)}/bin ({ratio:.0f}x median)",
                severity=severity,
                hosts=tuple(hosts),
                first_ts=lo,
                last_ts=min(hi, index.t1),
                frames=_cap(frames, cfg.max_refs),
                frame_count=len(frames),
                timestamps=[lo + k * cfg.spike_bin_s for k in range(b - a)],
                explanation=(
                    f"{fmt_bytes(total)} in {span_frames} packets between {fmt_ts(lo)} and {fmt_ts(hi)} UTC. "
                    f"Peak {fmt_bytes(peak)} per {cfg.spike_bin_s:g}s bin against a capture median of "
                    f"{fmt_bytes(med)} (robust z >= {cfg.spike_z:g}). Largest contributors: {tops}. "
                    f"The top pair carried {top_share:.0%} of the spike. Bulk transfers such as backups or "
                    "software updates produce the same signature."
                ),
                confidence=confidence,
                confidence_reason=reason,
                metrics={"peak_bytes": peak, "median_bytes": med, "mad_bytes": mad, "bins": nbins, "bin_s": cfg.spike_bin_s, "ratio": round(ratio, 2)},
            )
        )
    return out


# --- TZ-R4 -------------------------------------------------------------------
def _dns_spikes(index: CaptureIndex, cfg: AnomalyConfig) -> list[Finding]:
    pk = index.packets
    nbins = int(index.span / cfg.dns_bin_s) + 1
    queries: dict[str, list] = defaultdict(list)
    responses: dict[str, list] = defaultdict(list)
    for i in index.order:
        p = pk[i]
        d = p.dns
        if d is None or p.app != "DNS" or p.src is None:
            continue
        if d.is_response:
            responses[p.dst].append(p)
        else:
            queries[p.src].append(p)
    out = []
    for src, qs in queries.items():
        if len(qs) < cfg.dns_min_queries:
            continue
        bins = [0] * nbins
        for p in qs:
            bins[min(nbins - 1, int((p.ts - index.t0) / cfg.dns_bin_s))] += 1
        baseline = statistics.median(bins)
        flags = [c >= cfg.dns_min_queries and c >= cfg.dns_min_factor * max(baseline, 1.0) for c in bins]
        for a, b in _bin_runs(flags):
            lo = index.t0 + a * cfg.dns_bin_s
            hi = index.t0 + b * cfg.dns_bin_s
            inq = [p for p in qs if lo <= p.ts < hi or (b == nbins and p.ts >= lo)]
            inr = [p for p in responses.get(src, []) if lo <= p.ts <= hi + 5]
            names = Counter(p.dns.qname for p in inq if p.dns and p.dns.qname)
            suffixes = Counter(".".join(n.split(".")[-2:]) for n in names.elements())
            nx = sum(1 for p in inr if p.dns and p.dns.rcode == 3)
            unique_ratio = len(names) / max(1, len(inq))
            top_suffix, top_count = suffixes.most_common(1)[0] if suffixes else ("-", 0)
            severity = "MEDIUM" if (nx > len(inr) / 2 and inr) or unique_ratio > 0.8 else "LOW"
            if inr:
                confidence, reason = "MEDIUM", f"{len(inr)} responses observed, so the query burst is corroborated by resolver replies."
            else:
                confidence, reason = "LOW", "No responses observed for this burst; the capture may be one-sided."
            frames = sorted([p.no for p in inq] + [p.no for p in inr])
            peak = max(bins[a:b])
            servers = sorted({p.dst for p in inq if p.dst}, key=ip_sort_key)
            out.append(
                Finding(
                    id=_fid("TZ-R4", src, a, b),
                    rule="TZ-R4",
                    title=f"{src} DNS burst: {len(inq)} queries",
                    severity=severity,
                    hosts=tuple([src] + servers[:4]),
                    first_ts=inq[0].ts,
                    last_ts=inq[-1].ts,
                    frames=_cap(frames, cfg.max_refs),
                    frame_count=len(frames),
                    timestamps=[p.ts for p in inq][: cfg.max_refs],
                    explanation=(
                        f"{src} sent {len(inq)} DNS queries between {fmt_ts(inq[0].ts)} and {fmt_ts(inq[-1].ts)} UTC "
                        f"(peak {peak} per {cfg.dns_bin_s:g}s; this host's median is {baseline:g}). "
                        f"{len(names)} distinct names ({unique_ratio:.0%} unique); most common suffix "
                        f"'{top_suffix}' ({top_count} queries). {nx} of {len(inr)} observed responses were NXDOMAIN. "
                        "Many unique names with failed lookups can indicate misconfiguration, generated domain "
                        "names, or data carried in DNS - none of which this rule can distinguish."
                    ),
                    confidence=confidence,
                    confidence_reason=reason,
                    metrics={
                        "queries": len(inq),
                        "distinct_names": len(names),
                        "nxdomain": nx,
                        "responses": len(inr),
                        "baseline_per_bin": baseline,
                        "bin_s": cfg.dns_bin_s,
                        "top_suffix": top_suffix,
                    },
                )
            )
    return out


# --- TZ-R5 -------------------------------------------------------------------
def _frequent_pairs(index: CaptureIndex, cfg: AnomalyConfig) -> list[Finding]:
    contacts: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    for src, events in _initiations(index).items():
        for ts, no, _proto, _port, dst in events:
            contacts[(src, dst)].append((ts, no))
    for i in index.order:
        p = index.packets[i]
        if p.transport in ("ICMP", "ICMPv6") and p.icmp_type in (8, 128) and p.src and p.dst:
            contacts[(p.src, p.dst)].append((p.ts, p.no))
    if len(contacts) < cfg.pair_min_pairs:
        return []
    counts = [len(v) for v in contacts.values()]
    med, mad = _robust(counts)
    scale = 1.4826 * mad if mad > 0 else 1.0
    out = []
    for (src, dst), evs in sorted(contacts.items()):
        n = len(evs)
        if n < cfg.pair_min_contacts:
            continue
        evs.sort()
        z = (n - med) / scale
        gaps = [b[0] - a[0] for a, b in zip(evs, evs[1:])]
        mean_gap = statistics.fmean(gaps) if gaps else 0.0
        cv = statistics.pstdev(gaps) / mean_gap if gaps and mean_gap > 0 else float("inf")
        periodic = cv <= cfg.pair_periodic_cv and n >= 8
        if not (z >= cfg.pair_z or (periodic and z >= cfg.pair_periodic_z)):
            continue
        severity = "MEDIUM" if periodic else "LOW"
        cadence = (
            f"Contacts recur every {mean_gap:.2f}s on average with low variation (CV {cv:.2f}), "
            "which is typical of automated check-ins such as update agents, monitoring - or beaconing."
            if periodic
            else f"Intervals are irregular (CV {cv:.2f}), so this is a volume observation rather than a cadence."
        )
        if len(contacts) >= 10:
            confidence, reason = "MEDIUM", f"Compared against {len(contacts)} host pairs in this capture."
        else:
            confidence, reason = "LOW", f"Only {len(contacts)} host pairs available as a baseline."
        out.append(
            Finding(
                id=_fid("TZ-R5", src, dst),
                rule="TZ-R5",
                title=f"Frequent contacts {src} -> {dst} ({n})" + (" periodic" if periodic else ""),
                severity=severity,
                hosts=(src, dst),
                first_ts=evs[0][0],
                last_ts=evs[-1][0],
                frames=_cap([no for _t, no in evs], cfg.max_refs),
                frame_count=n,
                timestamps=[t for t, _ in evs][: cfg.max_refs],
                explanation=(
                    f"{src} initiated {n} separate contacts with {dst} over {fmt_duration(evs[-1][0] - evs[0][0])}; "
                    f"the median pair in this capture has {med:g} (robust z = {z:.1f}). {cadence}"
                ),
                confidence=confidence,
                confidence_reason=reason,
                metrics={
                    "contacts": n,
                    "median_contacts": med,
                    "robust_z": round(z, 2),
                    "mean_interval_s": round(mean_gap, 3),
                    "interval_cv": None if cv == float("inf") else round(cv, 3),
                    "pairs_in_baseline": len(contacts),
                },
            )
        )
    return out


__all__ = ["RULES", "SEVERITY_ORDER", "Finding", "Rule", "detect"]

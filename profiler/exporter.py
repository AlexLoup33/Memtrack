"""
exporter.py — HTML report generator for the memprof profiler.

Public API
----------
export_html(stats, output_path="report.html") -> str
    Build a self-contained HTML report from an already-analysed stats dict
    (as returned by analyze_trace) and write it to disk.

profile_and_export(target_bin, output_path="report.html", trace_file="trace.jsonl") -> str
    Full pipeline: run the binary under LD_PRELOAD, parse the trace,
    print the Rich terminal report, then write the HTML report.
    Returns the absolute path of the HTML file.

Timeline data source
--------------------
The HTML timeline is driven by stats["timeline"], which analyze_trace()
already builds.  Each entry has:
    { "ts": float,            # seconds since program start
      "memory": int,          # live bytes after malloc  (key = "memory")
      "ram":    int,          # live bytes after free    (key = "ram")
      "action": "malloc"|"free" }

read / write events have no timeline entry in analyzer.py, so we inject
lightweight markers from the running io counters at render time.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# System signature registry
# ---------------------------------------------------------------------------

SYSTEM_SIGNATURES: dict[str, dict[str, str]] = {
    # ── glibc / libc ────────────────────────────────────────────────────────
    "_IO_file_doallocate": {
        "cause": "Standard I/O buffer allocation by libc (triggered by printf, std::cout, or fopen).",
        "resolution": "If triggered by fopen, ensure you call fclose(). If it comes from standard output "
                      "(printf/cout), the OS frees it at exit. Usually safe to ignore.",
    },
    # Matches both __GI___strdup (internal glibc symbol) and
    # libc.so.6(__strdup+0x…) (raw backtrace format from -rdynamic)
    "__strdup": {
        "cause": "String duplication via strdup() inside the C standard library.",
        "resolution": "The caller of strdup() is responsible for calling free() on the returned pointer.",
    },
    # Legacy alias kept for traces produced by older interceptors
    "__GI___strdup": {
        "cause": "String duplication via strdup() inside the C standard library.",
        "resolution": "The caller of strdup() is responsible for calling free() on the returned pointer.",
    },
    "backtrace_symbols": {
        "cause": "Internal allocation by glibc to format stack trace addresses into human-readable strings.",
        "resolution": "If you use this function in your own profiler/code, you must call free() on the returned pointer.",
    },
    # ── dynamic linker ───────────────────────────────────────────────────────
    # Covers all anonymous offsets from ld-linux-x86-64.so.2(+0x…):
    # environment/RPATH string copies, soname tables, TLS blocks, etc.
    "ld-linux-x86-64.so.2": {
        "cause": "Internal allocation by the dynamic linker (ld-linux). "
                 "Typically: environment variable copies, shared-library path strings, "
                 "TLS (thread-local storage) blocks, or soname/RPATH tables built at startup.",
        "resolution": "Managed entirely by the dynamic linker. These are false positives — "
                      "the linker owns and frees this memory at process exit. Safe to ignore.",
    },
    "ld-linux.so": {
        "cause": "Internal allocation by the dynamic linker (32-bit variant). "
                 "Same category as ld-linux-x86-64.so.2.",
        "resolution": "Managed by the dynamic linker. False positive — safe to ignore.",
    },
    # ── dynamic loading (user-triggered) ────────────────────────────────────
    "dlopen": {
        "cause": "Dynamic loading of a shared library (.so file).",
        "resolution": "Ensure you call dlclose() for every dynamically loaded library before program exit.",
    },
    # ── POSIX threads ────────────────────────────────────────────────────────
    "pthread_create": {
        "cause": "Memory allocated by the system for a new thread's stack.",
        "resolution": "Ensure every created thread is properly cleaned up using either pthread_join() or pthread_detach().",
    },
    # ── C++ runtime ──────────────────────────────────────────────────────────
    "__cxa_atexit": {
        "cause": "Internal C++ runtime allocation to register global/static object destructors.",
        "resolution": "Managed by the C++ ABI (Application Binary Interface). This is a false positive and safe to ignore.",
    },
    "__cxxabiv1::__cxa_get_globals": {
        "cause": "Internal C++ runtime allocation for exception handling (try/catch mechanisms).",
        "resolution": "Managed by the C++ ABI. Safe to ignore.",
    },
}


def analyze_caller(caller_string: str) -> dict | None:
    for signature, details in SYSTEM_SIGNATURES.items():
        if signature in caller_string:
            return {**details, "signature": signature}
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clean_caller(caller: str) -> str:
    return caller.split("/")[-1] if "/" in caller else caller


def _classify_leaks(active_ptrs: dict) -> tuple[dict, dict]:
    """Split active_ptrs into (user_leaks, system_leaks)."""
    user: dict = {}
    system: dict = {}
    for ptr, data in active_ptrs.items():
        caller = data.get("caller", "unknown")
        match = analyze_caller(caller)
        if match:
            system[ptr] = {**data, "_analysis": match}
        else:
            user[ptr] = data
    return user, system


def _fmt_bytes(n: int | float) -> str:
    n = int(n)
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 ** 2:.2f} MB"


def _h(s: Any) -> str:
    return html.escape(str(s))


def _normalise_timeline(raw: list[dict]) -> list[dict]:
    """
    Normalise the timeline list produced by analyze_trace.

    analyze_trace uses key "memory" for malloc events and key "ram" for free
    events (inconsistency in the source).  We unify both to "memory" so the
    D3 code only has to deal with one field name.
    """
    out = []
    for entry in raw:
        mem = entry.get("memory") if entry.get("memory") is not None else entry.get("ram", 0)
        out.append({
            "ts":     entry.get("ts", 0),
            "memory": mem,
            "action": entry.get("action", "unknown"),
        })
    return out


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def _build_html(stats: dict) -> str:
    leaks = stats.get("active_ptrs", {})
    user_leaks, system_leaks = _classify_leaks(leaks)
    timeline = _normalise_timeline(stats.get("timeline", []))

    total_user_lost = sum(d.get("size", 0) for d in user_leaks.values())
    total_sys_lost  = sum(d.get("size", 0) for d in system_leaks.values())
    total_lost      = total_user_lost + total_sys_lost

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # JSON payloads embedded in the page
    timeline_json = json.dumps(timeline)
    leaks_json = json.dumps({
        ptr: {
            "size":       d.get("size", 0),
            "caller":     _clean_caller(d.get("caller", "unknown")),
            "kind":       "system" if ptr in system_leaks else "user",
            "cause":      system_leaks[ptr]["_analysis"]["cause"]       if ptr in system_leaks else "",
            "resolution": system_leaks[ptr]["_analysis"]["resolution"]  if ptr in system_leaks else "",
        }
        for ptr, d in leaks.items()
    })
    stats_json = json.dumps({
        "allocations":   stats.get("allocations",   0),
        "frees":         stats.get("frees",          0),
        "peak_memory":   stats.get("peak_memory",    0),
        "io_reads":      stats.get("io_reads",       0),
        "io_read_bytes": stats.get("io_read_bytes",  0),
        "io_writes":     stats.get("io_writes",      0),
        "io_write_bytes":stats.get("io_write_bytes", 0),
    })

    # ------------------------------------------------------------------
    # Table row helpers
    # ------------------------------------------------------------------
    def user_leak_rows() -> str:
        if not user_leaks:
            return '<tr><td colspan="3" class="empty-row">No user leaks detected ✓</td></tr>'
        rows = []
        for ptr, d in user_leaks.items():
            size   = d.get("size", 0)
            caller = _clean_caller(d.get("caller", "unknown"))
            rows.append(
                f'<tr>'
                f'<td class="mono">{_h(ptr)}</td>'
                f'<td class="num leak-red">{_h(size)} B</td>'
                f'<td class="mono caller">{_h(caller)}</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    def system_leak_rows() -> str:
        if not system_leaks:
            return '<tr><td colspan="5" class="empty-row">No system allocations flagged</td></tr>'
        rows = []
        for ptr, d in system_leaks.items():
            size     = d.get("size", 0)
            caller   = _clean_caller(d.get("caller", "unknown"))
            analysis = d["_analysis"]
            rows.append(
                f'<tr>'
                f'<td class="mono dim">{_h(ptr)}</td>'
                f'<td class="num warn-yellow">{_h(size)} B</td>'
                f'<td class="mono caller">{_h(caller)}</td>'
                f'<td class="cause-cell">{_h(analysis["cause"])}</td>'
                f'<td class="resolution-cell">{_h(analysis["resolution"])}</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    # Status badge
    if len(user_leaks) == 0:
        status_class, status_label = "status-ok",       "CLEAN"
    elif len(user_leaks) <= 3:
        status_class, status_label = "status-warn",     "LEAKS"
    else:
        status_class, status_label = "status-critical", "CRITICAL"

    leak_section = (
        "<div class='banner-ok'>✓ No user memory leaks detected — all pointers freed.</div>"
        if not user_leaks else
        f"""
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Pointer</th>
                <th class="right">Bytes Lost</th>
                <th>Caller</th>
              </tr>
            </thead>
            <tbody>
              {user_leak_rows()}
            </tbody>
          </table>
        </div>
        <div class="total-line">
          Total lost: <strong class="leak-red">{_h(_fmt_bytes(total_user_lost))}</strong>
          across {len(user_leaks)} pointer(s)
        </div>
        """
    )

    sys_total_line = (
        f'<div class="total-line">System total: '
        f'<strong class="warn-yellow">{_h(_fmt_bytes(total_sys_lost))}</strong> '
        f'across {len(system_leaks)} pointer(s)</div>'
        if system_leaks else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Memory Profiling Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

:root {{
  --bg:         #0D1117;
  --surface:    #161B22;
  --border:     #21262D;
  --border-hi:  #30363D;
  --text:       #C9D1D9;
  --text-dim:   #6E7681;
  --text-hi:    #F0F6FC;
  --green:      #3FB950;
  --green-dim:  #1A3A20;
  --red:        #F85149;
  --red-dim:    #3D1A1A;
  --yellow:     #D29922;
  --yellow-dim: #3A2D0A;
  --blue:       #58A6FF;
  --blue-dim:   #0D2044;
  --purple:     #BC8CFF;
  --sidebar-w:  240px;
  --font:       'JetBrains Mono', 'Fira Code', monospace;
}}

html, body {{
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  font-size: 13px;
  line-height: 1.6;
}}

/* ── Layout ── */
.layout {{ display: flex; min-height: 100vh; }}

.sidebar {{
  width: var(--sidebar-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  position: sticky; top: 0;
  height: 100vh; overflow-y: auto;
  flex-shrink: 0;
  display: flex; flex-direction: column;
  padding: 20px 0;
}}

.main {{ flex: 1; min-width: 0; padding: 32px 40px; max-width: 1400px; }}

/* ── Sidebar ── */
.sidebar-logo {{
  padding: 0 20px 20px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 16px;
}}
.sidebar-logo .title {{
  font-size: 11px; font-weight: 600;
  color: var(--text-hi);
  letter-spacing: .08em; text-transform: uppercase;
}}
.sidebar-logo .subtitle {{ font-size: 10px; color: var(--text-dim); margin-top: 2px; }}

.status-badge {{
  display: inline-block; margin-top: 10px;
  padding: 2px 8px; border-radius: 3px;
  font-size: 10px; font-weight: 700; letter-spacing: .1em;
}}
.status-ok       {{ background: var(--green-dim);  color: var(--green);  border: 1px solid var(--green);  }}
.status-warn     {{ background: var(--yellow-dim); color: var(--yellow); border: 1px solid var(--yellow); }}
.status-critical {{ background: var(--red-dim);    color: var(--red);    border: 1px solid var(--red);    }}

.nav-section {{
  padding: 8px 20px 4px;
  font-size: 10px; font-weight: 600;
  color: var(--text-dim);
  text-transform: uppercase; letter-spacing: .08em;
}}
.nav-item {{
  display: flex; align-items: center; gap: 8px;
  padding: 6px 20px; font-size: 12px; color: var(--text-dim);
  cursor: pointer; text-decoration: none;
  border-left: 2px solid transparent;
  transition: color .15s, border-color .15s, background .15s;
}}
.nav-item:hover  {{ color: var(--text); background: rgba(255,255,255,.04); }}
.nav-item.active {{ color: var(--blue); border-left-color: var(--blue); background: rgba(88,166,255,.06); }}

.nav-dot {{ width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }}
.dot-green  {{ background: var(--green);  }}
.dot-red    {{ background: var(--red);    }}
.dot-yellow {{ background: var(--yellow); }}
.dot-blue   {{ background: var(--blue);   }}

.sidebar-meta {{
  margin-top: auto;
  padding: 16px 20px 0;
  border-top: 1px solid var(--border);
  font-size: 10px; color: var(--text-dim); line-height: 1.8;
}}

/* ── Page header ── */
.page-header {{ margin-bottom: 32px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
.page-header h1 {{ font-size: 20px; font-weight: 600; color: var(--text-hi); margin-bottom: 4px; }}
.page-header .meta {{ font-size: 11px; color: var(--text-dim); }}

/* ── Sections ── */
.section {{ margin-bottom: 48px; scroll-margin-top: 24px; }}
.section-title {{
  font-size: 12px; font-weight: 600; color: var(--text-dim);
  text-transform: uppercase; letter-spacing: .08em;
  margin-bottom: 16px;
  display: flex; align-items: center; gap: 8px;
}}
.section-title::after {{ content: ''; flex: 1; height: 1px; background: var(--border); }}

/* ── Cards ── */
.cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px; }}
.card .label {{ font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 8px; }}
.card .value {{ font-size: 22px; font-weight: 600; color: var(--text-hi); line-height: 1; }}
.card .unit  {{ font-size: 11px; color: var(--text-dim); margin-top: 4px; }}
.card.accent-green  {{ border-top: 2px solid var(--green);  }}
.card.accent-red    {{ border-top: 2px solid var(--red);    }}
.card.accent-yellow {{ border-top: 2px solid var(--yellow); }}
.card.accent-blue   {{ border-top: 2px solid var(--blue);   }}
.card.accent-purple {{ border-top: 2px solid var(--purple); }}

/* ── Tables ── */
.table-wrap {{ overflow-x: auto; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
thead th {{
  background: var(--surface); padding: 10px 14px;
  text-align: left; font-size: 10px; font-weight: 600;
  color: var(--text-dim); text-transform: uppercase; letter-spacing: .07em;
  border-bottom: 1px solid var(--border); white-space: nowrap;
}}
thead th.right {{ text-align: right; }}
tbody tr {{ border-bottom: 1px solid var(--border); transition: background .1s; }}
tbody tr:last-child {{ border-bottom: none; }}
tbody tr:hover {{ background: rgba(255,255,255,.03); }}
tbody td {{ padding: 9px 14px; vertical-align: top; }}

.mono    {{ font-family: var(--font); }}
.dim     {{ color: var(--text-dim); }}
.num     {{ text-align: right; font-variant-numeric: tabular-nums; }}
.caller  {{ font-size: 11px; }}
.cause-cell      {{ font-size: 11px; max-width: 260px; color: var(--text); }}
.resolution-cell {{ font-size: 11px; max-width: 280px; color: var(--green); }}
.leak-red    {{ color: var(--red);    }}
.warn-yellow {{ color: var(--yellow); }}
.ok-green    {{ color: var(--green);  }}
.empty-row   {{ text-align: center; color: var(--text-dim); padding: 20px; }}

.total-line {{ font-size: 12px; padding: 6px 0 0; text-align: right; color: var(--text-dim); }}
.total-line strong {{ color: var(--text-hi); }}

.banner-ok {{
  background: var(--green-dim); border: 1px solid var(--green);
  border-radius: 6px; padding: 14px 18px;
  color: var(--green); font-size: 13px; font-weight: 500;
}}

/* ── Timeline ── */
.timeline-wrap {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; padding: 20px; overflow-x: auto;
}}
#timeline svg {{ display: block; }}

.legend {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 14px; }}
.legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--text-dim); }}
.legend-dot  {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}

/* ── Tooltip ── */
.tt {{
  position: fixed;
  background: #1C2128; border: 1px solid var(--border-hi);
  border-radius: 5px; padding: 10px 12px;
  font-family: var(--font); font-size: 11px; color: var(--text);
  pointer-events: none; z-index: 9999;
  max-width: 320px; line-height: 1.7;
  box-shadow: 0 8px 24px rgba(0,0,0,.5);
  display: none;
}}
.tt .tt-ptr  {{ color: var(--text-dim); font-size: 10px; }}
.tt .tt-size {{ font-weight: 600; }}
.tt .tt-red  {{ color: var(--red);    }}
.tt .tt-yel  {{ color: var(--yellow); }}
.tt .tt-grn  {{ color: var(--green);  }}
.tt .tt-blu  {{ color: var(--blue);   }}
</style>
</head>
<body>
<div class="layout">

<!-- Sidebar -->
<nav class="sidebar">
  <div class="sidebar-logo">
    <div class="title">memprof</div>
    <div class="subtitle">Profiling Report</div>
    <div class="status-badge {status_class}">{_h(status_label)}</div>
  </div>

  <div class="nav-section">Overview</div>
  <a class="nav-item active" href="#exec-stats">
    <span class="nav-dot dot-green"></span>Execution Stats
  </a>
  <a class="nav-item" href="#io">
    <span class="nav-dot dot-blue"></span>I/O Profiling
  </a>

  <div class="nav-section">Memory</div>
  <a class="nav-item" href="#user-leaks">
    <span class="nav-dot dot-red"></span>User Leaks
    <span style="margin-left:auto;font-size:10px;color:var(--red)">{len(user_leaks)}</span>
  </a>
  <a class="nav-item" href="#system-leaks">
    <span class="nav-dot dot-yellow"></span>System Allocs
    <span style="margin-left:auto;font-size:10px;color:var(--yellow)">{len(system_leaks)}</span>
  </a>

  <div class="nav-section">Visualisation</div>
  <a class="nav-item" href="#timeline">
    <span class="nav-dot dot-blue"></span>Timeline
  </a>

  <div class="sidebar-meta">
    Generated<br/>{_h(generated_at)}
  </div>
</nav>

<!-- Main -->
<main class="main">

  <div class="page-header">
    <h1>Memory Profiling Report</h1>
    <div class="meta">Generated {_h(generated_at)}</div>
  </div>

  <!-- Execution Stats -->
  <section class="section" id="exec-stats">
    <div class="section-title">Execution Stats</div>
    <div class="cards">
      <div class="card accent-green">
        <div class="label">Allocations</div>
        <div class="value">{_h(stats.get('allocations', 0))}</div>
        <div class="unit">total malloc / new calls</div>
      </div>
      <div class="card accent-green">
        <div class="label">Frees</div>
        <div class="value">{_h(stats.get('frees', 0))}</div>
        <div class="unit">total free / delete calls</div>
      </div>
      <div class="card accent-purple">
        <div class="label">Peak Memory</div>
        <div class="value">{_h(_fmt_bytes(stats.get('peak_memory', 0)))}</div>
        <div class="unit">high-water mark</div>
      </div>
      <div class="card {'accent-red' if user_leaks else 'accent-green'}">
        <div class="label">Active Leaks</div>
        <div class="value {'leak-red' if user_leaks else 'ok-green'}">{len(user_leaks)}</div>
        <div class="unit">unfreed user pointers</div>
      </div>
      <div class="card accent-yellow">
        <div class="label">System Allocs</div>
        <div class="value warn-yellow">{len(system_leaks)}</div>
        <div class="unit">likely false positives</div>
      </div>
    </div>
  </section>

  <!-- I/O -->
  <section class="section" id="io">
    <div class="section-title">I/O Profiling</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th class="right">System Calls</th>
            <th class="right">Data Transferred</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="ok-green">Read</td>
            <td class="num">{_h(stats.get('io_reads', 0))}</td>
            <td class="num">{_h(_fmt_bytes(stats.get('io_read_bytes', 0)))}</td>
          </tr>
          <tr>
            <td style="color:var(--blue)">Write</td>
            <td class="num">{_h(stats.get('io_writes', 0))}</td>
            <td class="num">{_h(_fmt_bytes(stats.get('io_write_bytes', 0)))}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <!-- User leaks -->
  <section class="section" id="user-leaks">
    <div class="section-title">User Memory Leaks</div>
    {leak_section}
  </section>

  <!-- System leaks -->
  <section class="section" id="system-leaks">
    <div class="section-title">System / Library Allocations</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Pointer</th>
            <th class="right">Bytes</th>
            <th>Caller</th>
            <th>Cause</th>
            <th>Resolution</th>
          </tr>
        </thead>
        <tbody>
          {system_leak_rows()}
        </tbody>
      </table>
    </div>
    {sys_total_line}
  </section>

  <!-- Timeline -->
  <section class="section" id="timeline">
    <div class="section-title">Memory Timeline</div>
    <div class="timeline-wrap">
      <div id="timeline"></div>
      <div class="legend">
        <div class="legend-item"><div class="legend-dot" style="background:var(--green)"></div>Live memory (area)</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--red)"></div>malloc event</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--text-dim)"></div>free event</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--purple)"></div>Peak</div>
      </div>
    </div>
  </section>

</main>
</div>

<div class="tt" id="tt"></div>

<!-- Embedded data -->
<script>
const TIMELINE = {timeline_json};
const LEAKS    = {leaks_json};
const STATS    = {stats_json};
</script>

<!-- Sidebar scroll-spy -->
<script>
(function() {{
  const items = document.querySelectorAll('.nav-item');
  const secs  = [...items].map(a => document.querySelector(a.getAttribute('href'))).filter(Boolean);
  new IntersectionObserver(entries => {{
    entries.forEach(e => {{
      if (!e.isIntersecting) return;
      items.forEach(a => a.classList.remove('active'));
      const hit = [...items].find(a => a.getAttribute('href') === '#' + e.target.id);
      if (hit) hit.classList.add('active');
    }});
  }}, {{ threshold: 0.3 }}).observe && secs.forEach(s =>
    new IntersectionObserver(entries => {{
      entries.forEach(e => {{
        if (!e.isIntersecting) return;
        items.forEach(a => a.classList.remove('active'));
        const hit = [...items].find(a => a.getAttribute('href') === '#' + e.target.id);
        if (hit) hit.classList.add('active');
      }});
    }}, {{ threshold: 0.3 }}).observe(s)
  );
}})();
</script>

<!-- D3 Timeline -->
<script>
(function () {{
  const C = {{
    malloc:  '#F85149',
    free:    '#6E7681',
    area:    'rgba(63,185,80,.18)',
    line:    '#3FB950',
    peak:    '#BC8CFF',
    grid:    '#21262D',
    txt:     '#6E7681',
  }};

  if (!TIMELINE.length) {{
    document.getElementById('timeline').innerHTML =
      '<p style="color:var(--text-dim);font-size:12px;padding:20px 0">' +
      'No timeline data — analyzer produced an empty timeline list.</p>';
    return;
  }}

  // ── Dimensions ──
  const MARGIN = {{ top: 24, right: 24, bottom: 36, left: 72 }};
  const cont   = document.getElementById('timeline');
  const W      = Math.max(cont.clientWidth || 900, 600);
  const H      = 220;
  const IW     = W - MARGIN.left - MARGIN.right;
  const IH     = H - MARGIN.top  - MARGIN.bottom;

  const svg = d3.select('#timeline').append('svg')
    .attr('width', W).attr('height', H);

  const g = svg.append('g')
    .attr('transform', `translate(${{MARGIN.left}},${{MARGIN.top}})`);

  // ── Scales ──
  const xExt = d3.extent(TIMELINE, d => d.ts);
  const xPad = (xExt[1] - xExt[0]) * 0.02 || 0.005;
  const x = d3.scaleLinear()
    .domain([xExt[0] - xPad, xExt[1] + xPad])
    .range([0, IW]);

  const maxMem = d3.max(TIMELINE, d => d.memory) || 1;
  const y = d3.scaleLinear()
    .domain([0, maxMem * 1.08])
    .range([IH, 0]);

  // ── Axes ──
  const xAxis = d3.axisBottom(x)
    .ticks(8)
    .tickFormat(d => d.toFixed(3) + 's')
    .tickSize(-IH);

  const yAxis = d3.axisLeft(y)
    .ticks(5)
    .tickFormat(d => {{
      if (d >= 1048576) return (d/1048576).toFixed(1) + ' MB';
      if (d >= 1024)    return (d/1024).toFixed(0)    + ' KB';
      return d + ' B';
    }})
    .tickSize(-IW);

  g.append('g').attr('transform', `translate(0,${{IH}})`).call(xAxis)
    .call(ax => {{
      ax.select('.domain').attr('stroke', C.grid);
      ax.selectAll('.tick line').attr('stroke', C.grid).attr('stroke-dasharray', '3,3');
      ax.selectAll('.tick text').attr('fill', C.txt)
        .attr('font-family', "'JetBrains Mono',monospace").attr('font-size', 10);
    }});

  g.append('g').call(yAxis)
    .call(ax => {{
      ax.select('.domain').attr('stroke', C.grid);
      ax.selectAll('.tick line').attr('stroke', C.grid).attr('stroke-dasharray', '3,3');
      ax.selectAll('.tick text').attr('fill', C.txt)
        .attr('font-family', "'JetBrains Mono',monospace").attr('font-size', 10);
    }});

  // ── Area ──
  g.append('path')
    .datum(TIMELINE)
    .attr('fill', C.area)
    .attr('d', d3.area()
      .x(d => x(d.ts))
      .y0(IH)
      .y1(d => y(d.memory))
      .curve(d3.curveStepAfter));

  // ── Line ──
  g.append('path')
    .datum(TIMELINE)
    .attr('fill', 'none')
    .attr('stroke', C.line)
    .attr('stroke-width', 1.5)
    .attr('d', d3.line()
      .x(d => x(d.ts))
      .y(d => y(d.memory))
      .curve(d3.curveStepAfter));

  // ── Peak marker ──
  const peakEntry = TIMELINE.reduce((a, b) => b.memory > a.memory ? b : a, TIMELINE[0]);
  g.append('line')
    .attr('x1', x(peakEntry.ts)).attr('x2', x(peakEntry.ts))
    .attr('y1', 0).attr('y2', IH)
    .attr('stroke', C.peak).attr('stroke-width', 1)
    .attr('stroke-dasharray', '4,3');
  g.append('text')
    .attr('x', x(peakEntry.ts) + 4).attr('y', 10)
    .attr('fill', C.peak)
    .attr('font-family', "'JetBrains Mono',monospace")
    .attr('font-size', 10)
    .text('peak');

  // ── Event dots ──
  const tt = document.getElementById('tt');

  function showTT(event, d) {{
    const isMalloc = d.action === 'malloc';
    tt.innerHTML =
      `<div><span class="${{isMalloc ? 'tt-red' : ''}} tt-size">${{d.action.toUpperCase()}}</span></div>` +
      `<div>Time: ${{d.ts.toFixed(4)}} s</div>` +
      `<div>Live mem: ${{d.memory}} B</div>`;
    tt.style.display = 'block';
    moveTT(event);
  }}
  function moveTT(event) {{
    const tx = event.clientX + 14, ty = event.clientY - 10;
    const tw = tt.offsetWidth;
    tt.style.left = (tx + tw > window.innerWidth ? tx - tw - 28 : tx) + 'px';
    tt.style.top  = ty + 'px';
  }}
  function hideTT() {{ tt.style.display = 'none'; }}

  g.selectAll('.evt')
    .data(TIMELINE)
    .enter().append('circle')
    .attr('class', 'evt')
    .attr('cx', d => x(d.ts))
    .attr('cy', d => y(d.memory))
    .attr('r', 3.5)
    .attr('fill', d => d.action === 'malloc' ? C.malloc : C.free)
    .attr('fill-opacity', .85)
    .style('cursor', 'pointer')
    .on('mouseover', showTT)
    .on('mousemove', moveTT)
    .on('mouseout',  hideTT);

}})();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_html(stats: dict, output_path: str = "report.html") -> str:
    """
    Build a self-contained HTML report from a stats dict and write it to disk.

    Parameters
    ----------
    stats       : dict returned by analyze_trace()
    output_path : destination file path

    Returns
    -------
    Absolute path of the written HTML file.
    """
    content = _build_html(stats)
    output_path = os.path.abspath(output_path)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"[memprof] HTML report → {output_path}")
    return output_path

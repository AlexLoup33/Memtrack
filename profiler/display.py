from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

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


def analyze_caller(caller_string: str) -> dict:
    for signature, details in SYSTEM_SIGNATURES.items():
        if signature in caller_string:
            return details
    return None


def render_analysis(stats):
    console = Console()

    if not stats:
        console.print("[bold red]Trace file not found or empty ![/bold red]")
        return

    summary = f"[bold green]Allocations:[/bold green] {stats['allocations']} | [bold green]Frees:[/bold green] {stats['frees']}\n"
    summary += f"[bold magenta]Memory Peak (High-water mark):[/bold magenta] {stats['peak_memory']} bytes"
    console.print(Panel(summary, title="[bold blue]Execution Stats[/bold blue]", border_style="blue"))

    io_table = Table(title="\nI/O Profiling", style="cyan")
    io_table.add_column("Action", style="bold")
    io_table.add_column("System Call", justify="right")
    io_table.add_column("Datas Transfered", justify="right")
    io_table.add_row("Read", str(stats['io_reads']), f"{stats['io_read_bytes']} bytes")
    io_table.add_row("Write", str(stats['io_writes']), f"{stats['io_write_bytes']} bytes")
    console.print(io_table)

    leaks = stats['active_ptrs']
    if not leaks:
        console.print("[bold green]No memory leaks detected![/bold green]")
        return

    # Classify leaks
    user_leaks = {}
    system_leaks = {}

    for ptr, data in leaks.items():
        caller = data.get("caller", "unknown")
        match = analyze_caller(caller)
        if match:
            system_leaks[ptr] = {**data, "_analysis": match}
        else:
            user_leaks[ptr] = data

    # --- User leaks table ---
    if user_leaks:
        user_table = Table(
            title=f"\n{len(user_leaks)} User Memory Leak(s) Detected",
            style="red",
            title_style="bold red",
        )
        user_table.add_column("Pointer", style="yellow")
        user_table.add_column("Bytes Lost", justify="right", style="red")
        user_table.add_column("Caller", style="magenta")

        total_user_lost = 0
        for ptr, data in user_leaks.items():
            size = data.get("size", 0)
            total_user_lost += size
            caller = data.get("caller", "unknown")
            clean_caller = caller.split("/")[-1] if "/" in caller else caller
            user_table.add_row(str(ptr), str(size), clean_caller)

        console.print(user_table)
        console.print(f"[bold red]  Total User Memory Lost: {total_user_lost} bytes[/bold red]\n")

    # --- System leaks table ---
    if system_leaks:
        sys_table = Table(
            title=f"\n {len(system_leaks)} System/Library Allocation(s) — Likely False Positive(s)",
            style="yellow",
            title_style="bold yellow",
        )
        sys_table.add_column("Pointer", style="dim")
        sys_table.add_column("Bytes", justify="right", style="dim")
        sys_table.add_column("Caller", style="cyan")
        sys_table.add_column("Cause", style="white")
        sys_table.add_column("Resolution", style="green")

        total_sys_lost = 0
        for ptr, data in system_leaks.items():
            size = data.get("size", 0)
            total_sys_lost += size
            caller = data.get("caller", "unknown")
            clean_caller = caller.split("/")[-1] if "/" in caller else caller
            analysis = data["_analysis"]

            sys_table.add_row(
                str(ptr),
                str(size),
                clean_caller,
                analysis["cause"],
                analysis["resolution"],
            )

        console.print(sys_table)
        console.print(f"[bold yellow]  Total System Memory: {total_sys_lost} bytes[/bold yellow]\n")

    # --- Grand total ---
    all_leaks = {**user_leaks, **system_leaks}
    total_lost = sum(d.get("size", 0) for d in leaks.values())
    user_lost = sum(d.get("size", 0) for d in user_leaks.values())

    summary_lines = f"[bold red]User leaks:[/bold red] {user_lost} bytes across {len(user_leaks)} pointer(s)"
    if system_leaks:
        sys_lost = sum(d.get("size", 0) for d in system_leaks.values())
        summary_lines += f"\n[bold yellow]System allocs:[/bold yellow] {sys_lost} bytes across {len(system_leaks)} pointer(s)"
    summary_lines += f"\n[bold white]Grand Total:[/bold white] {total_lost} bytes across {len(all_leaks)} pointer(s)"

    console.print(Panel(summary_lines, title="[bold]Memory Summary[/bold]", border_style="red"))
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

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
    if leaks: 
        leak_table = Table(title=f"\n {len(leaks)} Memory Leaks detected", style="red")
        leak_table.add_column("Pointer", style="yellow")
        leak_table.add_column("Bytes Lost", justify="right", style="red")
        leak_table.add_column("Caller", style="magenta")

        total_lost = 0
        
        for ptr, data in leaks.items():
            size = data.get("size", 0)
            total_lost += size

            caller = data.get("caller", "unknown")
            clean_caller = caller.split("/")[-1] if "/" in caller else caller

            leak_table.add_row(str(ptr), str(size), clean_caller)

        console.print(leak_table)
        console.print(f"[bold red]Total Memory Lost:[/bold red] {total_lost} bytes")
    else:
        console.print("[bold green]No memory leaks detected![/bold green]")
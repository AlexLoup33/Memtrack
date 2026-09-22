import json
import os

def analyze_trace(trace_file):
    if not os.path.exists(trace_file):
        return None

    stats = {
        "current_memory": 0,
        "peak_memory": 0,
        "allocations": 0,
        "frees": 0,
        "active_ptrs": {},
        "io_reads": 0,
        "io_writes": 0,
        "io_read_bytes": 0,
        "io_write_bytes": 0,
        "timeline": []
    }

    with open(trace_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            action = event.get("action")

            if action == "malloc":
                size = event.get("size", 0)
                ptr = event.get("ptr")
                caller = event.get("caller", "unknown")
                stats["allocations"] += 1
                stats["current_memory"] += size

                if stats["current_memory"] > stats["peak_memory"]:
                    stats["peak_memory"] = stats["current_memory"]

                stats["active_ptrs"][ptr] = {"size": size, "caller": caller}
                stats["timeline"].append({
                    "ts": event.get("ts", 0),
                    "memory": stats["current_memory"],
                    "action": "malloc"
                })

            elif action == "free":
                ptr = event.get("ptr")
                stats["frees"] += 1
                if ptr in stats["active_ptrs"]:
                    freed_size = stats["active_ptrs"][ptr].get("size", 0)
                    stats["current_memory"] -= freed_size
                    del stats["active_ptrs"][ptr]
                    
                stats["timeline"].append({
                    "ts": event.get("ts", 0),
                    "ram": stats["current_memory"],
                    "action": "free"
                })

            elif action == "read":
                stats["io_reads"] += 1
                stats["io_read_bytes"] += event.get("ret", 0)

            elif action == "write":
                stats["io_writes"] += 1
                stats["io_write_bytes"] += event.get("ret", 0)

        return stats
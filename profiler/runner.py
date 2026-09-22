import os
import sys
import subprocess
import yaml


def run_target(target_bin):
    if not os.path.exists(target_bin):
        print(f"Error : '{target_bin}' not found.")
        sys.exit(1)

    env = os.environ.copy()
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    interceptor_path = os.path.join(project_root, "interceptor", "memtrack.so")
    
    if not os.path.exists(interceptor_path):
        print(f"Critical Error : Interceptor not found at :\n{interceptor_path}")
        print("Please ensure the interceptor is built and located in the correct directory.")
        sys.exit(1)

    env["LD_PRELOAD"] = interceptor_path
    env["MEMTRACK_OUT"] = "trace.jsonl"
    
    print(f"Starting {target_bin} under surveillance...")
    print("The terminal is yours. Press Ctrl+C to force stop.")
    print("-" * 50)
    
    try:
        subprocess.run(
            [target_bin], 
            env=env, 
            check=True,
            stdin=sys.stdin,   
            stdout=sys.stdout, 
            stderr=sys.stderr
        )
    except subprocess.CalledProcessError as e:
        print(f"\nShutdown (Code {e.returncode})")
    except KeyboardInterrupt:
        print("\nManual interruption.")
    finally:
        print("-" * 50)
        print("Profiling completed. Trace saved.")
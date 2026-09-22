<div style="text-align: center;">
    <img src="assets/memtracker.jpeg" height="200"/>
</div>

# MemTrack

A lightweight, zero-instrumentation memory profiler and execution analyzer for C and C++ applications.

MemTrack relies on an `LD_PRELOAD` shared library to intercept memory management functions (`malloc`, `free`) and I/O system calls at runtime. It decouples data collection from analysis by streaming events to a buffered JSONL trace. A dedicated Python toolchain then parses this trace to calculate active memory, detect leaks, and generate an interactive HTML timeline report, ensuring minimal overhead on the target application during execution.

## Installation

Clone the repository and compile the C interceptor library:

```bash
git clone https://github.com/AlexLoup33/Memtracker.git
cd memtrack/interceptor
make
```

Ensure you have Python 3.6+ installed. Install the required Python dependencies for the CLI interface:
```bash
pip install -r requirements.txt
```

## Usage

Before using the tool, feel free to know that to maximise the potential of the app by compiling your own C or C++ code with `-rdynamic` flag.

There is two way to use the tool: 

1. Profile the target application

Run your target binary using the Python orchestrator. This automatically injects the LD_PRELOAD library and captures the execution trace. For accurate caller tracking, ensure your target application is compiled with the `-g` and `-rdynamic` flag.

```bash
python memtrack.py run ./your_target_bin
```

2. Analyze and export the trace

Parse the generated trace.jsonl file to display execution statistics, peak memory usage, and memory leak detection in the terminal:

```bash
python memtrack.py analyze trace.jsonl
```

## Contributing
Contributions are welcome to expand the tracing capabilities or improve the visualization tools.


1. Fork the project.
2. Create your feature branch (git checkout -b feature/AmazingFeature).
3. Commit your changes (git commit -m 'Add some AmazingFeature').
4. Push to the branch (git push origin feature/AmazingFeature).
5. Open a Pull Request.

Please ensure that your C code does not introduce blocking operations in the interception hooks to maintain the low-overhead philosophy of the profiler.

## Contributors

- Alexandre Lou-Poueyou - Initial work & Core Development

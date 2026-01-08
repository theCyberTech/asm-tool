"""
Parallel module runner for executing scan modules concurrently.

Execution groups based on dependencies:
- Group 1 (Sequential): discover - must run first to find targets
- Group 2 (Parallel): portscan, certificates, fingerprint, takeover, dns
- Group 3 (Parallel): urls, emails, apis
- Group 4 (Sequential): vulnscan - runs last, uses all discovered data
"""

import io
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Any
from contextlib import contextmanager


@dataclass
class ModuleResult:
    """Result from a module execution"""
    name: str
    success: bool
    output: str
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class ExecutionGroup:
    """A group of modules that can run in parallel"""
    name: str
    modules: List[str]
    parallel: bool = True


class OutputCapture:
    """Thread-safe output capture to prevent interleaving"""

    def __init__(self):
        self._lock = threading.Lock()
        self._buffers: Dict[str, io.StringIO] = {}
        self._original_stdout = None
        self._original_stderr = None

    @contextmanager
    def capture(self, module_name: str):
        """Context manager to capture output for a specific module"""
        buffer = io.StringIO()
        self._buffers[module_name] = buffer

        # Thread-local stdout redirection
        thread_id = threading.current_thread().ident

        # Store original
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        try:
            # Create a wrapper that writes to both buffer and original
            sys.stdout = _ThreadAwareWriter(old_stdout, buffer, thread_id)
            sys.stderr = _ThreadAwareWriter(old_stderr, buffer, thread_id)
            yield buffer
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def get_output(self, module_name: str) -> str:
        """Get captured output for a module"""
        if module_name in self._buffers:
            return self._buffers[module_name].getvalue()
        return ""

    def flush_all(self, console) -> None:
        """Flush all captured output to console in order"""
        with self._lock:
            for name, buffer in self._buffers.items():
                output = buffer.getvalue()
                if output.strip():
                    console.print(output, end="")
            self._buffers.clear()


class _ThreadAwareWriter:
    """Writer that captures output only for specific thread"""

    def __init__(self, original, buffer: io.StringIO, target_thread_id: int):
        self._original = original
        self._buffer = buffer
        self._target_thread_id = target_thread_id
        self._lock = threading.Lock()

    def write(self, text):
        current_thread = threading.current_thread().ident
        if current_thread == self._target_thread_id:
            with self._lock:
                self._buffer.write(text)
        # Always write to original for immediate feedback
        self._original.write(text)

    def flush(self):
        self._original.flush()

    def __getattr__(self, name):
        return getattr(self._original, name)


class ParallelRunner:
    """
    Runs scan modules in parallel groups while respecting dependencies.

    Execution order:
    1. discover (sequential) - must complete first to find targets
    2. portscan, certificates, fingerprint, takeover, dns (parallel)
    3. urls, emails, apis (parallel)
    4. vulnscan (sequential) - runs last with all discovered data
    """

    # Default execution groups
    GROUPS = [
        ExecutionGroup("Discovery", ["discover"], parallel=False),
        ExecutionGroup("Asset Analysis", ["portscan", "certificates", "fingerprint", "takeover", "dns"], parallel=True),
        ExecutionGroup("Content Discovery", ["urls", "emails", "apis"], parallel=True),
        ExecutionGroup("Vulnerability Scan", ["vulnscan"], parallel=False),
    ]

    def __init__(self, ctx, console, max_workers: int = 5):
        """
        Initialize the parallel runner.

        Args:
            ctx: Click context with db and config
            console: Rich console for output
            max_workers: Maximum parallel workers per group
        """
        self.ctx = ctx
        self.console = console
        self.max_workers = max_workers
        self.results: List[ModuleResult] = []
        self._module_funcs: Dict[str, Callable] = {}

    def register_module(self, name: str, func: Callable) -> None:
        """Register a module function by name"""
        self._module_funcs[name] = func

    def run(self, domain: str, parallel: bool = True) -> List[ModuleResult]:
        """
        Run all module groups.

        Args:
            domain: Target domain to scan
            parallel: If False, run everything sequentially

        Returns:
            List of ModuleResult for each module
        """
        self.results = []

        for group in self.GROUPS:
            self._run_group(group, domain, use_parallel=parallel and group.parallel)

        return self.results

    def _run_group(self, group: ExecutionGroup, domain: str, use_parallel: bool) -> None:
        """Run a single execution group"""
        if not group.modules:
            return

        # Filter to only registered modules
        modules_to_run = [m for m in group.modules if m in self._module_funcs]
        if not modules_to_run:
            return

        if use_parallel and len(modules_to_run) > 1:
            self._run_parallel(group.name, modules_to_run, domain)
        else:
            self._run_sequential(group.name, modules_to_run, domain)

    def _run_sequential(self, group_name: str, modules: List[str], domain: str) -> None:
        """Run modules sequentially"""
        for module_name in modules:
            result = self._run_module(module_name, domain)
            self.results.append(result)

    def _run_parallel(self, group_name: str, modules: List[str], domain: str) -> None:
        """Run modules in parallel with output buffering"""
        import time

        self.console.print(f"\n[bold cyan]Running {group_name} in parallel ({len(modules)} modules)...[/]")

        results_map: Dict[str, ModuleResult] = {}

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(modules))) as executor:
            futures = {
                executor.submit(self._run_module, name, domain): name
                for name in modules
            }

            for future in as_completed(futures):
                module_name = futures[future]
                try:
                    result = future.result()
                    results_map[module_name] = result
                    # Show completion status
                    status = "[green]done[/]" if result.success else "[red]failed[/]"
                    self.console.print(f"  [dim]{module_name}:[/] {status}")
                except Exception as e:
                    results_map[module_name] = ModuleResult(
                        name=module_name,
                        success=False,
                        output="",
                        error=str(e)
                    )
                    self.console.print(f"  [dim]{module_name}:[/] [red]error: {e}[/]")

        # Add results in original order for consistency
        for module_name in modules:
            if module_name in results_map:
                self.results.append(results_map[module_name])

    def _run_module(self, module_name: str, domain: str) -> ModuleResult:
        """Run a single module and capture its result"""
        import time

        func = self._module_funcs.get(module_name)
        if not func:
            return ModuleResult(
                name=module_name,
                success=False,
                output="",
                error=f"Module {module_name} not registered"
            )

        start_time = time.time()
        output = ""
        error = None
        success = True

        try:
            # Call the module function
            func(domain)
        except Exception as e:
            success = False
            error = str(e)

        duration = time.time() - start_time

        return ModuleResult(
            name=module_name,
            success=success,
            output=output,
            error=error,
            duration=duration
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary"""
        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        failed = total - successful
        total_duration = sum(r.duration for r in self.results)

        return {
            "total_modules": total,
            "successful": successful,
            "failed": failed,
            "total_duration": total_duration,
            "modules": [
                {
                    "name": r.name,
                    "success": r.success,
                    "duration": r.duration,
                    "error": r.error
                }
                for r in self.results
            ]
        }

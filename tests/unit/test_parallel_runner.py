"""
Unit tests for the parallel module runner
"""

import pytest
import time
from unittest.mock import MagicMock, patch
from asm.core.parallel_runner import (
    ParallelRunner,
    ModuleResult,
    ExecutionGroup,
    OutputCapture,
)


class TestModuleResult:
    """Test ModuleResult dataclass"""

    def test_basic_result(self):
        result = ModuleResult(
            name="test_module",
            success=True,
            output="test output",
        )
        assert result.name == "test_module"
        assert result.success is True
        assert result.output == "test output"
        assert result.error is None
        assert result.duration == 0.0

    def test_failed_result(self):
        result = ModuleResult(
            name="failed_module",
            success=False,
            output="",
            error="Something went wrong",
            duration=1.5,
        )
        assert result.success is False
        assert result.error == "Something went wrong"
        assert result.duration == 1.5


class TestExecutionGroup:
    """Test ExecutionGroup dataclass"""

    def test_parallel_group(self):
        group = ExecutionGroup(
            name="Test Group",
            modules=["mod1", "mod2", "mod3"],
            parallel=True,
        )
        assert group.name == "Test Group"
        assert len(group.modules) == 3
        assert group.parallel is True

    def test_sequential_group(self):
        group = ExecutionGroup(
            name="Sequential",
            modules=["mod1"],
            parallel=False,
        )
        assert group.parallel is False


class TestParallelRunner:
    """Test ParallelRunner class"""

    @pytest.fixture
    def mock_ctx(self):
        ctx = MagicMock()
        ctx.obj = {"db": MagicMock(), "config": MagicMock()}
        return ctx

    @pytest.fixture
    def mock_console(self):
        return MagicMock()

    @pytest.fixture
    def runner(self, mock_ctx, mock_console):
        return ParallelRunner(mock_ctx, mock_console, max_workers=3)

    def test_init(self, runner):
        assert runner.max_workers == 3
        assert runner.results == []
        assert runner._module_funcs == {}

    def test_register_module(self, runner):
        def dummy_func(domain):
            pass

        runner.register_module("test", dummy_func)
        assert "test" in runner._module_funcs

    def test_run_sequential(self, runner):
        """Test sequential execution"""
        call_order = []

        def make_func(name):
            def func(domain):
                call_order.append(name)
            return func

        runner.register_module("mod1", make_func("mod1"))
        runner.register_module("mod2", make_func("mod2"))
        runner.register_module("mod3", make_func("mod3"))

        # Override groups for testing
        runner.GROUPS = [
            ExecutionGroup("Test", ["mod1", "mod2", "mod3"], parallel=False)
        ]

        runner.run("example.com", parallel=False)

        assert call_order == ["mod1", "mod2", "mod3"]
        assert len(runner.results) == 3
        assert all(r.success for r in runner.results)

    def test_run_parallel(self, runner):
        """Test parallel execution"""
        executed = set()
        lock = __import__("threading").Lock()

        def make_func(name):
            def func(domain):
                with lock:
                    executed.add(name)
                time.sleep(0.01)  # Small delay to ensure parallelism
            return func

        runner.register_module("mod1", make_func("mod1"))
        runner.register_module("mod2", make_func("mod2"))
        runner.register_module("mod3", make_func("mod3"))

        # Override groups for testing
        runner.GROUPS = [
            ExecutionGroup("Test", ["mod1", "mod2", "mod3"], parallel=True)
        ]

        runner.run("example.com", parallel=True)

        assert executed == {"mod1", "mod2", "mod3"}
        assert len(runner.results) == 3

    def test_run_with_failure(self, runner):
        """Test handling of module failures"""
        def success_func(domain):
            pass

        def fail_func(domain):
            raise Exception("Module failed")

        runner.register_module("success", success_func)
        runner.register_module("fail", fail_func)

        runner.GROUPS = [
            ExecutionGroup("Test", ["success", "fail"], parallel=False)
        ]

        runner.run("example.com", parallel=False)

        assert len(runner.results) == 2

        success_result = next(r for r in runner.results if r.name == "success")
        assert success_result.success is True

        fail_result = next(r for r in runner.results if r.name == "fail")
        assert fail_result.success is False
        assert "Module failed" in fail_result.error

    def test_run_respects_groups(self, runner):
        """Test that execution respects group ordering"""
        execution_times = {}

        def make_func(name):
            def func(domain):
                execution_times[name] = time.time()
                time.sleep(0.05)
            return func

        runner.register_module("discover", make_func("discover"))
        runner.register_module("portscan", make_func("portscan"))
        runner.register_module("vulnscan", make_func("vulnscan"))

        runner.GROUPS = [
            ExecutionGroup("Discovery", ["discover"], parallel=False),
            ExecutionGroup("Analysis", ["portscan"], parallel=True),
            ExecutionGroup("Vuln", ["vulnscan"], parallel=False),
        ]

        runner.run("example.com", parallel=True)

        # Verify ordering
        assert execution_times["discover"] < execution_times["portscan"]
        assert execution_times["portscan"] < execution_times["vulnscan"]

    def test_get_summary(self, runner):
        """Test summary generation"""
        runner.results = [
            ModuleResult("mod1", True, "", duration=1.0),
            ModuleResult("mod2", True, "", duration=2.0),
            ModuleResult("mod3", False, "", error="Failed", duration=0.5),
        ]

        summary = runner.get_summary()

        assert summary["total_modules"] == 3
        assert summary["successful"] == 2
        assert summary["failed"] == 1
        assert summary["total_duration"] == 3.5
        assert len(summary["modules"]) == 3

    def test_unregistered_module_skipped(self, runner):
        """Test that unregistered modules are skipped"""
        runner.register_module("mod1", lambda d: None)
        # mod2 not registered

        runner.GROUPS = [
            ExecutionGroup("Test", ["mod1", "mod2"], parallel=False)
        ]

        runner.run("example.com", parallel=False)

        # Only mod1 should have run
        assert len(runner.results) == 1
        assert runner.results[0].name == "mod1"

    def test_parallel_faster_than_sequential(self, runner):
        """Test that parallel execution is faster with sleep-based modules"""
        def slow_func(domain):
            time.sleep(0.1)

        runner.register_module("mod1", slow_func)
        runner.register_module("mod2", slow_func)
        runner.register_module("mod3", slow_func)

        runner.GROUPS = [
            ExecutionGroup("Test", ["mod1", "mod2", "mod3"], parallel=True)
        ]

        start = time.time()
        runner.run("example.com", parallel=True)
        parallel_time = time.time() - start

        runner.results = []
        runner.GROUPS = [
            ExecutionGroup("Test", ["mod1", "mod2", "mod3"], parallel=False)
        ]

        start = time.time()
        runner.run("example.com", parallel=False)
        sequential_time = time.time() - start

        # Parallel should be significantly faster
        assert parallel_time < sequential_time * 0.7


class TestOutputCapture:
    """Test OutputCapture class"""

    def test_get_output_empty(self):
        capture = OutputCapture()
        assert capture.get_output("nonexistent") == ""

    def test_capture_creates_buffer(self):
        capture = OutputCapture()
        with capture.capture("test_module"):
            pass
        assert "test_module" in capture._buffers


class TestDefaultGroups:
    """Test default execution group configuration"""

    def test_default_groups_defined(self):
        assert len(ParallelRunner.GROUPS) == 4

    def test_discover_first(self):
        first_group = ParallelRunner.GROUPS[0]
        assert "discover" in first_group.modules
        assert first_group.parallel is False

    def test_vulnscan_last(self):
        last_group = ParallelRunner.GROUPS[-1]
        assert "vulnscan" in last_group.modules
        assert last_group.parallel is False

    def test_middle_groups_parallel(self):
        for group in ParallelRunner.GROUPS[1:-1]:
            assert group.parallel is True

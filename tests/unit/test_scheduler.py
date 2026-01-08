"""
Unit tests for ASM Core Scheduler module
"""

import json

from asm.core.scheduler import Scheduler
from tests.fixtures import MockConfig, TEST_DOMAIN, TempDirectory


class TestScheduler:
    """Test cases for Scheduler class"""

    def test_scheduler_initialization(self):
        """Test scheduler initialization"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            assert scheduler.config == config
            assert scheduler.data_dir == temp_dir
            assert scheduler.schedule_file == temp_dir / "schedules.json"
            assert scheduler.schedules == []

    def test_scheduler_initialization_with_existing_schedules(self):
        """Test scheduler initialization with existing schedule file"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            # Create existing schedules file
            schedule_file = temp_dir / "schedules.json"
            existing_schedules = [
                {
                    "id": 1,
                    "domains": ["example.com"],
                    "cron": "0 6 * * *",
                    "scan_type": "full",
                    "created_at": "2023-12-25T10:30:00Z",
                    "enabled": True,
                }
            ]
            schedule_file.write_text(json.dumps(existing_schedules))

            scheduler = Scheduler(config, temp_dir)

            assert len(scheduler.schedules) == 1
            assert scheduler.schedules[0]["domains"] == ["example.com"]

    def test_add_job(self):
        """Test adding a new scheduled job"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            domains = (TEST_DOMAIN,)
            cron_expr = "0 0 * * *"

            scheduler.add_job(domains, cron_expr)

            assert len(scheduler.schedules) == 1
            job = scheduler.schedules[0]
            assert job["domains"] == [TEST_DOMAIN]
            assert job["cron"] == cron_expr
            assert job["scan_type"] == "full"
            assert job["enabled"] is True
            assert "id" in job
            assert "created_at" in job

    def test_add_job_with_custom_scan_type(self):
        """Test adding a job with custom scan type"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            domains = (TEST_DOMAIN,)
            cron_expr = "0 */6 * * *"
            scan_type = "certificates"

            scheduler.add_job(domains, cron_expr, scan_type)

            job = scheduler.schedules[0]
            assert job["scan_type"] == scan_type

    def test_add_job_multiple_jobs(self):
        """Test adding multiple jobs"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add first job
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *", "full")

            # Add second job
            scheduler.add_job(("another.com",), "0 12 * * *", "discover")

            assert len(scheduler.schedules) == 2
            assert scheduler.schedules[0]["domains"] == [TEST_DOMAIN]
            assert scheduler.schedules[1]["domains"] == ["another.com"]
            assert scheduler.schedules[0]["id"] == 1
            assert scheduler.schedules[1]["id"] == 2

    def test_remove_job_existing(self):
        """Test removing an existing job"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add job first
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *")
            job_id = scheduler.schedules[0]["id"]

            # Remove job
            result = scheduler.remove_job(job_id)

            assert result is True
            assert len(scheduler.schedules) == 0

    def test_remove_job_nonexistent(self):
        """Test removing a non-existent job"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Try to remove non-existent job
            result = scheduler.remove_job(999)

            assert result is False
            assert len(scheduler.schedules) == 0

    def test_list_jobs(self):
        """Test listing all jobs"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add multiple jobs
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *", "full")
            scheduler.add_job(("test.com",), "0 12 * * *", "discover")

            jobs = scheduler.list_jobs()

            assert len(jobs) == 2
            assert jobs[0]["domains"] == [TEST_DOMAIN]
            assert jobs[1]["domains"] == ["test.com"]

    def test_generate_crontab_empty(self):
        """Test generating crontab with no jobs"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            crontab = scheduler.generate_crontab()

            assert "# ASM Tool Scheduled Scans" in crontab
            assert "# Generated automatically - do not edit manually" in crontab
            assert (
                "" in crontab.split("\n")[-1] or len(crontab.strip().split("\n")) == 3
            )  # Header lines only

    def test_generate_crontab_with_jobs(self):
        """Test generating crontab with jobs"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add jobs
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *", "full")
            scheduler.add_job(("test.com",), "0 */6 * * *", "certificates")

            crontab = scheduler.generate_crontab()

            assert f"cd /app && python -m asm scan {TEST_DOMAIN}" in crontab
            assert "cd /app && python -m asm certificates --all-known" in crontab
            assert "# ASM Tool Scheduled Scans" in crontab

    def test_generate_crontab_disabled_job(self):
        """Test generating crontab with disabled job"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add job
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *", "full")

            # Disable the job
            scheduler.schedules[0]["enabled"] = False

            crontab = scheduler.generate_crontab()

            # Disabled job should not appear in crontab
            assert f"cd /app && python -m asm scan {TEST_DOMAIN}" not in crontab

    def test_generate_crontab_different_scan_types(self):
        """Test generating crontab for different scan types"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add jobs with different types
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *", "full")
            scheduler.add_job(("test.com",), "0 12 * * *", "discover")
            scheduler.add_job(("api.example.com",), "0 18 * * *", "custom_scan")

            crontab = scheduler.generate_crontab()

            assert f"cd /app && python -m asm scan {TEST_DOMAIN}" in crontab
            assert "cd /app && python -m asm discover test.com" in crontab
            assert "cd /app && python -m asm custom_scan api.example.com" in crontab

    def test_export_crontab(self):
        """Test exporting crontab to file"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add job
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *", "full")

            # Export to file
            export_path = temp_dir / "crontab.txt"
            scheduler.export_crontab(export_path)

            assert export_path.exists()
            content = export_path.read_text()
            assert f"cd /app && python -m asm scan {TEST_DOMAIN}" in content

    def test_persistence_schedules_saved(self):
        """Test that schedules are persisted to file"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add job
            scheduler.add_job((TEST_DOMAIN,), "0 6 * * *", "full")

            # Create new scheduler instance to test persistence
            scheduler2 = Scheduler(config, temp_dir)

            assert len(scheduler2.schedules) == 1
            assert scheduler2.schedules[0]["domains"] == [TEST_DOMAIN]

    def test_edge_case_empty_domains_list(self):
        """Test adding job with empty domains list"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            # Add job with empty domains
            scheduler.add_job((), "0 6 * * *", "full")

            # Should still create job but with empty domains
            assert len(scheduler.schedules) == 1
            assert scheduler.schedules[0]["domains"] == []

    def test_edge_case_very_long_cron_expression(self):
        """Test adding job with very long cron expression"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            long_cron = "0 0 1 2 3 4 5 6 7 8 9 10 11 12"
            scheduler.add_job((TEST_DOMAIN,), long_cron, "full")

            job = scheduler.schedules[0]
            assert job["cron"] == long_cron

    def test_edge_case_unicode_domains(self):
        """Test adding job with Unicode characters in domains"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            scheduler = Scheduler(config, temp_dir)

            unicode_domain = "tëst.example.com"
            scheduler.add_job((unicode_domain,), "0 6 * * *", "full")

            job = scheduler.schedules[0]
            assert job["domains"] == [unicode_domain]

    def test_edge_case_invalid_schedule_file(self):
        """Test scheduler initialization with invalid JSON file"""
        config = MockConfig()

        with TempDirectory() as temp_dir:
            # Create invalid JSON file
            schedule_file = temp_dir / "schedules.json"
            schedule_file.write_text("invalid json content")

            # Should handle gracefully and start with empty schedules
            scheduler = Scheduler(config, temp_dir)
            assert scheduler.schedules == []

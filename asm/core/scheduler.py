"""
Scheduler module for recurring scans
"""

import json
from pathlib import Path
from typing import List, Tuple
from datetime import datetime, timezone

from .config import Config


class Scheduler:
    """Manage scheduled scan jobs

    Note: This creates cron-compatible schedule files.
    For actual scheduling, use host's cron or a container orchestrator.
    """

    def __init__(self, config: Config, data_dir: Path):
        """
        Initialize scheduler with configuration and data directory

        Args:
            config: Configuration object containing scan settings
            data_dir: Directory for storing schedule files
        """
        self.config = config
        self.data_dir = data_dir
        self.schedule_file = data_dir / "schedules.json"
        self.schedules = self._load_schedules()

    def _load_schedules(self) -> List[dict]:
        """
        Load existing schedules from JSON file

        Returns:
            List[dict]: List of scheduled job configurations
        """
        if self.schedule_file.exists():
            try:
                with open(self.schedule_file) as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def _save_schedules(self) -> None:
        """
        Save schedules to JSON file

        Persists current schedule configuration to disk with proper formatting.
        """
        with open(self.schedule_file, "w") as f:
            json.dump(self.schedules, f, indent=2)

    def add_job(
        self, domains: Tuple[str, ...], cron_expr: str, scan_type: str = "full"
    ) -> None:
        """
        Add a scheduled scan job

        Args:
            domains: Tuple of target domains for the job
            cron_expr: Cron expression for scheduling (e.g., "0 6 * * *")
            scan_type: Type of scan ('full', 'discover', 'certificates', etc.)
        """
        job = {
            "id": len(self.schedules) + 1,
            "domains": list(domains),
            "cron": cron_expr,
            "scan_type": scan_type,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "enabled": True,
        }
        self.schedules.append(job)
        self._save_schedules()

    def remove_job(self, job_id: int) -> bool:
        """
        Remove a scheduled job

        Args:
            job_id: ID of job to remove

        Returns:
            bool: True if job found and removed, False otherwise
        """
        for i, job in enumerate(self.schedules):
            if job["id"] == job_id:
                self.schedules.pop(i)
                self._save_schedules()
                return True
        return False

    def list_jobs(self) -> List[dict]:
        """
        List all scheduled jobs

        Returns:
            List[dict]: List of all scheduled job configurations
        """
        return self.schedules

    def generate_crontab(self) -> str:
        """
        Generate crontab entries for all jobs

        Returns:
            str: Complete crontab file content with ASM job commands
        """
        lines = [
            "# ASM Tool Scheduled Scans",
            "# Generated automatically - do not edit manually",
            "",
        ]

        for job in self.schedules:
            if not job.get("enabled", True):
                continue

            domains = " ".join(job["domains"])
            scan_type = job.get("scan_type", "full")

            if scan_type == "full":
                cmd = f"cd /app && python -m asm scan {domains}"
            elif scan_type == "discover":
                cmd = f"cd /app && python -m asm discover {domains}"
            elif scan_type == "certificates":
                cmd = "cd /app && python -m asm certificates --all-known"
            else:
                cmd = f"cd /app && python -m asm {scan_type} {domains}"

            lines.append(f"{job['cron']} {cmd}")

        return "\n".join(lines)

    def export_crontab(self, path: Path) -> None:
        """
        Export crontab to file

        Args:
            path: File path to write crontab content
        """
        path.write_text(self.generate_crontab())

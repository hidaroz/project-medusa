"""
Progress Tracking
Real-time progress indicators
"""

from typing import Optional, Dict, Any
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.console import Console
from contextlib import contextmanager


console = Console()


class ProgressTracker:
    """
    Progress tracker for operations

    Provides progress bars and status updates
    """

    def __init__(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        )

        self.tasks: Dict[str, TaskID] = {}
        self._started = False

    def start(self):
        """Start progress display"""
        if not self._started:
            self.progress.start()
            self._started = True

    def stop(self):
        """Stop progress display"""
        if self._started:
            self.progress.stop()
            self._started = False

    def add_task(
        self,
        task_id: str,
        description: str,
        total: Optional[int] = None
    ) -> TaskID:
        """
        Add a new task

        Args:
            task_id: Unique task identifier
            description: Task description
            total: Total steps (None for indeterminate)

        Returns:
            Task ID
        """
        if not self._started:
            self.start()

        task = self.progress.add_task(description, total=total)
        self.tasks[task_id] = task

        return task

    def update_task(
        self,
        task_id: str,
        advance: int = 1,
        description: Optional[str] = None
    ):
        """
        Update task progress

        Args:
            task_id: Task identifier
            advance: Steps to advance
            description: New description (optional)
        """
        if task_id not in self.tasks:
            return

        task = self.tasks[task_id]

        kwargs = {"advance": advance}
        if description:
            kwargs["description"] = description

        self.progress.update(task, **kwargs)

    def complete_task(self, task_id: str):
        """Mark task as complete"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            self.progress.update(task, completed=True)

    def remove_task(self, task_id: str):
        """Remove a task"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            self.progress.remove_task(task)
            del self.tasks[task_id]

    @contextmanager
    def task(self, description: str, total: Optional[int] = None):
        """
        Context manager for tasks

        Args:
            description: Task description
            total: Total steps

        Example:
            with tracker.task("Scanning ports", total=65535) as task:
                for port in ports:
                    # do work
                    task.update(advance=1)
        """
        import uuid

        task_id = str(uuid.uuid4())

        class TaskContext:
            def __init__(self, tracker, task_id):
                self.tracker = tracker
                self.task_id = task_id

            def update(self, advance=1, description=None):
                self.tracker.update_task(self.task_id, advance, description)

        self.add_task(task_id, description, total)

        try:
            yield TaskContext(self, task_id)
        finally:
            self.complete_task(task_id)

    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()

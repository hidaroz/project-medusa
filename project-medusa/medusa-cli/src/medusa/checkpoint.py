"""
Checkpoint management for MEDUSA Autonomous Mode
Enables pause/resume functionality for long-running operations
"""

import json
import os
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CheckpointManager:
    """Manage operation checkpoints for pause/resume"""

    def __init__(self, operation_id: str, checkpoint_dir: str = "./checkpoints"):
        """
        Initialize checkpoint manager

        Args:
            operation_id: Unique operation identifier
            checkpoint_dir: Directory for checkpoint files
        """
        self.operation_id = operation_id
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_file = os.path.join(checkpoint_dir, f"{operation_id}.json")

        # Create checkpoint directory
        Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)

    def save(self, checkpoint_data: Dict[str, Any]) -> str:
        """
        Save checkpoint

        Args:
            checkpoint_data: Checkpoint state data

        Returns:
            Path to checkpoint file
        """
        try:
            # Add metadata
            checkpoint_data["_checkpoint_metadata"] = {
                "saved_at": datetime.now().isoformat(),
                "operation_id": self.operation_id,
                "version": "1.0"
            }

            # Save to file
            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint_data, f, indent=2)

            logger.info(f"Checkpoint saved: {self.checkpoint_file}")
            return self.checkpoint_file

        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}", exc_info=True)
            raise

    def load(self) -> Optional[Dict[str, Any]]:
        """
        Load checkpoint if it exists

        Returns:
            Checkpoint data or None if not found
        """
        if not os.path.exists(self.checkpoint_file):
            return None

        try:
            with open(self.checkpoint_file, 'r') as f:
                checkpoint_data = json.load(f)

            logger.info(f"Checkpoint loaded: {self.checkpoint_file}")
            return checkpoint_data

        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}", exc_info=True)
            return None

    def exists(self) -> bool:
        """Check if checkpoint exists"""
        return os.path.exists(self.checkpoint_file)

    def delete(self):
        """Delete checkpoint file"""
        if os.path.exists(self.checkpoint_file):
            os.remove(self.checkpoint_file)
            logger.info(f"Checkpoint deleted: {self.checkpoint_file}")

    @classmethod
    def list_checkpoints(cls, checkpoint_dir: str = "./checkpoints") -> list:
        """
        List available checkpoints

        Args:
            checkpoint_dir: Directory containing checkpoints

        Returns:
            List of checkpoint info dicts
        """
        checkpoints = []

        if not os.path.exists(checkpoint_dir):
            return checkpoints

        for filename in os.listdir(checkpoint_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(checkpoint_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)

                    metadata = data.get("_checkpoint_metadata", {})
                    checkpoints.append({
                        "operation_id": metadata.get("operation_id", filename[:-5]),
                        "saved_at": metadata.get("saved_at", "Unknown"),
                        "filepath": filepath,
                        "current_phase": data.get("current_phase", "unknown"),
                        "completed_phases": data.get("completed_phases", []),
                    })

                except Exception as e:
                    logger.warning(f"Failed to read checkpoint {filepath}: {e}")
                    continue

        return sorted(checkpoints, key=lambda x: x["saved_at"], reverse=True)


class PhaseCheckpoint:
    """Checkpoint data for a specific phase"""

    def __init__(self, phase_name: str):
        """
        Initialize phase checkpoint

        Args:
            phase_name: Name of the phase
        """
        self.phase_name = phase_name
        self.started_at = datetime.now().isoformat()
        self.completed_at: Optional[str] = None
        self.status = "in_progress"
        self.findings = []
        self.techniques = []
        self.errors = []
        self.progress = 0
        self.metadata = {}

    def mark_complete(self):
        """Mark phase as complete"""
        self.status = "complete"
        self.completed_at = datetime.now().isoformat()
        self.progress = 100

    def mark_failed(self, error: str):
        """Mark phase as failed"""
        self.status = "failed"
        self.completed_at = datetime.now().isoformat()
        self.errors.append({
            "timestamp": datetime.now().isoformat(),
            "error": error
        })

    def add_finding(self, finding: Dict[str, Any]):
        """Add finding to phase"""
        self.findings.append(finding)

    def add_technique(self, technique: Dict[str, Any]):
        """Add technique to phase"""
        self.techniques.append(technique)

    def set_progress(self, progress: int):
        """Set progress percentage"""
        self.progress = min(100, max(0, progress))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "phase_name": self.phase_name,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "findings": self.findings,
            "techniques": self.techniques,
            "errors": self.errors,
            "progress": self.progress,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PhaseCheckpoint':
        """Create from dictionary"""
        checkpoint = cls(data["phase_name"])
        checkpoint.started_at = data.get("started_at", checkpoint.started_at)
        checkpoint.completed_at = data.get("completed_at")
        checkpoint.status = data.get("status", "in_progress")
        checkpoint.findings = data.get("findings", [])
        checkpoint.techniques = data.get("techniques", [])
        checkpoint.errors = data.get("errors", [])
        checkpoint.progress = data.get("progress", 0)
        checkpoint.metadata = data.get("metadata", {})
        return checkpoint


class OperationCheckpoint:
    """Complete operation checkpoint"""

    def __init__(self, operation_id: str, target: str, mode: str):
        """
        Initialize operation checkpoint

        Args:
            operation_id: Unique operation ID
            target: Target URL/IP
            mode: Operation mode
        """
        self.operation_id = operation_id
        self.target = target
        self.mode = mode
        self.started_at = datetime.now().isoformat()
        self.current_phase: Optional[str] = None
        self.completed_phases: list = []
        self.phase_checkpoints: Dict[str, PhaseCheckpoint] = {}
        self.operation_data: Dict[str, Any] = {}
        self.aborted = False
        self.abort_reason: Optional[str] = None

    def start_phase(self, phase_name: str):
        """Start a new phase"""
        self.current_phase = phase_name
        if phase_name not in self.phase_checkpoints:
            self.phase_checkpoints[phase_name] = PhaseCheckpoint(phase_name)

    def complete_phase(self, phase_name: str):
        """Mark phase as complete"""
        if phase_name in self.phase_checkpoints:
            self.phase_checkpoints[phase_name].mark_complete()
            if phase_name not in self.completed_phases:
                self.completed_phases.append(phase_name)

    def get_phase(self, phase_name: str) -> Optional[PhaseCheckpoint]:
        """Get phase checkpoint"""
        return self.phase_checkpoints.get(phase_name)

    def should_skip_phase(self, phase_name: str) -> bool:
        """Check if phase should be skipped (already completed)"""
        return phase_name in self.completed_phases

    def mark_aborted(self, reason: str):
        """Mark operation as aborted"""
        self.aborted = True
        self.abort_reason = reason

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "operation_id": self.operation_id,
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "current_phase": self.current_phase,
            "completed_phases": self.completed_phases,
            "phase_checkpoints": {
                name: checkpoint.to_dict()
                for name, checkpoint in self.phase_checkpoints.items()
            },
            "operation_data": self.operation_data,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OperationCheckpoint':
        """Create from dictionary"""
        checkpoint = cls(
            data["operation_id"],
            data["target"],
            data["mode"]
        )
        checkpoint.started_at = data.get("started_at", checkpoint.started_at)
        checkpoint.current_phase = data.get("current_phase")
        checkpoint.completed_phases = data.get("completed_phases", [])

        # Restore phase checkpoints
        for name, phase_data in data.get("phase_checkpoints", {}).items():
            checkpoint.phase_checkpoints[name] = PhaseCheckpoint.from_dict(phase_data)

        checkpoint.operation_data = data.get("operation_data", {})
        checkpoint.aborted = data.get("aborted", False)
        checkpoint.abort_reason = data.get("abort_reason")

        return checkpoint

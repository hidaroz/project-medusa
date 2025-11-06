# MEDUSA Checkpoint System Guide

## Overview

The checkpoint system enables pause/resume functionality for long-running penetration testing operations. This is essential for operations that may take hours or days to complete.

## Why Checkpoints?

Penetration tests can be interrupted for many reasons:
- **Network issues**: Connection drops or timeouts
- **User interruption**: Need to stop and resume later
- **System resources**: Machine needs to be rebooted
- **Review process**: Need to analyze findings before continuing
- **Time constraints**: Can't complete in one session

Checkpoints ensure you never lose progress.

## Features

### ✅ Automatic Checkpointing
- Checkpoint saved after each phase completion
- No manual intervention required
- Minimal performance impact

### 🔄 Smart Resume
- Resume from last completed phase
- Skip already-completed work
- Preserve all findings and data

### 💾 Persistent State
- JSON-based checkpoint files
- Human-readable format
- Includes all operation data

### 🛡️ Error Recovery
- Saves checkpoint on errors
- Saves checkpoint on Ctrl+C
- Clean recovery path

## How It Works

### Automatic Saving

Checkpoints are automatically saved:
1. After each phase completes
2. On KeyboardInterrupt (Ctrl+C)
3. On uncaught exceptions
4. Before exiting

### Checkpoint Location

```
./checkpoints/
├── auto_20250511_143022.json
├── auto_20250511_150000.json
└── auto_20250511_162045.json
```

### Checkpoint Contents

```json
{
  "operation_id": "auto_20250511_143022",
  "target": "http://localhost:8080",
  "mode": "autonomous",
  "started_at": "2025-05-11T14:30:22",
  "current_phase": "enumeration",
  "completed_phases": ["reconnaissance"],
  "phase_checkpoints": {
    "reconnaissance": {
      "phase_name": "reconnaissance",
      "status": "complete",
      "findings": [...],
      "techniques": [...],
      "progress": 100
    },
    "enumeration": {
      "phase_name": "enumeration",
      "status": "in_progress",
      "findings": [...],
      "progress": 45
    }
  }
}
```

## Usage

### Starting a New Operation

```bash
# Start autonomous mode
medusa autonomous --target http://localhost:8080

Starting Autonomous Assessment against http://localhost:8080
Operation ID: auto_20250511_143022

=== Phase 1: Reconnaissance ===
[Scanning...]
```

### Interrupting an Operation

Press `Ctrl+C` to interrupt:

```bash
^C
⚠ Operation interrupted
Progress has been saved. Resume with:
  medusa autonomous --resume auto_20250511_143022
```

### Resuming an Operation

```bash
medusa autonomous --resume auto_20250511_143022

Resuming Operation auto_20250511_143022
Last phase: enumeration
Completed: reconnaissance

Skipping reconnaissance (already completed)

=== Phase 2: Enumeration ===
[Continuing from where you left off...]
```

### Listing Checkpoints

```bash
medusa checkpoints list

Available Checkpoints:
Operation ID              Saved At             Phase          Completed
auto_20250511_143022     2025-05-11 14:35:22  enumeration    reconnaissance
auto_20250511_120000     2025-05-11 12:10:45  exploitation   recon, enum
```

### Deleting a Checkpoint

```bash
# Delete specific checkpoint
medusa checkpoints delete auto_20250511_143022
✓ Checkpoint deleted

# Clear all checkpoints
medusa checkpoints clear
⚠ This will delete all checkpoints. Continue? [y/N] y
✓ All checkpoints cleared
```

## Phases and Checkpointing

### Phase Flow

```
Reconnaissance → Enumeration → Exploitation → Post-Exploitation
     ↓               ↓               ↓               ↓
 Checkpoint      Checkpoint      Checkpoint      Checkpoint
```

### Phase States

Each phase can be in one of these states:
- **pending**: Not started
- **in_progress**: Currently running
- **complete**: Successfully finished
- **failed**: Encountered an error

### Resume Logic

When resuming:
1. Load checkpoint file
2. Identify completed phases
3. Skip to next incomplete phase
4. Continue from there

Example:
```
Completed: [reconnaissance, enumeration]
Current: exploitation
→ Skip reconnaissance ✓
→ Skip enumeration ✓
→ Run exploitation ← Start here
→ Run post-exploitation
```

## Best Practices

### 1. Name Your Operations

Use meaningful operation IDs:
```bash
# Default: auto_20250511_143022
# Better: Add context in notes/tags (future feature)
```

### 2. Review Between Phases

Interrupt and review findings:
```bash
# After reconnaissance
Ctrl+C
medusa report view auto_20250511_143022

# Review findings, then resume
medusa autonomous --resume auto_20250511_143022
```

### 3. Regular Backups

Checkpoint files are your safety net:
```bash
# Back up checkpoint directory
cp -r ./checkpoints ./checkpoints_backup_$(date +%Y%m%d)
```

### 4. Clean Up Completed Operations

Delete checkpoints after successful completion:
```bash
# Checkpoints are auto-deleted on success
# But you can manually clean up failed ones
medusa checkpoints clear --completed
```

### 5. Monitor Disk Space

Large operations create large checkpoints:
```bash
# Check checkpoint size
du -sh ./checkpoints

# Clean old checkpoints
find ./checkpoints -mtime +7 -delete
```

## Troubleshooting

### Checkpoint Not Found

```bash
medusa autonomous --resume auto_20250511_143022
Error: Checkpoint not found for operation: auto_20250511_143022
```

**Solutions:**
- Check operation ID spelling
- Check `./checkpoints/` directory exists
- Verify checkpoint file exists
- Check file permissions

### Corrupted Checkpoint

```bash
Error: Failed to load checkpoint: Invalid JSON
```

**Solutions:**
- Check JSON validity: `cat checkpoint.json | jq .`
- Restore from backup if available
- Start fresh operation

### Resume Starts from Beginning

If resume doesn't skip phases:
- Check `completed_phases` in checkpoint
- Verify phase names match exactly
- Check checkpoint wasn't manually edited

### Out of Disk Space

```bash
Error: Failed to save checkpoint: No space left on device
```

**Solutions:**
- Free up disk space
- Move checkpoint directory to larger disk
- Reduce checkpoint frequency (not recommended)

## Advanced Usage

### Manual Checkpoint Management

```python
from medusa.checkpoint import CheckpointManager

# Create manager
mgr = CheckpointManager("my_operation")

# Save checkpoint
checkpoint_data = {
    "current_phase": "enumeration",
    "findings": [...],
    # ... other data
}
mgr.save(checkpoint_data)

# Load checkpoint
data = mgr.load()
if data:
    print(f"Resuming from {data['current_phase']}")
```

### Checkpoint Inspection

```bash
# View checkpoint contents
cat ./checkpoints/auto_20250511_143022.json | jq .

# Extract specific info
jq '.completed_phases' checkpoint.json
jq '.phase_checkpoints.reconnaissance.findings' checkpoint.json
```

### Checkpoint Migration

Moving to a different machine:

```bash
# On source machine
tar -czf checkpoints.tar.gz ./checkpoints

# On target machine
tar -xzf checkpoints.tar.gz
medusa autonomous --resume auto_20250511_143022
```

## Performance

### Checkpoint Overhead

- **Save time**: < 100ms per checkpoint
- **File size**: 100KB - 10MB depending on findings
- **Impact**: Negligible on operation time

### Optimization

Checkpoints are optimized for:
- Fast serialization (JSON)
- Minimal memory usage
- Quick resume (lazy loading)

## Security Considerations

### Checkpoint Contents

Checkpoints may contain sensitive data:
- Target URLs and IPs
- Discovered vulnerabilities
- Credentials found
- Exploitation details

### Recommendations

1. **Encrypt checkpoints** for sensitive operations:
   ```bash
   # Encrypt checkpoint directory
   tar -czf - ./checkpoints | openssl enc -aes-256-cbc -out checkpoints.enc
   ```

2. **Restrict permissions**:
   ```bash
   chmod 700 ./checkpoints
   ```

3. **Secure deletion**:
   ```bash
   # Secure delete
   shred -vfz -n 3 checkpoint.json
   ```

4. **Separate sensitive operations**:
   ```bash
   # Use different checkpoint directories
   medusa autonomous --checkpoint-dir /secure/path
   ```

## Integration

### CI/CD Pipelines

Use checkpoints in automated testing:

```yaml
# .gitlab-ci.yml
pentest:
  script:
    - medusa autonomous --target $TARGET || true
    - medusa autonomous --resume $(ls checkpoints/*.json | head -1)
  artifacts:
    paths:
      - checkpoints/
      - reports/
```

### Monitoring

Monitor checkpoint status:

```bash
# Check if operation is in progress
if [ -f ./checkpoints/auto_20250511_143022.json ]; then
    echo "Operation in progress"
    jq '.current_phase' ./checkpoints/auto_20250511_143022.json
fi
```

### Automation

Resume automatically on failure:

```bash
#!/bin/bash
OPERATION_ID="auto_$(date +%Y%m%d_%H%M%S)"

# Try to run
if ! medusa autonomous --target $TARGET; then
    echo "Failed, checking for checkpoint..."
    if [ -f "./checkpoints/${OPERATION_ID}.json" ]; then
        echo "Resuming from checkpoint..."
        medusa autonomous --resume $OPERATION_ID
    fi
fi
```

## Limitations

### Current Limitations

1. **Single operation per ID**: Can't have multiple operations with same ID
2. **No parallel operations**: One operation at a time with checkpoints
3. **Manual cleanup**: Must manually delete old checkpoints
4. **Phase granularity**: Checkpoints per phase, not per sub-task

### Future Enhancements

- [ ] Checkpoint compression
- [ ] Checkpoint encryption
- [ ] Auto-cleanup policies
- [ ] Cross-machine resume
- [ ] Checkpoint versioning
- [ ] Sub-phase checkpoints

## FAQ

**Q: Can I resume on a different machine?**
A: Yes, copy the checkpoint file to the new machine.

**Q: What happens if I modify a checkpoint file?**
A: The operation will resume with your changes, but may fail if invalid.

**Q: Can I have multiple checkpoints for the same operation?**
A: No, each operation ID has one checkpoint file that gets updated.

**Q: How long are checkpoints kept?**
A: Forever, unless manually deleted or operation completes successfully.

**Q: Can I resume if the target changed?**
A: Resume will use the original target from the checkpoint.

**Q: What if I lose the checkpoint file?**
A: You'll need to start the operation from scratch.

## See Also

- [Autonomous Mode Guide](./AUTONOMOUS_MODE_GUIDE.md)
- [Interactive Shell Guide](./INTERACTIVE_SHELL_GUIDE.md)
- [API Documentation](./API_DOCS.md)

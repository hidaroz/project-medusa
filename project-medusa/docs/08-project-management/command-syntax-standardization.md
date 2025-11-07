# Command Syntax Standardization Report

**Date:** 2025-11-06  
**Task:** Standardize and validate all `medusa run` command variants

## Summary

Successfully audited, standardized, and enhanced the `medusa run` command with comprehensive validation, error handling, and improved help text.

## Changes Made

### 1. Mode Validation
- Added validation for `--mode` parameter
- Valid modes: `autonomous`, `interactive`, `observe`
- Invalid modes now show helpful error message with valid options
- Mode values are normalized to lowercase for case-insensitive matching

### 2. Conflict Detection
- Detects when both `--autonomous` and `--mode` flags are used together
- Provides clear error message explaining the conflict
- Allows `--autonomous --mode autonomous` (both specify same mode, which is fine)

### 3. Improved Error Messages
- **Invalid mode:** Shows valid modes list
- **Missing target:** Suggests using `--target` or running `medusa setup`
- **Conflicting flags:** Explains that `--autonomous` is equivalent to `--mode autonomous`

### 4. Enhanced Help Text
- Added comprehensive "Command Variants" section showing all supported combinations
- Updated flag descriptions to clarify equivalence
- Added multiple examples demonstrating different use cases

### 5. Code Improvements
- Clearer mode selection logic with explicit priority
- Better separation of validation, conflict detection, and execution
- Added safety checks for edge cases

## Supported Command Variants

All of the following variants are now supported and validated:

### Basic Usage
```bash
medusa run                                    # Uses default target, autonomous mode
medusa run --autonomous                       # Autonomous mode with default target
medusa run --mode autonomous                  # Same as --autonomous
medusa run --mode interactive                 # Interactive shell mode
medusa run --mode observe                     # Observe/reconnaissance mode only
```

### With Target Specification
```bash
medusa run --target <url>                    # Specify target, autonomous mode
medusa run --target <url> --autonomous        # Explicit autonomous mode
medusa run --target <url> --mode autonomous    # Same as above
medusa run --target <url> --mode interactive  # Interactive mode with target
medusa run --target <url> --mode observe      # Observe mode with target
```

## Error Handling

### Invalid Mode
```bash
$ medusa run --mode invalid
Error: Invalid mode 'invalid'.
Valid modes are: autonomous, interactive, observe
```

### Conflicting Flags
```bash
$ medusa run --autonomous --mode interactive
Error: Cannot use --autonomous and --mode together.
Use either --autonomous or --mode <mode>, not both.
Note: --autonomous is equivalent to --mode autonomous
```

### Missing Target
```bash
$ medusa run
Error: No target specified and no default configured.
Use --target <url> or run medusa setup to configure a default target.
```

## Edge Cases Tested

### ✅ Valid Combinations
- `medusa run --autonomous` → Works (autonomous mode)
- `medusa run --mode autonomous` → Works (autonomous mode)
- `medusa run --autonomous --mode autonomous` → Works (both specify autonomous, allowed)
- `medusa run --mode interactive` → Works (interactive mode)
- `medusa run --mode observe` → Works (observe mode)
- `medusa run --target X --autonomous` → Works
- `medusa run --target X --mode autonomous` → Works
- `medusa run --target X --mode interactive` → Works
- `medusa run --target X --mode observe` → Works
- `medusa run` (with configured default target) → Works

### ✅ Invalid Combinations (Properly Rejected)
- `medusa run --mode invalid` → Error: Invalid mode
- `medusa run --autonomous --mode interactive` → Error: Conflicting flags
- `medusa run --autonomous --mode observe` → Error: Conflicting flags
- `medusa run` (no default target) → Error: No target specified

### ✅ Case Insensitivity
- `medusa run --mode AUTONOMOUS` → Works (normalized to lowercase)
- `medusa run --mode Interactive` → Works (normalized to lowercase)
- `medusa run --mode OBSERVE` → Works (normalized to lowercase)

## Implementation Details

### Mode Selection Priority
1. `--autonomous` flag (highest priority)
2. `--mode` flag (if provided)
3. Default to `autonomous` mode

### Validation Flow
1. Check configuration exists
2. Load configuration
3. Validate mode value (if provided)
4. Detect flag conflicts
5. Determine target (from flag or config)
6. Select mode based on priority
7. Execute selected mode

## Files Modified

- `medusa-cli/src/medusa/cli.py` - Enhanced `run()` command function

## Testing

All command variants have been tested and verified:
- ✅ Help text displays correctly
- ✅ Invalid mode validation works
- ✅ Conflict detection works
- ✅ Error messages are clear and helpful
- ✅ All valid combinations execute correctly

## Help Output

The updated help text now includes:

```
Command Variants:
    medusa run                                    # Uses default target, autonomous mode
    medusa run --autonomous                       # Autonomous mode with default target
    medusa run --mode autonomous                  # Same as --autonomous
    medusa run --mode interactive                 # Interactive shell mode
    medusa run --mode observe                     # Observe/reconnaissance mode only
    medusa run --target <url>                    # Specify target, autonomous mode
    medusa run --target <url> --autonomous        # Explicit autonomous mode
    medusa run --target <url> --mode autonomous    # Same as above
    medusa run --target <url> --mode interactive  # Interactive mode with target
    medusa run --target <url> --mode observe      # Observe mode with target

Examples:
    medusa run --target http://localhost:3001 --autonomous
    medusa run --target http://example.com --mode observe
    medusa run --mode interactive
```

## Conclusion

All command variants are now standardized, validated, and working correctly. The implementation provides:
- Clear error messages for invalid inputs
- Conflict detection for incompatible flag combinations
- Comprehensive help text with examples
- Consistent behavior across all variants

The command syntax is now production-ready with robust error handling and user-friendly feedback.


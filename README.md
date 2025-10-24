# OrphanReaper

A PowerShell script to automatically detect and kill orphaned processes on Windows, with special handling for suspended processes.

## Features

- **Orphan Process Detection**: Finds processes whose parent has exited
- **High CPU Process Cleanup**: Kills orphaned processes consuming excessive CPU
- **Suspended Process Handling**: Detects and terminates suspended/frozen processes
- **Tray UI**: System tray icon for easy monitoring and control
- **Configurable**: Flexible settings for grace periods, CPU thresholds, and process filters
- **Whitelist Support**: Exclude processes matching specific command-line patterns

## Quick Start

### Run Once
```powershell
.\OrphanReaper.ps1
```

### Start Tray Monitor
```powershell
.\OrphanReaper.ps1 -Tray -CheckOnInterval 5 -KillSuspended -SuspendedGraceMinutes 60
```

### List Processes (Dry Run)
```powershell
.\OrphanReaper.ps1 -List
```

## Parameters

- **`-Names`**: Process names to monitor (default: `bash.exe`)
- **`-FolderPaths`**: Executable folder paths to monitor (default: Git bin folders)
- **`-GraceMinutes`**: Grace period before killing high-CPU processes (default: 2)
- **`-CpuThresholdPercent`**: CPU threshold for killing (default: 7%)
- **`-SampleSeconds`**: CPU sampling duration (default: 3)
- **`-KillSuspended`**: Enable killing of suspended processes
- **`-SuspendedGraceMinutes`**: Grace period for suspended processes (default: 60)
- **`-WhitelistCmdRegex`**: Regex pattern to whitelist processes (default: `\bnpm["']?\s+run\b`)
- **`-CheckOnInterval`**: Monitoring interval in minutes (0 = run once)
- **`-Tray`**: Launch system tray UI
- **`-DryRun`**: Test mode - shows what would be killed without actually killing
- **`-List`**: List all matching processes with their status

## Use Cases

### Git Bash Orphan Cleanup
Automatically cleans up orphaned Git Bash processes that can accumulate when terminals are closed abruptly or VSCode crashes.

### Suspended Process Detection
Detects and kills bash.exe processes that have been suspended by Windows (e.g., when laptop sleeps), which can accumulate over time.

## Tray UI Features

- **Start/Stop Monitor**: Control the background watcher
- **Run Once Now**: Manually trigger a cleanup cycle
- **Settings**: Configure grace periods, CPU thresholds, and killing options
- **Open Log Folder**: Quick access to logs

## Requirements

- Windows PowerShell 5.1 or later
- Administrator privileges (recommended for killing processes)

## Files

- **`OrphanReaper.ps1`**: Main script
- **`OrphanReaper.ico`**: Idle tray icon
- **`OrphanReaper-monitoring.ico`**: Active monitoring tray icon
- **`OrphanReaper/reaper.log`**: Activity log
- **`OrphanReaper/pid.txt`**: Current watcher PID (when running)

## License

MIT License - Feel free to use and modify as needed.


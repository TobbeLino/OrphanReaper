# Kill-Orphan-MSYS.ps1 — one-shot / repeating watcher / tray UI in one file
# Run once (default), repeat with -CheckOnInterval <minutes>, or start tray with -Tray.

[CmdletBinding()]
param(
	[string[]]$Names = @('bash.exe'),
	[string[]]$FolderPaths = @('C:\Program Files\Git\usr\bin', 'C:\Program Files\Git\mingw64\bin'),
	[double]$GraceMinutes = 2.0,
	[int]$SampleSeconds = 3,
	[double]$CpuThresholdPercent = 7.0,
	[string]$WhitelistCmdRegex = '\bnpm["'']?\s+run\b',
	[switch]$KillSuspended,					# kill suspended processes
	[double]$SuspendedGraceMinutes = 60.0,	# grace period for suspended processes
	[switch]$List,
	[switch]$DryRun,
	[double]$CheckOnInterval = 0,	 		# 0 = run once then exit
	[switch]$Tray,							# launch tray UI controller
	[switch]$PauseWhenDone					# optional: force pause at the end in one-shot mode
)

$ErrorActionPreference = 'SilentlyContinue'
$StopEventName = 'OrphanReaperStopEvent'
# NEW: a mutex the tray holds for its whole lifetime
# Tip: use Global\ so it works across sessions
$TrayMutexName	= 'Global\OrphanReaperTrayLock'
function Get-Timestamp {
	return (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
}

# ------------------------------------
# Paths & state files
# ------------------------------------
$ScriptPath = $MyInvocation.MyCommand.Path
# Normalize all state paths to absolute, independent of working directory
$BaseDir = Split-Path -Parent $ScriptPath
$StateDir = Join-Path $BaseDir 'OrphanReaper'
$PidFile = Join-Path $StateDir 'pid.txt'
$StopFile = Join-Path $StateDir 'stop.flag'
$LogFile = Join-Path $StateDir 'reaper.log'
$iconPath = Join-Path $BaseDir 'OrphanReaper.ico'
$onIconPath = Join-Path $BaseDir 'OrphanReaper-monitoring.ico'
$offIconPath = $iconPath
New-Item -Force -ItemType Directory -Path $StateDir | Out-Null

function Write-Log {
	param([string]$text)
	"[{0}] {1}" -f (Get-Timestamp), $text | Out-File -FilePath $LogFile -Append -Encoding utf8
}

# Load array parameters from environment variables if set (used when launched by tray)
# Load switch parameters from environment variables (more reliable than command-line parsing)
if ($env:ORPHANREAPER_KILLSUSPENDED) {
	$KillSuspended = $env:ORPHANREAPER_KILLSUSPENDED -eq "True"
}
if ($env:ORPHANREAPER_DRYRUN) {
	$DryRun = $env:ORPHANREAPER_DRYRUN -eq "True"
}

if ($env:ORPHANREAPER_NAMES) {
	$Names = $env:ORPHANREAPER_NAMES -split '\|'
}
if ($env:ORPHANREAPER_FOLDERPATHS) {
	$FolderPaths = $env:ORPHANREAPER_FOLDERPATHS -split '\|'
}

# Log startup parameters
$mode = if($Tray){"Tray"}elseif($CheckOnInterval -gt 0){"Watcher"}elseif($List){"List"}else{"Run-Once"}
Write-Log "[INFO] Starting OrphanReaper ($mode) - Names=$($Names -join ',') KillSuspended=$KillSuspended SuspendedGrace=$($SuspendedGraceMinutes)m Grace=$($GraceMinutes)m CPU=$($CpuThresholdPercent)% Interval=$($CheckOnInterval)m DryRun=$DryRun"

# ------------------------------------
# Core helpers
# ------------------------------------
function Get-AllProcsCim { Get-CimInstance Win32_Process }

function Get-PidIndex ($list) { $h=@{}; foreach($p in $list){ $h[[int]$p.ProcessId]=$true }; $h }

function Get-Candidates($names, $folderPaths, $all) {
	# Normalize folder paths for comparison (remove trailing slashes, lowercase)
	$normalizedFolders = @()
	if ($folderPaths -and $folderPaths.Count -gt 0) {
		$normalizedFolders = @($folderPaths | ForEach-Object { $_.TrimEnd('\', '/').ToLower() })
	}

	$all | Where-Object {
		# Match by name (always match if name is in list, regardless of path)
		if ($names -and $names.Count -gt 0 -and $_.Name -in $names) { return $true }

		# ALSO match by executable path in specified folders (for other executables in those folders)
		if ($normalizedFolders.Count -gt 0 -and $_.ExecutablePath) {
			$exeFolder = (Split-Path -Parent $_.ExecutablePath).ToLower()
			if ($exeFolder -in $normalizedFolders) { return $true }
		}

		return $false
	}
}

function Is-Orphan($p, $pidIdx) { if(-not $p.ParentProcessId){return $true}; return -not $pidIdx.ContainsKey([int]$p.ParentProcessId) }

function Is-Suspended($processId) {
	try {
		$proc = Get-Process -Id $processId -ErrorAction Stop
		# Check if all threads are in wait state (suspended)
		$threads = $proc.Threads
		if ($threads.Count -eq 0) { return $false }

		foreach ($thread in $threads) {
			# ThreadState 5 = Wait, WaitReason 5 = Suspended
			if ($thread.ThreadState -ne 5 -or $thread.WaitReason -ne 5) {
				return $false
			}
		}
		return $true
	} catch {
		return $false
	}
}

function Get-AgeMinutes($p) {
	try {
		$s=[Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate)
		if($s){ return ((Get-Date)-$s).TotalMinutes }
	} catch {}
	try { ((Get-Date)-(Get-Process -Id $p.ProcessId -ea Stop).StartTime).TotalMinutes } catch { [double]::NaN }
}

function Build-ChildMap($all) {
	$map=@{}; ($all | Group-Object ParentProcessId) | ForEach-Object {
		$ppid=[int]$_.Name
		if($ppid -gt 0){ $map[$ppid]=@($_.Group | ForEach-Object { [int]$_.ProcessId }) }
	}; $map
}

# CPU snapshot using Get-Process deltas across ALL candidate PIDs once (fast, no perf counters)
function Get-CpuPercentSnapshot([int[]]$pids, [int]$intervalSec) {
	$cores=[Environment]::ProcessorCount
	if($pids.Count -eq 0){ return @{} }
	$cpu1=@{}
	$procs1=Get-Process -Id $pids -ErrorAction SilentlyContinue
	foreach($p in $procs1){ $cpu1[$p.Id]=[double]$p.CPU }
	Start-Sleep -Seconds $intervalSec
	$result=@{}
	$procs2=Get-Process -Id $pids -ErrorAction SilentlyContinue
	foreach($p in $procs2){
		$prev= if($cpu1.ContainsKey($p.Id)){$cpu1[$p.Id]} else {[double]::NaN}
		if(-not [double]::IsNaN($prev)){
			$delta=[math]::Max(0,([double]$p.CPU-$prev))
			$pct=($delta/$intervalSec)*(100/$cores)
			$result[$p.Id]=[math]::Round($pct,2)
		} else { $result[$p.Id]=0.0 }
	}
	$result
}
function Get-ParentProcessName {
	try {
		$me	 = Get-CimInstance Win32_Process -Filter "ProcessId = $PID"
		$ppid = $me.ParentProcessId
		(Get-CimInstance Win32_Process -Filter "ProcessId = $ppid").Name
	} catch { $null }
}

# ------------------------------------
# One reap cycle (list/dry-run/kill)
# ------------------------------------
function Invoke-ReapCycle {
	param(
		[string[]]$Names,
		[string[]]$FolderPaths,
		[double]$GraceMinutes,
		[int]$SampleSeconds,
		[double]$CpuThresholdPercent,
		[string]$WhitelistCmdRegex,
		[switch]$KillSuspended,
		[double]$SuspendedGraceMinutes,
		[switch]$List,
		[switch]$DryRun
	)

	$all = Get-AllProcsCim
	$cands = Get-Candidates -names $Names -folderPaths $FolderPaths -all $all
	if(-not $cands){ Write-Verbose "No matching processes"; return }

	$pidIdx	 = Get-PidIndex $all
	$childMap = Build-ChildMap $all

	$pids	 = @($cands | ForEach-Object { [int]$_.ProcessId })
	$cpuDict = Get-CpuPercentSnapshot -pids $pids -intervalSec $SampleSeconds

	if($List){
		$rows = foreach($p in $cands){
			$age = Get-AgeMinutes $p
			$orph = Is-Orphan $p $pidIdx
			$kids = $childMap.ContainsKey([int]$p.ProcessId)
			$susp = Is-Suspended $p.ProcessId
			$cpu = if($cpuDict.ContainsKey([int]$p.ProcessId)){$cpuDict[[int]$p.ProcessId]}else{0.0}
			[pscustomobject]@{
				Name=$p.Name; PID=$p.ProcessId; ParentPID=$p.ParentProcessId; Orphan=$orph;
				Suspended=$susp; HasChildren=$kids; AgeMin=if([double]::IsNaN($age)){'unknown'}else{'{0:N1}'-f $age};
				AvgCPU=$cpu; Path=$p.ExecutablePath; Cmd=($p.CommandLine -replace '\s+',' ');
			}
		}
		$rows |
			Sort-Object -Property @{Expression='Orphan';Descending=$true},
							@{Expression='Suspended';Descending=$true},
							@{Expression='HasChildren';Descending=$false},
							@{Expression={[double]($_.AvgCPU)};Descending=$true},
							@{Expression='AgeMin';Descending=$true} |
			Format-Table -AutoSize
		return
	}

	$killed=0
	foreach($p in $cands){
		$age = Get-AgeMinutes $p
		$isOrphan = Is-Orphan $p $pidIdx
		$hasChildren = $childMap.ContainsKey([int]$p.ProcessId)
		$isSuspended = Is-Suspended $p.ProcessId

		if(-not $isOrphan) { continue }
		if($WhitelistCmdRegex -and $p.CommandLine -match $WhitelistCmdRegex) { continue }
		if($hasChildren) { continue }

		$cpu = if($cpuDict.ContainsKey([int]$p.ProcessId)){$cpuDict[[int]$p.ProcessId]}else{0.0}

		# Determine if we should kill this process
		$shouldKill = $false
		$reason = ""

		if ($isSuspended -and $KillSuspended) {
			# Suspended process: check against suspended grace period, skip CPU check
			if (-not [double]::IsNaN($age) -and $age -ge $SuspendedGraceMinutes) {
				$shouldKill = $true
				$reason = "SUSPENDED"
			}
		} elseif (-not $isSuspended) {
			# Normal process: check CPU threshold and regular grace period
			if (-not [double]::IsNaN($age) -and $age -ge $GraceMinutes -and $cpu -ge $CpuThresholdPercent) {
				$shouldKill = $true
				$reason = "HIGH CPU"
			}
		}

		if (-not $shouldKill) { continue }

		$ageOut = if([double]::IsNaN($age)){'unknown'}else{'{0:N1}'-f $age}
		$msg = ('Orphan {0} PID={1} Age={2}m CPU={3:N2}% Reason={4} CMD="{5}"' -f $p.Name, $p.ProcessId, $ageOut, $cpu, $reason, ($p.CommandLine -replace '\s+',' '))
		if($DryRun){
			Write-Host ("[{0}] [DRY RUN] {1}" -f (Get-Timestamp), $msg)
		} else {
			try {
				Stop-Process -Id $p.ProcessId -Force
				$killed++
				Write-Log "[KILLED] $msg"
				Write-Host ("[{0}] [KILLED] {1}" -f (Get-Timestamp), $msg)
			} catch {
				$err=$_.Exception.Message
				Write-Log "[ERROR] $msg :: $err"
			}
		}
	}
	if (-not $DryRun) {
		Write-Host ("[{0}] Done. Killed {1} orphan(s)" -f (Get-Timestamp), $killed)
		Write-Log ("[INFO] Reaping done. Killed {1} orphan(s)" -f (Get-Timestamp), $killed)
	} else {
		Write-Host ("[{0}] Dry run complete" -f (Get-Timestamp))
	}
}

# ------------------------------------
# Watcher loop (interval mode)
# ------------------------------------
function Run-WatcherLoop {
	param(
		[double]$CheckOnInterval,
		[string[]]$Names,
		[string[]]$FolderPaths,
		[double]$GraceMinutes,
		[int]$SampleSeconds,
		[double]$CpuThresholdPercent,
		[string]$WhitelistCmdRegex,
		[switch]$KillSuspended,
		[double]$SuspendedGraceMinutes,
		[switch]$DryRun
	)

	Write-Log "[INFO] Watcher loop starting with Names=$($Names -join ','), FolderPaths=$($FolderPaths -join ',')"
	$PID | Out-File -FilePath $PidFile -Encoding ascii

	# Construct sync primitives
	$stopEvt = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, $StopEventName)
	$trayMutex = $null
	try { $trayMutex = [System.Threading.Mutex]::OpenExisting($TrayMutexName) } catch { $trayMutex = $null }

	# If the tray isn't around (no mutex), policy: exit immediately to avoid orphaned watcher
	if (-not $trayMutex) {
		Write-Log "[ERROR] Tray mutex not found. Exiting."
		Write-Host "[Watcher] Tray mutex not found. Exiting."
		Remove-Item $PidFile -ErrorAction SilentlyContinue
		return
	}

	try {
		while ($true) {
			# Also bail out if stop requested already
			if ($stopEvt.WaitOne(0)) {
				Write-Log "[INFO] Stop event signaled, exiting"
				break
			}

			# Write-Log "[INFO] Starting reap cycle"
			Invoke-ReapCycle -Names $Names -FolderPaths $FolderPaths -GraceMinutes $GraceMinutes -SampleSeconds $SampleSeconds `
											 -CpuThresholdPercent $CpuThresholdPercent -WhitelistCmdRegex $WhitelistCmdRegex `
											 -KillSuspended:$KillSuspended -SuspendedGraceMinutes $SuspendedGraceMinutes `
											 -DryRun:$DryRun

			# Sleep, but wake instantly if tray dies (mutex is abandoned) or stop is requested
			$waitSeconds = [int]([math]::Max(1, $CheckOnInterval * 60))
			# Write-Log ("[INFO] Sleeping {0} minute(s)..." -f [math]::Round($CheckOnInterval,2))
			Write-Host ("[{0}] Sleeping {1} minute(s)..." -f (Get-Timestamp), [math]::Round($CheckOnInterval,2))

			$handles = [System.Threading.WaitHandle[]]@($stopEvt, $trayMutex)
			$signaled = [System.Threading.WaitHandle]::WaitAny($handles, [TimeSpan]::FromSeconds($waitSeconds))

			if ($signaled -eq 0) {
				# stop event set
				Write-Log "[INFO] Stop event received during sleep, exiting"
				break
			} elseif ($signaled -eq 1) {
				# tray mutex acquired -> tray exited (abandoned)
				Write-Log "[INFO] Tray exited (mutex abandoned), exiting"
				try { $trayMutex.ReleaseMutex() } catch {}
				break
			} else {
				# timeout -> loop continues
				# Write-Log "[INFO] Sleep complete, continuing"
			}
		}
	} catch {
		$err=$_.Exception.Message
		Write-Log "[ERROR] Watcher loop exception: $err"
		Write-Host "[ERROR] $err"
	} finally {
		Remove-Item $PidFile -ErrorAction SilentlyContinue
		if ($stopEvt)	 { $stopEvt.Dispose() }
		if ($trayMutex) { $trayMutex.Dispose() }
		Write-Host ("[{0}] Monitor stopped." -f (Get-Timestamp))
	}
}


function Is-WatcherRunning {
	if (-not (Test-Path $PidFile)) { return $false }
	$pidText = (Get-Content -Path $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
	if (-not $pidText) { return $false }
	$watcherPid = 0
	[void][int]::TryParse($pidText, [ref]$watcherPid)
	if ($watcherPid -le 0) { return $false }

	try {
		$proc = Get-Process -Id $watcherPid -ErrorAction Stop
		return $true
	} catch {
		return $false
	}
}

# ------------------------------------
# Tray UI (with icons + auto-sync timer)
# ------------------------------------
function Run-Tray {
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing
	Add-Type -AssemblyName Microsoft.VisualBasic

	# --- Single-instance tray, and lifetime handle for watcher detection ---
	$createdNew = $false
	try {
		$script:TrayMutex = New-Object System.Threading.Mutex($true, $TrayMutexName, [ref]$createdNew)
	} catch {
		$createdNew = $false
	}
	if (-not $createdNew) {
		[System.Windows.Forms.MessageBox]::Show(
			"Another OrphanReaper tray is already running.",
			"OrphanReaper", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information
		) | Out-Null
		return
	}
	# IMPORTANT: Do NOT release this mutex on normal exit.
	# If the tray is killed unexpectedly, the mutex becomes 'abandoned' and signals the watcher to stop.

	# Initialize script-scope variables for tray settings (so they persist and can be configured)
	if (-not $script:KillSuspended) { $script:KillSuspended = $KillSuspended }
	if (-not $script:SuspendedGraceMinutes) { $script:SuspendedGraceMinutes = $SuspendedGraceMinutes }
	if (-not $script:DryRun) { $script:DryRun = $DryRun }

	function Load-Icon($path) {
		try { if (Test-Path $path) { return [System.Drawing.Icon]::new($path) } } catch {}
		return [System.Drawing.SystemIcons]::Application
	}

	$notify = New-Object System.Windows.Forms.NotifyIcon
	$idleIcon	 = if (Test-Path $offIconPath) { Load-Icon $offIconPath } else { $null }
	$activeIcon = if (Test-Path $onIconPath)	{ Load-Icon $onIconPath }	else { $null }
	$defaultIcon= Load-Icon $iconPath

	if ($idleIcon -and $activeIcon) {
		$notify.Icon = $idleIcon
	} else {
		$notify.Icon = $defaultIcon
	}
	$notify.Text = "OrphanReaper - Idle"
	$notify.Visible = $true

	$interval = if($CheckOnInterval -le 0){ 5 } else { [int]$CheckOnInterval }
	$menu = New-Object System.Windows.Forms.ContextMenuStrip

	# Status indicator at the top (non-clickable, bold)
	$miStatus = $menu.Items.Add("Idle")
	$miStatus.Enabled = $false
	$miStatus.Font = New-Object System.Drawing.Font($miStatus.Font, [System.Drawing.FontStyle]::Bold)
	$menu.Items.Add("-")

	$miStart	 = $menu.Items.Add("Start monitor ($([int]$interval) min)")
	$miStop	 = $menu.Items.Add("Stop monitor")
	$menu.Items.Add("-")
	$miRunOnce = $menu.Items.Add("Run once now")
	$miOpenLog = $menu.Items.Add("Open log folder")
	$menu.Items.Add("-")
	$miSettings= $menu.Items.Add("Settings...")
	$menu.Items.Add("-")
	$miExit	 = $menu.Items.Add("Exit")

	$notify.ContextMenuStrip = $menu

	function Start-Watcher {
		if (Is-WatcherRunning) {
			[System.Windows.Forms.MessageBox]::Show("Already monitoring.","OrphanReaper") | Out-Null
			return
		}

		if (Test-Path $StopFile) { Remove-Item $StopFile -ErrorAction SilentlyContinue }

		$interval = if ($CheckOnInterval -le 0) { 5 } else { [int]$CheckOnInterval }
		$script:CheckOnInterval = $interval

		# Build watcher arguments - use simple params only
		$procArgs = @(
			'-NoProfile','-ExecutionPolicy','Bypass','-File', $ScriptPath,
			'-GraceMinutes', $GraceMinutes,
			'-CpuThresholdPercent', $CpuThresholdPercent,
			'-SampleSeconds', $SampleSeconds,
			'-SuspendedGraceMinutes', $script:SuspendedGraceMinutes,
			'-CheckOnInterval', $interval
		)
		if ($WhitelistCmdRegex)	{ $procArgs += @('-WhitelistCmdRegex', $WhitelistCmdRegex) }
		# KillSuspended and DryRun are now passed via environment variables

		$exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

		$psi = New-Object System.Diagnostics.ProcessStartInfo
		$psi.FileName				 = $exe
		$psi.UseShellExecute	= $false
		$psi.CreateNoWindow	 = $true
		$psi.WindowStyle			= [Diagnostics.ProcessWindowStyle]::Hidden

		# IMPORTANT: When UseShellExecute=false, env vars don't inherit automatically
		# Copy current environment variables first
		foreach ($key in [Environment]::GetEnvironmentVariables().Keys) {
			$psi.EnvironmentVariables[$key] = [Environment]::GetEnvironmentVariable($key)
		}

		# Use environment variables to pass arrays and switches (much more reliable than command-line parsing)
		if ($script:Names -and $script:Names.Count -gt 0) {
			$psi.EnvironmentVariables["ORPHANREAPER_NAMES"] = ($script:Names -join '|')
		}
		if ($script:FolderPaths -and $script:FolderPaths.Count -gt 0) {
			$psi.EnvironmentVariables["ORPHANREAPER_FOLDERPATHS"] = ($script:FolderPaths -join '|')
		}
		# Pass switch parameters via environment variables to avoid parsing issues
		$psi.EnvironmentVariables["ORPHANREAPER_KILLSUSPENDED"] = if ($script:KillSuspended) { "True" } else { "False" }
		$psi.EnvironmentVariables["ORPHANREAPER_DRYRUN"] = if ($script:DryRun) { "True" } else { "False" }

		# Build simple argument list
		foreach ($arg in $procArgs) {
			if ($psi.Arguments) { $psi.Arguments += ' ' }
			if ($arg -match '\s') { $psi.Arguments += '"{0}"' -f $arg }
			else { $psi.Arguments += $arg }
		}

		Write-Log "[INFO] Starting watcher: $exe $($psi.Arguments)"

		try {
			$proc = [Diagnostics.Process]::Start($psi)
			Write-Log "[INFO] Watcher process started with PID: $($proc.Id)"
		} catch {
			Write-Log "[ERROR] Failed to start watcher: $($_.Exception.Message)"
			[System.Windows.Forms.MessageBox]::Show("Failed to start watcher: $($_.Exception.Message)","OrphanReaper Error") | Out-Null
			return
		}

		$notify.Text = "OrphanReaper - Monitoring ($interval min)"
		$miStatus.Text = "Monitoring"
		if ($activeIcon) { $notify.Icon = $activeIcon }
	}

	function Stop-Watcher {
		# Signal the event
		try { $evt = [System.Threading.EventWaitHandle]::OpenExisting($StopEventName) } catch { $evt = $null }
		if ($evt) {
			$evt.Set()
			$evt.Dispose()
		}

		# Wait up to ~12s for watcher to exit; then force-kill if needed
		$deadline = (Get-Date).AddSeconds(12)
		while ((Get-Date) -lt $deadline) {
			if (-not (Is-WatcherRunning)) { break }
			Start-Sleep -Milliseconds 300
		}
		if (Is-WatcherRunning) {
			try {
				$watcherPid = [int](Get-Content -Path $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
				if ($watcherPid -gt 0) { Stop-Process -Id $watcherPid -Force -ErrorAction SilentlyContinue }
			} catch {}
		}
		Remove-Item $PidFile -ErrorAction SilentlyContinue

		$notify.Text = "OrphanReaper - Idle"
		$miStatus.Text = "Idle"
		if ($idleIcon) { $notify.Icon = $idleIcon } else { $notify.Icon = $defaultIcon }
	}

	function Run-Once {
		# Build argument string manually with environment variables
		$argList = @(
			'-NoProfile','-ExecutionPolicy','Bypass','-File', $ScriptPath,
			'-GraceMinutes', $GraceMinutes,
			'-CpuThresholdPercent', $CpuThresholdPercent,
			'-SampleSeconds', $SampleSeconds,
			'-SuspendedGraceMinutes', $script:SuspendedGraceMinutes,
			'-PauseWhenDone'
		)
		if ($WhitelistCmdRegex)	{ $argList += @('-WhitelistCmdRegex', $WhitelistCmdRegex) }
		# KillSuspended and DryRun are passed via environment variables

		# Build command with environment variables for arrays and switches
		$cmd = "powershell.exe"
		$envVars = @{}
		if ($script:Names -and $script:Names.Count -gt 0) {
			$envVars["ORPHANREAPER_NAMES"] = ($script:Names -join '|')
		}
		if ($script:FolderPaths -and $script:FolderPaths.Count -gt 0) {
			$envVars["ORPHANREAPER_FOLDERPATHS"] = ($script:FolderPaths -join '|')
		}
		$envVars["ORPHANREAPER_KILLSUSPENDED"] = if ($script:KillSuspended) { "True" } else { "False" }
		$envVars["ORPHANREAPER_DRYRUN"] = if ($script:DryRun) { "True" } else { "False" }

		# Build environment variable prefix for command
		$envPrefix = ""
		foreach ($key in $envVars.Keys) {
			$envPrefix += "`$env:$key='$($envVars[$key])'; "
		}

		# Create a wrapper command that sets env vars then runs the script
		$wrapperCmd = "$envPrefix & '$cmd' $($argList -join ' ')"
		Start-Process powershell.exe -ArgumentList "-NoProfile","-Command",$wrapperCmd
	}

	$miStart.Add_Click({ Start-Watcher })
	$miStop.Add_Click({ Stop-Watcher })
	$miRunOnce.Add_Click({ Run-Once })
	$miOpenLog.Add_Click({ Start-Process explorer.exe $StateDir | Out-Null })
	$miSettings.Add_Click({
		$g = [Microsoft.VisualBasic.Interaction]::InputBox("Grace minutes:", "OrphanReaper", "$GraceMinutes")
		if($g -and $g -match '^\d+(\.\d+)?$'){ $script:GraceMinutes = [double]$g }
		$c = [Microsoft.VisualBasic.Interaction]::InputBox("CPU threshold %:", "OrphanReaper", "$CpuThresholdPercent")
		if($c -and $c -match '^\d+(\.\d+)?$'){ $script:CpuThresholdPercent = [double]$c }
		$s = [Microsoft.VisualBasic.Interaction]::InputBox("CPU sample seconds:", "OrphanReaper", "$SampleSeconds")
		if($s -and $s -match '^\d+(\.\d+)?$'){ $script:SampleSeconds = [int]$s }
		$i = [Microsoft.VisualBasic.Interaction]::InputBox("Interval minutes:", "OrphanReaper", "$CheckOnInterval")
		if($i -and $i -match '^\d+(\.\d+)?$'){ $script:CheckOnInterval = [double]$i; $miStart.Text = "Start monitor ($([int]$script:CheckOnInterval) min)" }
		$w = [Microsoft.VisualBasic.Interaction]::InputBox("Whitelist regex:", "OrphanReaper", "$WhitelistCmdRegex")
		if($w -ne $null){ $script:WhitelistCmdRegex = $w }

		# Suspended process settings
		$sg = [Microsoft.VisualBasic.Interaction]::InputBox("Suspended grace minutes:", "OrphanReaper", "$($script:SuspendedGraceMinutes)")
		if($sg -and $sg -match '^\d+(\.\d+)?$'){ $script:SuspendedGraceMinutes = [double]$sg }
		$ks = [Microsoft.VisualBasic.Interaction]::InputBox("Kill suspended processes? (True/False):", "OrphanReaper", "$($script:KillSuspended)")
		if($ks -ne $null -and $ks -match '^(True|False|1|0|Yes|No)$'){
			$script:KillSuspended = $ks -match '^(True|1|Yes)$'
			Write-Log "[INFO] KillSuspended changed to: $($script:KillSuspended)"
		}
	})
	$miExit.Add_Click({
		Write-Host "$miExit.Add_Click"
		if (Is-WatcherRunning) {
			Write-Host "Stopping background watcher before exit..."
			Stop-Watcher
		}
		$notify.Visible = $false
		$notify.Dispose()
		[System.Windows.Forms.Application]::Exit()
	})

	$notify.Add_MouseClick({
		param($s,$e)
		if($e.Button -eq [System.Windows.Forms.MouseButtons]::Left){
			# Show context menu on left click
			# Use reflection to call the ShowContextMenu method
			$mi = [System.Windows.Forms.NotifyIcon].GetMethod("ShowContextMenu",
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
			$mi.Invoke($notify, $null)
		}
	})

	# auto-sync tray state every 2s (in case watcher is started/stopped externally)
	$timer = New-Object System.Windows.Forms.Timer
	$timer.Interval = 5000
	$timer.Add_Tick({
		$running = Is-WatcherRunning
		# Write-Host "[TIMER] running=$running pidfile=$PidFile exists=$([bool](Test-Path $PidFile))"
		if ($running) {
			$notify.Text = "OrphanReaper - Monitoring ($([int]$CheckOnInterval) min)"
			$miStatus.Text = "Monitoring"
			if ($activeIcon) { $notify.Icon = $activeIcon }
		} else {
			$notify.Text = "OrphanReaper - Idle"
			$miStatus.Text = "Idle"
			if ($idleIcon) { $notify.Icon = $idleIcon } else { $notify.Icon = $defaultIcon }
		}
	})
	$timer.Start()

	[System.Windows.Forms.Application]::EnableVisualStyles()

	# Auto-start monitoring if interval was supplied on the tray's command line
	if ($CheckOnInterval -gt 0) {
		Write-Log ('[INFO] Starting monitor ({0} min)' -f $CheckOnInterval)
		Start-Watcher
	}

	[System.Windows.Forms.Application]::Run()
}

# ------------------------------------
# MAIN
# ------------------------------------
if($Tray) {
	Run-Tray
	exit
}

if($CheckOnInterval -le 0) {
	Invoke-ReapCycle -Names $Names -FolderPaths $FolderPaths -GraceMinutes $GraceMinutes -SampleSeconds $SampleSeconds `
					 -CpuThresholdPercent $CpuThresholdPercent -WhitelistCmdRegex $WhitelistCmdRegex `
					 -KillSuspended:$KillSuspended -SuspendedGraceMinutes $SuspendedGraceMinutes `
					 -List:$List -DryRun:$DryRun

	# Pause only if launched by Explorer or explicitly requested
	$parent = Get-ParentProcessName
	if((($parent -and $parent -ieq 'explorer.exe') -or $PauseWhenDone) -and -not $List){
		Write-Host ""
		Write-Host -NoNewline "Press ENTER to close this window "
		$null = Read-Host
	}
	exit
}

# repeating watcher in this process
Run-WatcherLoop -CheckOnInterval $CheckOnInterval -Names $Names -FolderPaths $FolderPaths -GraceMinutes $GraceMinutes `
				-SampleSeconds $SampleSeconds -CpuThresholdPercent $CpuThresholdPercent `
				-WhitelistCmdRegex $WhitelistCmdRegex -KillSuspended:$KillSuspended -SuspendedGraceMinutes $SuspendedGraceMinutes `
				-DryRun:$DryRun

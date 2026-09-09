param(
    [ValidateSet("all", "alea-dummy-dll", "faceit-ac-2026-09-08")]
    [string]$Target = "all",
    [switch]$SkipBuild,
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "builds\Release\KEVLAR.exe"
$matrixPath = Join-Path $PSScriptRoot "acceptance_matrix.json"
$matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json

if (-not $SkipBuild) {
    & (Join-Path $root "build.ps1") Release | Out-Host
    if ($LASTEXITCODE) { throw "build failed" }
}
if (-not (Test-Path -LiteralPath $exe)) { throw "KEVLAR.exe not found: $exe" }

$selected = @($matrix.targets | Where-Object { $Target -eq "all" -or $_.id -eq $Target })
if (-not $selected.Count) { throw "no target selected" }

$fails = @()
$runCount = [int]$matrix.global.deterministic_runs
foreach ($case in $selected) {
    if (-not (Test-Path -LiteralPath $case.path)) {
        $fails += "$($case.id): target missing"
        continue
    }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $case.path).Hash.ToLowerInvariant()
    if ($actualHash -ne $case.sha256.ToLowerInvariant()) {
        $fails += "$($case.id): SHA-256 mismatch ($actualHash)"
        continue
    }

    $signatures = @()
    for ($runIndex = 1; $runIndex -le $runCount; $runIndex++) {
        $log = Join-Path $env:TEMP ("kevlar_acceptance_{0}_{1}.log" -f $case.id, $runIndex)
        $commandFile = Join-Path $env:TEMP ("kevlar_acceptance_{0}_{1}.cmd" -f $case.id, $runIndex)
        $commandText = "@echo off`r`n`"$exe`" `"$($case.path)`" --strict-exports --max-insns $($case.max_instructions) --no-pause > `"$log`" 2> `"$log.err`"`r`nexit /b %errorlevel%`r`n"
        [System.IO.File]::WriteAllText($commandFile, $commandText, [System.Text.Encoding]::ASCII)
        $proc = Start-Process -FilePath "cmd.exe" -ArgumentList @("/d", "/c", $commandFile) `
            -WorkingDirectory (Split-Path $exe) -PassThru
        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            & taskkill.exe /PID $proc.Id /T /F | Out-Null
            Remove-Item -LiteralPath $commandFile -Force -ErrorAction SilentlyContinue
            $fails += "$($case.id) run ${runIndex}: timed out after ${TimeoutSeconds}s"
            continue
        }
        $proc.WaitForExit()
        $proc.Refresh()
        $exitCode = $proc.ExitCode
        Remove-Item -LiteralPath $commandFile -Force -ErrorAction SilentlyContinue
        if ($exitCode -ne 0) {
            $fails += "$($case.id) run ${runIndex}: emulator exit code $exitCode"
        }

        $out = (Get-Content -LiteralPath $log -Raw) + (Get-Content -LiteralPath ($log + ".err") -Raw)
        foreach ($pattern in $case.required_log_patterns) {
            if ($out -notmatch [regex]::Escape([string]$pattern)) {
                $fails += "$($case.id) run ${runIndex}: missing required pattern: $pattern"
            }
        }
        foreach ($pattern in $matrix.global.forbid_log_patterns) {
            if ($out -match [regex]::Escape([string]$pattern)) {
                $fails += "$($case.id) run ${runIndex}: forbidden pattern observed: $pattern"
            }
        }
        if ($case.required_regex_patterns) {
            foreach ($pattern in $case.required_regex_patterns) {
                if ($out -notmatch [string]$pattern) {
                    $fails += "$($case.id) run ${runIndex}: required lifecycle expression did not match"
                }
            }
        }
        if ($matrix.global.require_nonempty_kernel_lifecycle -and $case.execution_mode -eq "kernel_driver") {
            $lifecycle = ($out -split "`r?`n" | Where-Object { $_ -match "\[LIFECYCLE\]" } | Select-Object -Last 1)
            $emptyLifecycle = "add_device=0x0 unload=0x0 device=0x0 dispatch=0 tracked_devices=0 ps=0/0/0 ob=0 cm=0 flt=0"
            if (-not $lifecycle -or $lifecycle -match [regex]::Escape($emptyLifecycle)) {
                $fails += "$($case.id) run ${runIndex}: kernel lifecycle is empty"
            }
        }
        if ($case.completion_patterns) {
            $completed = $false
            foreach ($pattern in $case.completion_patterns) {
                if ($out -match [regex]::Escape([string]$pattern)) { $completed = $true; break }
            }
            if (-not $completed) { $fails += "$($case.id) run ${runIndex}: no terminal completion pattern observed" }
        }

        $signature = (($out -split "`r?`n") |
            Where-Object { $_ -match "(DllMain|DriverEntry) returned:|\[LIFECYCLE\]" }) -join "`n"
        $signatures += $signature
    }
    if (@($signatures | Select-Object -Unique).Count -ne 1) {
        $fails += "$($case.id): deterministic result/lifecycle signature mismatch across $runCount runs"
    }
    if (-not ($fails | Where-Object { $_ -like "$($case.id)*" })) {
        Write-Host "TARGET PASS - $($case.id) ($runCount deterministic runs)" -ForegroundColor Green
    }
}

if ($fails.Count) {
    Write-Host "TARGET ACCEPTANCE FAIL" -ForegroundColor Red
    $fails | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "TARGET ACCEPTANCE PASS" -ForegroundColor Green
exit 0

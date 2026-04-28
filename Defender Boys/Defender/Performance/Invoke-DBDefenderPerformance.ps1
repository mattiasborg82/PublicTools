function Invoke-DBDefenderPerformance {
    <#
    .SYNOPSIS
    Invokes a Microsoft Defender Antivirus performance recording.

    .DESCRIPTION
    This function starts a performance recording for Microsoft Defender Antivirus, analyzes the recording, and optionally exports the results to JSON or CSV.

    .PARAMETER Seconds
    The duration of the performance recording in seconds. Default is 300 seconds.

    .PARAMETER OutputDirectory
    The directory where the recording and reports will be saved. Default is "$env:TEMP\DBDefenderPerformance".

    .PARAMETER Name
    The base name for the recording and report files. Default is "DefenderPerformance".

    .PARAMETER Top
    The number of top items to include in the report. Default is 20.

    .PARAMETER Raw
    If specified, includes raw data in the report.

    .PARAMETER ExportJson
    If specified, exports the report to a JSON file.

    .PARAMETER ExportCsv
    If specified, exports the top scans to a CSV file.

    .PARAMETER WPRPath
    The path to the Windows Performance Recorder (WPR) executable.

    .EXAMPLE
    Invoke-DBDefenderPerformance -Seconds 300 -ExportJson -ExportCsv
    Invoke-DBDefenderPerformance -Seconds 900 -Top 50 -Raw -ExportJson
    
    Useful cleanup if a previous WPR trace is stuck:
    wpr -cancel -instancename MSFT_MpPerformanceRecording


    #>

    [CmdletBinding()]
    param(
        [int]$Seconds = 300,
        [string]$OutputDirectory = "$env:TEMP\DBDefenderPerformance",
        [string]$Name = "DefenderPerformance",
        [int]$Top = 20,
        [switch]$Raw,
        [switch]$ExportJson,
        [switch]$ExportCsv,
        [string]$WPRPath
    )

    begin {
        $ErrorActionPreference = "Stop"

        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )

        if (-not $isAdmin) {
            throw "Run PowerShell as Administrator. New-MpPerformanceRecording requires elevated privileges."
        }

        foreach ($cmd in @("New-MpPerformanceRecording", "Get-MpPerformanceReport")) {
            if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
                throw "Required cmdlet not found: $cmd. Check that the DefenderPerformance module is available."
            }
        }

        if ($Seconds -lt 30) {
            throw "Use at least 30 seconds. Recommended default is 300 seconds."
        }

        if (-not (Test-Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $etlPath = Join-Path $OutputDirectory "$Name-$timestamp.etl"
        $jsonPath = Join-Path $OutputDirectory "$Name-$timestamp.json"
        $csvPath = Join-Path $OutputDirectory "$Name-$timestamp-TopScans.csv"
    }

    process {
        Write-Host "Starting Microsoft Defender Antivirus performance recording for $Seconds seconds..."
        Write-Host "Timestamp: $(Get-Date)"
        Write-Host "Reproduce the performance issue during this window."

        $recordArgs = @{
            RecordTo = $etlPath
            Seconds  = $Seconds
        }

        if ($WPRPath) {
            if (-not (Test-Path $WPRPath)) {
                throw "WPRPath does not exist: $WPRPath"
            }

            $recordArgs["WPRPath"] = $WPRPath
        }

        New-MpPerformanceRecording @recordArgs

        if (-not (Test-Path $etlPath)) {
            throw "Recording did not create expected ETL file: $etlPath"
        }

        Write-Host "Recording saved to: $etlPath"
        Write-Host "Analyzing recording..."

        $reportArgs = @{
            Path                         = $etlPath
            TopFiles                     = $Top
            TopScansPerFile              = 5
            TopProcessesPerFile          = 5
            TopPaths                     = $Top
            TopPathsDepth                = 4
            TopScansPerPath              = 5
            TopExtensions                = $Top
            TopProcesses                 = $Top
            TopScansPerProcess           = 5
            TopScans                     = $Top
            Overview                     = $true
        }

        if ($Raw -or $ExportJson -or $ExportCsv) {
            $reportArgs["Raw"] = $true
        }

        $report = Get-MpPerformanceReport @reportArgs

        if ($ExportJson) {
            $report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-Host "JSON report saved to: $jsonPath"
        }

        if ($ExportCsv) {
            if ($report.TopScans) {
                $report.TopScans | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Host "TopScans CSV saved to: $csvPath"
            } else {
                Write-Warning "No TopScans data found to export."
            }
        }

        [pscustomobject]@{
            RecordingPath = $etlPath
            JsonPath      = if ($ExportJson) { $jsonPath } else { $null }
            CsvPath       = if ($ExportCsv) { $csvPath } else { $null }
            Seconds       = $Seconds
            Report        = $report
        }
    }
}

function Convert-DBDefenderPerformanceReport {
    <#
    .SYNOPSIS
    Converts a raw Microsoft Defender Antivirus performance report into a structured summary with findings.
    .DESCRIPTION
    This function takes the raw output from Get-MpPerformanceReport and processes it to extract insights, such as slow scans, common reasons for scans, and potentially expensive file types or paths. It can also include raw data if specified.
    .PARAMETER Report
    The raw report object obtained from Get-MpPerformanceReport.
    .PARAMETER Top
    The number of top items to include in the summary for various categories. Default is 20.
    .PARAMETER SlowScanMs
    The threshold in milliseconds to consider a scan as "slow". Default is 250 ms.
    .PARAMETER IncludeRaw
    If specified, includes the raw report data in the output summary.
.EXAMPLE
    $report = Get-MpPerformanceReport -Path "C:\Temp\DefenderPerformance-20260428-095235.etl" -Raw
    $summary = Convert-DBDefenderPerformanceReport -Report $report -Top 10 -SlowScanMs 200 -IncludeRaw
    $summary | Format-Table -AutoSize

    $summary.SlowScans | Format-Table DurationMs, ScanType, Reason, SkipReason, Extension, Path -AutoSize
    $summary.ByReason | Format-Table -AutoSize
    $summary.ByExtension | Format-Table -AutoSize
    $summary.ByParentPath | Format-Table -AutoSize
    $summary.SlowScans |
        Where-Object Reason -eq "EDRSensor" |
        Select-Object DurationMs, ScanType, Extension, Path |
        Format-Table -AutoSize

    # Additional analysis example: Check authenticode signatures of slow scans involving executables
    $summary.SlowScans |
        Where-Object { $_.Extension -in ".exe", ".dll" } |
        Select-Object -ExpandProperty Path -Unique |
        ForEach-Object {
            if (Test-Path -LiteralPath $_) {
                Get-AuthenticodeSignature -FilePath $_ |
                    Select-Object Path, Status, StatusMessage, SignerCertificate
            }
        }
    .NOTES
    This function is meant to be used in conjunction with Invoke-DBDefenderPerformance. It helps interpret the raw performance data and extract actionable insights.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Report,
        [int]$Top = 20,
        [double]$SlowScanMs = 250,
        [switch]$IncludeRaw
    )

    function Convert-TicksToMs {
        param([nullable[long]]$Ticks)
        if ($null -eq $Ticks) { return $null }
        return [math]::Round(($Ticks / 10000), 2)
    }

    function Convert-FileTimeToDateTime {
        param([nullable[long]]$FileTime)
        if ($null -eq $FileTime) { return $null }
        try {
            return [DateTime]::FromFileTimeUtc($FileTime).ToLocalTime()
        } catch {
            return $null
        }
    }

    function Get-ParentPath {
        param([string]$Path)

        if ([string]::IsNullOrWhiteSpace($Path)) { return "[empty]" }
        if ($Path -match "^pid:\d+$") { return "[pid]" }
        if ($Path -match "^\\\\\.\\proc\\") { return "[process]" }

        try {
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                return Split-Path -Path $Path -Parent
            }

            $parent = Split-Path -Path $Path -Parent
            if ($parent) { return $parent }

            return $Path
        } catch {
            return $Path
        }
    }

    function Get-ExtensionSafe {
        param([string]$Path)

        if ([string]::IsNullOrWhiteSpace($Path)) { return "[empty]" }
        if ($Path -match "^pid:\d+$") { return "[pid]" }

        try {
            $ext = [IO.Path]::GetExtension($Path)
            if ([string]::IsNullOrWhiteSpace($ext)) { return "[none]" }
            return $ext.ToLowerInvariant()
        } catch {
            return "[unknown]"
        }
    }

    $overview = $Report.Overview

    $allScans = @()
    if ($Report.TopScans) {
        $allScans = @($Report.TopScans) | ForEach-Object {
            [pscustomobject]@{
                ScanType       = $_.ScanType
                Reason         = if ($_.Reason) { $_.Reason } else { "[empty]" }
                SkipReason     = $_.SkipReason
                DurationMs     = Convert-TicksToMs $_.Duration
                DurationTicks  = $_.Duration
                Path           = if ($_.Path) { $_.Path } else { "[empty]" }
                ParentPath     = Get-ParentPath $_.Path
                Extension      = Get-ExtensionSafe $_.Path
                StartTime      = Convert-FileTimeToDateTime $_.StartTime
                EndTime        = Convert-FileTimeToDateTime $_.EndTime
            }
        }
    }

    $slowScans = $allScans |
        Where-Object { $_.DurationMs -ge $SlowScanMs } |
        Sort-Object DurationMs -Descending |
        Select-Object -First $Top

    $byReason = $allScans |
        Group-Object Reason |
        ForEach-Object {
            $items = @($_.Group)
            [pscustomobject]@{
                Reason          = $_.Name
                Count           = $items.Count
                TotalMs         = [math]::Round(($items | Measure-Object DurationMs -Sum).Sum, 2)
                AverageMs       = [math]::Round(($items | Measure-Object DurationMs -Average).Average, 2)
                MaxMs           = [math]::Round(($items | Measure-Object DurationMs -Maximum).Maximum, 2)
            }
        } |
        Sort-Object TotalMs -Descending |
        Select-Object -First $Top

    $byExtension = $allScans |
        Group-Object Extension |
        ForEach-Object {
            $items = @($_.Group)
            [pscustomobject]@{
                Extension       = $_.Name
                Count           = $items.Count
                TotalMs         = [math]::Round(($items | Measure-Object DurationMs -Sum).Sum, 2)
                AverageMs       = [math]::Round(($items | Measure-Object DurationMs -Average).Average, 2)
                MaxMs           = [math]::Round(($items | Measure-Object DurationMs -Maximum).Maximum, 2)
            }
        } |
        Sort-Object TotalMs -Descending |
        Select-Object -First $Top

    $byParentPath = $allScans |
        Group-Object ParentPath |
        ForEach-Object {
            $items = @($_.Group)
            [pscustomobject]@{
                ParentPath      = $_.Name
                Count           = $items.Count
                TotalMs         = [math]::Round(($items | Measure-Object DurationMs -Sum).Sum, 2)
                AverageMs       = [math]::Round(($items | Measure-Object DurationMs -Average).Average, 2)
                MaxMs           = [math]::Round(($items | Measure-Object DurationMs -Maximum).Maximum, 2)
            }
        } |
        Sort-Object TotalMs -Descending |
        Select-Object -First $Top

    $hints = @()
    if ($overview.PerfHints) {
        $hints = @($overview.PerfHints) | ForEach-Object {
            $text = [string]$_
            $severity = "Info"

            if ($text -match "^\[(.*?)\]") {
                $severity = $matches[1]
            }

            [pscustomobject]@{
                Severity = $severity
                Hint     = $text
            }
        }
    }

    $interestingFindings = New-Object System.Collections.Generic.List[object]

    foreach ($r in $byReason | Where-Object { $_.Reason -eq "EDRSensor" }) {
        $interestingFindings.Add([pscustomobject]@{
            Finding = "EDRSensor-driven scans are present"
            Why     = "This often means Defender for Endpoint sensor activity triggered scan work."
            Evidence = "Count=$($r.Count), TotalMs=$($r.TotalMs), MaxMs=$($r.MaxMs)"
            Action  = "Correlate with Defender for Endpoint timeline, file activity, and process activity. Do not blindly exclude."
        })
    }

    foreach ($e in $byExtension | Where-Object { $_.Extension -in ".exe", ".dll", ".ps1", ".ps1xml", ".html", ".js", ".json" }) {
        $interestingFindings.Add([pscustomobject]@{
            Finding = "Potentially expensive extension: $($e.Extension)"
            Why     = "Executable, script, and structured text files can cause more inspection work."
            Evidence = "Count=$($e.Count), TotalMs=$($e.TotalMs), MaxMs=$($e.MaxMs)"
            Action  = "Check whether this is expected developer/build/update activity."
        })
    }

    foreach ($p in $byParentPath | Where-Object { $_.ParentPath -match "\\node_modules\\|\\AppData\\Local\\Temp\\|\\Downloads|\\Installer|\\Programs\\Microsoft VS Code" }) {
        $interestingFindings.Add([pscustomobject]@{
            Finding = "Noisy path: $($p.ParentPath)"
            Why     = "This path pattern commonly changes often or contains many small files."
            Evidence = "Count=$($p.Count), TotalMs=$($p.TotalMs), MaxMs=$($p.MaxMs)"
            Action  = "Validate whether the process/path is trusted, expected, signed, and business-required before considering tuning."
        })
    }

    [pscustomobject]@{
        Summary = [pscustomobject]@{
            StartTime              = Convert-FileTimeToDateTime $overview.StartTime
            EndTime                = Convert-FileTimeToDateTime $overview.EndTime
            RecordingSeconds       = if ($overview.StartTime -and $overview.EndTime) {
                [math]::Round((($overview.EndTime - $overview.StartTime) / 10000000), 2)
            } else {
                $null
            }
            OnDemandScans          = $overview.OnDemandScans
            FileScans              = $overview.FileScans
            ProcessScans           = $overview.ProcessScans
            OnDemandScansMs        = Convert-TicksToMs $overview.OnDemandScansDuration
            FileScansMs            = Convert-TicksToMs $overview.FileScansDuration
            ProcessScansMs         = Convert-TicksToMs $overview.ProcessScansDuration
            MaxScanMs              = Convert-TicksToMs $overview.MaxScanDuration
            MedianScanMs           = Convert-TicksToMs $overview.MedianScanDuration
            SkipScanCount          = $overview.SkipScanCount
        }

        Findings      = $interestingFindings
        SlowScans     = $slowScans
        ByReason      = $byReason
        ByExtension   = $byExtension
        ByParentPath  = $byParentPath
        PerfHints     = $hints

        Raw           = if ($IncludeRaw) { $Report } else { $null }
    }
}

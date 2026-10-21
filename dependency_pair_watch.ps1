param(
    [ValidateSet('Preview','Once','Watch')][string]$Mode = 'Preview',
    [string]$Python,
    [string]$ReviewedSource,
    [switch]$ConfirmPublicNetwork,
    [ValidateRange(1,12)][int]$Checks = 8,
    [ValidateRange(900,21600)][int]$IntervalSeconds = 7200
)
$ErrorActionPreference = 'Stop'
try {
    if ($Mode -eq 'Preview' -or -not $ConfirmPublicNetwork) {
        @{status='PREVIEW'; network_calls=0; task_mutations=0; settings_changes=0; writes=0; notifications=0} | ConvertTo-Json -Compress
        exit 0
    }
    if (-not [IO.Path]::IsPathRooted($Python) -or $Python.StartsWith('\\')) { throw 'Explicit local interpreter required' }
    if ($ReviewedSource -cnotmatch '^[a-f0-9]{40}$') { throw 'Reviewed standalone commit required' }
    $version = & $Python -I -S -B -c 'import sys; print(sys.version.split()[0])'
    if ($LASTEXITCODE -ne 0 -or ([string]$version).Trim() -cne '3.13.9') { throw 'Reviewed interpreter required' }
    $count = if ($Mode -eq 'Once') { 1 } else { $Checks }
    $announced = @{}
    for ($i=0; $i -lt $count; $i++) {
        $raw = & $Python -I -S -B (Join-Path $PSScriptRoot 'standalone_backup_launch.py') --operation watch --reviewed-source $ReviewedSource --confirm-run --confirm-public-network
        if ($LASTEXITCODE -ne 0) { throw 'Public metadata observation unavailable' }
        $report = $raw | ConvertFrom-Json
        if ($report.status -notin @('PUBLIC_PAIR_WATCH_UNCHANGED_BLOCKED','PUBLIC_PAIR_CANDIDATE_REQUIRES_FULL_REVIEW')) { throw 'Unknown public observation' }
        if ($report.notify_candidate -eq $true) {
            foreach ($pair in $report.candidates) {
                if ($pair.streamlit -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}$' -or $pair.pillow -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}$') { throw 'Invalid public version' }
                $key = [string]$pair.streamlit + '/' + [string]$pair.pillow
                if (-not $announced.ContainsKey($key)) {
                    $shell = New-Object -ComObject WScript.Shell
                    [void]$shell.Popup('An official dependency pair may be compatible. Review the public JSON report; full resolution, audit and regression are still required. Do not change capture or install anything automatically.',0,'Dependency review candidate',64)
                    $announced[$key]=$true
                }
            }
        }
        $raw # public fixed-schema metadata only; unchanged checks have no popup
        if ($i+1 -lt $count) { Start-Sleep -Seconds $IntervalSeconds }
    }
} catch {
    @{status='PUBLIC_WATCH_STOPPED_REVIEW_REQUIRED'; raw_error_printed=$false; task_mutations=0; settings_changes=0; install_authorised=$false} | ConvertTo-Json -Compress
    exit 2
}

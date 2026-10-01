# TEMPORARY diagnostic for #983; remove before merge.
# Per-second CPU and disk samples while the probe runs: total CPU, disk queue,
# and every process above 15% of one core.
$counters = @(
    '\Processor(_Total)\% Processor Time',
    '\PhysicalDisk(_Total)\Current Disk Queue Length',
    '\Process(*)\% Processor Time'
)
Get-Counter -Counter $counters -SampleInterval 1 -MaxSamples 150 -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_.Timestamp.ToUniversalTime().ToString('HH:mm:ss.fff')
    $total = ($_.CounterSamples | Where-Object { $_.Path -like '*processor(_total)*' }).CookedValue
    $disk = ($_.CounterSamples | Where-Object { $_.Path -like '*physicaldisk*' }).CookedValue
    $top = $_.CounterSamples |
        Where-Object { $_.Path -like '*\process(*' -and $_.InstanceName -notin @('_total', 'idle') -and $_.CookedValue -gt 15 } |
        Sort-Object CookedValue -Descending | Select-Object -First 6
    $procs = ($top | ForEach-Object { '{0}={1:N0}' -f $_.InstanceName, $_.CookedValue }) -join ' '
    '{0} CPU total={1:N0} diskq={2:N1} {3}' -f $t, $total, $disk, $procs
}

# Sample the memory of every process with one name, until told to stop.
#
#   powershell -ExecutionPolicy Bypass -File tools\measure\memsample.ps1 -Name crs-sidecar -Out C:\tmp\mem.txt
#   ... run the replay ...
#   echo stop > C:\tmp\mem.txt.stop
#   python tools\measure\memsum.py C:\tmp\mem.txt
#
# Every 500 ms, one line: each running process as id:working set:private
# bytes:peak working set, in bytes. Give -Out as a Windows path; a Git Bash
# path such as /c/tmp is not one.
param([string]$Name, [string]$Out)
Remove-Item -ErrorAction SilentlyContinue $Out
while (-not (Test-Path "$Out.stop")) {
  $p = @(Get-Process -Name $Name -ErrorAction SilentlyContinue)
  if ($p.Count -gt 0) {
    $line = ($p | ForEach-Object { "$($_.Id):$($_.WorkingSet64):$($_.PrivateMemorySize64):$($_.PeakWorkingSet64)" }) -join ' '
    Add-Content -Encoding ascii -Path $Out -Value $line
  }
  Start-Sleep -Milliseconds 500
}
Remove-Item "$Out.stop"

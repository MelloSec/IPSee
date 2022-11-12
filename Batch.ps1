$ips = get-content .\ips.txt
Import-module .\IPSee.ps1
foreach($i in $ips){ echo Get-IPInfo $i  } > .\batchinfo.txt
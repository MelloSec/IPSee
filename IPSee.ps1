[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$ip,
    [Parameter(Mandatory=$false)]
    [string]$shodanKey,
    [Parameter(Mandatory=$false)]
    [string]$neutrinoUser,
    [Parameter(Mandatory=$false)]
    [string]$neutrinoKey,
    [Parameter(Mandatory=$false)]
    [string]$inputFile
)




# Now, if the -inputFile parameter is used, the script will read the IP addresses from the file, store them in an array, and loop through the array to call the necessary functions for each IP address.

# Note that the foreach loop in the -ip branch is redundant since there will only be one IP address in the array. However, I left it in there to keep the code consistent.


function Get-IPInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ip
    )

    $IPObject = Invoke-RestMethod -Method GET -Uri "https://ipapi.co/$ip/json"

    [PSCustomObject]@{
        IP        =  $IPObject.IP
        City      =  $IPObject.City
        Country   =  $IPObject.Country_Name
        Region    =  $IPObject.Region
        Postal    =  $IPObject.Postal
        TimeZone  =  $IPObject.TimeZone
        ASN       =  $IPObject.asn
        Owner     =  $IPObject.org
    }
}

function Check-NeutrinoBlocklist($ip, $userId, $apiKey) {
    $IPObject = Invoke-RestMethod -Method GET -Uri "https://neutrinoapi.net/ip-blocklist?user-id=$userId&api-key=$apiKey&ip=$ip"

    [PSCustomObject]@{
        CIDR                =  $IPObject."cidr"
        IsListed            =  $IPObject."is-listed"
        IsHijacked          =  $IPObject."is-hijacked"
        IsSpider            =  $IPObject."is-spider"
        IsTor               =  $IPObject."is-tor"
        IsProxy             =  $IPObject."is-proxy"
        IsMalware           =  $IPObject."is-malware"
        IsVpn               =  $IPObject."is-vpn"
        IsBot               =  $IPObject."is-bot"
        IsSpamBot           =  $IPObject."is-spam-bot"
        IsExploitBot        =  $IPObject."is-exploit-bot"
        ListCount           =  $IPObject."list-count"
        Blocklists          =  $IPObject."blocklists"
        LastSeen            =  $IPObject."last-seen"
        Sensors             =  $IPObject."sensors"
    }
}

if ($inputFile) {
    $ips = Get-Content $inputFile

    foreach ($ip in $ips) {
        Write-Host "Checking IP: $ip"

        $ipInfo = Get-IPInfo $ip
        Write-Host "IP information:"
        $ipInfo | Format-List

        if ($neutrinoKey -and $neutrinoUser) {
            $neutrinoInfo = Check-NeutrinoBlocklist $ip $neutrinoUser $neutrinoKey
            Write-Host "Neutrino IP blocklist information:"
            $neutrinoInfo | Format-List
        }


        # Add more functionality here as needed
    }
} elseif ($ip) {
    # If -ip parameter was used
    $ips = @($ip)

    foreach ($ip in $ips) {
        Write-Host "Checking IP: $ip"

        $ipInfo = Get-IPInfo $ip
        Write-Host "IP information:"
        $ipInfo | Format-List

        if ($neutrinoKey -and $neutrinoUser) {
            $neutrinoInfo = Check-NeutrinoBlocklist $ip $neutrinoUser $neutrinoKey
            Write-Host "Neutrino IP blocklist information:"
            $neutrinoInfo | Format-List
        }


        # Add more functionality here as needed
    }
} else {
    Write-Error "Either -ip or -inputFile parameter must be specified."
    return
}


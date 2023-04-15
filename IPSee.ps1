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
function Get-MyIp {
    Invoke-WebRequest "http://ifconfig.me/ip"
}
$myip = Get-MyIp
$myinfo = Get-IPInfo $myip
Write-Output "Your current exit node:" ($myinfo | Format-List)
}

function Show-Help {
$scriptName = $MyInvocation.MyCommand.Name
Write-Host "Usage: $scriptName [-ip <IP address>] [-shodanKey <API key>] [-neutrinoUser <username>] [-neutrinoKey <API key>] [-inputFile <path>]"
Write-Host ""
Write-Host "Retrieves information about an IP address, including city, country, region, postal code, time zone, ASN, and owner."
Write-Host ""
Write-Host "Optional parameters:"
Write-Host "-ip <IP address>      The IP address to check."
Write-Host "-shodanKey <API key>  The API key for the Shodan service. (Not implemented yet)"
Write-Host "-neutrinoUser <username>   The username for the Neutrino service."
Write-Host "-neutrinoKey <API key> The API key for the Neutrino service."
Write-Host "-inputFile <path>     The path to a file containing a list of IP addresses to check."
Write-Host ""
}

if ($ip) {
$ips = @($ip)
} elseif ($inputFile) {
$ips = Get-Content $inputFile
} else {
Show-Help
return
}

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


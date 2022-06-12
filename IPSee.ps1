# function Invoke-IPSee {


    # Makes GET request the ipapi.com API to retrieve selected information about the IP address and store it in a CustomObject
    # By default this uses your public IP from above
    # You can also pass any IP address to this function and retrieve the same information.
    function Get-IPInfo {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
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
    Get-IPInfo $ip

    function Check-NeutrinoBlocklist {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [string]$ip,
            [Parameter(Mandatory)]
            [string]$userId,
            [Parameter(Mandatory)]
            [string]$apiKey
        )
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
    $BlockList = Check-NeutrinoBlocklist $ip $userId $apiKey
    $BlockList



    function Check-NeutrinoUrlInfo {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [string]$url,
            [Parameter(Mandatory)]
            [string]$userId,
            [Parameter(Mandatory)]
            [string]$apiKey
        )
        $URLObject = Invoke-RestMethod -Method GET -Uri "https://neutrinoapi.net/url-info?user-id=$userid&api-key=$apiKey&url=$url"
    }
    # $URLCheck = Check-NeutrinoUrlInfo $url $userId $apiKey
    # $URLCheck


    # Checks your current IP
    # Could we make this a switch, so that you either want to look up your own IP first? If not, then we go on to just do a lookup on whatever IP was passed
    function Get-MyIp {
        Invoke-RestMethod -Method GET -Uri "http://ifconfig.me/ip"
    }
    $myip = Get-MyIp
    $myinfo = Get-IPInfo $myip
    Write-Output "Your current exit node:" ($myinfo | Format-List)
    # End


# } Un-Comment main function when ready to build parameters and switch

# That SANS API had some cool granular stuff we could do if we get something bad
# We could feed in lists of IPs check reputation then do more thorough lookups, add to a database and alert
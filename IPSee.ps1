function Get-MyIp {
    $myip = curl 'http://ifconfig.me/ip'
    $ipaddr = $myip.Content.ToString()
}
Get-MyIp

function Get-IPInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ip = $ipaddr
    )
    $IPObject = Invoke-RestMethod -Method Get -Uri "https://ipapi.co/$ip/json"

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

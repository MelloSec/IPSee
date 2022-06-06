function Get-MyIp {
    $myip = curl 'http://ifconfig.me/ip'
    $ip = $myip.Content.ToString()
}
Get-MyIp

function Get-IPInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ip
    )
    $IPObject = Invoke-RestMethod -Method Get -Uri "https://ipapi.co/$ip/json"

    [PSCustomObject]@{
        IP        =  $IPObject.IP
        City      =  $IPObject.City
        Country   =  $IPObject.Country_Name
        Code      =  $IPObject.Country_Code
        Location  =  $IPObject.Latitude
        Longitude =  $IPObject.Longitude
        TimeZone  =  $IPObject.TimeZone
    }
}
Get-IPInfo $ip

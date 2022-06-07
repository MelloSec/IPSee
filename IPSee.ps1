# IPSee - IP Lookup Tool
# MelloSec
# A tool I made to check your exit node / do IP lookups when playing with malware

# Checks your current IP
function Get-MyIp {
    Invoke-WebRequest "http://ifconfig.me/ip"
}
$myip = Get-MyIp
$ip = $myip.Content.ToString()

# Makes GET request the ipapi.com API to retrieve selected information about the IP address and store it in a CustomObject
# By default this uses your public IP from above
# You can also pass any IP address to this function and retrieve the same information.
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




# function get-nslookup
# {
#     nslookup $myip
# }
# get-nslookup

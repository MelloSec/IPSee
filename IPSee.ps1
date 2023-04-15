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
    [string]$inputFile,
    [Parameter(Mandatory=$false)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [switch]$Shodan,
    [Parameter(Mandatory=$false)]
    [switch]$vtKey

)

# Install-Module -Name Get-ShodanAPIInfo
# Install-Module -Name Get-ShodanDNSDomain
# Install-Module -Name Get-ShodanDNSResolve
# Install-Module -Name Get-ShodanDNSReverse
# Install-Module -Name Get-VirusIPReport
# Install-Module -Name Get-VirusDomainReport

# Import-Module -Name Get-ShodanDNSResolve
# Install-Module -Name Get-ShodanDNSReverse
# Import-Module -Name Get-ShodanDNSDomain
# Import-Module -Name Get-VirusIPReport
# Import-Module -Name Get-VirusDomainReport


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

function Check-NeutrinoBlocklist($ip, $userId, $vtKeyKey) {
    $IPObject = Invoke-RestMethod -Method GET -Uri "https://neutrinoapi.net/ip-blocklist?user-id=$userId&api-key=$vtKeyKey&ip=$ip"

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

function Check-NeutrinoRealtime($ip, $userId, $vtKeyKey) {
    $IPObject = Invoke-RestMethod -Method GET -Uri "https://neutrinoapi.net/ip-probe?user-id=$userId&api-key=$vtKeyKey&ip=$ip"

    [PSCustomObject]@{
        ip                  =  $IPObject.ip
        valid               =  $IPObject.valid
        isV6                =  $IPObject.{"is-v6"}
        isV4Mapped          =  $IPObject.{"is-v4-mapped"}
        isBogon             =  $IPObject.{"is-bogon"}
        country             =  $IPObject.country
        countryCode         =  $IPObject.{"country-code"}
        countryCode3        =  $IPObject.{"country-code3"}
        continentCode       =  $IPObject.{"continent-code"}
        currencyCode        =  $IPObject.{"currency-code"}
        city                =  $IPObject.city
        region              =  $IPObject.region
        regionCode          =  $IPObject.{"region-code"}
        hostname            =  $IPObject.hostname
        hostDomain          =  $IPObject.{"host-domain"}
        providerDomain      =  $IPObject.{"provider-domain"}
        providerWebsite     =  $IPObject.{"provider-website"}
        providerDescription =  $IPObject.{"provider-description"}
        providerType        =  $IPObject.{"provider-type"}
        isHosting           =  $IPObject.{"is-hosting"}
        isIsp               =  $IPObject.{"is-isp"}
        isVpn               =  $IPObject.{"is-vpn"}
        isProxy             =  $IPObject.{"is-proxy"}
        vpnDomain           =  $IPObject.{"vpn-domain"}
        asn                 =  $IPObject.asn
        asCidr              =  $IPObject.{"as-cidr"}
        asCountryCode       =  $IPObject.{"as-country-code"}
        asCountryCode3      =  $IPObject.{"as-country-code3"}
        asDomains           =  $IPObject.{"as-domains"}
        asDescription       =  $IPObject.{"as-description"}
        asAge               =  $IPObject.{"as-age"}
    }
}

function Check-NeutrinoDomain($domain, $userId, $vtKeyKey) {
    $DomainObject = Invoke-RestMethod -Method GET -Uri "https://neutrinoapi.com/api/domain-lookup?user-id=$userId&api-key=$vtKeyKey&domain=$domain"

    [PSCustomObject]@{
        valid               =  $DomainObject.valid
        fqdn                =  $DomainObject.fqdn
        domain              =  $DomainObject.domain
        isSubdomain         =  $DomainObject.{"is-subdomain"}
        tld                 =  $DomainObject.tld
        tldCc               =  $DomainObject.{"tld-cc"}
        rank                =  $DomainObject.rank
        isGov               =  $DomainObject.{"is-gov"}
        isOpennic           =  $DomainObject.{"is-opennic"}
        isPending           =  $DomainObject.{"is-pending"}
        isAdult             =  $DomainObject.{"is-adult"}
        isMalicious         =  $DomainObject.{"is-malicious"}
        blocklists          =  $DomainObject.blocklists
        sensors             =  $DomainObject.sensors | ForEach-Object {
            [PSCustomObject]@{
                id              =  $_.id
                blocklist       =  $_.blocklist
                description     =  $_.description
                registeredDate  =  $_.{"registered-date"}
                age             =  $_.age
            }
        }
        registrarName       =  $DomainObject.{"registrar-name"}
        registrarId         =  $DomainObject.{"registrar-id"}
        dnsProvider         =  $DomainObject.{"dns-provider"}
        mailProvider        =  $DomainObject.{"mail-provider"}
    }
}

function Get-VirusDomainReport {
    param(
    [string]$domain,
    [string]$vtKey
    )
    If (!$vtKey){
        Write-Host "Please provide your api key Ex. Get-VirusDomainReport -api {string} -domain {string}"
    }Else {
        If (!$domain){
        Write-Host "Please provide a domain. Ex: Get-VirusDomainReport -api {string} -domain {string}"
        }Else {
            #Use Resource ID to pull the scan results
            $scanoutputuri="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$vtKey&domain=$domain"
            $scanoutput=((Invoke-WebRequest -Uri $scanoutputuri).content | ConvertFrom-Json)
            
            $operainfo=($scanoutput)."Opera domain info"
            $bitdefenderinfo=($scanoutput)."BitDefender domain info"
            $alexainfo=($scanoutput)."Alexa domain info"
            $forcepointcategory=($scanoutput)."Forcepoint ThreatSeeker category"
            $wotinfo=(($scanoutput)."WOT domain info" -Split {$_ -eq ";"} | ConvertFrom-String -Delimiter "=")
            #$subdomains=(($scanoutput).subdomains).Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
            #$undetectedurls=(Write-Host ($scanoutput).undetected_urls | ConvertFrom-StringData -Delimiter ",")
            #$whois=($scanoutput).whois
    
            Write-Host "Domain Report for $domain"
            Write-Host "Opera Info: $operainfo"
            Write-Host "BitDefender Info: $bitdefenderinfo"
            Write-Host "Alexa Info: $alexainfo"
            Write-Host "ForcePoint Category: $forcepointcategory"
            Write-Host "WOT Info: $wotinfo"
            Write-Host "Domain WHOIS:"
            ($scanoutput).whois
            #Write-Host "Subdomains:"
            #(($scanoutput).subdomains).Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
            #Write-Host "Undetected URLs:"
            #(Write-Host ($scanoutput).undetected_urls | ConvertFrom-StringData -Delimiter ",")
        }
    }
    }
    # For IP
    function Get-VirusDomain {
        param(
        [string]$ip,
        [string]$vtKey
        )
        If (!$vtKey){
            Write-Host "Please provide your api key Ex. Get-VirusDomain -api {string} -ip {string}"
        }Else {
            If (!$ip){
            Write-Host "Please provide a domain. Ex: Get-VirusDomain -api {string} -ip {string}"
            }Else {
                #Use Resource ID to pull the scan results
                $scanoutputuri="https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$vtKey&ip=$ip"
                $scanoutput=((Invoke-WebRequest -Uri $scanoutputuri).content | ConvertFrom-Json)
                
                $asn=($scanoutput).asn
                $asownder=($scanoutput).as_owner
                $country=($scanoutput).country
                $responsecode=($scanoutput).response_code
        
                Write-Host "ASN: $asn"
                Write-Host "ASN Owner: $asownder"
                Write-Host "Country of Origin: $country"
                Write-Host "Response Code: $responsecode"
        
            }
        }
        }




# Logic
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
            $neutrinoRealtime = Check-NeutrinoRealtime $ip $neutrinoUser $neutrinoKey
            $neutrinoRealtime | Format-Table
        }

        # if ($virusTotal)
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
            $neutrinoRealtime = Check-NeutrinoRealtime $ip $neutrinoUser $neutrinoKey
            Write-Host "Neutrino Real-time IP scan"
            $neutrinoRealtime | Format-List
        }

        if ($Shodan) {
            if (!$shodanKey) {
                $shodanKey = Read-Host "Enter Shodan API key" -AsSecureString | ConvertFrom-SecureString
                Write-Output "Lookup hostnames associated with IP on Shodan"
                Get-ShodanDNSReverse -ips $ip -API $shodanKey
            }
        }

        Get-VirusDomain -vtKey $vtKey -ip $ip
    
    }
}  elseif ($domain) {
    
    # # Neutrino
    # Write-Host "Checking neutrino domain information"
    # $neutrinoDomain = Check-NeutrinoDomain $domain $neutrinoUser $neutrinoKey
    # $neutrinoDomain | Format-List

    # Shodan
    if (!$shodanKey) {
        $shodanKey = Read-Host "Enter Shodan API key" -AsSecureString | ConvertFrom-SecureString
    }
    Write-Output "Grabbing IP address(es) associated with $domain"
    Get-ShodanDNSResolve -domain $domain -API $shodanKey
    Write-Output "Gathering all subdomains and dns entries for specified domain on Shodan"
    $shodanDNS = Get-ShodanDNSdomain -domain $domain -API $shodanKey  
    $shodanDNS | Format-List
    $vtDNS = Get-VirusDomainReport -vtkey $vtKey -domain $domain
} else {
function Get-MyIp {
    Invoke-WebRequest "http://ifconfig.me/ip"
}
Show-Help
$myip = Get-MyIp
$myinfo = Get-IPInfo $myip
Write-Output "Your current public IP:" ($myinfo | Format-List)
}



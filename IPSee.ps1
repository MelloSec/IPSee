param (
    [Parameter(Mandatory=$false)]
    [string]$ip,
    [Parameter(Mandatory=$false)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$inputFile,
    [Parameter(Mandatory=$false)]
    [string]$shodanKey,
    [Parameter(Mandatory=$false)]
    [string]$vtKey,
    [Parameter(Mandatory=$false)]
    [string]$neutrinoKey,
    [Parameter(Mandatory=$false)]
    [string]$neutrinoUser,
    [Parameter(Mandatory=$false)]
    [switch]$Shodan,
    [Parameter(Mandatory=$false)]
    [switch]$VT,
    [Parameter(Mandatory=$false)]
    [switch]$Neutrino,
    [Parameter(Mandatory=$false)]
    [switch]$Self
)

# Help

function Show-Help {
    [CmdletBinding()]
    param()

    $helpText = @"
SYNTAX
    IPSee [[-IP] <String>] [[-Domain] <String>] [[-InputFile] <String>] [-Self]
        [-Shodan [<String>]] [-Neutrino [<String>]] [-VT [<String>]] [-ShodanKey <String>]
        [-NeutrinoKey <String>] [-VTKey <String>] [<CommonParameters>]

PARAMETERS
    -IP <String>
        The IP address to perform lookups on.

    -Domain <String>
        The domain name to perform lookups on.

    -InputFile <String>
        The path to a text file containing a list of IP addresses or domain names to perform lookups on.



SWITCHES
    -Self [<SwitchParameter>]
        Look up information for your own public IP address.

    -Shodan  [<SwitchParameter>]
        Perform lookups using the Shodan module. Optionally provide a specific IP address or domain name to use for Shodan lookups.

    -Neutrino  [<SwitchParameter>]
        Perform lookups using the Neutrino module. Optionally provide a specific IP address or domain name to use for Neutrino lookups.

    -VT  [<SwitchParameter>]
        Perform lookups using the VirusTotal module. Optionally provide a specific IP address or domain name to use for VirusTotal lookups.

KEYS
    -ShodanKey <String>
        Specify your Shodan API key.

    -NeutrinoKey <String>
        Specify your Neutrino API key.

    -VTKey <String>
        Specify your VirusTotal API key.
"@

    Write-Output $helpText
}


# Function blocks

# Default IP Information, requires no key 
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
        Tld       =  $IPObject.country_tld
        Region    =  $IPObject.Region
        Postal    =  $IPObject.Postal
        TimeZone  =  $IPObject.TimeZone
        ASN       =  $IPObject.asn
        Owner     =  $IPObject.org
        Hostname  =  $IPObject.hostname
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

function Get-ShodanDNSInfo {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$domain,
        
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$shodanKey
    )

    Write-Output "Grabbing IP address(es) associated with $domain"
    Get-ShodanDNSResolve -domain $domain -API $shodanKey
    Write-Output "Gathering all subdomains and DNS entries for specified domain on Shodan"
    $shodanDNS = Get-ShodanDNSdomain -domain $domain -API $shodanKey
    $shodanDNS | Format-List
}

function Get-ShodanHostnameInfo {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$ip,
        
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$shodanKey
    )

    Write-Output "Lookup hostnames associated with IP on Shodan"
    Get-ShodanDNSReverse -ips $ip -API $shodanKey
}

function Get-VirusDomainReport {
    param (
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$domain,
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$vtKey
    )

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

function Get-VirusIpReport {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string]$ip,
        [string]$vtKey
    )

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


function Get-MyIp {
    Invoke-WebRequest "http://ifconfig.me/ip"
}




# Resolve Dependencies and Service Keys

# Shodan key check
if ($Shodan) {
    $modules = @('Get-ShodanDNSResolve', 'Get-ShodanDNSReverse', 'Get-ShodanDNSDomain')
    foreach ($module in $modules) {
        if (-not (Get-Module -Name $module)) {
            try {
                Import-Module -Name $module
            } catch {
                Install-Module -Name $module -force
                Import-Module -Name $module
            }
        }
    }
    if ([string]::IsNullOrEmpty($shodanKey)) {
        $shodanKey = Read-Host -Prompt "Enter your Shodan API key" #-AsSecureString
      # $shodanKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($shodanKey))

    }
}

# VirusTotal key check
if ($VT) {
    $modules = @('Get-VirusIPReport', 'Get-VirusDomainReport')
    foreach ($module in $modules) {
        if (-not (Get-Module -Name $module)) {
            try {
                Import-Module -Name $module
            } catch {
                Install-Module -Name $module
                Import-Module -Name $module
            }
        }
    }
    if ([string]::IsNullOrEmpty($vtKey)) {
        $vtKey = Read-Host -Prompt "Enter your VirusTotal API key" # -AsSecureString
       #  $vtKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($vtKey))
    }
}

# Neutrino key check
if ($Neutrino) {
    if ([string]::IsNullOrEmpty($neutrinoUser)) {
        $neutrinoUser = Read-Host -Prompt "Enter your username"
    }
    if ([string]::IsNullOrEmpty($neutrinoKey)) {
        $neutrinoKey = Read-Host -Prompt "Enter your Neutrino API key" # -AsSecureString
       #  $neutrinoKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($neutrinoKey))
    }   
}

# Nested Conditionals for target format IP, domain, etc and related functions
if ($ip) {
    Write-Output "Performing IP-related lookups for IP $ip"
    # IP related logic
    Write-Host "Checking IP: $ip"

    $ipInfo = Get-IPInfo $ip
    Write-Host "IP information:"
    $ipInfo | Format-List
    
    if ($Neutrino) {
        $neutrinoInfo = Check-NeutrinoBlocklist $ip $neutrinoUser $neutrinoKey
        Write-Host "Neutrino IP blocklist information:"
        $neutrinoInfo | Format-List
        $neutrinoRealtime = Check-NeutrinoRealtime $ip $neutrinoUser $neutrinoKey
        $neutrinoRealtime | Format-Table
    }
    
    if ($VT) { 
        Write-Output "Retrieving IP report from Virtus Total"
        Get-VirusIpReport -ip $ip -vtKey $vtKey
    }
    
    if ($Shodan) { 
        Write-Output "Looking up hostnames associated with IP on Shodan"    
        Get-ShodanDNSReverse -ips $ip -API $shodanKey 
    }


}
elseif ($domain) {
    Write-Output "Performing domain-related lookups for domain $domain"
    # Domain related logic
     if ($Neutrino) { 
        Write-Host "Checking neutrino domain information"
        $neutrinoDomain = Check-NeutrinoDomain $domain $neutrinoUser $neutrinoKey
        $neutrinoDomain | Format-List
        }
     if ($Shodan) {
        Write-Output "Grabbing IP address(es) associated with $domain from Shodan"
        Get-ShodanDNSResolve -domain $domain -API $shodanKey
        Write-Output "Gathering all subdomains and dns entries for specified domain on Shodan"
        $shodanDNS = Get-ShodanDNSdomain -domain $domain -API $shodanKey  
        $shodanDNS | Format-List
        }

    if ($VT){
        Write-Output "Checking domain reputation on Virus Total"
        $vtDNS = Get-VirusDomainReport -vtkey $vtKey -domain $domain
        $vtDNs | Format-List
    }
}
elseif ($inputFile) {
    Write-Output "Performing input file-related lookups for file $inputFile"
    # Input file related logic
    $ips = Get-Content $inputFile

    foreach ($ip in $ips) {
        Write-Host "Checking IP: $ip"

        $ipInfo = Get-IPInfo $ip
        Write-Host "IP information:"
        $ipInfo | Format-List
    }
}
elseif ($Self) {
    $myip = Get-MyIp
    $myinfo = Get-IPInfo $myip
    Write-Output "Your current public IP:" ($myinfo | Format-List)
    $ip = $myip
    if ($Neutrino) {
        $neutrinoInfo = Check-NeutrinoBlocklist $ip $neutrinoUser $neutrinoKey
        Write-Host "Neutrino IP blocklist information:"
        $neutrinoInfo | Format-List
        $neutrinoRealtime = Check-NeutrinoRealtime $ip $neutrinoUser $neutrinoKey
        $neutrinoRealtime | Format-Table
    }
    
    if ($VT) { 
        Write-Output "Retrieving IP report from Virtus Total"
        Get-VirusIpReport -ip $ip -vtKey $vtKey
    }
    
    if ($Shodan) { 
        Write-Output "Looking up hostnames associated with $ip on Shodan"    
        Get-ShodanDNSReverse -ips $ip -API $shodanKey 
    }
}
else {
    Write-Output "No input specified, showing Help menu and current IP information"
    Show-Help
    $myip = Get-MyIp
    $myinfo = Get-IPInfo $myip
    Write-Output "Your current public IP:" ($myinfo | Format-List)
}
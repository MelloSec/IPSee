# IPSee
=========
### MelloSec

## IP Lookup with Reputation and Optional Url Scan

Default lookup is basic from a free API. Register for a free neutrino and/or VirusTotal key or provide a paid Shodan key for more information.

Get Information about an IP Address. Will get your own if run with no options and show this help message:

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



Get-IPInfo

![image](https://user-images.githubusercontent.com/65114647/173243403-e087f571-97db-4d12-8524-6b82a8f9a090.png)

Domain lookup through the neutrino API:

![image](https://user-images.githubusercontent.com/65114647/173244216-98e944fe-91c9-4ae7-b1fc-0b442bbfd15b.png)


Can also get your current public IP.

Get-MyIp

![image](https://user-images.githubusercontent.com/65114647/173103528-ed3c3532-3ce5-48d1-b302-88729254e237.png)

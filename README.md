# Hardening IIS via Security Control Configuration

This repo contains PowerShell scripts to harden a default IIS 10 configuration on Windows Server 2019.
Based on the CIS v1.1.1 benchmarks.
Ref: https://www.cisecurity.org/benchmark/microsoft_iis/

## High Level CIS IIS 10 Security Controls

### 1. Basic Configurations

#### 1.1 Ensure web content is on non-system partition
Isolating web content from system files may reduce the probability of:
  - Web sites/applications exhausting system disk space
  - File IO vulnerability in the web site/application from affecting the confidentiality and/or integrity of system files

Ensure no virtual directories are mapped to the system drive:
```ps1
Get-Website | Format-List Name, PhysicalPath
```

To change the mapping for the application named app1 which resides under the Default Web Site, open IIS Manager:
1. Expand the server node
2. Expand Sites
3. Expand Default Web Site
4. Click on app1
5. In the Actions pane, select Basic Settings
6. In the Physical path text box, put the new loocation of the application, e.g. `D:\wwwroot\app1`

#### 1.2 Ensure 'host headers' are on all sites
Requiring a Host header for all sites may reduce the probability of:
  - DNS rebinding attacks successfully compromising or abusing site data or functionality
  - IP-based scans successfully identifying or interacting with a target application hosted on IIS

Identify sites that are not configured to require host headers:
```ps1
Get-WebBinding -Port * | Format-List bindingInformation
```

Perform the following in IIS Manager to configure host headers for the Default Web Site:
1. Open IIS Manager
2. In the Connections pane expand the Sites node and select Default Web Site
3. In the Actions pane click Bindings
4. In the Site Bindings dialog box, select the binding for which host headers are going to be configured, Port 80 in this example
5. Click Edit
6. Under host name, enter the sites FQDN, such as <www.examplesite.com>
7. Click OK, then Close

#### 1.3 Ensure 'directory browsing' is set to disabled 
Ensuring that directory browsing is disabled may reduce the probability of disclosing
sensitive content that is inadvertently accessible via IIS.

Ensure Directory Browsing has been disabled at the server level:
```ps1
Set-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis:\ -Name Enabled -Value False
```

#### 1.4 Ensure 'Application pool identity' is configured for all application pools
Setting Application Pools to use unique least privilege identities such as
`ApplicationPoolIdentity` reduces the potential harm the identity could cause should the
application ever become compromised.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter
'system.applicationHost/applicationPools/add[@name='<apppool
name>']/processModel' -name 'identityType' -value 'ApplicationPoolIdentity'
```
The example code above will set just the `DefaultAppPool`. Run this command for each
configured Application Pool. Additionally, `ApplicationPoolIdentity` can be made the
default for all Application Pools by using the Set Application Pool Defaults action on the
Application Pools node.

#### 1.5 Ensure 'unique application pools' is set for sites
By setting sites to run under unique Application Pools, resource-intensive applications can
be assigned to their own application pools which could improve server and application
performance.In addition, it can help maintain application availability: if an application in
one pool fails, applications in other pools are not affected.Last, isolating applications helps
mitigate the potential risk of one application being allowed access to the resources of
another application. It is also recommended to stop any application pool that is not in use
or was created by an installation such as .Net 4.0.

Ensure a unique application pool is assigned for each site:
```ps1
Set-ItemProperty -Path 'IIS:\Sites\<website name>' -Name applicationPool -Value <apppool name>
```
By default, all Sites created will use the Default Application Pool (DefaultAppPool).

#### 1.6 Ensure 'application pool identity' is configured for anonymous user identity
Configuring the anonymous user identity to use the application pool identity will help
ensure site isolation - provided sites are set to use the application pool identity. Since a
unique principal will run each application pool, it will ensure the identity is least privilege.
Additionally, it will simplify Site management.

To configure `anonymousAuthentication` at the server level:
```ps1
Set-ItemProperty -Path IIS:\AppPools\<apppool name> -Name passAnonymousToken -Value True
```
The default identity for the anonymous user is the IUSR virtual account.

#### 1.7 Ensure WebDav feature is disabled
WebDAV is not widely used, and it has serious security concerns because it may allow
clients to modify unauthorized files on the web server. Therefore, the WebDav feature
should be disabled.

```ps1
Remove-WindowsFeature Web-DAV-Publishing
```




| 2. Configure Authentication and Authorization                                               |
| :------------------------------------------------------------------------------------------ |
| 2.1 Ensure 'global authorization rule' is set to restrict access                            |
| 2.2 Ensure access to sensitive site features is restricted to authenticated principals only |
| 2.3  Ensure 'forms authentication' requires SSL                                             |
| 2.4 Ensure 'forms authentication' is set to use cookies                                     |
| 2.5 Ensure 'cookie protection mode' is configured for forms authentication                  |
| 2.6 Ensure transport layer security for 'basic authentication' is configured                |
| 2.7 Ensure 'passwordFormat' is not set to clear                                             |
| 2.8 Ensure 'credentials' are not stored in configuration files                              |


| 3. ASP.NET Configuration Recommendations                                                    |
| :------------------------------------------------------------------------------------------ |
| 3.1 Ensure 'deployment method retail' is set                                                |
| 3.2 Ensure 'debug' is turned off                                                            |
| 3.3 Ensure custom error messages are not off                                                |
| 3.4 Ensure IIS HTTP detailed errors are hidden from displaying remotely                     |
| 3.5 Ensure ASP.NET stack tracing is not enabled                                             |
| 3.6 Ensure 'httpcookie' mode is configured for session state                                |
| 3.7 Ensure 'cookies' are set with HttpOnly attribute                                        |
| 3.8 Ensure 'MachineKey validation method - .Net 3.5' is configured                          |
| 3.9 Ensure 'MachineKey validation method - .Net 4.5' is configured                          |
| 3.10  Ensure global .NET trust level is configured                                          |
| 3.11 Ensure X-Powered-By Header is removed                                                  |
| 3.12 Ensure Server Header is removed                                                        |


| 4. Request Filtering and other Restriction Modules                                          |
| :------------------------------------------------------------------------------------------ |
| 4.1 Ensure 'maxAllowedContentLength' is configured                                          |
| 4.2 Ensure 'maxURL request filter' is configured                                            |
| 4.3 Ensure 'MaxQueryString request filter' is configured                                    |
| 4.4 Ensure non-ASCII characters in URLs are not allowed                                     |
| 4.5 Ensure Double-Encoded requests will be rejected                                         |
| 4.6 Ensure 'HTTP Trace Method' is disabled                                                  |
| 4.7  Ensure Unlisted File Extensions are not allowed                                        |
| 4.8 Ensure Handler is not granted Write and Script/Execute                                  |
| 4.9 Ensure ‘notListedIsapisAllowed’ is set to false                                         |
| 4.10  Ensure ‘notListedCgisAllowed’ is set to false                                         |
| 4.11 Ensure ‘Dynamic IP Address Restrictions’ is enabled                                    |


| 5. IIS Logging Recommendations                                                              |
| :------------------------------------------------------------------------------------------ |
| 5.1 Ensure Default IIS web log location is moved                                            |
| 5.2 Ensure Advanced IIS logging is enabled                                                  |
| 5.3 Ensure ‘ETW Logging’ is enabled                                                         |


| 6. FTP Requests                                                                             |
| :------------------------------------------------------------------------------------------ |
| 6.1 Ensure FTP requests are encrypted                                                       |
| 6.2 Ensure FTP Logon attempt restrictions is enabled                                        |


| 7. Transport Encryption                                                                     |
| :------------------------------------------------------------------------------------------ |
| 7.1 Ensure HSTS Header is set                                                               |
| 7.2 Ensure SSLv2 is Disabled                                                                |
| 7.3 Ensure SSLv3 is Disabled                                                                |
| 7.4 Ensure TLS 1.0 is Disabled                                                              |
| 7.5 Ensure TLS 1.1 is Disabled                                                              |
| 7.6 Ensure TLS 1.2 is Enabled                                                               |
| 7.7 Ensure NULL Cipher Suites is Disabled                                                   |
| 7.8 Ensure DES Cipher Suites is Disabled                                                    |
| 7.9 Ensure RC4 Cipher Suites is Disabled                                                    |
| 7.10 Ensure AES 128/128 Cipher Suite is Disabled                                            |
| 7.11 Ensure AES 256/256 Cipher Suite is Enabled                                             |
| 7.12 Ensure TLS Cipher Suite Ordering is Configured                                         |
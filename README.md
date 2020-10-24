# Hardening IIS via Security Control Configuration

This repo contains PowerShell scripts to harden a default IIS 10 configuration on Windows Server 2019.
Based on the CIS v1.1.1 benchmarks.
Ref: https://www.cisecurity.org/benchmark/microsoft_iis/

## 1. Basic Configurations

### Ensure web content is on non-system partition
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

### Ensure 'host headers' are on all sites
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

### Ensure 'directory browsing' is set to disabled 
Ensuring that directory browsing is disabled may reduce the probability of disclosing
sensitive content that is inadvertently accessible via IIS.

Ensure Directory Browsing has been disabled at the server level:
```ps1
Set-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis:\ -Name Enabled -Value False
```

### Ensure 'Application pool identity' is configured for all application pools
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

### Ensure 'unique application pools' is set for sites
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

### Ensure 'application pool identity' is configured for anonymous user identity
Configuring the anonymous user identity to use the application pool identity will help
ensure site isolation - provided sites are set to use the application pool identity. Since a
unique principal will run each application pool, it will ensure the identity is least privilege.
Additionally, it will simplify Site management.

To configure `anonymousAuthentication` at the server level:
```ps1
Set-ItemProperty -Path IIS:\AppPools\<apppool name> -Name passAnonymousToken -Value True
```
The default identity for the anonymous user is the IUSR virtual account.

### Ensure WebDav feature is disabled
WebDAV is not widely used, and it has serious security concerns because it may allow
clients to modify unauthorized files on the web server. Therefore, the WebDav feature
should be disabled.

```ps1
Remove-WindowsFeature Web-DAV-Publishing
```

## 2. Configure Authentication and Authorization

### Ensure 'global authorization rule' is set to restrict access
Configuring a global Authorization rule that restricts access will ensure inheritance of the
settings down through the hierarchy of web directories; if that content is copied elsewhere,
the authorization rules flow with it. This will ensure access to current and future content is
only granted to the appropriate principals, mitigating risk of accidental or unauthorized
access.

To configure URL Authorization at the server level:
```ps1
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/authorization" 
-name "." -AtElement @{users='*';roles='';verbs=''}

Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/authorization" 
-name "." -value @{accessType='Allow';roles='Administrators'}
```
The default server-level setting is to allow all users access.

### Ensure access to sensitive site features is restricted to authenticated principals only
Configuring authentication will help mitigate the risk of unauthorized users accessing data
and/or services, and in some cases reduce the potential harm that can be done to a system.

The example below disabled Windows Authentication and ensures that Forms Authentication is configured, 
cookies will always be used, and SSL is required:

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter 'system.webServer/security/authentication/anonymousAuthentication' 
-name 'enabled' -value 'True'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter 'system.webServer/security/authentication/windowsAuthentication' 
-name 'enabled' -value 'False'

# Add the forms tag within <system.web>:
<system.web>
  <authentication>
    <forms cookieless="UseCookies" requireSSL="true" />
  </authentication>
</system.web>
```

### Ensure 'forms authentication' requires SSL
Requiring SSL for Forms Authentication will protect the confidentiality of credentials
during the login process, helping mitigate the risk of stolen user information.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' 
-filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'
```

### Ensure 'forms authentication' is set to use cookies
Using cookies to manage session state may help mitigate the risk of session hi-jacking
attempts by preventing ASP.NET from having to move session information to the URL.
Moving session information identifiers into the URL may cause session IDs to show up in
proxy logs, browsing history, and be accessible to client scripting via `document.location`.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' 
-filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
```

### Ensure 'cookie protection mode' is configured for forms authentication
By encrypting and validating the cookie, the confidentiality and integrity of data within the
cookie is assured. This helps mitigate the risk of attacks such as session hijacking and
impersonation.

```ps1
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter 'system.web/authentication/forms' -name 'protection'
```
When cookies are used for Forms Authentication, the default cookie protection mode is
`All`, meaning the application encrypts and validates the cookie.

### Ensure transport layer security for 'basic authentication' is configured
Credentials sent in clear text can be easily intercepted by malicious code or persons.
Enforcing the use of Transport Layer Security will help mitigate the chances of hijacked
credentials.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location '<website name>' 
-filter 'system.webServer/security/access' -name 'sslFlags' -value 'Ssl'
```

### Ensure 'passwordFormat' is not set to clear
Authentication credentials should always be protected to reduce the risk of stolen
authentication credentials.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter 'system.web/authentication/forms/credentials' -name 'passwordFormat' -value 'SHA1'
```
The default `passwordFormatmethod` is SHA1.

### Ensure 'credentials' are not stored in configuration files
Authentication credentials should always be protected to reduce the risk of stolen
authentication credentials. For security reasons, it is recommended that user credentials
not be stored an any IIS configuration files.

```ps1
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<websitename>' 
-filter 'system.web/authentication/forms/credentials' -name '.'
```







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
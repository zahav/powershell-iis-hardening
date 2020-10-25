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
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter 'system.applicationHost/applicationPools/add[@name='<apppoolname>']/processModel' 
-name 'identityType' -value 'ApplicationPoolIdentity'
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
-filter 'system.web/authentication/forms' 
-name 'requireSSL' -value 'True'
```

### Ensure 'forms authentication' is set to use cookies
Using cookies to manage session state may help mitigate the risk of session hi-jacking
attempts by preventing ASP.NET from having to move session information to the URL.
Moving session information identifiers into the URL may cause session IDs to show up in
proxy logs, browsing history, and be accessible to client scripting via `document.location`.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' 
-filter 'system.web/authentication/forms' 
-name 'cookieless' -value 'UseCookies'
```

### Ensure 'cookie protection mode' is configured for forms authentication
By encrypting and validating the cookie, the confidentiality and integrity of data within the
cookie is assured. This helps mitigate the risk of attacks such as session hijacking and
impersonation.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter 'system.web/authentication/forms' 
-name 'protection' -value 'All'
```
When cookies are used for Forms Authentication, the default cookie protection mode is
`All`, meaning the application encrypts and validates the cookie.

### Ensure transport layer security for 'basic authentication' is configured
Credentials sent in clear text can be easily intercepted by malicious code or persons.
Enforcing the use of Transport Layer Security will help mitigate the chances of hijacked
credentials.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location '<website name>' 
-filter 'system.webServer/security/access' 
-name 'sslFlags' -value 'Ssl'
```

### Ensure 'passwordFormat' is not set to clear
Authentication credentials should always be protected to reduce the risk of stolen
authentication credentials.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter 'system.web/authentication/forms/credentials' 
-name 'passwordFormat' -value 'SHA1'
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

## 3. ASP.NET Configuration Recommendations

### Ensure 'deployment method retail' is set
Utilizing the switch specifically intended for production IIS servers will eliminate the risk
of vital application and system information leakages that would otherwise occur if tracing
or debug were to be left enabled, or `customErrors` were to be left off.

```ps1
# Open the machine.config file located in: %systemroot%\Microsoft.NET\Framework\<framework version>\Config
# Add the line <deployment retail='true' /> within the <system.web> section:
<system.web>
  <deployment retail="true" />
</system.web>

# Do the same for the 'Microsoft.NET\Framework64' directory
```

### Ensure 'debug' is turned off
Setting `<compilation debug>` to false ensures that detailed error information does not
inadvertently display during live application usage, mitigating the risk of application
information leakage falling into unscrupulous hands.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter "system.web/compilation" 
-name "debug" -value "False"
```

### Ensure custom error messages are not off
`customErrors` can be set to On or RemoteOnly without leaking detailed application
information to the client. Ensuring that `customErrors` is not set to Off will help mitigate the
risk of malicious persons learning detailed application error and server configuration
information.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' 
-filter "system.web/customErrors" 
-name "mode" -value "RemoteOnly"
```

### Ensure IIS HTTP detailed errors are hidden from displaying remotely
The information contained in custom error messages can provide clues as to how
applications function, opening up unnecessary attack vectors. Ensuring custom errors are
never displayed remotely can help mitigate the risk of malicious persons obtaining
information as to how the application works.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter "system.webServer/httpErrors" 
-name "errorMode" -value "DetailedLocalOnly"
```
The default `errorMode` is DetailedLocalOnly.

### Ensure ASP.NET stack tracing is not enabled
In an active Web Site, tracing should not be enabled because it can display sensitive
configuration and detailed stack trace information to anyone who views the pages in the
site. If necessary, the `localOnly` attribute can be set to true to have trace information
displayed only for localhost requests. Ensuring that ASP.NET stack tracing is not on will
help mitigate the risk of malicious persons learning detailed stack trace information.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter "system.web/trace" 
-name "enabled" -value "False"
```
The default value for ASP.NET tracing is off.

### Ensure 'httpcookie' mode is configured for session state
Cookies that have been properly configured help mitigate the risk of attacks such as session
hi-jacking attempts by preventing ASP.NET from having to move session information to the
URL; moving session information in URI causes session IDs to show up in proxy logs, and is
accessible to client scripting via `document.location`.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>'
-filter "system.web/sessionState" 
-name "mode" -value "StateServer"
```

### Ensure 'cookies' are set with HttpOnly attribute
When cookies are set with the `HttpOnly flag`, they cannot be accessed by client side
scripting running in the user's browser. Preventing client-side scripting from accessing
cookie content may reduce the probability of a cross site scripting attack materializing into
a successful session hijack.

```ps1
# Locate and open the application's web.config file
# Add the httpCookies tag within <system.web>:
<configuration>
  <system.web>
    <httpCookies httpOnlyCookies="true" />
  </system.web>
</configuration>
```

### Ensure 'MachineKey validation method - .Net 3.5' is configured
Setting the validation property to AES will provide confidentiality and integrity protection
to the viewstate. AES is the strongest encryption algorithm supported by the validation
property. Setting the validation property to SHA1 will provide integrity protection to the
viewstate. SHA1 is the strongest hashing algorithm supported by the validation property.

```
%systemroot%\system32\inetsrv\appcmd set config /commit:WEBROOT
/section:machineKey /validation:SHA1 
```
The default Machine Key validation method is SHA1.

### Ensure 'MachineKey validation method - .Net 4.5' is configured
Setting the validation property to AES will provide confidentiality and integrity protection
to the viewstate. AES is the strongest encryption algorithm supported by the validation
property. SHA-2 is the strongest hashing algorithm supported by the validation property so it should
be used as the validation method for the MachineKey in .Net 4.5.

```ps1
# Use AES encryption for the ASP.NET Machine Key
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' 
-filter "system.web/machineKey" 
-name "validation" -value "AES"
```
The default Machine Key validation method is SHA256.

### Ensure global .NET trust level is configured
This only applies to .Net 2.0. Future versions have stopped supporting this feature.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' 
-filter "system.web/trust" 
-name "level" -value "Medium"
```
By default, ASP.NET web applications run under the full trust setting

### Ensure X-Powered-By Header is removed
While this is not the only way to fingerprint a site through the response headers, it makes it
harder and prevents some potential attackers.

```ps1
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webserver/httpProtocol/customHeaders" 
-name "." -AtElement @{name='XPowered-By'}
```

### Ensure Server Header is removed
While this is not the only way to fingerprint a site through the response headers, it makes it
harder and prevents some potential attackers. The server header removal directive is a
new feature in IIS 10 that can assist in mitigating this risk.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' 
-filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value "True"
```

## 4. Request Filtering and other Restriction Modules

### Ensure 'maxAllowedContentLength' is configured
Setting an appropriate value that has been tested for the `maxAllowedContentLength` filter
will lower the impact an abnormally large request would otherwise have on IIS and/or web
applications. This helps to ensure availability of web content and services, and may also
help mitigate the risk of buffer overflow type attacks in unmanaged components.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/requestFiltering/requestLimits" 
-name "maxAllowedContentLength" -value 30000000
```
When request filtering is installed on a system, the default value is:
`maxAllowedContentLength=“30000000”`, which is approximately 28.6MB.

### Ensure 'maxURL request filter' is configured
With a properly configured Request Filter limiting the amount of data accepted in the URL,
chances of undesired application behaviors affecting the availability of content and services
are reduced.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/requestFiltering/requestLimits" 
-name "maxUrl" -value 4096
```
When Request Filtering is installed on a system, the default value for `maxURL=“4096”`.

### Ensure 'MaxQueryString request filter' is configured
With a properly configured Request Filter limiting the amount of data accepted in the
query string, chances of undesired application behaviors such as app pool failures are
reduced.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/requestFiltering/requestLimits" 
-name "maxQueryString" -value 2048
```
When request filtering is installed on a system, the default value is `maxQueryString=“2048”`.

### Ensure non-ASCII characters in URLs are not allowed
This feature can help defend against canonicalization attacks, reducing the potential attack
surface of servers, sites, and/or applications.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/requestFiltering" 
-name "allowHighBitCharacters" -value "False"
```
When Request Filtering is installed on a system, the default behavior is to allow high-bit
characters in URI.

### Ensure Double-Encoded requests will be rejected
This feature will help prevent attacks that rely on URLs that have been crafted to contain
double-encoded request(s).

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/requestFiltering" 
-name "allowDoubleEscaping" -value "True"
```
When Request Filtering is installed on a system, the default behavior is to not allow doubleencoded requests.

### Ensure 'HTTP Trace Method' is disabled
Attackers may abuse HTTP TRACE functionality to gain access to information in HTTP
headers such as cookies and authentication data. This risk can be mitigated by not allowing
the TRACE verb.

```ps1
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/requestFiltering/verbs" 
-name "." -value @{verb='TRACE';allowed='False'}
```

### Ensure Unlisted File Extensions are not allowed
Disallowing all but the necessary file extensions can greatly reduce the attack surface of
applications and servers.

```ps1
# Set the list of allowed extensions (customise to suit your needs)
$SitePath = 'MACHINE/WEBROOT/APPHOST'
$Filter = 'system.webServer/security/requestFiltering/fileExtensions'
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.aspx';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.ashx';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.js';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.css';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.json';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.png';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.woff';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.woff2';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.ttf';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.jpg';allowed='True'}
Add-WebConfigurationProperty -pspath $SitePath -filter $Filter -name "." -value @{fileExtension='.svg';allowed='True'}

# Ensure Unlisted File Extensions are not allowed (e.g. .config, .backup, .bat)
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/requestFiltering/fileExtensions" 
-name "allowUnlisted" -value "False"
```

### Ensure Handler is not granted Write and Script/Execute
By allowing both `Execute/Script` and `Write` permissions, a handler can run malicious code
on the target server. Ensuring these two permissions are never together will help lower the
risk of malicious code being executed on the server.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/handlers" 
-name "accessPolicy" -value "Read,Script"
```
The default handlers `accessPolicy` is `Read, Script`.

### Ensure ‘notListedIsapisAllowed’ is set to false
Restricting this attribute to `false` will help prevent potentially malicious ISAPI extensions
from being run.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/isapiCgiRestriction" 
-name "notListedIsapisAllowed" -value "False"
```
The default value for `notListedIsapisAllowed` is false.

### Ensure ‘notListedCgisAllowed’ is set to false
Restricting this attribute to `false` will help prevent unlisted CGI extensions, including
potentially malicious CGI scripts from being run.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/isapiCgiRestriction" 
-name "notListedCgisAllowed" -value "False"
```
The default value for notListedCgisAllowed is false.

### Ensure ‘Dynamic IP Address Restrictions’ is enabled
Dynamic IP address filtering allows administrators to configure the server to block access
for IPs that exceed the specified number of requests or requests frequency. Ensure that you
receive the Forbidden page once the block has been enforced.

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" 
-name "enabled" -value "True"

# You can customise this value to suit your needs. Start with 5 and adjust as necessary
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" 
-name "maxConcurrentRequests" -value <number of requests>
```

## 5. IIS Logging Recommendations

### Ensure Default IIS web log location is moved
Moving IIS logging to a restricted, non-system drive will help mitigate the risk of logs being
maliciously altered, removed, or lost in the event of system drive failure(s).

```ps1
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' 
-filter "system.applicationHost/sites/siteDefaults/logFile" 
-name "directory" -value <new log location>
```

### Ensure Advanced IIS logging is enabled
Many of the fields available in Advanced Logging many can provide extensive, real-time
data and details not otherwise obtainable. Developers and security professionals can use
this information to identify and remediate application vulnerabilities/attack patterns.

To enable Advanced Logging using the UI:
1. Open Internet Information Services (IIS) Manager
2. Click the server in the Connections pane
3. Double-click the Logging icon on the Home page
4. Click Select Fields

Note: IIS Advanced Logging is enabled by default.

### Ensure ‘ETW Logging’ is enabled
IIS flushes log information to disk, therefore prior to IIS, administrators do not have access
to real-time logging information. Text-based log files can also be difficult and time
consuming to process. By enabling ETW, administrators have access to use standard query
tools for viewing real-time logging information.

To configure ETW logging:
1. Open IIS Manager
2. Select the server or site to enable ETW
3. Select Logging.
4. Ensure Log file format is W3C.
5. Select Both log file and ETW event
6. Save your settings.






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
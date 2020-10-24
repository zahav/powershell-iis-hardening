# Hardening IIS via Security Control Configuration

This repo contains PowerShell scripts to harden a default IIS 10 configuration on Windows Server 2019.
Based on the CIS v1.1.1 benchmarks.
Ref: https://www.cisecurity.org/benchmark/microsoft_iis/

## High Level CIS IIS 10 Security Controls
| 1. Basic Configurations                                                                     |
| :------------------------------------------------------------------------------------------ |
| 1.1 Ensure web content is on non-system partition                                           |
| 1.2 Ensure 'host headers' are on all sites                                                  |
| 1.3 Ensure 'directory browsing' is set to disabled                                          |
| 1.4 Ensure 'Application pool identity' is configured for all application pools              |
| 1.5 Ensure 'unique application pools' is set for sites                                      |
| 1.6 Ensure 'application pool identity' is configured for anonymous user  identity           |
| 1.7 Ensure WebDav feature is disabled                                                       |


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
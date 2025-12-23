## Description



WinServiceAuditor is a PowerShell based Windows service auditing tool that enumerates service configurations and analyzes access control lists to detect potential misconfigurations. It focuses on identifying services running with elevated privileges that grant unsafe permissions such as ChangeConfig, WriteDac, WriteOwner, or GenericAll, to low-privileged identities, which could lead to privilege escalation.



---



## Usage



```
.\WinServiceAuditor.ps1
```



---



## Credits

The Get-ServiceAcl function was adapted from publicly available examples by:

* Rohn’s PowerShell Blog [[https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/]]
* cube0x0’s Gist [[https://gist.github.com/cube0x0/1cdef7a90473443f72f28df085241175]]

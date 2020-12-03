This tool can extract/decrypt the password that was stored in the LSA by SysInternals [AutoLogon](https://docs.microsoft.com/en-us/sysinternals/downloads/autologon). I made this to be used with [Cobalt Strike's execute-assembly](https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/):
<pic>
Compiled with .NET 3.0 (Windows Vista's default)+. Needs to be run as SYSTEM. Not just as a high intgrity process because the special registry keys need are only visible to SYSTEM and can only be decyrpted by SYSTEM. 

# Why?
In order to support Keosk mode Windows needs to keep the user's password in a reversable format. This was being kept at HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon under "DefaultUserName" and "DefaultPassword" . Autologon was updated to store the passwords in the LSA Secrets registry keys that are only visible to SYSTEM. [keithga ](https://keithga.wordpress.com/2013/12/19/sysinternals-autologon-and-securely-encrypting-passwords/) provided a binary that popped a Message but no source code or command line version.

# How it works
Through pInvoke calls: 
* LSAOpenPolicy()
* LsaRetrievePrivateData()

# Credits
* Reverse Engineered this: https://keithga.wordpress.com/2013/12/19/sysinternals-autologon-and-securely-encrypting-passwords/
* Copy and Pasted EVERYTHING from here: https://www.pinvoke.net/default.aspx/advapi32/LsaOpenPolicy.html
* Icon from: https://icon-icons.com/icon/lock-secure-password/99595
* SysInternals: https://docs.microsoft.com/en-us/sysinternals/downloads/autologon

So thanks to who actually did the work: keithga, frohwalt

Compiled Version [HERE](https://www/)
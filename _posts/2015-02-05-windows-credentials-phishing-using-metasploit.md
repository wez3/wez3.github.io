---
id: 318
title: Windows credentials phishing using Metasploit
date: 2015-02-05T09:40:52+01:00
author: wesley
layout: post
permalink: /2015/02/windows-credentials-phishing-using-metasploit/
---
A while ago i came across a <a href="http://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/" target="_blank">blog post</a> from @enigma0x3. In this blog post a method was [<img style="float: right;" src="https://forsec.nl/wp-content/uploads/2015/02/Untitled2.png" alt="Untitled2" width="236" height="198" />](https://forsec.nl/wp-content/uploads/2015/02/Untitled2.png)described to perform a phishing attack to gather user credentials using Powershell. It is a great way to get the credentials of a user. This attack can be used if privilege escalation is hard (**try harder**) or not a option. In real life scenario&#8217;s i noticed that privilege escalation can be hard, for example on fully patched terminal servers. With this phishing method, you still can get the (network)credentials of the user. These credentials can be used to pivot into the network. I got some ideas to improve the attack:

  * Built the script into Metasploit, so the script code can be sent through the existing Metasploit connection
  * Popup the script on a certain user activity (starting new processes), if the popup is appearing without any action, it can be suspicious.
  * Also some bugfixes were possible in the existing Powershell script

<!--more-->

**Metasploit post module**

I decided to create the Metasploit post module. The Metasploit module has two flavors:

<ol class="task-list">
  <li>
    Popup a loginprompt immediately, if the user fills in the credentials, they will be sent back. In order to perform this attack, only the SESSION parameter needs to be set.
  </li>
  <li>
    Popup a loginprompt when a specific process is started. For example set PROCESS &#8220;outlook.exe&#8221;, will wait on the user to start outlook. When outlook is started, a loginprompt popups which indicates that outlook.exe needs the user permissions. In the PROCESS option also &#8220;*&#8221; can be specified, this will use the first starting application as it&#8217;s target.
  </li>
</ol>

The following module options are available for configuration:

<pre>
DESCRIPTION: Message shown in the loginprompt
PROCESS: Prompt if a specific process is started by the target. (e.g. calc.exe or specify * for all processes)
SESSION: meterpreter session the run the module on
</pre>

**Example**

The following example will prompt a loginprompt when the process &#8220;calc.exe&#8221; is started:

<pre>
use post/windows/gather/phish_windows_credentials
set PROCESS calc.exe
set SESSION 1
run
</pre>

[<img class="alignnone size-full wp-image-321" src="https://forsec.nl/wp-content/uploads/2015/02/phish_windows_creds_serverside1.png" alt="phish_windows_creds_serverside1" width="1207" height="518" />](https://forsec.nl/wp-content/uploads/2015/02/phish_windows_creds_serverside1.png)

The target will see the following loginprompt after starting calc.exe:

[<img class="alignnone wp-image-325 size-full" src="https://forsec.nl/wp-content/uploads/2015/02/Untitled2.png" alt="" width="670" height="563" />](https://forsec.nl/wp-content/uploads/2015/02/Untitled2.png)

When the target filled in it&#8217;s user credentials, the following output will appear:

[<img class="alignnone size-full wp-image-323" src="https://forsec.nl/wp-content/uploads/2015/02/phish_windows_credentials_serverside2.png" alt="phish_windows_credentials_serverside2" width="1132" height="782" />](https://forsec.nl/wp-content/uploads/2015/02/phish_windows_credentials_serverside2.png)

The module is merged into the official Metasploit repository and is available on github:

The ruby script:

<a title="https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/phish_windows_credentials.rb" href="https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/phish_windows_credentials.rb" target="_blank">https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/phish_windows_credentials.rb</a>

The Powershell script:

<a title="https://github.com/rapid7/metasploit-framework/blob/master/data/post/powershell/Invoke-LoginPrompt.ps1" href="https://github.com/rapid7/metasploit-framework/blob/master/data/post/powershell/Invoke-LoginPrompt.ps1" target="_blank">https://github.com/rapid7/metasploit-framework/blob/master/data/post/powershell/Invoke-LoginPrompt.ps1</a>

Happy phishing.
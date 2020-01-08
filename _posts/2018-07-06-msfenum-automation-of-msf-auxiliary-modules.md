---
id: 500
title: 'Msfenum: automation of MSF auxiliary modules'
date: 2018-07-06T10:58:40+01:00
author: wesley
layout: post
permalink: /2018/07/msfenum-automation-of-msf-auxiliary-modules/
---
[<img style="float: right;" src="https://forsec.nl/wp-content/uploads/2018/07/msfenum.png" alt="" width="261" height="239" />](https://forsec.nl/wp-content/uploads/2018/07/msfenum.png)Low hanging fruit scans can be very useful when performing a penetration test. Especially when performing a internal penetration test a low hanging fruit scan can be very effective. Usually when performing a internal penetration test I am using among other things the Metasploit auxiliary modules to quickly enumerate the network. The modules can give some interesting findings very quickly, such as:

  * open SMB/NFS shares;
  * End-of-life systems, such as Windows XP & Windows 2003 server;
  * MS17-010 vulnerable systems.

Those findings are quick wins and can give you an entry point to the network in order to escalate privileges (e.g. MS17-010 -> DA creds) pretty fast. This helps to tell your customer that you were able to obtain high network permissions within a few hours (if you are able, a malicious attacker is able as well).

<!--more-->

Automating these steps would be useful to give us a quick initial view of a client network. Allowing us more time for more manual validation steps. Next to this we can use this to standardize some of the pentesters workflow to make sure all team members perform the same baseline checks.

**Writing a tool called &#8216;msfenum&#8217;**

Metasploit makes it pretty easy to run those auxiliary modules, however I was looking for a way to make this even faster (plug into the network and run all the modules). I was thinking about writing a tool to automate this, which only needs an IP-range to be scanned. I shared my idea with [@rikvduijn](https://twitter.com/rikvduijn), he got pretty enthusiastic about the idea. He got an idea on how to structure this tool and started writing the skeleton the same night :-).

The next day I looked into the thing that he wrote, the skeleton was a nice start to create a tiny, modular system to run those auxiliary modules automatically. So I continued on that skeleton improve it. Also one of my other collegeaus [@Ag0s_](https://twitter.com/Ag0s_), started writing some cool additions / improvements in msfenum. 🙂

**Running msfenum**

The usage of msfenum is very simple. Use a Linux system with Metasploit Framework installed, such as Kali. Clone the github page:

<pre class="brush: plain; title: ; notranslate" title="">git clone https://github.com/wez3/msfenum
</pre>

Run the command (TARGET_FILE is a file with IPs/IP-ranges line by line):

<pre class="brush: plain; title: ; notranslate" title="">python msfenum.py TARGET_FILE -t &lt;numberofthreads&gt;
</pre>

After running msfenum, all auxiliary output history is stored in the &#8220;logs/&#8221; folder in separate files per module. Also, a summary is printed by the tool after it completed:

[<img class="alignnone size-full wp-image-534" src="https://forsec.nl/wp-content/uploads/2018/07/msfenum_results.png" alt="" width="655" height="801" />](https://forsec.nl/wp-content/uploads/2018/07/msfenum_results.png)

**Adding a module**

A nice thing about the skeleton is that the scripts exists of a very simple structure on how to add auxiliary modules. This requires the following:

_config file_

There is a config file present. Here the modules you like to add can be defined in the &#8220;modules&#8221; entry.

_modules folder_

After adding it to the config file, a module file needs to be created in the &#8220;modules/&#8221; folder. Create a new file with the name of the modules (value after the last &#8220;/&#8221;, e.g. smb_version). Add the specific RC commands to run for your newly added module.

**Contribution**

That&#8217;s it. The module is added. The modules system was created in the hope, other people, with useful auxiliary scans can commit the useful scans back on the Github page. This way, we can help each other to improve (internal) penetration tests :-).

Some possible additions for the future are:

  * parsing the MSF output logs to show results in a standardised way;
  * new modules!
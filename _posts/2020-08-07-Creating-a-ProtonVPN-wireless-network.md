---
title: 'Creating a ProtonVPN wireless network'
author: wesley
layout: post
---
Sometimes I prefer to encrypt my connection or hide my IP-address. During Black Friday I bought a ProtonVPN Plus account which allows me to switch IP-addresses and countries easily. At home I’m using a network based on Ubiquiti hardware <3. I already have quite some network configuration such as different VLANs to protect devices from each other, for example I separated all my home automation from the other devices. 

Adding a separate wireless network that automatically tunnels all my traffic through ProtonVPN is on my wishlist for quite a while. That would allow me to seperate my research devices from other devices and hide my home IP-address at the same time.

So the first thing I do of course is: Googling. I found some information on how to configure ProtonVPN on the Ubiquiti USG itself, however this required modifications on the CLI. Which I didn’t like, I will brick my network for sure. I want to keep that part clean as its working great.
<!--more-->

### Another approach
I decided to take another approach. In my network there is also an Intel NUC with ESX running with a lot space left for virtual machines. I added a Ubuntu VM (20.04) to the NUC that will be a ProtonVPN router. The idea is: passing all traffic through this box, which then passes in onto the ProtonVPN tunnel.

### Steps
After installing the virtual machine on my ESX, I modified the DHCP settings in my Ubiquiti USG. I modified the ‘default gateway’ to the IP-address of the Ubuntu virtual machine, for example 192.168.1.2. We want this default gateway to be assigned to all the clients on the wireless network.

On the Ubuntu VM add the following line to /etc/sysctl.conf, this allows traffic being routed through the VM:
```
net.ipv4.ip_forward=1
```

Install ProtonVPN on the Ubuntu box with these commands:

```
sudo apt install -y openvpn dialog python3-pip python3-setuptools
sudo pip3 install protonvpn-cli
```

Initialize the configuration, walk through the steps by filling in your ProtonVPN details:

```
sudo protonvpn init
```

Lets do some additional configuration. One thing I noticed is that whenever a connection is established with ProtonVPN, I’m not able to SSH in the box anymore due to the added routes. To prevent this, we configure split tunneling through the following command. Choose the option split tunneling and set it for the subnet where your Ubuntu VM is located, e.g. 192.168.1.1/24:

```
protonvpn configure
```

Now its time for the last step: using IP tables to forward all the traffic from the clients through the ProtonVPN tunnel. In order to do so I created a bash script which I run on a reboot of the VM. This initializes the VPN connection and configures IP tables to route all traffic through the ProtonVPN connection:

```
sudo protonvpn c
sudo iptables -t nat -A POSTROUTING -o proton0 -j MASQUERADE
sudo iptables -A FORWARD -i proton0 -o ens160 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i ens160 -o proton0 -j ACCEPT
```

To prevent DNS leaks, we configure the ProtonVPN DNS-server. Modify the DHCP-server settings (in my case Ubiquiti USG), to use the following DNS-server:

```
10.50.0.1
``` 
 
If everything went fine, all your clients traffic should be routed through the ProtonVPN tunnel. Use the website <a href="https://ipleak.net/">ipleak.net</a> to verify if everything is working as expected.

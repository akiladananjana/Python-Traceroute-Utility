# Python-Traceroute-Utility
Traceroute Utility Implementation using Python 

# Basic Info 
Traceroute is a network diagnostic tool used to track in real-time the pathway taken by a packet on an IP network from source to destination, reporting the IP addresses of all the routers it pinged in between. Traceroute also records the time taken for each hop the packet makes during its route to the destination.

# Usage

I developed this tool using Ubuntu 20.04 VM with Python 3.8.2 and also recommended to use that version. Fire up the terminal, navigate to traceroute utility directory 
and execute the following command:</br>

``` python3 traceroute.py 8.8.8.8 ens33 ``` </br>

8.8.8.8 : Destination IP</br>
ens33 : Interface name that needs to be source for traceroute tool</br>

![Python Traceroute Image](https://i.ibb.co/Sd84tSN/Screenshot-2021-04-11-at-22-53-52.png)</br>

# Required Packages
* netifaces : To read the NIC information.

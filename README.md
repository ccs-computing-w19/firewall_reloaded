# firewall_reloaded

A host-based linux firewall system similar to IPTables or nftables.

Uses the netfilter framework to handle and respond to packets that require action.

Rules will be defined in a configuration file, and will be able to be changed through the command line. 

The goal is to begin with a basic packet filtering approach, and move on to more complex filtering through methods such as stateful analysis. 

Created on linux kernel 4.19

**Set up**

Debian systems:

sudo apt-get install build-essential linux-headers-\`uname -r\`

**Run**

make
sudo insmod lkmfirewall.ko options="'Enter IP or port'" ip="'Enter an IP addr'"

**Remove**

sudo rmmod lkmfirewall



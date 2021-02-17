README for sshblack 
-------------------

This is an updated version of the original sshblack tool found at http://www.pettingers.org/code/sshblack.html
Please refer to that page, and release 2.8.1 in this Git repository, for background information and design.

This version of sshblack replaces the ```iptables``` firewall used in RHEL/CentOS 6.
In RHEL/CentOS 7 and 8 the firewall functionality is replaced by *Firewalld*.
The CLI command ```firewall-cmd``` is now used to administer the firewall.

Installation
------------

The files in this folder are installed to the system using the script ```install.sh```
which has been tested on CentOS 7 and 8 systems.

In addition, this crontab job is useful for getting E-mail alerts:

```
0 8 * * * /bin/grep user=root /var/log/secure; /bin/grep Evil /var/log/messages
```


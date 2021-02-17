Installation of sshblack
------------------------

The installation script ```install.sh`` has been tested on CentOS 7 and 8 systems.

Also, this crontab job is useful for getting E-mail alerts:

```
0 8 * * * /bin/grep user=root /var/log/secure; /bin/grep Evil /var/log/messages
```

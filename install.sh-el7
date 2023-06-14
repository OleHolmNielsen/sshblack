#!/bin/sh

# This installation script has been tested on CentOS 7 and 8 systems

echo Installing sshblack files

export bindir=/usr/local/sbin

echo Install files to $bindir
# The install command is part of the coreutils RPM
install sshblack.pl bl unbl list unlist sshblack-save-state $bindir

echo Install logrotate file
cp sshblacklisting.logrotate /etc/logrotate.d/sshblacklisting
chmod 644 /etc/logrotate.d/sshblacklisting

echo Create init file in /usr/libexec/sshblack
mkdir /usr/libexec/sshblack 
install init-sshblack /usr/libexec/sshblack

echo Create Systemd service file in /usr/lib/systemd/system
install -m 644 sshblack.service /usr/lib/systemd/system

echo Start and enable the sshblack service
systemctl enable sshblack
systemctl start sshblack
systemctl status sshblack

echo Create firewall chain BLACKLIST and rule for SSH port 22 
firewall-cmd --permanent --direct --add-chain ipv4 filter BLACKLIST
firewall-cmd --direct --add-rule ipv4 filter INPUT_direct 7 -p tcp --dport 22 -m state --state NEW -j BLACKLIST

echo Create directory /var/lib/sshblack
mkdir -v /var/lib/sshblack
echo Create logfile /var/log/sshblacklisting
touch /var/log/sshblacklisting

echo Initialize sshblack-save-state
$bindir/sshblack-save-state

echo Create crontab job for sshblack-save-state
# The file /etc/crontab is part of the crontabs RPM
if test -s /etc/crontab
then
	grep sshblack-save-state /etc/crontab || echo "*/5 * * * * $bindir/sshblack-save-state" >> /etc/crontab
else
	echo No file /etc/crontab, please install crontab job manually
fi

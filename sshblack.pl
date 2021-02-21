#!/usr/bin/perl -w
#
# sshblack.pl Version 3.0.1
#
# based on sshblack.pl version 2.8.1 from http://www.pettingers.org/code/sshblack.html
# based on mailmgr (c) 2003, Julian Haight, All Rights reserved under GPL license:
# http://www.gnu.org/licenses/gpl.txt
# -------------------------------------------------------
# This is a script which tails the security log file and dynamically blocks
# connections from hosts which meet certain criteria, using
# command-line kernel-level firewall configuration tools provided by
# the operating system (specifically, Firewalld).
# If you prefer to use something other than Firewalld, you can have
# the script execute any command for blocking and unblocking hosts by
# modifying $ADDRULE and $DELRULE.  Please see the sshblack homepage
# for many examples.
# As the script is modifying the firewall, it will need root access.
#
# Note: this script can also be modified to monitor ANY log file
# including apache (web) logs and sendmail (mail) logs.  The
# aggressiveness can be adjusted by setting the variables in the
# first few lines.  It will probably work well right out of the box.
#
# If you have the DAEMONIZE variable set below, you can run the script by
# simply typing the filename from the command prompt. If you clear the
# DAEMONIZE variable, you will need to place it in the background manually
# or let it run from the console prompt.

##############################################################################

use strict;
use Socket;
$|=1;
#
########### Configure Parameters Below ###############
#
# Daemonize sshblack to background
my($DAEMONIZE) = '1';
#
# The INPUT log file you want to monitor
my($LOG) = '/var/log/secure';
#
# The log file for OUTPUT from the script
my($OUTPUTLOG) = '/var/log/sshblacklisting';
#
# The text database file to keep track of attackers
# my($CACHE) = '/var/tmp/ssh-blacklist-pending';
my($CACHE) = '/var/lib/sshblack/ssh-blacklist-pending';
#
# REGEX for whitelisted IPs - never blacklist these addresses
# 
# my($LOCALNET) = '^(?:127\.0\.0\.1|192\.168\.0)';
my($LOCALNET) = '^(?:127\.0\.0\.1|130\.225\.86|130\.225\.87|10\.54)';
#
# Set $ADDRULE to the complete command line instruction for ADDING
# attackers to the blacklist with the following change:
# - Substitute the literal string 'ipaddress' in the location where
# you want the attacker's IP address to be.
#
# Please see the SSHBLACK HOMEPAGE for many more examples of commands
#
# ######### ########### Firewalld VERSION ############ ###########

# Using firewall-cmd on CentOS 7
my($ADDRULE) = '/usr/bin/firewall-cmd --quiet --direct --add-rule ipv4 filter BLACKLIST 0 -s ipaddress -j DROP';

# Set $DELRULE to the complete command line instruction for REMOVING
# attackers from the blacklist with the following change:
# - Substitute the literal string 'ipaddress' in the location where
# you want the attacker's IP address to be.
#
# Please see the SSHBLACK website for many more examples of commands
#
# ######### ########### Firewalld VERSION ############ ###########

# Using firewall-cmd on CentOS 7
my($DELRULE) = '/usr/bin/firewall-cmd --quiet --direct --remove-rule ipv4 filter BLACKLIST 0 -s ipaddress -j DROP';

my($need2query) = 1;	# The firewalld needs to be queried before deleting a rule
my($QUERYRULE) = 'firewall-cmd --direct --query-rule ipv4 filter BLACKLIST 0 -s ipaddress -j DROP';	# Do not use --quiet here.

# Regex of reasons to get firewalled. Separate with pipe (|).
# This VARIES BASED ON THE VERSION OF SOFTWARE YOU ARE RUNNING
# Look at your logs and adjust as necessary.
# Most ssh daemons will list "Failed Password" even if it is
# an illegal user. If you put both Illegal and Failed here
# you might get double hits.
#
# Original
# my($REASONS) = '(Failed password|Failed none|Invalid user)';
my($REASONS) = '(Failed password|Failed none|Invalid user|Bye Bye \[preauth\])';
#
# Maximum time (sec) before they are removed from the database
# unless they are already blacklisted
my($AGEOUT) = 600;
#
# Time delay (day) before they are released from the blacklist in DAYS!
my($RELEASEDAYS) = 4;
#
# Time delay (sec) to check the database for cleanup
my($CHECK) = 300;
#
# Maximum number of booboos before they get listed
my($MAXHITS) = 4;
#
# Maximum number of address listings before we hibernate.
# This is an anti-DoS measure that will likely never fire.
# my($DOSBAIL) = 200;
my($DOSBAIL) = 500;
#
# Set the level of verbosity.  1 = more periodic detail printed.
# 0 = only important stuff will be printed.
my($CHATTY) = 1;
#
# E-mail administrator (default of "root") on critical actions
my($EMAILME) = 1;
#
# Where the advisory E-mail is to be sent: you@domain.tld
my($NOTIFY) = 'root';
#
########### No user defined paramters below ################
#
#
#
my($OCT) = '(?:25[012345]|2[0-4]\d|1?\d\d?)';
my($IP) = $OCT . '\.' . $OCT . '\.' . $OCT . '\.' . $OCT;

$RELEASEDAYS *= 86400; # Lots of seconds!
# $RELEASEDAYS = 130;     #For testing

if ( $DAEMONIZE ) {
  # Fork off a daemon (replaces Proc::Daemon::Init;)
  my($pid);
  if ( defined( $pid = fork() ) ) {
    # This is the Parent (original, to be exited)
    if ( $pid ) {
      exit 0;
    }
    # This is the Child (daemon, keep running)
    else {
      # Send STDOUT and STDERR to LOGFILE
      open (STDOUT, ">>$OUTPUTLOG") or die "failed to open STDOUT";
      open (STDERR, ">&STDOUT") or die "failed to open STDERR";
    }
  }
  else {
    # Something went wrong attempting to fork: bail out
    die "Unable to fork: $!";
  }
}

logit("SSHBLACK is Starting...",'1','0');

# Poor man's touch command
open (TOUCH, ">> $CACHE"); close (TOUCH);

# Start the monitoring
taillog();

sub taillog {
   my($offset, $name, $line, $ip, $reason, $stall, $ind, $doscount) = '';
   my (@loser, @buildlist) = ();
   my($need2reload) = 0;

   $offset = (-s $LOG); # Don't start at beginning, go to end

   logit("Monitoring your log file for future attacks",$CHATTY,'0');

   while (1==1) {
       sleep(1);
       # sleep(60);
       $| = 1;
       $stall += 1;
       if ((-s $LOG) < $offset) {
           logit("Log shrunk, resetting...",'1','0') ;
           $offset = 0;
       }
       open(TAIL, $LOG) || print STDERR "Error opening $LOG: $!\n";

        if (seek(TAIL, $offset, 0)) {
           # found offset, log not rotated
       } else {
           # log reset, follow
           $offset=0;
           seek(TAIL, $offset, 0);
       }
       while ($line = <TAIL>) {
           chop($line);
           if (($REASONS) && ($line =~ m/$REASONS/)) {
               $reason = $1;
               if ($line =~ m/$IP/) {
                  $ip = ($line =~ m/$IP/g) [-1];

                  logit("Watching $ip as potential attacker",$CHATTY,'0');

                 open(LIST, $CACHE) || print STDERR "Error opening $CACHE: $!\n";
                 $ind = 0;
                 @buildlist = <LIST>;
                 foreach $line(@buildlist) {
                   @loser = split(/,/, $line);
                   # [0] is IP, [1] is time, [2] is hits
                   if ($loser[0] eq $ip) {
                     # Already listed, increase count
                     $loser[2] += 1;

                     if ($loser[2] == $MAXHITS) {
                     # See ya!
                       logit("$ip being blocked because of $reason",'1',$EMAILME);
                       blockIp($ip);
			$need2reload++;	# Firewalld needs reloading
                       $loser[2] += 1; # Avoid double listings (???)
                     }
                     $line = join(',', @loser); # put back together for saving
                     $line .= "\n";
                     $buildlist[$ind] = $line;
                     $ip = 'logged';
                   } # End if already listed
                   $ind += 1;
                 } # End foreach read
                 close (LIST);
                 if ($ip ne 'logged') {
                    $line = $ip . ',' . time() . ',' . 1 . "\n";
                    push (@buildlist, $line);
                 }

                 open (LIST, ">$CACHE") || print STDERR "Error opening $CACHE: $!\n";
                 print LIST @buildlist;
                 close (LIST);
               } # End if IP
               next;
           } # End if match reasons
       } # End while read line

       $offset=tell(TAIL);
       close(TAIL);

       if ($stall >= $CHECK) {
        # Time to do cleanup. At period CHECK we look at all listings from the
        # database to see if they are a) blacklisted and have served their time
        # which is set by RELEASEDAYS or b) not blacklisted but have not hit
        # with MAXHITS in the past AGEOUT seconds or c) not blacklisted and have
        # not been in the database for AGEOUT seconds.  If we find either condition
        # (a) or (b) we remove them from the database and (if required) remove
        # them from the Firewalld blacklist.

        $stall = 0; # Clear out cleanup timer
        $doscount = 0; # Clear the denial-of-service counter
        @buildlist = ();
        open(LIST, $CACHE) || print STDERR "Error opening $CACHE: $!\n";
        while ($line = <LIST>) {
           $doscount += 1;
           @loser = split(/,/, $line);
           # [0] is IP, [1] is time, [2] is hits
           if ($loser[2] >= $MAXHITS) {
                # already blacklisted
                if (($loser[1] + $RELEASEDAYS) > time()) {
                   # have not served their time on the blacklist
                   push (@buildlist, $line);
                }
                else {
                   freeIp($loser[0]);
		$need2reload++;	# Firewalld needs reloading
		# Suppress the Freed mails
                   # logit("Freed $loser[0]", $CHATTY, $EMAILME);
                   logit("Freed $loser[0]", $CHATTY, 0);
                } #set free after $RELEASEDAYS

           }
           elsif (($loser[1] + $AGEOUT) > time()){
                # Not listed and not aged out
                   push (@buildlist, $line);
           }
           # If we have more than DOSBAIL listings, we are probably
           # under denial of service attack.  Hibernate so we don't
           # fill up the Firewalld chain or route table.
           if ($doscount > $DOSBAIL) {
              logit("SSHblack: Possible DOS attack. Sleeping.",'1',$EMAILME);
              sleep(86400);
           }
        } # End while reading
        close (LIST);
        # open for writing
        open (LIST, ">$CACHE") || print STDERR "Error opening $CACHE: $!\n";
        print LIST @buildlist;
        close (LIST);
        @buildlist = ();
       } # End cleanup check

	if ($need2reload > 0) {
	# firewall-cmd version needs to reload
	logit("Reloading firewalld",$CHATTY,'0');
	system('/usr/bin/firewall-cmd --reload --quiet');
	$need2reload = 0;
	}

   } # End while endless loop
} # End sub taillog

#################################################
sub blockIp {
#
# This subroutine executes the actual command that does the blacklisting
# action.  It first checks for a whitelisted host/network.  If the attacking
# IP address is not in the whitelist, the literal string 'ipaddress' in the
# $ADDRULE string is replaced with the IP address of the attacker and the command
# is executed.
#

   my($ip) = @_;
   my($rule) = $ADDRULE;

   if ($ip =~ m/$LOCALNET/) {
      logit("Whitelisted host at $ip -- NOT BLACKLISTING",'1','0');
      return;
   }

   $rule =~ s/ipaddress/$ip/;

   logit("Block host at $ip",'1','0');
   system("$rule");

   return;
} # End sub blockIp

#############################################
sub freeIp {
#
# This subroutine removes an attacker from the blacklist.  The literal string
# 'ipaddress' in the $DELRULE string is replaced with the IP address of the attacker
# and the command is executed.
#
   my($ip) = @_;
   logit("Free host at $ip",'1','0');

   my($rule) = $DELRULE;
   $rule =~ s/ipaddress/$ip/;

   if ($need2query == 0) {
     system("$rule");
   } else {
      my($query) = $QUERYRULE;
      $query =~ s/ipaddress/$ip/;
      my($result) = `$query`;	# firewalld query returns yes\n or no\n
      if ($result =~ /yes/) {
        logit("freeIp: Delete rule for host at $ip",'1','0');
        system("$rule");
      } else {
        logit("freeIp: No firewalld rule found for host at $ip",'1','0');   # Do nothing
      }
   }
   return;
} # End sub freeIp

#############################################
sub logit
{
#
# Pass the following into logit:
#     Text of message to be logged
#     Output is to be printed in all cases-verbose (1) or not-brief (0)
#     Message to be emailed to administrator (1) or not (0)

   my ($message, $chatty, $mailme) = @_;
   my ($notify_address) = $NOTIFY;

   if ($chatty)
   {
      print STDOUT '[', scalar localtime, ']  ', "$message", "\n";
   }
   if ($mailme)
   {
      system("mail -s '$message' '$notify_address' < /dev/null >/dev/null 2>&1");
   }
   return;
}  # End sub logit

#
# End sshblack.pl

exemon
======

An audispd plugin outputting human-readable logs of program executions running on a system.

Installation
============

1.       gcc -o exemon exemon.c -lauparse
2.   Put your exemon wherever you want it (but it must be chmod 0750
     and owned by root) and add this to your /etc/audisp/plugins.d/exemon.conf:

         active = yes
         direction = out
         path = <path_to_exemon>
         type = always
         format = string
3.   Add the following to /etc/audit/auditctl.conf (append it to the very end):

         -a exit,always -F arch=b32 -S 11
         -a exit,always -F arch=b64 -S 59
	 
     You can also use the word "execve" rather than the number here. 

     For additional filtering, consult man auditctl -- there are additional
     filter options you can use to filter out specific users executing 
     something, as well as any number of other options. 
4.       service auditd restart

You might also want to change disp_qos in /etc/audit/auditd.conf to "lossless".
Mostly because strange things can happen on the off-chance the plugin takes
too long. 


Known Issues
============

Sometimes auditd will spit out an event in the middle of another event. This
causes libauparse to consider the interrupted event closed, and it will begin
to process the interrupting event as its own event (which may itself be
interrupted by the previous). This will probably show up as an error message
in the logfile. I'm working on a way around this involving using the 'serial'
of the event to ensure that all of the required pieces for logging are available.



Nessus Integration for DefenseStorm

to pull this repository and submodules:

git clone --recurse-submodules https://github.com/DefenseStorm/tenablescScanResults.git

If this is the first integration on this DVM, Do the following:
cp ds-integration/ds_events.conf /etc/syslog-ng/conf.d

Edit /etc/syslog-ng/syslog-ng.conf and add local7 to the excluded list for filter f_syslog3 and filter f_messages. The lines should look like the following:

filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };

filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news,local7); };

Restart syslog-ng service syslog-ng restart

Copy the template config file and update the settings
cp tenablescScanResults.conf.template tenablescScanResults.conf

change the following items in the config file based on your configuration token console site

	accesskey 
	secretkey
	hostname = <hostname of tenableSC>
	scan_list = all <or comma separated list of scan names>

Add these modules if they are not yet there:
	pip3 install pytenable

Add the following entry to the root crontab so the script will run every day at 2am.

0 2 * * * cd /usr/local/tenablescScanResults; ./tenablescScanResults.py

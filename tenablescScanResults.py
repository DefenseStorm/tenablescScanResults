#!/usr/bin/env python3

import sys,os,getopt
import traceback
import io
import os
import fcntl
import json
import time
import csv
import requests
from random import randrange
from datetime import datetime

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

from tenable.sc import TenableSC

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):

    def tenablesc_main(self): 

        # Get JDBC Config info
        try:
            self.accesskey = self.ds.config_get('tenablesc', 'accesskey')
            self.secretkey = self.ds.config_get('tenablesc', 'secretkey')
            self.hostname = self.ds.config_get('tenablesc', 'hostname')
            self.scan_list = self.ds.config_get('tenablesc', 'scan_list').split(',')
            self.state_dir = self.ds.config_get('tenablesc', 'state_dir')
            self.days_ago = self.ds.config_get('tenablesc', 'days_ago')
            self.last_run = self.ds.get_state(self.state_dir)

            current_time = time.time()

            if self.last_run == None:
                self.ds.log("INFO", "No previous state.  Collecting logs for last " + str(self.days_ago) + " days")
                self.last_run = current_time - ( 60 * 60 * 24 * int(self.days_ago))
                #adjusting to run for 48-24 hours ago rather than the last 24
                self.last_run = self.last_run - (60 * 60 * 24)
            #adjusting to run for 48-24 hours ago rather than the last 24
            self.current_run = current_time - (60 * 60 * 24)
        except Exception as e:
                traceback.print_exc()
                self.ds.log("ERROR", "Failed to get required configurations")
                self.ds.log('ERROR', "Exception {0}".format(str(e)))


        try:
            sc = TenableSC(self.hostname, access_key = self.accesskey, secret_key = self.secretkey)
        except Exception as e:
                traceback.print_exc()
                self.ds.log("ERROR", "Failed to get connect to Tenable.SC")
                self.ds.log('ERROR', "Exception {0}".format(str(e)))
                return

        scans = sc.scan_instances.list()['usable']
        for scan in scans:
            if scan['status'] == 'Completed':
                if 'all' not in self.scan_list and scan['name'] not in self.scan_list:
                    self.ds.log("INFO", 'Scan not in scan_list: ' + scan['name'])
                details = sc.scan_instances.details(scan['id'])
                if not int(details['finishTime']) > self.last_run:
                    self.ds.log("INFO", 'Scan too old: ' + scan['name'] + '(' + str(details['finishTime']) + ')')
                    continue
                vulns = sc.analysis.scan(scan['id'])
                self.ds.log("INFO", 'Processing Scan: ' + scan['name'] + '(' + str(scan['id']) + ')' + '(' + str(details['finishTime']) + ')')
       
                for vuln in vulns:
                    vuln['message'] = 'Scan Result - ' + details['finishTime']
                    vuln['scan'] = scan['name']
                    vuln['scanner'] = 'TenableSC'
                    vuln['timestamp'] = details['finishTime']
                    self.ds.writeJSONEvent(vuln)
        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")

    def run(self):
        try:
            pid_file = self.ds.config_get('tenablesc', 'pid_file')
            fp = io.open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of this integration is already running")
                # another instance is running
                sys.exit(0)
            self.tenablesc_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print (os.path.basename(__file__))
        print ('\n  No Options: Run a normal cycle\n')
        print ('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print ('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print ('        in the current directory\n')
        print ('  -l    Log to stdout instead of syslog Local6\n')
        print ('  -a    Generate a .csv file that can be used for Asset Import in Grid\n')
        print ('  -k    Keep scan files (.nessus and .csv files)\n')
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.conf_file = None
    
        try:
            opts, args = getopt.getopt(argv,"htlkac:")
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
            elif opt in ("-c"):
                self.conf_file = arg
            elif opt in ("-a"):
                self.gen_assets_file = True
            elif opt in ("-k"):
                self.keep_files = True
    
        try:
            self.ds = DefenseStorm('tenablescScanResults', testing=self.testing, send_syslog = self.send_syslog, config_file = self.conf_file)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()

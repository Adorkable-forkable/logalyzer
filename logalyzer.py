#!/usr/bin/python

import sys, stat, os
from optparse import OptionParser

import ParseLogs


#
# Logalyzer.  Compiled with python 2.6
#

# callback for the user flag
def user_call(option, opt_str, value, parser):
    if len(parser.rargs) is not 0:
        value = parser.rargs[0]
    else:
        value = None
    setattr(parser.values, option.dest, value)


# entry
if __name__ == "__main__":

    # default location
    log = '/var/log/auth.log'

    # parsing options
    parser = OptionParser(epilog =
                          "Combine flags to view user-specific information.  \'-u test -i\' lists IP addresses "
                          "associated with user test")
    parser.add_option("-u", help = "Specify user.  Blank lists all users.", action = "callback",
                      callback = user_call, default = None, dest = "user")
    parser.add_option("--full", help = "Full log dump for specified user", action = "store_true",
                      default = False, dest = "fullu")
    parser.add_option("-l", help = "Specify log file.  Default is auth.log", default = None, dest = "log")
    parser.add_option("-f", help = "List failures", action = "store_true", default = False, dest = "fail")
    parser.add_option("-s", help = "List success logs", action = "store_true", default = False, dest = "success")
    parser.add_option("-c", help = "List commands by user", action = "store_true", default = False, dest = "commands")
    parser.add_option("-i", help = "List IP Addresses", action = "store_true", default = False, dest = "ip")
    parser.add_option("-g", help = "Location of GeoIP database. Default is GeoLite2-Country.mmdb",
                      default = "GeoLite2-Country.mmdb", dest = "geoipdb")

    # get arguments
    (options, args) = parser.parse_args()

    # if they're trying to access /var/log/auth.log without proper privs, bail
    if not os.getuid() is 0 and options.log is None:
        print("[-] Please run with SUDO or specify a log file\n")
        parser.print_help()
        sys.exit(1)

    # check if they specified another file
    if options.log is not None:
        log = options.log

    # parse logs
    LOGS = ParseLogs.ParseLogs(log, options.geoipdb)
    if LOGS is None:
        sys.exit(1)

    # validate the user
    if options.user:
        if not options.user in LOGS:
            print("[-] User \'%s\' is not present in the logs." % options.user)
            sys.exit(1)

    # tag log location first
    print('[!] Log file: ', log)

    if options.user is not None:
        # output user-specific commands
        if options.commands:
            print("[+] Commands for user \'%s\'" % options.user)
            for com in LOGS[options.user].commands:
                print("\t", com)

        # output user-specific success logs
        if options.success:
            print("[+] Successes logs for user \'%s\'" % options.user)
            for log in LOGS[options.user].succ_logs:
                print("\t", log)

        # output user-specific failures
        if options.fail:
            print("[+] Failures for user \'%s\'" % options.user)
            for fail in LOGS[options.user].fail_logs:
                print("\t", fail)

        # output user-specific ip addresses
        if options.ip:
            print("[+] Logged IPs for user \'%s\'" % options.user)
            for i in LOGS[options.user].ips:
                print("\t", i)

        # print(out all information regarding specified user)
        if options.commands is None and options.success is None and options.fail is None and options.ip is None and options.fullu is None:
            print("[!] Logs associated with user \'%s\'" % options.user)
            print('[+] First log: ', LOGS[options.user].first_date())
            print('[+] Last log: ', LOGS[options.user].last_date())
            print("[!] Failure Logs")
            for fail in LOGS[options.user].fail_logs:
                print("\t", fail)
            print("[!] Success Logs")
            for succ in LOGS[options.user].succ_logs:
                print("\t", succ)
            print("[!] Associated IPs")
            for ip in LOGS[options.user].ips:
                print("\t", ip)
            print("[!] Commands")
            for comm in LOGS[options.user].commands:
                print("\t", comm)

        # dump the full log for the user if specified
        if options.fullu:
            print("[!] Full Log")
            for log in LOGS[options.user].logs:
                print(log)
    else:
        # output all commands
        if options.commands:
            print("[+] All commands")
            for i in LOGS:
                for comms in LOGS[i].commands:
                    print("{0}:\t{1}".format(i, comms))
            sys.exit(1)

        # output all successes
        if options.success:
            print("[+] All successes")
            for i in LOGS:
                for fail in LOGS[i].succ_logs:
                    print("{0}:\t{1}".format(i, fail))
            sys.exit(1)

        # output all failures
        if options.fail:
            print("[+] All failures")
            for i in LOGS:
                for fail in LOGS[i].fail_logs:
                    print("{0}:\t{1}".format(i, fail))
            sys.exit(1)

        # output all logged IP addresses
        if options.ip:
            print("[+] All logged IP Addresses")
            for i in LOGS:
                for ip in LOGS[i].ips:
                    print("{0}:\t{1}".format(i, ip))
            sys.exit(1)

        # if they supplied us with an empty user, dump all of the logged users
        if options.commands is None and options.success is None and options.fail is None and options.ip is None:
            print("[+] All users")
            if len(LOGS) > 0:
                for i in LOGS:
                    print(i)

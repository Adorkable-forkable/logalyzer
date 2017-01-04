import re
import sys
import gzip
import geoip2.database, maxminddb.errors, geoip2.errors

#
# ParseLogs.py
# Parsing component of Logalyzer.  Compiled in Python 2.6
#

# log object
# Stuck into a dictionary by user:Log, where log houses
# logs, fails, successes, logged IPs, and commands used
class Log:
    # dump date of first log
    def first_date(self):
        if len(self.logs) > 0:
            date = None
            i = 0
            # sometimes the first few aren't right, so look
            # until we find one
            while i < len(self.logs) and date is None:
                date = ParseDate(self.logs[i])
                i += 1
            return date
    # dump date of last log
    def last_date(self):
        if len(self.logs) > 0:
            return ParseDate(self.logs[len(self.logs) - 1])
    def __init__(self, usr):
        self.usr = usr
        self.logs = []
        self.fail_logs = []
        self.succ_logs = []
        self.ips = []
        self.countries = []
        self.commands = []

# parse user from various lines
def ParseUsr(line):
    usr = None
    if "Accepted " in line:
        usr = re.search(r'(\bfor\s)(\w+)', line)
    elif "sudo:" in line:
        usr = re.search(r'(sudo:\s+)(\w+)', line)
    elif "authentication failure" in line:
        usr = re.search(r'USER=\w+', line)
    elif "for invalid user" in line:
        usr = re.search(r'(\buser\s)(\w+)', line)
    if usr is not None:
        return usr.group(2)

# parse an IP from a line
def ParseIP(line):
    ip = re.search(r'(\bfrom\s)(\b((\s*((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s*)|(\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*)\b))', line)
    if ip is not None:
        return ip.group(2).strip()

# Look up country of origin
def LookupCountry(ip, geoipdatabase):
    try:
        reader = geoip2.database.Reader(geoipdatabase)
    except IOError as e:
        print "[-] Could not find GeoIP database {0}".format(geoipdatabase)
        print "[-] Please make sure you have downloaded Maxmind's GeoIP2 lite or compatible database"
        sys.exit(1)
    except maxminddb.errors.InvalidDatabaseError as e:
        print "[-] Database {0} doesn't look to be a valid database".format(geoipdatabase)
        print "[-] Please make sure you have downloaded Maxmind's GeoIP2 lite or compatible database"
        sys.exit(1)
    try:
        response = reader.country(ip)
        return response.country.name
    except geoip2.errors.AddressNotFoundError as e:
        print "[w] {0} might be invalid".format(ip)
        return "Unkown"


# parse a date from the line
def ParseDate(line):
    date = re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}', line)
    if date is not None:
        return date.group(0)

# parse a command from a line
def ParseCmd(line):
    # parse command to end of line
    cmd = re.search(r'(\bCOMMAND=)(.+?$)', line)
    if cmd is not None:
        return cmd.group(2)

# begin parsing the passed LOG
def ParseLogs(LOG, GEOPIP):
    # initialize the dictionary
    logs = {}

    # parse the log
    f = None
    try:
        f = gzip.open(LOG, 'r') if '.gz' in LOG else open(LOG, 'r')
        log = f.read()
    except Exception, e:
        print '[-] Error opening \'%s\': %s'%(LOG,e)
        return None
    finally:
        if f is not None: f.close()

    for line in log.split('\n'):
        # match a login
        if "Accepted " in line:
            usr = ParseUsr(line)

            # add 'em if they don't exist
            if not usr in logs:
                logs[usr] = Log(usr)

            ip = ParseIP(line)
            country = LookupCountry(ip, GEOPIP)
            # set info
            if not ip in logs[usr].ips:
                logs[usr].ips.append([ip, country])
            logs[usr].succ_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))

        # match a failed login
        elif "Failed password for" in line:
            # parse user
            usr = ParseUsr(line)

            if not usr in logs:
                logs[usr] = Log(usr)

            ip = ParseIP(line)
            country = LookupCountry(ip, GEOPIP)

            if not ip in logs[usr].ips:
                logs[usr].ips.append([ip, country])
            logs[usr].fail_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))

        # match failed auth
        elif ":auth): authentication failure;" in line:
            # so there are three flavors of authfail we care about;
            # su, sudo, and ssh.  Lets parse each.
            usr = re.search(r'(\blogname=)(\w+)', line)
            if usr is not None:
                usr = usr.group(2)
            # parse a fail log to ssh
            if "(sshd:auth)" in line:
                # ssh doesn't have a logname hurr
                usr = ParseUsr(line)
                if not usr in logs:
                    logs[usr] = Log(usr)

                ip = ParseIP(line)
                country = LookupCountry(ip, GEOPIP)

                logs[usr].ips.append([ip, country])
            # parse sudo/su fails
            else:
                if not usr in logs:
                    logs[usr] = Log(usr)
            logs[usr].fail_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))
            # match commands
        elif "sudo:" in line:
            # parse user
            usr = ParseUsr(line)
            if not usr in logs:
                logs[usr] = Log(usr)

            cmd = ParseCmd(line)
            # append the command if it isn't there already
            if cmd is not None:
                if not cmd in logs[usr].commands:
                    logs[usr].commands.append(cmd)
            logs[usr].logs.append(line.rstrip('\n'))
    return logs

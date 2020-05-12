import codecs
import json
import re
from datetime import datetime, timedelta

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus
from ldap3.core.exceptions import LDAPKeyError, LDAPCursorError, LDAPInvalidDnError
from ldap3.utils import dn
from ldap3.protocol.formatters.formatters import format_sid
from builtins import str
from future.utils import iteritems

from ldapdomaindump.ldap.logsimple import *
from ldapdomaindump.ldap.constants import *


class ReportWriter(object):
    def __init__(self, config):
        self.config = config
        self.dd = None
        if self.config.lookuphostnames:
            self.computerattributes = [
                "cn",
                "sAMAccountName",
                "dNSHostName",
                "IPv4",
                "operatingSystem",
                "operatingSystemServicePack",
                "operatingSystemVersion",
                "lastLogon",
                "userAccountControl",
                "whenCreated",
                "objectSid",
                "description",
            ]
        else:
            self.computerattributes = CUST_COMPUTERATTRIBUTES
        self.userattributes = [
            "cn",
            "name",
            "sAMAccountName",
            "memberOf",
            "primaryGroupId",
            "whenCreated",
            "whenChanged",
            "lastLogon",
            "userAccountControl",
            "pwdLastSet",
            "objectSid",
            "description",
        ]
        # In grouped view, don't include the memberOf property to reduce output size
        self.userattributes_grouped = [
            "cn",
            "name",
            "sAMAccountName",
            "whenCreated",
            "whenChanged",
            "lastLogon",
            "userAccountControl",
            "pwdLastSet",
            "objectSid",
            "description",
        ]
        self.groupattributes = [
            "cn",
            "sAMAccountName",
            "memberOf",
            "description",
            "whenCreated",
            "whenChanged",
            "objectSid",
        ]
        self.policyattributes = [
            "distinguishedName",
            "lockOutObservationWindow",
            "lockoutDuration",
            "lockoutThreshold",
            "maxPwdAge",
            "minPwdAge",
            "minPwdLength",
            "pwdHistoryLength",
            "pwdProperties",
            "ms-DS-MachineAccountQuota",
        ]
        self.trustattributes = [
            "cn",
            "flatName",
            "securityIdentifier",
            "trustAttributes",
            "trustDirection",
            "trustType",
        ]

    # Escape HTML special chars
    def htmlescape(self, html):
        return (
            html.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("'", "&#39;")
            .replace('"', "&quot;")
        )

    # Unescape special DN characters from a CN (only needed if it comes from a DN)
    def unescapecn(self, cn):
        for c in ' "#+,;<=>\\\00':
            cn = cn.replace("\\" + c, c)
        return cn

    # Convert password max age (in 100 nanoseconds), to days
    def nsToDays(self, length):
        # ldap3 >= 2.6 returns timedelta
        if isinstance(length, timedelta):
            return length.total_seconds() / 86400
        else:
            return abs(length) * 0.0000001 / 86400

    def nsToMinutes(self, length):
        # ldap3 >= 2.6 returns timedelta
        if isinstance(length, timedelta):
            return length.total_seconds() / 60
        else:
            return abs(length) * 0.0000001 / 60

    # Parse bitwise flags into a list
    def parseFlags(self, attr, flags_def):
        outflags = []
        if attr is None or attr.value is None:
            return outflags
        for flag, val in iteritems(flags_def):
            if attr.value & val:
                outflags.append(flag)
        return outflags

    # Parse bitwise trust direction - only one flag applies here, 0x03 overlaps
    def parseTrustDirection(self, attr, flags_def):
        outflags = []
        if attr is None:
            return outflags
        for flag, val in iteritems(flags_def):
            if attr.value == val:
                outflags.append(flag)
        return outflags

    # Generate a HTML table from a list of entries, with the specified attributes as column
    def generateHtmlTable(
        self,
        listable,
        attributes,
        header="",
        firstTable=True,
        specialGroupsFormat=False,
    ):
        of = []
        # Only if this is the first table it is an actual table, the others are just bodies of the first table
        # This makes sure that multiple tables have their columns aligned to make it less messy
        if firstTable:
            of.append("<table>")
        # Table header
        if header != "":
            of.append(
                '<thead><tr><td colspan="%d" id="cn_%s">%s</td></tr></thead>'
                % (len(attributes), self.formatId(header), header)
            )
        of.append("<tbody><tr>")
        for hdr in attributes:
            try:
                # Print alias of this attribute if there is one
                of.append("<th>%s</th>" % self.htmlescape(attr_translations[hdr]))
            except KeyError:
                of.append("<th>%s</th>" % self.htmlescape(hdr))
        of.append("</tr>\n")
        for li in listable:
            # Whether we should format group objects separately
            if specialGroupsFormat and "group" in li["objectClass"].values:
                # Give it an extra class and pass it to the function below to make sure the CN is a link
                liIsGroup = True
                of.append('<tr class="group">')
            else:
                liIsGroup = False
                of.append("<tr>")
            for att in attributes:
                try:
                    of.append("<td>%s</td>" % self.formatAttribute(li[att], liIsGroup))
                except (LDAPKeyError, LDAPCursorError):
                    of.append("<td>&nbsp;</td>")
            of.append("</tr>\n")
        of.append("</tbody>\n")
        return "".join(of)

    # Generate several HTML tables for grouped reports
    def generateGroupedHtmlTables(self, groups, attributes):
        first = True
        for groupname, members in iteritems(groups):
            yield self.generateHtmlTable(
                members, attributes, groupname, first, specialGroupsFormat=True
            )
            if first:
                first = False

    # Write generated HTML to file
    def writeHtmlFile(
        self, rel_outfile, body, genfunc=None, genargs=None, closeTable=True
    ):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, "w", "utf8") as of:
            of.write('<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">')
            # Include the style
            try:
                with open(
                    os.path.join(os.path.dirname(__file__), "style.css"), "r"
                ) as sf:
                    of.write('<style type="text/css">')
                    of.write(sf.read())
                    of.write("</style>")
            except IOError:
                logging.warning(
                    "style.css not found in package directory, styling will be skipped"
                )
            of.write("</head><body>")
            # If the generator is not specified, we should write the HTML blob directly
            if genfunc is None:
                of.write(body)
            else:
                for tpart in genfunc(*genargs):
                    of.write(tpart)
            # Does the body contain an open table?
            if closeTable:
                of.write("</table>")
            of.write("</body></html>")

    # Write generated JSON to file
    def writeJsonFile(self, rel_outfile, jsondata, genfunc=None, genargs=None):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, "w", "utf8") as of:
            # If the generator is not specified, we should write the JSON blob directly
            if genfunc is None:
                of.write(jsondata)
            else:
                for jpart in genfunc(*genargs):
                    of.write(jpart)

    # Write generated Greppable stuff to file
    def writeGrepFile(self, rel_outfile, body):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, "w", "utf8") as of:
            of.write(body)

    # Format a value for HTML
    def formatString(self, value):
        if type(value) is datetime:
            try:
                return value.strftime("%x %X")
            except ValueError:
                # Invalid date
                return "0"
        # Make sure it's a unicode string
        if type(value) is bytes:
            return value.encode("utf8")
        if type(value) is str:
            return value  # .encode('utf8')
        if type(value) is int:
            return str(value)
        if value is None:
            return ""
        # Other type: just return it
        return value

    # Format an attribute to a human readable format
    def formatAttribute(self, att, formatCnAsGroup=False):
        aname = att.key.lower()
        # User flags
        if aname == "useraccountcontrol":
            return ", ".join(self.parseFlags(att, uac_flags))
        # List of groups
        if aname == "member" or aname == "memberof" and type(att.values) is list:
            return self.formatGroupsHtml(att.values)
        # Primary group
        if aname == "primarygroupid":
            try:
                return self.formatGroupsHtml([self.dd.groups_dnmap[att.value]])
            except KeyError:
                return "NOT FOUND!"
        # Pwd flags
        if aname == "pwdproperties":
            return ", ".join(self.parseFlags(att, pwd_flags))
        # Domain trust flags
        if aname == "trustattributes":
            return ", ".join(self.parseFlags(att, trust_flags))
        if aname == "trustdirection":
            if att.value == 0:
                return "DISABLED"
            else:
                return ", ".join(self.parseTrustDirection(att, trust_directions))
        if aname == "trusttype":
            return ", ".join(self.parseFlags(att, trust_type))
        if aname == "securityidentifier":
            return format_sid(att.raw_values[0])
        if aname == "minpwdage" or aname == "maxpwdage":
            return "%.2f days" % self.nsToDays(att.value)
        if aname == "lockoutobservationwindow" or aname == "lockoutduration":
            return "%.1f minutes" % self.nsToMinutes(att.value)
        if aname == "objectsid":
            return '<abbr title="%s">%s</abbr>' % (att.value, att.value.split("-")[-1])
        # Special case where the attribute is a CN and it should be made clear its a group
        if aname == "cn" and formatCnAsGroup:
            return self.formatCnWithGroupLink(att.value)
        # Other
        return self.htmlescape(self.formatString(att.value))

    def formatCnWithGroupLink(self, cn):
        return 'Group: <a href="#cn_%s" title="%s">%s</a>' % (
            self.formatId(cn),
            self.htmlescape(cn),
            self.htmlescape(cn),
        )

    # Convert a CN to a valid HTML id by replacing all non-ascii characters with a _
    def formatId(self, cn):
        return re.sub(r"[^a-zA-Z0-9_\-]+", "_", cn)

    # Fallback function for dirty DN parsing in case ldap3 functions error out
    def parseDnFallback(self, dn):
        try:
            indcn = dn[3:].index(",CN=")
            indou = dn[3:].index(",OU=")
            if indcn < indou:
                cn = dn[3:].split(",CN=")[0]
            else:
                cn = dn[3:].split(",OU=")[0]
        except ValueError:
            cn = dn
        return cn

    # Format groups to readable HTML
    def formatGroupsHtml(self, grouplist):
        outcache = []
        for group in grouplist:
            try:
                cn = self.unescapecn(dn.parse_dn(group)[0][1])
            except LDAPInvalidDnError:
                # Parsing failed, do it manually
                cn = self.unescapecn(self.parseDnFallback(group))
            outcache.append(
                '<a href="%s.html#cn_%s" title="%s">%s</a>'
                % (
                    self.config.users_by_group,
                    quote_plus(self.formatId(cn)),
                    self.htmlescape(group),
                    self.htmlescape(cn),
                )
            )
        return ", ".join(outcache)

    # Format groups to readable HTML
    def formatGroupsGrep(self, grouplist):
        outcache = []
        for group in grouplist:
            try:
                cn = self.unescapecn(dn.parse_dn(group)[0][1])
            except LDAPInvalidDnError:
                # Parsing failed, do it manually
                cn = self.unescapecn(self.parseDnFallback(group))
            outcache.append(cn)
        return ", ".join(outcache)

    # Format attribute for grepping
    def formatGrepAttribute(self, att):
        aname = att.key.lower()
        # User flags
        if aname == "useraccountcontrol":
            return ", ".join(self.parseFlags(att, uac_flags))
        # List of groups
        if aname == "member" or aname == "memberof" and type(att.values) is list:
            return self.formatGroupsGrep(att.values)
        if aname == "primarygroupid":
            try:
                return self.formatGroupsGrep([self.dd.groups_dnmap[att.value]])
            except KeyError:
                return "NOT FOUND!"
        # Domain trust flags
        if aname == "trustattributes":
            return ", ".join(self.parseFlags(att, trust_flags))
        if aname == "trustdirection":
            if att.value == 0:
                return "DISABLED"
            else:
                return ", ".join(self.parseTrustDirection(att, trust_directions))
        if aname == "trusttype":
            return ", ".join(self.parseFlags(att, trust_type))
        if aname == "securityidentifier":
            return format_sid(att.raw_values[0])
        # Pwd flags
        if aname == "pwdproperties":
            return ", ".join(self.parseFlags(att, pwd_flags))
        if aname == "minpwdage" or aname == "maxpwdage":
            return "%.2f days" % self.nsToDays(att.value)
        if aname == "lockoutobservationwindow" or aname == "lockoutduration":
            return "%.1f minutes" % self.nsToMinutes(att.value)
        return self.formatString(att.value)

    # Generate grep/awk/cut-able output
    def generateGrepList(self, entrylist, attributes):
        hdr = self.config.grepsplitchar.join(attributes)
        out = [hdr]
        for entry in entrylist:
            eo = []
            for attr in attributes:
                try:
                    eo.append(self.formatGrepAttribute(entry[attr]) or "")
                except (LDAPKeyError, LDAPCursorError):
                    eo.append("")
            out.append(self.config.grepsplitchar.join(eo))
        return "\n".join(out)

    # Convert a list of entities to a JSON string
    # String concatenation is used here since the entities have their own json generate
    # method and converting the string back to json just to process it would be inefficient
    def generateJsonList(self, entrylist):
        out = "[" + ",".join([entry.entry_to_json() for entry in entrylist]) + "]"
        return out

    # Convert a group key/value pair to json
    # Same methods as previous function are used
    def generateJsonGroup(self, group):
        out = "{%s:%s}" % (json.dumps(group[0]), self.generateJsonList(group[1]))
        return out

    # Convert a list of group dicts with entry lists to JSON string
    # Same methods as previous functions are used, except that text is returned
    # from a generator rather than allocating everything in memory
    def generateJsonGroupedList(self, groups):
        # Start of the list
        yield "["
        firstGroup = True
        for group in iteritems(groups):
            if not firstGroup:
                # Separate items
                yield ","
            else:
                firstGroup = False
            yield self.generateJsonGroup(group)
        yield "]"

    # Generate report of all computers grouped by OS family
    def generateComputersByOsReport(self, dd):
        grouped = dd.sortComputersByOS(dd.computers)
        if self.config.outputhtml:
            # Use the generator approach to save memory
            self.writeHtmlFile(
                "%s.html" % self.config.computers_by_os,
                None,
                genfunc=self.generateGroupedHtmlTables,
                genargs=(grouped, self.computerattributes),
            )
        if self.config.outputjson and self.config.groupedjson:
            self.writeJsonFile(
                "%s.json" % self.config.computers_by_os,
                None,
                genfunc=self.generateJsonGroupedList,
                genargs=(grouped,),
            )

    # Generate report of all groups and detailled user info
    def generateUsersByGroupReport(self, dd):
        grouped = dd.sortUsersByGroup(dd.users)
        if self.config.outputhtml:
            # Use the generator approach to save memory
            self.writeHtmlFile(
                "%s.html" % self.config.users_by_group,
                None,
                genfunc=self.generateGroupedHtmlTables,
                genargs=(grouped, self.userattributes_grouped),
            )
        if self.config.outputjson and self.config.groupedjson:
            self.writeJsonFile(
                "%s.json" % self.config.users_by_group,
                None,
                genfunc=self.generateJsonGroupedList,
                genargs=(grouped,),
            )

    # Generate report with just a table of all users
    def generateUsersReport(self, dd):
        # Copy dd to this object, to be able to reference it
        self.dd = dd
        dd.mapGroupsIdsToDns()
        if self.config.outputhtml:
            html = self.generateHtmlTable(dd.users, self.userattributes, "Domain users")
            self.writeHtmlFile("%s.html" % self.config.usersfile, html)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.users)
            self.writeJsonFile("%s.json" % self.config.usersfile, jsonout)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.users, self.userattributes)
            self.writeGrepFile("%s.grep" % self.config.usersfile, grepout)

    # Generate report with just a table of all computer accounts
    def generateComputersReport(self, dd):
        if self.config.outputhtml:
            html = self.generateHtmlTable(
                dd.computers, self.computerattributes, "Domain computer accounts"
            )
            self.writeHtmlFile("%s.html" % self.config.computersfile, html)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.computers)
            self.writeJsonFile("%s.json" % self.config.computersfile, jsonout)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.computers, self.computerattributes)
            self.writeGrepFile("%s.grep" % self.config.computersfile, grepout)

    # Generate report with just a table of all computer accounts
    def generateGroupsReport(self, dd):
        if self.config.outputhtml:
            html = self.generateHtmlTable(
                dd.groups, self.groupattributes, "Domain groups"
            )
            self.writeHtmlFile("%s.html" % self.config.groupsfile, html)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.groups)
            self.writeJsonFile("%s.json" % self.config.groupsfile, jsonout)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.groups, self.groupattributes)
            self.writeGrepFile("%s.grep" % self.config.groupsfile, grepout)

    # Generate policy report
    def generatePolicyReport(self, dd):
        if self.config.outputhtml:
            html = self.generateHtmlTable(
                dd.policy, self.policyattributes, "Domain policy"
            )
            self.writeHtmlFile("%s.html" % self.config.policyfile, html)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.policy)
            self.writeJsonFile("%s.json" % self.config.policyfile, jsonout)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.policy, self.policyattributes)
            self.writeGrepFile("%s.grep" % self.config.policyfile, grepout)

    # Generate policy report
    def generateTrustsReport(self, dd):
        if self.config.outputhtml:
            html = self.generateHtmlTable(
                dd.trusts, self.trustattributes, "Domain trusts"
            )
            self.writeHtmlFile("%s.html" % self.config.trustsfile, html)
        if self.config.outputjson:
            jsonout = self.generateJsonList(dd.trusts)
            self.writeJsonFile("%s.json" % self.config.trustsfile, jsonout)
        if self.config.outputgrep:
            grepout = self.generateGrepList(dd.trusts, self.trustattributes)
            self.writeGrepFile("%s.grep" % self.config.trustsfile, grepout)

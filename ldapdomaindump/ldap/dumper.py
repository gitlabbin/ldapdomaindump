try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus
import dns.resolver
import ldap3
from ldap3.abstract import attribute, attrDef
from ldap3.core.exceptions import LDAPAttributeError

from ldapdomaindump.ldap.exporter import *
from ldapdomaindump.ldap.constants import *


# Class containing the default config
class DomainDumpConfig(object):
    def __init__(self):
        # Base path
        self.basepath = '.'

        # Output files basenames
        self.groupsfile = 'domain_groups'  # Groups
        self.usersfile = 'domain_users'  # User accounts
        self.computersfile = 'domain_computers'  # Computer accounts
        self.policyfile = 'domain_policy'  # General domain attributes
        self.trustsfile = 'domain_trusts'  # Domain trusts attributes

        # Combined files basenames
        self.users_by_group = 'domain_users_by_group'  # Users sorted by group
        self.computers_by_os = 'domain_computers_by_os'  # Computers sorted by OS

        # Output formats
        self.outputhtml = False
        self.outputjson = False
        self.outputgrep = True

        # Output json for groups
        self.groupedjson = False

        # Default field delimiter for greppable format is a tab
        self.grepsplitchar = '\t'

        # Other settings
        self.lookuphostnames = False  # Look up hostnames of computers to get their IP address
        self.dnsserver = ''  # Addres of the DNS server to use, if not specified default DNS will be used
        self.minimal = False  # Only query minimal list of attributes


# Domaindumper main class
class DomainDumper(object):
    def __init__(self, server, connection, config, root=None):
        self.server = server
        self.connection = connection
        self.config = config
        # Unless the root is specified we get it from the server
        if root is None:
            self.root = self.getRoot()
        else:
            self.root = root
        self.users = None  # Domain users
        self.groups = None  # Domain groups
        self.computers = None  # Domain computers
        self.policy = None  # Domain policy
        self.groups_dnmap = None  # CN map for group IDs to CN
        self.groups_dict = None  # Dictionary of groups by CN
        self.trusts = None  # Domain trusts

    # Get the server root from the default naming context
    def getRoot(self):
        return self.server.info.other['defaultNamingContext'][0]

    # Query the groups of the current user
    def getCurrentUserGroups(self, username, domainsid=None):
        self.connection.search(self.root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))' % username,
                               attributes=['cn', 'memberOf', 'primaryGroupId'])
        try:
            groups = self.connection.entries[0]['memberOf'].values
            if domainsid is not None:
                groups.append(self.getGroupDNfromID(domainsid, self.connection.entries[0]['primaryGroupId'].value))
            return groups
        except LDAPKeyError:
            # No groups, probably just member of the primary group
            if domainsid is not None:
                primarygroup = self.getGroupDNfromID(domainsid, self.connection.entries[0]['primaryGroupId'].value)
                return [primarygroup]
            else:
                return []
        except IndexError:
            # The username does not exist (might be a computer account)
            return []

    # Check if the user is part of the Domain Admins or Enterprise Admins group, or any of their subgroups
    def isDomainAdmin(self, username):
        domainsid = self.getRootSid()
        groups = self.getCurrentUserGroups(username, domainsid)
        # Get DA and EA group DNs
        dagroupdn = self.getDAGroupDN(domainsid)
        eagroupdn = self.getEAGroupDN(domainsid)
        # First, simple checks
        for group in groups:
            if 'CN=Administrators' in group or 'CN=Domain Admins' in group or dagroupdn == group:
                return True
            # Also for enterprise admins if applicable
            if 'CN=Enterprise Admins' in group or (eagroupdn is not False and eagroupdn == group):
                return True
        # Now, just do a recursive check in both groups and their subgroups using LDAP_MATCHING_RULE_IN_CHAIN
        self.connection.search(self.root,
                               '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=%s))' % (
                                   username, dagroupdn), attributes=['cn', 'sAMAccountName'])
        if len(self.connection.entries) > 0:
            return True
        self.connection.search(self.root,
                               '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=%s))' % (
                                   username, eagroupdn), attributes=['cn', 'sAMAccountName'])
        if len(self.connection.entries) > 0:
            return True
        # At last, check the users primary group ID
        return False

    # Get all users
    def getAllUsers(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search('%s' % (self.root),
                                                         '(&(objectCategory=person)(objectClass=user))',
                                                         attributes=MINIMAL_USERATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        else:
            self.connection.extend.standard.paged_search('%s' % (self.root),
                                                         '(&(objectCategory=person)(objectClass=user))',
                                                         attributes=ldap3.ALL_ATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        return self.connection.entries

    # Get all computers in the domain
    def getAllComputers(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search('%s' % (self.root),
                                                         '(&(objectClass=computer)(objectClass=user))',
                                                         attributes=CUST_COMPUTERATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        else:
            self.connection.extend.standard.paged_search('%s' % (self.root),
                                                         '(&(objectClass=computer)(objectClass=user))',
                                                         attributes=ldap3.ALL_ATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        return self.connection.entries

    # Get all user SPNs
    def getAllUserSpns(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search('%s' % (self.root),
                                                         '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))',
                                                         attributes=MINIMAL_USERATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        else:
            self.connection.extend.standard.paged_search('%s' % (self.root),
                                                         '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))',
                                                         attributes=ldap3.ALL_ATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        return self.connection.entries

    # Get all defined groups
    def getAllGroups(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search(self.root, '(objectClass=group)',
                                                         attributes=MINIMAL_GROUPATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        else:
            self.connection.extend.standard.paged_search(self.root, '(objectClass=group)',
                                                         attributes=ldap3.ALL_ATTRIBUTES, paged_size=PAGE_SIZE,
                                                         generator=False)
        return self.connection.entries

    # Get the domain policies (such as lockout policy)
    def getDomainPolicy(self):
        self.connection.search(self.root, '(objectClass=domain)', attributes=ldap3.ALL_ATTRIBUTES)
        return self.connection.entries

    # Get domain trusts
    def getTrusts(self):
        self.connection.search(self.root, '(objectClass=trustedDomain)', attributes=ldap3.ALL_ATTRIBUTES)
        return self.connection.entries

    # Get all defined security groups
    # Syntax from:
    # https://ldapwiki.willeke.com/wiki/Active%20Directory%20Group%20Related%20Searches
    def getAllSecurityGroups(self):
        self.connection.search(self.root, '(groupType:1.2.840.113556.1.4.803:=2147483648)',
                               attributes=ldap3.ALL_ATTRIBUTES)
        return self.connection.entries

    # Get the SID of the root object
    def getRootSid(self):
        self.connection.search(self.root, '(objectClass=domain)', attributes=['objectSid'])
        try:
            sid = self.connection.entries[0].objectSid
        except (LDAPAttributeError, LDAPCursorError, IndexError):
            return False
        return sid

    # Get group members recursively using LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
    def getRecursiveGroupmembers(self, groupdn):
        self.connection.extend.standard.paged_search(self.root,
                                                     '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=%s))' % groupdn,
                                                     attributes=MINIMAL_USERATTRIBUTES, paged_size=PAGE_SIZE,
                                                     generator=False)
        return self.connection.entries

    # Resolve group ID to DN
    def getGroupDNfromID(self, domainsid, gid):
        self.connection.search(self.root, '(objectSid=%s-%d)' % (domainsid, gid), attributes=['distinguishedName'])
        return self.connection.entries[0]['distinguishedName'].value

    # Get Domain Admins group DN
    def getDAGroupDN(self, domainsid):
        return self.getGroupDNfromID(domainsid, 512)

    # Get Enterprise Admins group DN
    def getEAGroupDN(self, domainsid):
        try:
            return self.getGroupDNfromID(domainsid, 519)
        except (LDAPAttributeError, LDAPCursorError, IndexError):
            # This does not exist, could be in a parent domain
            return False

    # Lookup all computer DNS names to get their IP
    def lookupComputerDnsNames(self):
        dnsresolver = dns.resolver.Resolver()
        dnsresolver.lifetime = 2
        ipdef = attrDef.AttrDef('ipv4')
        if self.config.dnsserver != '':
            dnsresolver.nameservers = [self.config.dnsserver]
        for computer in self.computers:
            try:
                answers = dnsresolver.query(computer.dNSHostName.values[0], 'A')
                ip = str(answers.response.answer[0][0])
            except dns.resolver.NXDOMAIN:
                ip = 'error.NXDOMAIN'
            except dns.resolver.Timeout:
                ip = 'error.TIMEOUT'
            except (LDAPAttributeError, LDAPCursorError):
                ip = 'error.NOHOSTNAME'
            # Construct a custom attribute as workaround
            ipatt = attribute.Attribute(ipdef, computer, None)
            ipatt.__dict__['_response'] = ip
            ipatt.__dict__['raw_values'] = [ip]
            ipatt.__dict__['values'] = [ip]
            # Add the attribute to the entry's dictionary
            computer._state.attributes['IPv4'] = ipatt

    # Create a dictionary of all operating systems with the computer accounts that are associated
    def sortComputersByOS(self, items):
        osdict = {}
        for computer in items:
            try:
                cos = computer.operatingSystem.value or 'Unknown'
            except (LDAPAttributeError, LDAPCursorError):
                cos = 'Unknown'
            try:
                osdict[cos].append(computer)
            except KeyError:
                # New OS
                osdict[cos] = [computer]
        return osdict

    # Map all groups on their ID (taken from their SID) to CNs
    # This is used for getting the primary group of a user
    def mapGroupsIdsToDns(self):
        dnmap = {}
        for group in self.groups:
            gid = int(group.objectSid.value.split('-')[-1])
            dnmap[gid] = group.distinguishedName.values[0]
        self.groups_dnmap = dnmap
        return dnmap

    # Create a dictionary where a groups CN returns the full object
    def createGroupsDictByCn(self):
        gdict = {grp.cn.values[0]: grp for grp in self.groups}
        self.groups_dict = gdict
        return gdict

    # Get CN from DN
    def getGroupCnFromDn(self, dnin):
        cn = self.unescapecn(dn.parse_dn(dnin)[0][1])
        return cn

    # Unescape special DN characters from a CN (only needed if it comes from a DN)
    def unescapecn(self, cn):
        for c in ' "#+,;<=>\\\00':
            cn = cn.replace('\\' + c, c)
        return cn

    # Sort users by group they belong to
    def sortUsersByGroup(self, items):
        groupsdict = {}
        # Make sure the group CN mapping already exists
        if self.groups_dnmap is None:
            self.mapGroupsIdsToDns()
        for user in items:
            try:
                ugroups = [self.getGroupCnFromDn(group) for group in user.memberOf.values]
            # If the user is only in the default group, its memberOf property wont exist
            except (LDAPAttributeError, LDAPCursorError):
                ugroups = []
            # Add the user default group
            try:
                ugroups.append(self.getGroupCnFromDn(self.groups_dnmap[user.primaryGroupId.value]))
            # Sometimes we can't query this group or it doesn't exist
            except KeyError:
                pass
            for group in ugroups:
                try:
                    groupsdict[group].append(user)
                except KeyError:
                    # Group is not yet in dict
                    groupsdict[group] = [user]

        # Append any groups that are members of groups
        for group in self.groups:
            try:
                for parentgroup in group.memberOf.values:
                    try:
                        groupsdict[self.getGroupCnFromDn(parentgroup)].append(group)
                    except KeyError:
                        # Group is not yet in dict
                        groupsdict[self.getGroupCnFromDn(parentgroup)] = [group]
            # Without subgroups this attribute does not exist
            except (LDAPAttributeError, LDAPCursorError):
                pass

        return groupsdict

    # Main function
    def dump_all(self):
        self.users = self.getAllUsers()
        self.computers = self.getAllComputers()
        self.groups = self.getAllGroups()
        if self.config.lookuphostnames:
            self.lookupComputerDnsNames()
        self.policy = self.getDomainPolicy()
        self.trusts = self.getTrusts()
        rw = ReportWriter(self.config)
        rw.generateUsersReport(self)
        rw.generateGroupsReport(self)
        rw.generateComputersReport(self)
        rw.generatePolicyReport(self)
        rw.generateTrustsReport(self)
        rw.generateComputersByOsReport(self)
        rw.generateUsersByGroupReport(self)

    def dump_computers(self):
        self.computers = self.getAllComputers()
        if self.config.lookuphostnames:
            self.lookupComputerDnsNames()
        rw = ReportWriter(self.config)
        rw.generateComputersReport(self)

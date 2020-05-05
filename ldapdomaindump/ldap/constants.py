# User account control flags
# From: https://blogs.technet.microsoft.com/askpfeplat/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory/
uac_flags = {'ACCOUNT_DISABLED': 0x00000002,
             'ACCOUNT_LOCKED': 0x00000010,
             'PASSWD_NOTREQD': 0x00000020,
             'PASSWD_CANT_CHANGE': 0x00000040,
             'NORMAL_ACCOUNT': 0x00000200,
             'WORKSTATION_ACCOUNT': 0x00001000,
             'SERVER_TRUST_ACCOUNT': 0x00002000,
             'DONT_EXPIRE_PASSWD': 0x00010000,
             'SMARTCARD_REQUIRED': 0x00040000,
             'TRUSTED_FOR_DELEGATION': 0x00080000,
             'NOT_DELEGATED': 0x00100000,
             'USE_DES_KEY_ONLY': 0x00200000,
             'DONT_REQ_PREAUTH': 0x00400000,
             'PASSWORD_EXPIRED': 0x00800000,
             'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x01000000,
             'PARTIAL_SECRETS_ACCOUNT': 0x04000000
             }

# Password policy flags
pwd_flags = {'PASSWORD_COMPLEX': 0x01,
             'PASSWORD_NO_ANON_CHANGE': 0x02,
             'PASSWORD_NO_CLEAR_CHANGE': 0x04,
             'LOCKOUT_ADMINS': 0x08,
             'PASSWORD_STORE_CLEARTEXT': 0x10,
             'REFUSE_PASSWORD_CHANGE': 0x20}

# Domain trust flags
# From: https://msdn.microsoft.com/en-us/library/cc223779.aspx
trust_flags = {'NON_TRANSITIVE': 0x00000001,
               'UPLEVEL_ONLY': 0x00000002,
               'QUARANTINED_DOMAIN': 0x00000004,
               'FOREST_TRANSITIVE': 0x00000008,
               'CROSS_ORGANIZATION': 0x00000010,
               'WITHIN_FOREST': 0x00000020,
               'TREAT_AS_EXTERNAL': 0x00000040,
               'USES_RC4_ENCRYPTION': 0x00000080,
               'CROSS_ORGANIZATION_NO_TGT_DELEGATION': 0x00000200,
               'PIM_TRUST': 0x00000400}

# Domain trust direction
# From: https://msdn.microsoft.com/en-us/library/cc223768.aspx
trust_directions = {'INBOUND': 0x01,
                    'OUTBOUND': 0x02,
                    'BIDIRECTIONAL': 0x03}
# Domain trust types
trust_type = {'DOWNLEVEL': 0x01,
              'UPLEVEL': 0x02,
              'MIT': 0x03}

# Common attribute pretty translations
attr_translations = {'sAMAccountName': 'SAM Name',
                     'cn': 'CN',
                     'operatingSystem': 'Operating System',
                     'operatingSystemServicePack': 'Service Pack',
                     'operatingSystemVersion': 'OS Version',
                     'userAccountControl': 'Flags',
                     'objectSid': 'SID',
                     'memberOf': 'Member of groups',
                     'primaryGroupId': 'Primary group',
                     'dNSHostName': 'DNS Hostname',
                     'whenCreated': 'Created on',
                     'whenChanged': 'Changed on',
                     'IPv4': 'IPv4 Address',
                     'lockOutObservationWindow': 'Lockout time window',
                     'lockoutDuration': 'Lockout Duration',
                     'lockoutThreshold': 'Lockout Threshold',
                     'maxPwdAge': 'Max password age',
                     'minPwdAge': 'Min password age',
                     'minPwdLength': 'Min password length',
                     'pwdHistoryLength': 'Password history length',
                     'pwdProperties': 'Password properties',
                     'ms-DS-MachineAccountQuota': 'Machine Account Quota',
                     'flatName': 'NETBIOS Domain name'}

MINIMAL_COMPUTERATTRIBUTES = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemServicePack',
                              'operatingSystemVersion', 'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid',
                              'description', 'objectClass']
MINIMAL_USERATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId', 'whenCreated', 'whenChanged',
                          'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'objectClass']
MINIMAL_GROUPATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'description', 'whenCreated', 'whenChanged',
                           'objectSid', 'distinguishedName', 'objectClass']

CUST_COMPUTERATTRIBUTES = ['name', 'OperatingSystem', 'extensionAttribute2',
                           'description', 'extensionAttribute1', 'extensionAttribute3',
                           'extensionAttribute4', 'extensionAttribute5', 'extensionAttribute6']

PAGE_SIZE = 1000

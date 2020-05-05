from __future__ import unicode_literals

import argparse
import getpass
import time

from future.utils import native_str
from ldap3 import Server, Connection, ALL, NTLM

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

from ldapdomaindump.ldap.dumper import *


def main():
    t0 = time.time()
    setup_logger()
    parser = argparse.ArgumentParser(
        description='Domain information dumper via LDAP. '
                    'Dumps users/computers/groups and OS/membership information to HTML/JSON/greppable output.')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    # Main parameters
    # maingroup = parser.add_argument_group("Main options")
    parser.add_argument("host", type=str, metavar='HOSTNAME',
                        help="Hostname/ip or ldap://host:port connection string to connect to (use ldaps:// to use SSL)")
    parser.add_argument("-u", "--user", type=native_str, metavar='USERNAME',
                        help="DOMAIN\\username for authentication, leave empty for anonymous authentication")
    parser.add_argument("-p", "--password", type=native_str, metavar='PASSWORD',
                        help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("-at", "--authtype", type=str, choices=['NTLM', 'SIMPLE'], default='NTLM',
                        help="Authentication type (NTLM or SIMPLE, default: NTLM)")

    # Output parameters
    outputgroup = parser.add_argument_group("Output options")
    outputgroup.add_argument("-o", "--outdir", type=str, metavar='DIRECTORY',
                             help="Directory in which the dump will be saved (default: current)")
    outputgroup.add_argument("--no-html", action='store_true', help="Disable HTML output")
    outputgroup.add_argument("--no-json", action='store_true', help="Disable JSON output")
    outputgroup.add_argument("--no-grep", action='store_true', help="Disable Greppable output")
    outputgroup.add_argument("--grouped-json", action='store_true', default=False,
                             help="Also write json files for grouped files (default: disabled)")
    outputgroup.add_argument("-d", "--delimiter", help="Field delimiter for greppable output (default: tab)")

    # Additional options
    miscgroup = parser.add_argument_group("Misc options")
    miscgroup.add_argument("-r", "--resolve", action='store_true',
                           help="Resolve computer hostnames "
                                "(might take a while and cause high traffic on large networks)")
    miscgroup.add_argument("-n", "--dns-server",
                           help="Use custom DNS resolver instead of system DNS (try a domain controller IP)")
    miscgroup.add_argument("-m", "--minimal", action='store_true', default=False,
                           help="Only query minimal set of attributes to limit memmory usage")

    args = parser.parse_args()
    # Create default config
    cnf = DomainDumpConfig()
    # Dns lookups?
    if args.resolve:
        cnf.lookuphostnames = True
    # Custom dns server?
    if args.dns_server is not None:
        cnf.dnsserver = args.dns_server
    # Minimal attributes?
    if args.minimal:
        cnf.minimal = True
    # Custom separator?
    if args.delimiter is not None:
        cnf.grepsplitchar = args.delimiter
    # Disable html?
    if args.no_html:
        cnf.outputhtml = False
    # Disable json?
    if args.no_json:
        cnf.outputjson = False
    # Disable grep?
    if args.no_grep:
        cnf.outputgrep = False
    # Custom outdir?
    if args.outdir is not None:
        cnf.basepath = args.outdir
    # Do we really need grouped json files?
    cnf.groupedjson = args.grouped_json

    # Prompt for password if not set
    authentication = None
    if args.user is not None:
        if args.authtype == 'SIMPLE':
            authentication = 'SIMPLE'
        else:
            authentication = NTLM
        if not '\\' in args.user:
            logging.warning('Username must include a domain, use: DOMAIN\\username')
            sys.exit(1)
        if args.password is None:
            args.password = getpass.getpass()
    else:
        logging.warning(
            'Connecting as anonymous user, dumping will probably fail. '
            'Consider specifying a username/password to login with')

    try:
        logging.info('Running : `%s` request from cmd', args.host)
        # define the server and the connection
        s = Server(args.host, get_info=ALL)
        logging.info('Connecting to host...')

        c = Connection(s, user=args.user, password=args.password, authentication=authentication)
        logging.info('Binding to host')
        # perform the Bind operation
        if not c.bind():
            logging.warning('Could not bind with specified credentials')
            logging.warning(c.result)
            sys.exit(1)
        logging.info('Bind OK')
        logging.info('Starting domain dump')
        # Create domaindumper object
        dd = DomainDumper(s, c, cnf)

        # Do the actual dumping
        dd.dump_computers()
    except Exception as e:
        logging.error("Fatal error in main loop", exc_info=True)
        # logging.error("Unexpected error:({0})".format(e))
        sys.exit(13)
    finally:
        t1 = time.time()
        total_time = t1 - t0
        logging.info("Total time taken: " + str(total_time) + " Seconds")

    logging.info('Domain dump finished')

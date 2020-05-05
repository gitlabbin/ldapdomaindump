import os
from codecs import open
from os import path

from setuptools import Command
from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    all_reqs = f.read().split('\n')

install_requires = [x.strip() for x in all_reqs if 'git+' not in x]
dependency_links = [x.strip().replace('git+', '') for x in all_reqs if x.startswith('git+')]


class CleanCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        os.system('rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')


setup(
    name='ldapdomaindump',
    version='0.9.2',
    description='Active Directory information dumper via LDAP',
    author='Dirk-jan Mollema',
    author_email='dirkjan@sanoweb.nl',
    url='https://github.com/dirkjanm/ldapdomaindump/',
    packages=find_packages(exclude=['docs', 'tests*']),
    install_requires=install_requires,
    dependency_links=dependency_links,
    package_data={'ldapdomaindump': ['style.css']},
    include_package_data=True,
    cmdclass={
        'clean': CleanCommand,
    },
    scripts=['bin/ldapdomaindump', 'bin/ldd2bloodhound', 'bin/ldd2pretty']
)

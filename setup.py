from setuptools import setup
from setuptools import find_packages

version = '0.1.8'

install_requires = [
    'acme',
    'certbot>=0.7.0',
    'pem',
    'requests>=2.11.1',
    'zope.interface',
]

setup(
    name='certbot-asa',
    version=version,
    description="Cisco ASA plugin for Let's Encrypt client",
    url='https://github.com/chrismarget/certbot-asa',
    author="Chris Marget",
    author_email='certbot-asa@marget.com',
    license='Apache License 2.0',
    install_requires=install_requires,
    packages=find_packages(),
    entry_points={
        'certbot.plugins': [
            'asa = certbot_asa.configurator:AsaConfigurator',
        ],
    },
)

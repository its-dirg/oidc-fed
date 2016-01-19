#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='oidc-fed',
    version='0.0.1',
    description='Example implementation of model for OpenID Connect federations.',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='Apache 2.0',
    url='https://github.com/its-dirg/oidc-fed',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    install_requires=[
        "oic",
        "typing"
    ],
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
    ]
)

#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='oidc-fed',
    version='0.0.1',
    description='Example implementation of model for OpenID Connect federations.',
    author='Rebecka Gulliksson',
    author_email='rebecka.gulliksson@its.umu.se',
    license='Apache 2.0',
    url='https://github.com/its-dirg/oidc-fed',
    packages=find_packages('src/', exclude=['services*']),
    package_dir={'': 'src'},
    install_requires=[
        'oic==0.8.3',
    ],
    zip_safe=False,
    classifiers=[
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ]
)

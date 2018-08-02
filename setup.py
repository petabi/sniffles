#!/usr/bin/env python
from glob import glob

from setuptools import Extension, find_packages, setup

setup(
    name='sniffles',
    version='3.4.1',
    description='Sniffles pcap generator',
    long_description='Packet capture generator for IDS evaluation',
    maintainer='Victor C. Valgenti',
    maintainer_email='vvalgenti@petabi.com',
    url='https://github.com/petabi/sniffles',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    entry_points={
        'console_scripts': [
            'sniffles = sniffles.sniffles:main',
            'rulegen = sniffles.rand_rule_gen:main',
            'regexgen = sniffles.regex_generator:main'
        ],
        'gui_scripts': [
        ],
    },
    data_files=[
        ('share/doc/sniffles', ['README.md', 'LICENSE']),
        ('share/examples/sniffles',
         ['examples/example1.xml',
          'examples/example2.xml',
          'examples/hdr_features_complex.txt',
          'examples/hdr_features_simple.txt',
          'examples/mac_definition_file.txt',
          'examples/re_features_complex.txt',
          'examples/re_features_simple.txt',
          'examples/sniffles_example_config.txt']),
    ],
    ext_modules=[
        Extension(
            'sniffles.pcrecomp',
            sources=glob('src/sniffles/*.c'),
            depends=glob('src/sniffles/*.h'),
            extra_compile_args=[
                '-DLINK_SIZE=2',
                '-DPARENS_NEST_LIMIT=250',
                '-DNEWLINE=10',
                '-DMAX_NAME_COUNT=10000',
                '-DMAX_NAME_SIZE=32'])],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    install_requires=[
        'sortedcontainers',
    ],
)

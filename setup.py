#!/usr/bin/env python

from setuptools import find_packages, setup, Extension

setup(name='sniffles',
      version='3.1.0',
      description='Sniffles pcap generator',
      long_descrip0tion='Packet capture generator for IDS evaluation',
      maintainer='Victor C. Valgenti',
      maintainer_email='vvalgenti@petabi.com',
      url='http://petabi.com',
      packages=find_packages(),
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
      ext_modules=[Extension('sniffles.pcrecomp',
                             sources=['sniffles/pcrecomp.c',
                                      'sniffles/pcre_chartables.c',
                                      'sniffles/pcre_compile.c',
                                      'sniffles/pcre_globals.c',
                                      'sniffles/pcre_newline.c',
                                      'sniffles/pcre_tables.c'],
                             depends=['sniffles/pcre_internal.h',
                                      'sniffles/ucp.h',
                                      'sniffles/pcre.h'],
                             extra_compile_args=['-DLINK_SIZE=2',
                                                 '-DPARENS_NEST_LIMIT=250',
                                                 '-DNEWLINE=10',
                                                 '-DMAX_NAME_COUNT=10000',
                                                 '-DMAX_NAME_SIZE=32'])]
      )

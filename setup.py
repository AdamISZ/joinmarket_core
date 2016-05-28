from setuptools import setup

setup(name='joinmarket_core',
      version='0.1',
      description='Joinmarket library for Bitcoin coinjoins',
      url='http://github.com/Joinmarket-Org/joinmarket',
      #author='Flying Circus',
      #author_email='flyingcircus@example.com',
      license='GPL',
      packages=['joinmarket_core'],
      install_requires=['libnacl',],
      zip_safe=False)
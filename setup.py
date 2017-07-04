# setup.py
from distutils.core import setup
import py2exe

import sys
sys.setrecursionlimit(1000000)

setup(console=["GEIP.py"],
      data_files=[("GeoLite2-City_20170404",
                   ["GeoLite2-City_20170404\GeoLite2-City.mmdb"])]
)
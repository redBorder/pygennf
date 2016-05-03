from setuptools import setup


setup(name="pygennf",
      version="0.1",
      description="UDP packets producer with scapy",
      author="Ana Rey",
      author_email="anarey@redborder.com",
      url="https://github.com/redBorder/",
      license="AGPL",
      scripts=["src/one-packet/pygennf_v9.py"],
      packages=['rb_netflow'],
      requires=[
          'scapy',
      ]
) 

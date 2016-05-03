from setuptools import setup

setup(name="pygennf",
      version="0.1",
      description="UDP packets producer with scapy",
      author="Ana Rey",
      author_email="anarey@redborder.com",
      url="https://github.com/redBorder/",
      license="AGPL",
      scripts=["src/pygennf_v5.py", "src/pygennf_v9.py", "src/pygennf_v10.py" ],
      packages=['rb_netflow'],
      requires=[
          'scapy',
      ]
) 

from setuptools import setup

setup(name="pygennf",
      version="0.1",
      description="UDP packets producer with scapy",
      author="Ana Rey",
      author_email="anarey@redborder.com",
      url="https://github.com/redBorder/",
      license="AGPL",
      scripts=["main_nf9.py", "main_nf10.py", "main_nf5.py" ],
      packages=['rb_netflow'],
      install_requires=[
          'scapy',
      ]
) 

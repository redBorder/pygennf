# pygennf

Netflow packets generator with Scape library

* Download it! [https://github.com/redBorder/pygennf/tree/master/download]

 > rpm: (python2.6) wget https://github.com/redBorder/pygennf/raw/master/download/pygennf-0.1-1.noarch.rpm
 
 > tar.gz: wget https://github.com/redBorder/pygennf/raw/master/download/pygennf-0.1.tar.gz

* How to install:
python setup.py install

* How to install the rpm packege:
rpm -vUh pygennf-0.1-1.noarch.rpm    

# Usage (without installation):

 * You need to install the scapy library:
 pip install scapy

 * python ./pygennf_v5.py --help

> usage: pygennf_v5.py [-h] [-s SRC_IP] [-sp SRC_PORT] [-d DST_IP]
>                      [-dp DST_PORT] [-t TIME_INTERVAL]
> 
> UDP packets producer with scapy
> 
> optional arguments:
>  -h, --help            show this help message and exit

>  -s SRC_IP, --source-ip SRC_IP
>                        IP source

>  -sp SRC_PORT, --source-port SRC_PORT
>                        Port dst

>  -d DST_IP, --dst-ip DST_IP
>                        IP source

>  -dp DST_PORT, --dst-port DST_PORT
>                        Port dst

>  -t TIME_INTERVAL, --time-interval TIME_INTERVAL
                        Time interval to wait to send other messages.

# Example of use:

 * Netflow 5:
> sudo python src/pygennf_v5.py -s 10.0.203.2 -d 10.0.30.89 -t 2
 * Netflow 9:
> sudo python src/pygennf_v9.py -s 10.0.203.2 -d 10.0.30.89 -t 2
 * Netflow 10:
> sudo python src/pygennf_v10.py -s 10.0.203.2 -d 10.0.30.89 -t 2


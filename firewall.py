#!/bin/env python
from piptables import *

#Define our internal subnets
SUBNETS = ["172.16.10.0/24", "172.17.10.0/24", "172.19.10.0/24"]
#Define some services
SERVICES = {"SSH": "22", "SMTP": "25", "HTTP": "80", "MYSQL": "3306"}
#Print Mode

#Flush the chains and tables
flush("tables")
flush("chains")

#Set the default policies
setpol(("INPUT", "DROP"))
setpol(("OUTPUT", "ACCEPT"))
setpol(("FORWARD", "DROP"))

#Allow Loopback
setrule({"chain": "input", "interface": ("in", "lo"), "action": "accept"})
setrule({"chain": "output", "interface": ("out", "lo"), "action": "accept"})

#Allow everything on local subnets
for subnet in SUBNETS:
    setrule({"chain": "input", "interface": ("in", "eth0"), "subnet": subnet,
             "action": "accept", "state": ["new", "related", "established"]})
    setrule({"chain": "output", "interface": ("out", "eth0"), "subnet": subnet,
             "action": "accept", "state": ["new", "related", "established"]})

#Allow everything coming from estores
setrule({"chain": "input", "interface": ("in", "eth0"), "action": "accept",
         "subnet": "69.10.153.3", "state": ["new", "established", "related"]})

#Allow ICMP
setrule({"chain": "input", "interface": ("in", "eth0"), "action": "accept",
         "state": ["new", "related", "established"], "icmp": "8"})

#Allow all ESTABLISHED, RELATED connections going out
setrule({"chain": "output", "interface": ("out", "eth0"),
         "state": ["established", "related"], "action": "accept"})


#Allow all HTTP connections going in in
setrule({"chain": "input", "interface": ("in", "eth0"), "dst-port": "80",
         "state": ["new", "established", "related"], "action": "accept"})

#Drop all NEW connections coming in
setrule({"chain": "input", "interface": ("in", "eth0"), "state": ["new"], "action": "drop"})

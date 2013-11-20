##############################
# AN EXAMPLE FIREWALL SCRIPT #
##############################
from blacksalt import BlackSalt
iptables = BlackSalt()
# When creating a BlackSalt instance you can pass in a dictionary
# of arguments, the allowed arguments are:
#   {
#       "iptables": "BIN LOCATION HERE", // This defaults to /sbin/iptables
#       "printmode": True or False,      // This defaults to True and will print the rules
#                                        // to stdout when generating the tables.
#       "scriptfile": "Name and location of file" // If set, generating rule will output
#                                                 // to this file
#   }
# These can be set after creation, by just setting the variables i.e.
# iptables.printmode = False
# iptables.scriptfile = "/usr/local/scripts/firewall"
# iptables.iptables = "/usr/local/bin/iptables"
#


SUBNETS = ["172.16.10.0/24", "172.17.10.0/24", "172.19.10.0/24"]
SERVICES = {"SSH": "22", "SMTP": "25", "HTTP": "80", "MYSQL": "3306"}
# Flush tables
iptables.flush()
# Set default policies
iptables.policy([("input", "drop"), ("output", "accept"), ("forward", "drop")])
# Allow everything on loop back interface
iptables.setrule({"chain": "input", "interface": ("in", "lo"), "action": "accept"})
iptables.setrule({"chain": "output", "interface": ("out", "lo"), "action": "accept"})

# Allow everything on local subnets
for subnet in SUBNETS:
    iptables.setrule({"chain": "input", "interface": ("in", "eth0"), "subnet": subnet,
             "action": "accept", "state": ["new", "related", "established"]})
    iptables.setrule({"chain": "output", "interface": ("out", "eth0"), "subnet": subnet,
             "action": "accept", "state": ["new", "related", "established"]})

# Allow everything coming from estores
iptables.setrule({"chain": "input", "interface": ("in", "eth0"), "action": "accept",
         "subnet": "69.10.153.3", "state": ["new", "established", "related"]})

# Allow ICMP Ping
iptables.setrule({"chain": "input", "interface": ("in", "eth0"), "action": "accept",
         "state": ["new", "related", "established"], "icmp": "8"})

# Allow all ESTABLISHED, RELATED connections going out
iptables.setrule({"chain": "output", "interface": ("out", "eth0"),
         "state": ["established", "related"], "action": "accept"})

# Allow all HTTP connections going in in
iptables.setrule({"chain": "input", "interface": ("in", "eth0"), "dst-port": "80",
         "state": ["new", "established", "related"], "action": "accept"})

# Drop all NEW connections coming in
iptables.setrule({"chain": "input", "interface": ("in", "eth0"), "state": ["new"], "action": "drop"})

# Generate the script
iptables.generate()

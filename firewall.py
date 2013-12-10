##############################
# AN EXAMPLE FIREWALL SCRIPT #
##############################
from blacksalt import BlackSalt
iptables = BlackSalt()
# When creating a BlackSalt instance you can pass in keyword arguments
# of arguments, the allowed arguments are:
#       iptables = "BIN LOCATION HERE" # This defaults to /sbin/iptables
#       printmode = True or False     # This defaults to True and will print the rules
#                                      # to stdout when generating the tables.
#       scriptfile = "Name and location of file"  #If set, generating rule will output
#                                                 # to this file
# These can be set after creation, by just setting the variables i.e.
# iptables.printmode = False
# iptables.scriptfile = "/usr/local/scripts/firewall"
# iptables.iptables = "/usr/local/bin/iptables"


SUBNETS = ["192.168.10.0/24", "192.168.11.0/24", "192.168.12.0/24"]
SERVICES = {"SSH": "22", "SMTP": "25", "HTTP": "80", "MYSQL": "3306"}

# Here we'll add connection tracking and ftp connection tracking, they
# can be added anywhere in a blacksalt script, they will always appear
# at the top.
iptables.setmodule(["ip_conntrack", "ip_conntrack_ftp"])
# Flush tables
iptables.flush()
# Set default policies
iptables.policy([("input", "drop"), ("output", "accept"), ("forward", "drop")])
# Allow everything on loop back interface
iptables.setrule(chain="input", interface={"name": "lo", "direction": "in"}, target="accept")
iptables.setrule(chain="output", interface={"name": "lo", "direction": "out"}, target="accept")

# Allow everything on local subnets
for subnet in SUBNETS:
    iptables.setrule(chain="input", interface={"direction": "in", "name": "eth0"}, subnet=subnet,
                     target="accept", state="new, related, established")
    iptables.setrule(chain="output", interface={"direction": "out", "name": "eth0"}, subnet=subnet,
                     target="accept", state="new, related, established")

# Allow ICMP Ping
iptables.setrule(chain="input", interface={"direction": "in", "name": "eth0"}, target="accept",
                 state="new, related, established", icmp=8)

# Allow all ESTABLISHED, RELATED connections going out
iptables.setrule(chain="output", interface={"direction": "out", "name": "eth0"},
                 state="established, related", target="accept")

# Allow all HTTP connections going in in
iptables.setrule(chain="input", interface={"direction": "in", "name": "eth0"}, dst="80",
                 state="new, established, related", target="accept")

# Drop all NEW connections coming in
iptables.setrule(chain="input", interface={"direction": "in", "name": "eth0"}, state="new", target="drop")

# Generate the script, but first disable outputting to the console, and save it in a scriptfile
iptables.printmode = False
iptables.scriptfile = "firewall.sh"
iptables.generate()

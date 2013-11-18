#!/bin/env python
#	PIPTABLES
#	Author: 	Leslie.A.Cordell
#	CreationDate:	2013/11/14
#	ModifiedDate:	2013/11/14
#
# This little helper library will allow the user to create easier, and
# fairly simple iptables rules, if PRINTMODE is set to true, it will
# only print the rules, not run them, it is set to true by default
# 	The IPTABLES variable is set by default to "/sbin/iptables"
#

import subprocess
import shlex

PRINTMODE = True
IPTABLES = "/sbin/iptables"


############
# SET RULE #
############
def setrule(opts):
    """
    This will take in a dictionary with options, construct and run an
    IPTables command.
    Available options are:
        {
            "interface": TUPLE ("interface STRING", "in/out"),
            "port-type": STRING,
            "dst-port": STRING/INT,
            "src-port": STRING/INT,
            "subnet": STRING,
            "state": LIST, #Loads (-m state) module, accepts list like ["new", "established", "related"]#
            "chain": STRING, #INPUT, OUTPUT, FORWARD
            "icmp": STRING/INT # (will automatically set port type to ICMP) #
            "action": STRING # ACCEPT, DROP, QUEUE, RETURN
            }
    """
    if type(opts) == dict:
        # SET SOME CONSTANTS #
        _ICMP = "icmp" in opts and opts["icmp"]
        _CHAIN = "chain" in opts and opts["chain"]
        _INTERFACE = "interface" in opts and opts["interface"]
        _PORT_TYPE = "port-type" in opts and opts["port-type"]
        _DST_PORT = "dst-port" in opts and opts["dst-port"]
        _SRC_PORT = "src-port" in opts and opts["src-port"]
        _BOTHPORTS = _DST_PORT and _SRC_PORT
        _VALIDPORTS = not _BOTHPORTS and _PORT_TYPE
        _SUBNET = "subnet" in opts and opts["subnet"]
        _STATE = "state" in opts and opts["state"]
        _ACTION = "action" in opts and opts["action"]

        #####################################
        # CATCH SOME ERRORS OR MODIFICATIONS#
        #####################################
        # If we get ICMP, set port-type to icmp
        if _ICMP:
            opts["port-type"] = "icmp"
            _PORT_TYPE = True
            # If we get both dst-port and src-port, then return an error
        if _BOTHPORTS:
            return displayresults("Error; both destination and source ports provided")
            # If we get a src-port and a dst-port with icmp, then return an error
        if (_DST_PORT or _SRC_PORT) and _ICMP:
            return displayresults("Error; You can't use the icmp option with dst-port or src-port options")
            # If we get a src-port and a dst-port, but not a port type, set the default port-type to tcp
        if (_DST_PORT or _SRC_PORT) and not _PORT_TYPE:
            opts["port-type"] = "tcp"
            _PORT_TYPE = True
            # If we now dont have both ports, set valid ports to true
            if not _BOTHPORTS:
                _VALIDPORTS = True
            # We need an action, return an error if we don't get one
        if not _ACTION:
            # Return an error if we get both source and destination ports
            return displayresults("Error; an action option is required; accept, drop, queue, return")
            # We need a chain, return an error if we don't get one
        if not _CHAIN:
            # Return an error if we get both source and destination ports
            return displayresults("Error; a chain option is required; INPUT, OUTPUT, FORWARD")
            # If our chain is INPUT, then set our interface to in
        if opts["chain"].lower() == "input":
            if _INTERFACE:
                # Set to -i if interface is tuple and chain is input
                if type(opts["interface"]) == tuple:
                    opts["interface"] = ("in", opts["interface"][1])
            # If our chain is OUTPUT, then set our interface to out
        if opts["chain"].lower() == "output":
            if _INTERFACE:
            # Set to -o if interface is tuple and chain is output
                if type(opts["interface"]) == tuple:
                    opts["interface"] = ("out", opts["interface"][1])

        # Begin IPTables rule with Append
        cmd = "%s -A" % IPTABLES

        ###########
        #SET CHAIN#
        ###########
        # Set chain INPUT, OUTPUT, FORWARD
        if _CHAIN:
            # Chain must be a string
            if type(opts["chain"]) == str:
                cmd = "%s %s" % (cmd, opts["chain"].upper())
            else:
                return displayresults("Chain must be a string")
        # Return an error if we don't get a policy
        else:
            return displayresults("Must specify a chain; INPUT, OUTPUT, FORWARD etc")

        ###############
        #SET INTERFACE#
        ###############
        # Set interface if we get one
        if _INTERFACE:
            if type(opts["interface"]) == tuple:  # Options must be a tuple
                # If it's input, set the -i option
                if opts["interface"][0] == "in":
                    cmd = "%s -i %s" % (cmd, opts["interface"][1])
                # If it's output, set the -i option
                elif opts["interface"][0] == "out":
                    cmd = "%s -o %s" % (cmd, opts["interface"][1])
                # If it's not a correct option, display an error
                else:
                    return displayresults(
                        "Interface must be a tuple with option in or out as first part i.e. ('in', 'eth0')")
            # If it's not a tuple, display an error
            else:
                return displayresults(
                    "Interface must be a tuple with option in or out as first part i.e. ('in', 'eth0')")

            ###############
            #SET PORT TYPE#
            ###############
            # Set port type if we have one
            if _PORT_TYPE:
                # Port type must be a string
                if type(opts["port-type"]) == str:
                    # Must be a valid option; tcp, udp, icmp, all
                    if opts["port-type"] in ["tcp", "udp", "icmp", "all"]:
                        cmd = "%s -p %s" % (cmd, opts["port-type"])
                    else:
                        return displayresults(
                            "Invalid port-type '%s'; must be tcp, udp, icmp or all" % (opts["port-type"]))
                # It it's not a string, display an error
                else:
                    return displayresults("Option port-type must be a string with option; tcp, udp, icmp or all")

        #####################
        # SET DST/SRC PORTS #
        #####################
        if _VALIDPORTS:
            # Port choice must be a string
            try:
                if _SRC_PORT and type(int(opts["src-port"])) == int:
                    cmd = "%s --sport %s" % (cmd, opts["src-port"])
                elif _DST_PORT and type(int(opts["dst-port"])) == int:
                    cmd = "%s --dport %s" % (cmd, opts["dst-port"])
                else:
                    return displayresults("Error with port choice")
            # If the string can't convert to an integer, throw an error
            except ValueError:
                return displayresults("Port choice should be a valid integer or integer string")

        #################
        # SET ICMP PORT #
        #################
        if _ICMP:
            if type(int(opts["icmp"])) == int:
                cmd = "%s --icmp-type %s" % (cmd, opts["icmp"])
            # If our icmp option doesn't convert to an integer, throw an error
            else:
                return displayresults("Invalid ICMP type; must be a valid integer or integer string")

        ##############
        # SET SUBNET #
        ##############
        if _SUBNET:
            # Subnet must be a string
            if type(opts["subnet"]) == str:
                cmd = "%s -s %s" % (cmd, opts["subnet"])
            # If it's not a string, display an error
            else:
                return displayresults("Subnet should be a valid subnet string, please refer to iptables(8) man page")

        #############
        # SET STATE #
        #############
        if _STATE:
            # State must be a list
            if type(opts["state"]) == list:
                # Loop our states, use a counter
                validstate = 0
                for idx, state in enumerate(opts["state"]):
                    # If it's a valid state, then set it to upper case
                    if state.lower() in ["new", "established", "related", "invalid"]:
                        opts["state"][idx] = state.upper()
                        # Add one to our validstate counter
                        validstate += 1
                    # If our valid state counter matches the length of our list, add the state string
                if validstate == len(opts["state"]):
                    cmd = "%s -m state --state %s" % (cmd, ",".join(opts["state"]))
                # Otherwise, report an error
                else:
                    return displayresults("Invalid option in state list")

            # If it's not a list, display an error
            else:
                return displayresults("""State option must be a list of valid states i.e.
                                        ['new', 'established', 'related', 'invalid']""")

        ##############
        # SET ACTION #
        ##############
        if _ACTION:
            if type(opts["action"]) == str:
                # If we get a valid option, then set it to uppercase and append it to our command
                if opts["action"].lower() in ["accept", "drop", "queue", "return"]:
                    cmd = "%s -j %s" % (cmd, opts["action"].upper())
                else:
                    return displayresults("Invalid action option; must be accept, drop, queue, return")

            # If it's not a string, display an error
            else:
                return displayresults("Action option must be a string")

        if not PRINTMODE:
            return displayresults(runcmd(cmd))

        # If we're in print mode, return silently and print the command
        print cmd
        return


###################
# Display Results #
###################
def displayresults(res):
    """
    Take in the results object, display any messages if there are any.
    """
    # If we get a dictionary, then print the lines
    if type(res) == dict:
        if res["res"] and res["res"][0]:
            for line in res["res"]:
                print line
        if res["err"]:
            print "Aborted..."
            exit(1)

    # If we get a string, it means there was an error in the command itself,
    # display the error and quit
    if type(res) == str:
        print "Error: %s" % res
        exit(1)


################
# SET POLICIES #
################
def setpol(opts):
    """
    Set default policies. Take in a tuple;
    ("INPUT", "DROP"), this will set the policy
    """
    # If we get a dictionary of options, proceed
    if type(opts) == tuple:
        # Loop our keys, construct our command
        cmd = "%s -P %s %s" % (IPTABLES, opts[0], opts[1])
        if not PRINTMODE:
            return displayresults(runcmd("%s -P %s %s" % (IPTABLES, opts[0].upper(), opts[1].upper())))

        # If we're in print mode, return silently and print the command
        print cmd
        return

    # Return an error if we don't get a tuple
    else:
        return displayresults("Tuple of arguments needed")


#########
# FLUSH	#
#########	
def flush(opt):
    """
    Take in a string; chains or tables, it will flush it
    """
    # If we get a list of options, proceed
    if type(opt) == str:
        # If 'chains' is in the list
        if opt.lower() == "chains":
            # Flush the chains; return the results dict
            cmd = "%s -X" % IPTABLES
            if not PRINTMODE:
                return displayresults(runcmd(cmd))

            # If we're in print mode, just print the command((
            print cmd
            return

        # If 'table' is in the list
        if opt.lower() == "tables":
            # Run the command and return the results object
            # Flush the chains; return the results dict
            cmd = "%s -F" % IPTABLES
            if not PRINTMODE:
                return displayresults(runcmd("%s -F" % IPTABLES))

            # If we're in print mode, just print the command((
            print cmd
            return

        # Otherwise return invalid option message
        return displayresults("Invalid Option")

    else:
        return displayresults("Must be a string; chains or tables as option")


###############
# RUN COMMAND #
###############
def runcmd(cmd):
    """
    Split a string into a command or accept a list of commands.
    This will shell it out
    """
    if type(cmd) == str:
        cmd = shlex.split(cmd)

    if type(cmd) == list:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        return {"res": proc.communicate()[0].split("\n"),
                "err": proc.returncode}


if __name__ == "__main__":
    pass

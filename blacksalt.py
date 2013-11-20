#	BLACKSALT
#	Author: 	Leslie.A.Cordell
#	CreationDate:	2013/11/18
#	ModifiedDate:	2013/11/18
#
# This little helper library will allow the user to create easier
# iptables rules, it will also allow IPTables management
# when run, including showing running IPTables rules and easy modification
# of running rules etc. Rules can range from simple to complex.
import os
__version__ = "0.2.0"


class BlackSalt():
    """
    This is the main class, whenever blacksalt is to be run, this class is
    imported; rules can be added, viewed, modified, etc. When using this
    with another script, it can be scripted as an easier form of an ITTables
    script, running it can export the rules to a new file.
    """

    ##############
    # INITIALIZE #
    ##############
    def __init__(self, params=None):
        """
        Initialisation; The parameters will be in the form of a dictionary,
        if certain parameters aren't passed we'll set default parameters
        """
        #  If our params are a dictionary, set true
        self.rules = []
        self.rule = ""
        self.printmode = True  # Default printmode to true unless set otherwise
        self.iptables = "/sbin/iptables"  # Default iptables bin to /sbin/iptables
        self.scriptfile = False
        # Create some aliases
        self.show = self.display = self.preview
        self.last = self.lastrule
        self.delete = self.rm = self.remove
        self.create = self.generate
        self.setpol = self.pol = self.policy
        if type(params) == dict:
            # If we have an iptables parameter store it as our IPTABLES bin location
            if "iptables" in params:
                self.iptables = params["iptables"]
            # Always default to true for printmode, unless we have a false parameter
            if "printmode" in params:
                self.printmode = params["printmode"]
            # If we get a scriptfile parameter, we'll write our firewall output to here
            # for the user.
            if "scriptfile" in params:
                self.scriptfile = params["scriptfile"]

    # Change default print
    def __repr__(self):
        _ruleslen = len(self.rules)
        if _ruleslen == 1:
            return str("<BlackSalt v%s: 1 rule defined>" % __version__)
        else:
            return str("<BlackSalt v%s: %s rules defined>" % (__version__, _ruleslen))

    #########
    # FLUSH #
    #########
    def flush(self, opt=None):
        """
        This will flush tables and chains; depending on what is provided.
        With no arguments, both tables and chains will flush; passing a
        string will flush the tables or chains depending i.e. tables will
        flush tables, chains will flush chains. Passing in a list will flush
        the chain names in the list.
        """
        # If we get a list of options, proceed
        if type(opt) == str:
            # If 'chains' is in the list
            if opt.lower() == "chains":
                # Flush the chains
                self.rule = "%s -X" % self.iptables
                self.rules.append(self.rule)
                return

            # If 'tables' is in the list
            if opt.lower() == "tables":
                # Flush the chains
                self.rule = "%s -F" % self.iptables
                self.rules.append(self.rule)
                return
            # Otherwise, flush the string as a chain name
            else:
                self.rule = "%s -X %s" % (self.iptables, opt)
                self.rules.append(self.rule)
                return

        # If we get a list, then we'll check the list for strings and add these as chains to flush
        elif type(opt) == list:
            for _rule in opt:
                # If the rule is a string, add it
                if type(_rule) == str:
                    self.flush(_rule)

        # If we get no options, then we will flush all chains and tables
        elif opt is None:
            # Flush the chains
            self.rule = "%s -F" % self.iptables
            self.rules.append(self.rule)
            self.rule = "%s -X" % self.iptables
            self.rules.append(self.rule)
            return

        else:
            print "Parameter must be a string or list. i.e 'chains' or 'tables' will flush these."
            print "A string that is not 'chains' or 'tables' will be treated as a specific chain to flush."
            print "A list of strings will create rules to flush these as chains individually or if"
            print "'tables' or 'chains' are included in this list, they will be flushed also."

    ###########
    #LAST RULE#
    ###########
    def lastrule(self):
        """
        Simply return the last command if there is one, or a message
        Aliases for this function: last()
        """
        print self.rule or "No rules have been set yet"

    ################
    #GENERATE RULES#
    ################
    def generate(self):
        """
        Output the rules, if we have scriptfile set up in the
        instance variables, try to open and output the
        rules to the files. If printmode is true, print to
        stdout.
        Aliases for this function: create()
        """
        _scriptfile = False

        if self.scriptfile:
            #  If the scriptfile already exists
            if os.path.exists(self.scriptfile):
                #  Prompt to overwrite
                _option = str(raw_input("%s exists, overwrite this file? [y/n] ").lower())
                while True:
                    #  Loop until we get either a y or n
                    #  Open the scriptfile for overwriting
                    if _option == "y":
                        _scriptfile = open(self.scriptfile, "w+")
                        break
                    elif _option == "n":
                        _scriptfile = None
                        break
                    else:
                        _option = raw_input("%s exists, overwrite this file? [y/n] ")

            #  If the scriptfile doesn't already exists try to open it
            else:
                try:
                    _scriptfile = open(self.scriptfile, "w+")
                except IOError as err:
                    print "Unable to open %s; check permissions and path exists" % err.filename

            #  If we have an open script file, write our rules out to it
            if "_scriptfile" in vars() and _scriptfile and not _scriptfile.closed:
                # Loop through our rules and write them to the file
                for _rule in self.rules:
                    _scriptfile.writelines("%s\n" % _rule)
                _scriptfile.close()

        #  If printmode is on, print the rules to the screen
        if self.printmode:
            for _rule in self.rules:
                print "%s" % _rule

        else:
            print "printmode and scriptfile disabled; enable to output"

    ################
    # REMOVE RULES #
    ################
    def remove(self, arg=None):
        """
        Pass in a integer of a line number to remove, if there
        are no arguments, display the script lines with line number
        Aliases for this function: rm(), delete()
        """
        if arg:
            try:
                self.rules.pop(int(arg)-1)
            except ValueError:
                print "Not a line number"
            except IndexError:
                print "Invalid line number"

        else:
            self.preview()

    #################
    # PREVIEW RULES #
    #################
    def preview(self):
        """
        Show a preview of the current rules
        Aliases for this function: show(), display()
        """
        if len(self.rules):
            for _lineno, _rule in enumerate(self.rules):
                print "[%s] %s" % (_lineno + 1, _rule)
        else:
            print "No rules set"

    ########################
    # SET DEFAULT POLICIES #
    ########################
    def policy(self, opts, opt2=None):
        """
        An easy way to set default chain policies
        Aliases for this function: pol(), setpol()
        """
        # If we get a tuple of options, proceed
        if type(opts) == tuple:
            # Construct the command only if tuple arguments are strings
            if type(opts[0]) == str and type(opts[1]) == str:
                self.rule = "%s -P %s %s" % (self.iptables, opts[0].upper(), opts[1].upper())
                self.rules.append(self.rule)
                return
            else:
                print "Tuple values must be strings i.e. ('INPUT', 'DROP')"
        # If we get two strings as options
        elif type(opts) == str and type(opt2) == str:
            self.rule = "%s -P %s %s" % (self.iptables, opts.upper(), opt2.upper())
            self.rules.append(self.rule)
            return
        # If we get a list of tuples, loop through the list, and call policy function recursively
        elif type(opts) == list:
            for _pol in opts:
                if type(_pol) == tuple:
                    # Recursively run function with list item
                    self.policy(_pol)
        # Return an error if we don't get a tuple
        else:
            print "Tuple of string arguments needed i.e. ('INPUT', 'DROP')"
            print "Or two strings i.e. 'INPUT', 'DROP'"
            print "Or a list of tuples i.e. [('INPUT', 'DROP'), ('OUTPUT', 'ACCEPT')]"
            return

    ############
    # SET RULE #
    ############
    def setrule(self, opts):
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
                print "Error; both destination and source ports provided"
                return
                # If we get a src-port and a dst-port with icmp, then return an error
            if (_DST_PORT or _SRC_PORT) and _ICMP:
                print "Error; You can't use the icmp option with dst-port or src-port options"
                return
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
                print "Error; an action option is required; accept, drop, queue, return"
                return
                # We need a chain, return an error if we don't get one
            if not _CHAIN:
                # Return an error if we get both source and destination ports
                print "Error; a chain option is required; INPUT, OUTPUT, FORWARD"
                return
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
            _rule = "%s -A" % self.iptables

            ###########
            #SET CHAIN#
            ###########
            # Set chain INPUT, OUTPUT, FORWARD
            if _CHAIN:
                # Chain must be a string
                if type(opts["chain"]) == str:
                    _rule = "%s %s" % (_rule, opts["chain"].upper())
                else:
                    print "Chain must be a string"
                    return
            # Return an error if we don't get a policy
            else:
                print "Must specify a chain; INPUT, OUTPUT, FORWARD etc"
                return

            ###############
            #SET INTERFACE#
            ###############
            # Set interface if we get one
            if _INTERFACE:
                if type(opts["interface"]) == tuple:  # Options must be a tuple
                    # If it's input, set the -i option
                    if opts["interface"][0] == "in":
                        _rule = "%s -i %s" % (_rule, opts["interface"][1])
                    # If it's output, set the -i option
                    elif opts["interface"][0] == "out":
                        _rule = "%s -o %s" % (_rule, opts["interface"][1])
                    # If it's not a correct option, display an error
                    else:
                        print "Interface must be a tuple with option in or out as first part i.e. ('in', 'eth0')"
                        return
                # If it's not a tuple, display an error
                else:
                    print "Interface must be a tuple with option in or out as first part i.e. ('in', 'eth0')"
                    return

                ###############
                #SET PORT TYPE#
                ###############
                # Set port type if we have one
                if _PORT_TYPE:
                    # Port type must be a string
                    if type(opts["port-type"]) == str:
                        # Must be a valid option; tcp, udp, icmp, all
                        if opts["port-type"] in ["tcp", "udp", "icmp", "all"]:
                            _rule = "%s -p %s" % (_rule, opts["port-type"])
                        else:
                            print "Invalid port-type '%s'; must be tcp, udp, icmp or all" % opts["port-type"]
                            return
                    # It it's not a string, display an error
                    else:
                        print "Option port-type must be a string with option; tcp, udp, icmp or all"
                        return

            #####################
            # SET DST/SRC PORTS #
            #####################
            if _VALIDPORTS:
                # Port choice must be a string
                try:
                    if _SRC_PORT and type(int(opts["src-port"])) == int:
                        _rule = "%s --sport %s" % (_rule, opts["src-port"])
                    elif _DST_PORT and type(int(opts["dst-port"])) == int:
                        _rule = "%s --dport %s" % (_rule, opts["dst-port"])
                    else:
                        print "Error with port choice"
                        return
                # If the string can't convert to an integer, throw an error
                except ValueError:
                    print "Port choice should be a valid integer or integer string"
                    return

            #################
            # SET ICMP PORT #
            #################
            if _ICMP:
                if type(int(opts["icmp"])) == int:
                    _rule = "%s --icmp-type %s" % (_rule, opts["icmp"])
                # If our icmp option doesn't convert to an integer, throw an error
                else:
                    print "Invalid ICMP type; must be a valid integer or integer string"
                    return

            ##############
            # SET SUBNET #
            ##############
            if _SUBNET:
                # Subnet must be a string
                if type(opts["subnet"]) == str:
                    _rule = "%s -s %s" % (_rule, opts["subnet"])
                # If it's not a string, display an error
                else:
                    print "Subnet should be a valid subnet string, please refer to iptables(8) man page"
                    return

            #############
            # SET STATE #
            #############
            if _STATE:
                # State must be a list
                if type(opts["state"]) == list:
                    # Loop our states, use a counter
                    _validstate = 0
                    for _idx, _state in enumerate(opts["state"]):
                        # If it's a valid state, then set it to upper case
                        if _state.lower() in ["new", "established", "related", "invalid"]:
                            opts["state"][_idx] = _state.upper()
                            # Add one to our validstate counter
                            _validstate += 1
                        # If our valid state counter matches the length of our list, add the state string
                    if _validstate == len(opts["state"]):
                        _rule = "%s -m state --state %s" % (_rule, ",".join(opts["state"]))
                    # Otherwise, report an error
                    else:
                        print
                        return

                # If it's not a list, display an error
                else:
                    print """State option must be a list of valid states i.e.
                                            ['new', 'established', 'related', 'invalid']"""
                    return

            ##############
            # SET ACTION #
            ##############
            if _ACTION:
                if type(opts["action"]) == str:
                    # If we get a valid option, then set it to uppercase and append it to our command
                    if opts["action"].lower() in ["accept", "drop", "queue", "return"]:
                        _rule = "%s -j %s" % (_rule, opts["action"].upper())
                    else:
                        print "Invalid action option; must be accept, drop, queue, return"
                        return

                # If it's not a string, display an error
                else:
                    print "Action option must be a string"
                    return

            # Store the rule in our rules list
            self.rule = _rule
            self.rules.append(self.rule)
            return
"""
BLACKSALT
Author: 	Leslie.A.Cordell
CreationDate:	2013/11/18
ModifiedDate:	2013/12/01

The MIT License (MIT)
Copyright (c) 2013 Leslie.A.Cordell
"""

import os
import re
__version__ = "0.2.1"


###############
# ERROR TYPES #
###############
class RuleError(Exception):
    pass


class IPTablesError(Exception):
    pass


#############
# BLACKSALT #
#############
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
    def __init__(self, **kwargs):
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
        # If we have an iptables parameter store it as our IPTABLES bin location
        if "iptables" in kwargs:
            self.iptables = kwargs["iptables"]
        # Always default to true for printmode, unless we have a false parameter
        if "printmode" in kwargs:
            self.printmode = kwargs["printmode"]
        # If we get a scriptfile parameter, we'll write our firewall output to here
        # for the user.
        if "scriptfile" in kwargs:
            self.scriptfile = kwargs["scriptfile"]

    # Change default print to similar format: <BlackSalt v0.2.0: 0 rules defined>
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
            print """Parameter must be a string or list. i.e 'chains' or 'tables' will flush these.
            A string that is not 'chains' or 'tables' will be treated as a specific chain to flush.
            A list of strings will create rules to flush these as chains individually or if
            'tables' or 'chains' are included in this list, they will be flushed also."""

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
                    _scriptfile.writelines("%s%s\n" % (self.iptables, _rule))
                _scriptfile.close()

        #  If printmode is on, print the rules to the screen
        if self.printmode:
            for _rule in self.rules:
                print "%s%s" % (self.iptables, _rule)

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

    def setrule(self, **kwargs):
        """
        @summary: The setrule function will generate an instance from the Rule class
                  and append it to the rules array.
                  Available options are:
                        interface= dict   i.e {"name": "eth1", "direction": "in"}
                        protocol= str     i.e. "tcp"
                        dst= str or int   i.e. 80
                        src= str or int   i.e. 22
                        subnet= str       i.e. 172.18.10.1 or 172.18.11.0/24 or 172.18.0.0/255.255.255.0
                        state= list, srt or comma delimited str i.e. ["new", "established", "related"]#
                        chain= str        i.e. INPUT, OUTPUT, FORWARD
                        icmp= str/int 1-255   i.e. 8
                        target= str       i.e. ACCEPT, DROP, QUEUE, RETURN
        @param opts: dict
        @rtype: None
        """
        try:
            _rule = Rule(**kwargs)
            self.rules.append(_rule)

        except RuleError as err:
            print err


class Rule():
    """
    This class will generate a new rule for us, we'll pass it parameters,
    depending on the parameters of the rule, the output function for the
    rule will change. An object of initializing parameters will be passed
    to create the rule
    """
    def __init__(self, **kwargs):
        self.protocol = None  # i.e tcp, udp, icmp
        self.protocols = ["tcp", "udp", "icmp"]  # The 3 default protocols
        self.interface = {"name": None, "direction": None}
        self.dst_port = None
        self.src_port = None
        self.subnet = None
        self.state = None  # Loads (-m state) module, accepts list like ["new", "established", "related"]#
        self.chain = None
        self.icmp = None  # This should be an int for ICMP code
        self.target = None  # ACCEPT, DROP, QUEUE, RETURN
        self.protocolsfile = "/etc/protocols"
        self.warning = None  # If this rule gets a warning, it will be stored here.
        #: Set the default protocols
        self.set_default_protocols()
        #: Set the rules
        self.setup(**kwargs)

    def __repr__(self):
        _rule = self.generate()
        if not _rule == "":
            return _rule

        return "No parameters set for rule"

    ##########
    # SET UP #
    ##########
    def setup(self, **kwargs):
        """
        @summary:  This is called on initialisation, the kwargs are forwarded
                   to this function which sets the rule up. It can also be used
                   again to reset or reinitialise the rule.
        @rtype: None
        @param **kwargs: protocol, interface, subnet, state, dst_port, src_port
                         chain, icmp, target
        """
        if "protocol" in kwargs:
            self.set_protocol(kwargs["protocol"])
        if "chain" in kwargs:
            #: We set chain before interface as interface makes a judgement based on the chain
            self.set_chain(kwargs["chain"])
        if "interface" in kwargs:
            self.set_interface(kwargs["interface"])
        if "dst" in kwargs:
            self.set_port(dst=kwargs["dst"])
        if "src" in kwargs:
            self.set_port(src=kwargs["src"])
        if "subnet" in kwargs:
            self.set_subnet(kwargs["subnet"])
        if "state" in kwargs:
            self.set_state(kwargs["state"])
        if "icmp" in kwargs:
            self.set_icmp(kwargs["icmp"])
        if "target" in kwargs:
            self.set_target(kwargs["target"])

    ###########
    # PREVIEW #
    ###########
    def preview(self):
        """
        @summary: Simple print rule params to screen
        @rtype: None
        @param: None
        """
        print "protocol: %s" % self.protocol
        print "interface: %s" % self.interface
        print "dst_port: %s" % self.dst_port
        print "src_port: %s" % self.src_port
        print "subnet: %s" % self.subnet
        print "state: %s" % self.state
        print "chain: %s" % self.chain
        print "icmp: %s" % self.icmp
        print "target: %s" % self.target
        return

    #########################
    # SET DEFAULT PROTOCOLS #
    #########################
    def set_default_protocols(self):
        """
        @summary: This function takes no arguments, instead it takes the protocolsfile
                  address and tries to open it if it exists. It will pass it and try to
                  pull out valid protocols, these can be used when specifying a rule.
                  They will be appended to the current list of allowed protocols
        @rtype: None
        @param: None
        """
        if os.path.exists(self.protocolsfile) and os.access(self.protocolsfile, os.R_OK):
            _protocolsfile = open(self.protocolsfile, 'r').readlines()
            for _line in _protocolsfile:
                if _line[0] not in ["#", "\w", "\n"]:
                    _allowedprotocol = _line.split(" ")[0]
                    if _allowedprotocol not in self.protocols:
                        self.protocols.append(_allowedprotocol)
        else:
            return

    ##########################
    # SET RULE PROTOCOL TYPE #
    ##########################
    def set_protocol(self, opts=None):
        """
        @summary: Sets the protocol to be used, it requires that the protocol is in the default
                  protocols which is collected from the system or tcp, udp or icmp
        @rtype: None
        @param opts: str
        """
        if type(opts) == str:
            if opts in self.protocols:
                self.protocol = opts
            else:
                print "protocol must be a valid protocol: %s" % ", ".join(self.protocols)
        else:
            print "protocol must be a string i.e. 'tcp'"
            return

    ####################
    # SET SRC/DST PORT #
    ####################
    def set_port(self, **kwargs):
        """
        @summary: Set the destination port, set the source port to None.
                  The argument must be dst=80 or src=80 etc
        @rtype: None
        @param **kwargs: dst=str/int, src=str/int
        """
        #: If we get a destination port
        if "dst" in kwargs:
            if kwargs["dst"] is None:
                self.dst_port = None

            if type(kwargs["dst"]) == str:
                try:
                    #: Try to convert the argument to an int
                    kwargs["dst"] = int(kwargs["dst"])
                except TypeError:
                    raise RuleError("dst option must be an integer or a string integer")

            if type(kwargs["dst"]) == int:
                #: Set the dst_port to the port number and set src_port to blank
                self.dst_port = kwargs["dst"]

        #: If we get a source port
        elif "src" in kwargs:
            if kwargs["src"] is None:
                self.src_port = None
            if type(kwargs["src"]) == str:
                try:
                    #: Try to convert the argument to an int
                        kwargs["src"] = int(kwargs["src"])
                except TypeError:
                    raise RuleError("src option must be an integer or a string integer")

            if type(kwargs["src"]) == int:
                #: Set the dst_port to the port number and set src_port to blank
                self.src_port = kwargs["src"]

        #: If we get an unknown kwarg, show an error
        else:
            raise RuleError("""Keyword arguments must be either dst=PORT and/or src=PORT,
            value must be an integer or integer string or None """)

    ##############
    # SET SUBNET #
    ##############
    def set_subnet(self, subnet):
        """
        @summary: Set subnet for this rule, it accepts only a string and must match proper
                  subnetting format:
                  xxx.xxx.xxx.xxx
                  xxx.xxx.xxx.xxx/24
                  xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx.xxx
        @rtype: None
        @param subnet: str
        """
        #_maxmask = "([01][0-9][0-9]|2[0-4][0-9]|25[0-5])" # 1-255
        _maxmask = "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"  # 1-255
        _maxcidr = "([1-9]|1[0-9]|2[0-4])"  # 1-24
        _netmatch = "%s\.%s\.%s\.%s" % (_maxmask, _maxmask, _maxmask, _maxmask)  # 1-255.1-255.1-255.1-255
        _patterns = [
            re.compile("^%s$" % _netmatch),
            re.compile("^%s\/%s$" % (_netmatch, _netmatch)),
            re.compile("^%s\/%s$" % (_netmatch, _maxcidr))
        ]
        if type(subnet) == str:
            #: If our subnet is a string and it matches one of our patterns, then set the subnet
            for _pattern in _patterns:
                if re.match(_pattern, subnet):
                    self.subnet = subnet
                    return
            #: If we don't match a pattern, return an error and set subnet to false
            raise RuleError("""Subnet must match the following patterns:
            1-255.1-255.1-255    i.e. 172.16.10.23
            1-255.1-255.1-255/1-24   i.e. 172.16.10.0/24
            1-255.1-255.1-255/1-255.1-255.1-255.1-255    i.e 172.16.10.0/255.255.255.0""")

    #############
    # SET STATE #
    #############
    def set_state(self, param):
        """
        @summary: This sets the allowed states, it accepts NEW, ESTABLISHED, RELATED,
                  INVALID as states. It can take in a string for one state, a
                  comma delimited string, or a list of states.
        @rtype: None
        @param param: str or list
        """
        _allowed = ["new", "established", "related", "invalid"]
        self.state = []
        #: If we get a string, split it by comma and re-run the function
        if type(param) == str:
            self.set_state(param.split(","))
        #: If we get a list, check parameter against allowed and add them to state
        elif type(param) == list:
            for _state in param:
                if type(_state) == str:
                    _state = _state.strip()
                    if type(_state) == str and _state.lower() in _allowed:
                        self.state.append(_state.upper().replace(" ", ""))

            return
        else:
            raise RuleError("Invalid State Format; must be string, a comma delimited string or list")

    #############
    # SET CHAIN #
    #############
    def set_chain(self, param):
        """
        @summary: This sets the chain of the rule. If the chain is input, it will
                  automatically set the interface direction to -i, and for output
                  it will set it to -o as these are the only valid directions for
                  the chains. Default chains are INPUT, OUTPUT, FORWARD. But others
                  may be specified.
        @rtype: None
        @param param: str, list or comma delimited str
        """
        _default = ["INPUT", "OUTPUT", "FORWARD"]
        if type(param) == str:
            #: If the chain is in the list of defaults add it as uppercase
            if param.upper() in _default:
                self.chain = param.upper()
                #: If the chain is input, set the interface direction to -i
                if self.chain and self.chain == "INPUT":
                    if type(self.interface) == dict:
                        self.interface["direction"] = "in"
                    else:
                        self.interface = {"name": None, "direction": "in"}

                #: If the chain is output, set the interface direction to -o
                if self.chain and self.chain == "OUTPUT":
                    if type(self.interface) == dict:
                        self.interface["direction"] = "out"
                    else:
                        self.interface = {"name": None, "direction": "out"}
            return
        raise RuleError("Chain must be a string")

    ############
    # SET ICMP #
    ############
    def set_icmp(self, param):
        """
        @summary: This simply sets the icmp protocol. Setting this will
                  adjust the presentation of the rule.
        @rtype : None
        @type param: int (1-40 for valid or 41-255 for reserved ICMP protocol)
        """
        _valid = range(1, 40)
        _reserved = range(41, 255)

        if type(param) == int:
            #: If our code is in the valid range; set icmp
            if param in _valid:
                self.icmp = param
                return
            if param in _reserved:
            #: If our code is in the reserved range; warn, set icmp
                self.icmp = param
                self.warn("You are using a reserved ICMP code; %s" % param)
                return

        return RuleError("ICMP must be an int from 1-40 or 41,255 for reserved")

    ##############
    # SET TARGET #
    ##############
    def set_target(self, param):
        """
        @summary: This will set the target or action for the rule
                  extentions can allow for other targets, a warning
                  is raised if a default rule isn't used, but an
                  exception is not raised.
        @rtype: None
        @param param: Case-insensitive String for target or action:
                      ACCEPT, DROP, QUEUE or RETURN
        """
        _default = ["ACCEPT", "DROP", "QUEUE", "RETURN"]
        if type(param) == str:
            if param.upper() in _default:
                self.target = param.upper()
            else:
                self.target = param
                self.warn("Using a non default target %s" % param)
            return

        raise RuleError("Target must be a string")

    #################
    # SET INTERFACE #
    #################
    def set_interface(self, params):
        """
        @summary: Set interface takes in a dict with "name" and "direction".
                  If 'out' is set as direction, but INPUT is set as the chain,
                  it is changed to 'in' If 'in' is set as the direction, but
                  OUTPUT is the chain, it is changed to 'out'. For the forward
                  chain or custom chains, this is ignored.
        @rtype: None
        @param params: dict {"name": "eth1", "direction": "in"}
        """
        _directions = ["in", "out"]

        if type(params) == dict:
            #: If we get a name and a direction
            if "name" in params and "direction" in params:
                if type(params["name"]) == str and type(params["direction"]) == str:
                    #: Make sure the name and directions are strings and the direction is valid.
                    if params["direction"] not in _directions:
                        raise RuleError("Invalid direction passed to interface; must be 'in' or 'out'")
                    #: Set the interface
                    self.interface = {"name": params["name"], "direction": params["direction"]}
                    #: If the chain is INPUT set direction to in
                    if self.chain and self.chain.upper() == "INPUT":
                        self.interface["direction"] = "in"
                    #: If the chain is OUTPUT set the direction to out
                    elif self.chain and self.chain.upper() == "OUTPUT":
                        self.interface["direction"] = "out"
                    return

            raise RuleError("set_interface needs to be called with a dictionary {'name': str, 'direction': str}")

        raise RuleError("set_interface needs to be called with a dictionary {'name': str, 'direction': str}")

    ############
    # GENERATE #
    ############
    def generate(self):
        """
        @summary: This will output the rule as a string using the currently defined
                  settings. It will try tocleverly judge, by what is set, what is
                  meant to be done. It takes no arguments and returns a string.
        @rtype: str
        @param: none
        """
        #: Initiate default and empty values
        _protocol = None
        _subnet = None
        _interface = None
        _dst_port = None
        _src_port = None
        _state = None
        _chain = None
        _icmp = None
        _target = None

        #: Check our variables and set the string values
        if self.protocol and type(self.protocol) == str:
            _protocol = "-p %s" % self.protocol
        if self.interface and type(self.interface) == dict:  # {"name": None, "direction": None}
            if "name" in self.interface and "direction" in self.interface:
                #: Make sure we get an interface name before we assign _interage or we'll
                #: End up with i.e. -i None  or -o None
                if self.interface["name"]:
                    if self.interface["direction"] == "in":
                        _interface = "-i %s" % str(self.interface["name"])
                    if self.interface["direction"] == "out":
                        _interface = "-o %s" % str(self.interface["name"])
        if self.dst_port and (type(self.dst_port) == str or type(self.dst_port) == int):
            _dst_port = "--dport %s" % str(self.dst_port)
        if self.src_port and (type(self.src_port) == str or type(self.src_port) == int):
            _src_port = "--sport %s" % str(self.src_port)
        if self.subnet and type(self.subnet) == str:
            _subnet = "-s %s" % self.subnet
        if self.state and type(self.state) == list:
            _state = "-m state --state %s" % ','.join(self.state)
        if self.chain and type(self.chain) == str:
            _chain = "-A %s" % self.chain
        if self.icmp and type(self.icmp) == int:
            _protocol = "-p icmp"
            _dst_port = None
            _src_port = None
            _icmp = "--icmp-type %d" % self.icmp
        if self.target and type(self.target) == str:
            _target = "-j %s" % self.target.upper()

        #: We'll now store these values in their generally expected order
        _rule = [_chain, _interface, _protocol, _icmp, _subnet, _src_port, _dst_port, _state, _target]
        _finalstr = ""
        #: We'll loop through our values and then construct our final rule if they exists
        for entry in _rule:
            if entry:
                _finalstr = "%s %s" % (_finalstr, entry)

        return _finalstr

    ########
    # WARN #
    ########
    def warn(self, msg):
        """
        @summary: Very simple function to print a warning.
                  Attaches warning to itself.
        @rtype: None
        @param msg: str (a warning message)
        """
        _msg = "Warning: %s" % msg
        self.warning = _msg
        print _msg

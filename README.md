blacksalt
=========

A firewall script generation tool and monitoring facility.

Currently blacksalt only handles simple IPTables rules, it is a handy tool for scripting firewalls using Python
rather than having to stick with just BASH to write your rules. Which means the full Python programming
environment is available and you have some things to work to generate your rules
  However, the goal of BlackSalt isn't just to generate IPTables rules, but eventually generate scripts for
other Firewalls like IPFW, PF, Mirkotik, and whatever other ones that may arise.
  The plans are to make one script output to many different formats, allowing for error checking also, module
addition, searching, running the script on the fly, viewing and modifying currently running rules, safe running
of remote firewalls (i.e resetting if getting kicked out) etc...
  

To generate simple rules however using what is available, you can do the following, also referring to the 
firewall.py script which is just a really basic example:

1. First import blacksalt and create an instance;
    ```python
    #Blacksalt takes 3 optional keyword arguments
    #iptables="/directory/of/iptables/bin" this defaults to /sbin/iptables
    #printmode=True  this defaults to true, when generating rules will print them to stdout
    #scriptfile="./firewall" this defaults to False, when set it will output the rules to this file on generate
    from blacksalt import *
    iptables = BlackSalt()
    ```

2. To flush tables and chains simple add the following line, (assuming your instance is named iptables);
    ```python
    # With no arguments this will flush all tables and chains, with a string it will flush that
    iptables.flush()
    # If the string is tables, it will flush the tables
    iptables.flush('tables')
    # If the string is chains, it will flush all chains
    iptables.flush('chains')
    # If the string is anything else, it will assume that is a chain and flush that chain.
    iptables.flush('blacklist')
    ```
        
3. To set default policies, add the following, (assuming your instance is named iptables);
    ```python
    # Order must be chain, policy
    iptables.policy("input", "drop")  # As two strings for one policy
    # or
    iptables.policy(("input", "drop")) # As a tuple
    # or
    iptables.policy([("input", "drop"), ("output", "accept"), ("forward", "drop")]) # As a list of tuples
    ```
    
3. Finally to set rules, (assuming your instance is named iptables);
    ```python
    #To allow anything coming in on loopback
    iptables.setrule(chain="input", interface={"name": "lo", "direction": "in"}, target="accept")
    #interface= dict   i.e {"name": "eth1", "direction": "in"}
    #                    protocol= str     i.e. "tcp"
    #                    dst= str or int   i.e. 80
    #                    src= str or int   i.e. 22
    #                    subnet= str       i.e. 172.18.10.1 or 172.18.11.0/24 or 172.18.0.0/255.255.255.0
    #                    state= list, srt or comma delimited str i.e. ["new", "established", "related"]#
    #                    chain= str        i.e. INPUT, OUTPUT, FORWARD
    #                    icmp= str/int 1-255   i.e. 8
    #                    target= str       i.e. ACCEPT, DROP, QUEUE, RETURN
    ```
                        
                        
  A More indepth wiki to come as more stuff is added...
    
  

# Linux-Kernel-Firewall
Stateless, Statefull and Deep packet Inspection Firewall.

General description :

The firewall includes a static rules table which is loaded from the user space, 
a connection table which keeps track of tcp connections and a proxy which does deep packet inspection for http and ftp. 
The implementation includes two char devices:
1.Fw_rules – managing the table of rules.
2.Fw_log – managing the list of logs.

How to run the firewall :

The kernel space :

The folder fw contains make file. After writing make at the command shell, writing insmod.ko will load
the firewall module to the kernel.

The user space :

1.The folder interface contains make file. After writing make at the command shell, writing \a.out command
will run the command specified .
the commands are : 

activate - activaing the firewall.

deactivate - deactivating the firewall

show_rules - show the static firwall rules table.

clear_rules - delete the current rules.

load_rules <path> - loading rules from a txt file to the kernel.

show_log - showing the logs of the firewall.

clear_log <char> - clearing the log table.

show_connection_table- shows the connection table of the Tcp connections.

2.Transparent proxy use to check the content of ftp the http data. for Htttp - blocks office file and content length above 2000. for ftp - blocks exe files, and checks the ftp authentication.

the folder proxy contains two files : proxy_part_1.py and proxy_part_2.py.
In order to start the proxy going you should open two command shell windows and write :
In the first window write:
python proxy_part_1.py
in the second window write :
python proxy_part_2.py
From this point the proxy will be up and listen and redirect, ftp and http packets.



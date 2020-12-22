# my-ping
This project is a network diagnostics ping tool. It is intended to run on Linux Ubuntu.

The default ping mode is ICMP echo. To use TCP ping, add the --tcp flag. To use RST probe, add the --rstprobe flag.

To compile, run "make myping".

Usage:

    ./myping --di <dst_ip>

Optional Flags:  

    --si <src_ip> 
    --de <dst_mac>
    --se <src_mac>
    --dp <dst_port>
    --sp <src_port>
    --ttl <time_to_live>
    --tcp
    --rstprobe
    --interface <network_interface_name>
    --devind <network_interface_index>

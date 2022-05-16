from ipaddress import ip_address

p4 = bfrt.ngaa.pipe

# server ip, use Ethernet mode, not ib mode
# network card name “ens3f0”
ip01="172.16.200.1"
ip02="172.16.200.2"
ip08="172.16.200.8"
ip11="172.16.200.31"
ip12="172.16.200.32"
ip14="172.16.200.34"
ip15="172.16.200.35"

mac01=0x08c0eb204fda
mac02=0x08c0eb289c60
mac08=0x08c0eb289ca8
mac11=0x08c0eb289d60
mac12=0x08c0eb289c58
mac14=0x88e9a40d7f54
mac15=0x9440c9b4d8d0

# can be found in “bf-sde.pm> show”, list "D_P"
port01=132
port02=140
port03=148

def ip2int(ip):
    ip_list = ip.strip().split('.')
    ip_int = int(ip_list[0])*256**3+int(ip_list[1])*256**2+int(ip_list[2])*256**1+int(ip_list[3])*256**0
    return ip_int

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    
    def _clear(table, verbose=False, batching=False):
        if verbose:
            print("Clearing table {:<40} ... ".
                  format(table['full_name']), end='', flush=True)
        try:    
            entries = table['node'].get(regex=True, print_ents=False)
            try:
                if batching:
                    bfrt.batch_begin()
                for entry in entries:
                    entry.remove()
            except Exception as e:
                print("Problem clearing table {}: {}".format(
                    table['name'], e.sts))
            finally:
                if batching:
                    bfrt.batch_end()
        except Exception as e:
            """
            if e.sts == 6:
                if verbose:
                    print('(Empty) ', end='')
            """
        finally:
            if verbose:
                print('Done')

        # Optionally reset the default action, but not all tables
        # have that
        try:
            table['node'].reset_default()
        except:
            pass
    
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members
    

    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)

    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)
            
    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            _clear(table, verbose=verbose, batching=batching)

print("entering clear all function")
clear_all()
print("exit clear all function")

switch_check = p4.Ingress.switch_check
ipRoute = p4.Ingress.ipRoute

# =============================================================
# parmeters in add_with functions below are:
# ngaa.p4 -> key in table (hdr.ipv4.dst_addr, "dst_addr" is what we need)
# ngaa.p4 -> action function's parameters in table (action ipv4_forward has two ,dst_addr and port)

# Attention: parameters can not be same, so we can use only one OR change the conflic name
# for example, we can change "action ipv4_forward(mac_addr_t dst_addr" to "action ipv4_forward(mac_addr_t dst_addr_m"
# to aviod the conflic to key "dst_addr"

# what does "add_with_ipv4_forward" do?
# extract the packet and match ip with ip01/ip02/..., if successfully matched, send packet to port0x
switch_check.add_with_set_agg(switch_id=b'00000000')
print("done set agg")
ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip14),dst_addr_m=mac14,port=port01)  # port not sure, is server14 port
print("done ip14")
ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip15),dst_addr_m=mac15,port=port01)  # port not sure, is switch01 port
print("done ip15")
# ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip01),dst_addr_m=mac01,port=port01)  # dstip, dstmac(no use), port
# print("done 01")
# ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip02),dst_addr_m=mac02,port=port02)
# print("done 02")
# ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip08),dst_addr_m=mac08,port=port01)  # dstip, dstmac(no use), port
# print("done 08")
# ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip11),dst_addr_m=mac11,port=port02)
# print("done 11")
# ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip12),dst_addr_m=mac12,port=port01)  # dstip, dstmac(no use), port
# print("done 12")
# ipRoute.add_with_ipv4_forward(dst_addr=ip_address(ip14),dst_addr_m=mac14,port=port02)
# print("done 13")

# =============================================================

# register_table_size = p4.Ingress.table_size_reg
# register_counter = p4.Ingress.test_reg

# set the size of the table
# register_table_size.mod(register_index=0,f1=table_size) 
# start from the first server
# register_counter.mod(register_index=0,f1=table_size-1)

# clean the counters
def clear_counters(table_node):
    for e in table_node.get(regex=True):
        e.data[b'$COUNTER_SPEC_BYTES'] = 0
        e.data[b'$COUNTER_SPEC_PKTS'] = 0
        e.push()

# dump everything
switch_check.dump(table=True)
ipRoute.dump(table=True)
# register_table_size.dump(table=True,from_hw=1)
# register_counter.dump(table=True,from_hw=1)

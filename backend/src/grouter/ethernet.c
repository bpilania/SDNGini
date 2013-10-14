/*
 * ethernet.c (Ethernet driver for the GINI router)
 * AUTHOR: Muthucumaru Maheswaran
 *
 * VERSION: 1.0
 */

#include <slack/err.h>

#include "packetcore.h"
#include "classifier.h"
#include "filter.h"
#include "protocols.h"
#include "message.h"
#include "gnet.h"
#include "arp.h"
#include "ip.h"
#include <netinet/in.h>
#include <stdlib.h>


extern pktcore_t *pcore;
extern classlist_t *classifier;
extern filtertab_t *filter;


extern router_config rconfig;

int findPacketSize(pkt_data_t *pkt)
{
	printf("\n ************************Check Point 4*************************** \n");

	ip_packet_t *ip_pkt;
	if (pkt->header.prot == htons(IP_PROTOCOL))
	{
		ip_pkt = (ip_packet_t *) pkt->data;
		return (14 + ntohs(ip_pkt->ip_pkt_len));
	}
	/*else if (pkt->header.prot == htons(ARP_PROTOCOL)){
		printf("************ARP Packet Received*******************");
		return 42;
	}*/
	// above assumes IP and ARP; we can compute this length by
	// reading the address lengths from the packet.
	else
		return sizeof(pkt_data_t);

	printf("\n ************************Check Point 5*************************** \n");

}


void *toEthernetDev(void *arg)
{
	printf("\n ************************Check Point 6*************************** \n");

	gpacket_t *inpkt = (gpacket_t *)arg;
	interface_t *iface;
	arp_packet_t *apkt;
	char tmpbuf[MAX_TMPBUF_LEN];
	int pkt_size;

	verbose(2, "[toEthernetDev]:: entering the function.. ");
	// find the outgoing interface and device...
	if ((iface = findInterface(inpkt->frame.dst_interface)) != NULL)
	{
		/* send IP packet or ARP reply */
		if (inpkt->data.header.prot == htons(ARP_PROTOCOL))
		{
			apkt = (arp_packet_t *) inpkt->data.data;
			COPY_MAC(apkt->src_hw_addr, iface->mac_addr);
			COPY_IP(apkt->src_ip_addr, gHtonl(tmpbuf, iface->ip_addr));
		}


		pkt_size = findPacketSize(&(inpkt->data));
/*
		//Printing packet values
			printf("\n=========== OUTGOING PACKET VALUES ================\n");
			printf("\n----------HEADER VALUES :");
			printf("\nSource MAC Address: %x : %x : %x : %x : %x : %x", inpkt->data.header.src[0],
					inpkt->data.header.src[1],inpkt->data.header.src[2],
					inpkt->data.header.src[3],inpkt->data.header.src[4],inpkt->data.header.src[5]);
			printf("\nDestination MAC Address: %x : %x : %x : %x : %x : %x", inpkt->data.header.dst[0],
					inpkt->data.header.dst[1],inpkt->data.header.dst[2],
					inpkt->data.header.dst[3],inpkt->data.header.dst[4],inpkt->data.header.dst[5]);

			printf("\nSource IP Address: %d.%d.%d.%d", inpkt->frame.src_ip_addr[0],
					inpkt->frame.src_ip_addr[1],inpkt->frame.src_ip_addr[2],
					inpkt->frame.src_ip_addr[3]);

			printf("\nProtocol is : %d",inpkt->data.header.prot);
			printf("\nDestination Interface is : %d",inpkt->frame.dst_interface);
			printf("\nIngress Port is : %d",inpkt->frame.src_interface);
			printf("\nNXTH IP Destination: %d.%d.%d.%d", inpkt->frame.nxth_ip_addr[0],inpkt->frame.nxth_ip_addr[1],
					inpkt->frame.nxth_ip_addr[2],inpkt->frame.nxth_ip_addr[3]);

			printf("\n --- IP PACKET:");
			ip_packet_t *ip_pkt;
			ip_pkt = (ip_packet_t *) inpkt->data.data;

			printf("\Destination MAC Address: %x : %x : %x : %x : %x : %x", inpkt->data.header.dst[0], inpkt->data.header.dst[1],
					inpkt->data.header.dst[2],
					inpkt->data.header.dst[3],inpkt->data.header.dst[4],inpkt->data.header.dst[5]);
			printf("\Source MAC Address: %x : %x : %x : %x : %x : %x", inpkt->data.header.src[0],
					inpkt->data.header.src[1],inpkt->data.header.src[2],
					inpkt->data.header.src[3],inpkt->data.header.src[4],inpkt->data.header.src[5]);
			printf("\nIP Source: %d.%d.%d.%d", ip_pkt->ip_src[0],ip_pkt->ip_src[1],ip_pkt->ip_src[2],ip_pkt->ip_src[3]);
			printf("\nIP Destination: %d.%d.%d.%d", ip_pkt->ip_dst[0],ip_pkt->ip_dst[1],ip_pkt->ip_dst[2],ip_pkt->ip_dst[3]);
			printf("\nIP Protocol is : %d",ip_pkt->ip_prot);
			printf("\nIP TOS: %d\n",ip_pkt->ip_tos);
*/


		verbose(2, "[toEthernetDev]:: vpl_sendto called for interface %d..%d bytes written ", iface->interface_id, pkt_size);
		vpl_sendto(iface->vpl_data, &(inpkt->data), pkt_size);
		free(inpkt);          // finally destroy the memory allocated to the packet..
	} else
		error("[toEthernetDev]:: ERROR!! Could not find outgoing interface ...");

	printf("\n ************************Check Point 7*************************** \n");

	// this is just a dummy return -- return value not used.
	return arg;
}


/*
 * TODO: Some form of conformance check so that only packets
 * destined to the particular Ethernet protocol are being captured
 * by the handler... right now.. this might capture other packets as well.
 */
void* fromEthernetDev(void *arg)
{
	printf("\n ************************Check Point 2*************************** \n");

	interface_t *iface = (interface_t *) arg;
	interface_array_t *iarr = (interface_array_t *)iface->iarray;
	uchar bcast_mac[] = MAC_BCAST_ADDR;

	gpacket_t *in_pkt;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);		// die as soon as cancelled
	while (1)
	{
		verbose(2, "[fromEthernetDev]:: Receiving a packet ...");
		if ((in_pkt = (gpacket_t *)malloc(sizeof(gpacket_t))) == NULL)
		{
			fatal("[fromEthernetDev]:: unable to allocate memory for packet.. ");
			return NULL;
		}

		bzero(in_pkt, sizeof(gpacket_t));
		vpl_recvfrom(iface->vpl_data, &(in_pkt->data), sizeof(pkt_data_t));
		pthread_testcancel();
		// check whether the incoming packet is a layer 2 broadcast or
		// meant for this node... otherwise should be thrown..
		// TODO: fix for promiscuous mode packet snooping.
		if ((COMPARE_MAC(in_pkt->data.header.dst, iface->mac_addr) != 0) &&
			(COMPARE_MAC(in_pkt->data.header.dst, bcast_mac) != 0))
		{
			verbose(1, "[fromEthernetDev]:: Packet dropped .. not for this router!? ");
			free(in_pkt);
			continue;
		}


			// copy fields into the message from the packet..
		in_pkt->frame.src_interface = iface->interface_id;
		COPY_MAC(in_pkt->frame.src_hw_addr, iface->mac_addr);
		COPY_IP(in_pkt->frame.src_ip_addr, iface->ip_addr);

		//Printing packet values
		/*	printf("\n=========== INCOMING PACKET VALUES ================\n");
			printf("\n----------HEADER VALUES :");
			printf("\nSource MAC Address: %x : %x : %x : %x : %x : %x", in_pkt->data.header.src[0],
					in_pkt->data.header.src[1],in_pkt->data.header.src[2],
					in_pkt->data.header.src[3],in_pkt->data.header.src[4],in_pkt->data.header.src[5]);
			printf("\nDestination MAC Address: %x : %x : %x : %x : %x : %x", in_pkt->data.header.dst[0],
					in_pkt->data.header.dst[1],in_pkt->data.header.dst[2],
					in_pkt->data.header.dst[3],in_pkt->data.header.dst[4],in_pkt->data.header.dst[5]);

			printf("\nSource IP Address: %d.%d.%d.%d", in_pkt->frame.src_ip_addr[0],
					in_pkt->frame.src_ip_addr[1],in_pkt->frame.src_ip_addr[2],
					in_pkt->frame.src_ip_addr[3]);

			printf("\nProtocol is : %d",in_pkt->data.header.prot);
			printf("\nDestination Interface is : %d",in_pkt->frame.dst_interface);
			printf("\nIngress Port is : %d",in_pkt->frame.src_interface);
			printf("\nNXTH IP Destination: %d.%d.%d.%d", in_pkt->frame.nxth_ip_addr[0],in_pkt->frame.nxth_ip_addr[1],
					in_pkt->frame.nxth_ip_addr[2],in_pkt->frame.nxth_ip_addr[3]);

			printf("\n --- IP PACKET:");
			ip_packet_t *ip_pkt;
			ip_pkt = (ip_packet_t *) in_pkt->data.data;
			printf("\nIP Source: %d.%d.%d.%d", ip_pkt->ip_src[0],ip_pkt->ip_src[1],ip_pkt->ip_src[2],ip_pkt->ip_src[3]);
			printf("\nIP Destination: %d.%d.%d.%d", ip_pkt->ip_dst[0],ip_pkt->ip_dst[1],ip_pkt->ip_dst[2],ip_pkt->ip_dst[3]);
			printf("\nIP Protocol is : %d",ip_pkt->ip_prot);
			printf("\nIP TOS: %d\n",ip_pkt->ip_tos);*/

		// check for filtering.. if the it should be filtered.. then drop
		if (filteredPacket(filter, in_pkt))
		{
			verbose(2, "[fromEthernetDev]:: Packet filtered..!");
			free(in_pkt);
			continue;   // skip the rest of the loop
		}

		verbose(2, "[fromEthernetDev]:: Packet is sent for enqueuing..");
		//ENQUEUE PACKET TO QUEUE_1
		printf("\n ENQUEUE PACKET TO QUEUE_1 \n");

		if (in_pkt->data.header.prot == htons(ARP_PROTOCOL))
		{
			printf("\n SIZE of ARP Packet is: %d \n", sizeof(gpacket_t));

			ARPProcess(in_pkt);

		}
		else{
			printf("\n SIZE of PING Packet is: %d \n", sizeof(gpacket_t));
/*			if(in_pkt->frame.src_interface == 1){
				printf("\n RECEIVED PACKET FROM INTERFACE 1");

			in_pkt->frame.dst_interface = 2;			// HATA DO MUJHE

			in_pkt->data.header.src[0] = in_pkt->data.header.dst[0];
			in_pkt->data.header.src[1] = in_pkt->data.header.dst[1];
			in_pkt->data.header.src[2] = in_pkt->data.header.dst[2];
			in_pkt->data.header.src[3] = in_pkt->data.header.dst[3];
			in_pkt->data.header.src[4] = in_pkt->data.header.dst[4];
			in_pkt->data.header.src[5] = in_pkt->data.header.dst[5];

			in_pkt->data.header.dst[0] = 254;
			in_pkt->data.header.dst[1] = 253;
			in_pkt->data.header.dst[2] = 2;
			in_pkt->data.header.dst[3] = 0;
			in_pkt->data.header.dst[4] = 0;
			in_pkt->data.header.dst[5] = 1;

			in_pkt->data.header.src[0] = 254;
			in_pkt->data.header.src[1] = 253;
			in_pkt->data.header.src[2] = 3;
			in_pkt->data.header.src[3] = 01;
			in_pkt->data.header.src[4] = 0;
			in_pkt->data.header.src[5] = 2;
			}
			else if(in_pkt->frame.src_interface == 2){
				printf("\n RECEIVED PACKET FROM INTERFACE 2");

				in_pkt->frame.dst_interface = 1;
				in_pkt->data.header.src[0] = in_pkt->data.header.dst[0];
				in_pkt->data.header.src[1] = in_pkt->data.header.dst[1];
				in_pkt->data.header.src[2] = in_pkt->data.header.dst[2];
				in_pkt->data.header.src[3] = in_pkt->data.header.dst[3];
				in_pkt->data.header.src[4] = in_pkt->data.header.dst[4];
				in_pkt->data.header.src[5] = in_pkt->data.header.dst[5];

				in_pkt->data.header.dst[0] = 254;
				in_pkt->data.header.dst[1] = 253;
				in_pkt->data.header.dst[2] = 2;
				in_pkt->data.header.dst[3] = 0;
				in_pkt->data.header.dst[4] = 0;
				in_pkt->data.header.dst[5] = 2;

				in_pkt->data.header.src[0] = 254;
				in_pkt->data.header.src[1] = 253;
				in_pkt->data.header.src[2] = 03;
				in_pkt->data.header.src[3] = 01;
				in_pkt->data.header.src[4] = 0;
				in_pkt->data.header.src[5] = 1;
			}*/

			writeQueue(queue1, (void *)in_pkt, sizeof(gpacket_t));
		}
	}

	printf("\n ************************Check Point 3*************************** \n");

}

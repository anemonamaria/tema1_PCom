#include <queue.h>
#include "skel.h"
#include <netinet/if_ether.h>
#include <netinet/ip.h>

typedef struct rtable_struct {
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
    int interface;
} rtable_struct;

typedef struct arp_struct {
    uint32_t ip;
    uint8_t mac[6];
}  arp_struct;

// functie de parsare a tabelei de rutare
void parse_routable(FILE *fin, rtable_struct *table) {
	int lines = 0;
	for (char c = getc(fin); c != EOF; c = getc(fin)) {
        if (c == '\n') {
            lines++;
        }
    }
    if (fseek(fin, 0L, SEEK_SET) != 0) {
        printf("File error");
    }

	char prefix[25], next_hop[25], mask[25];
	int interface;
    for (int i = 0; i < lines; i++) {
        fscanf(fin, "%s %s %s %d\n", prefix, next_hop, mask, &interface);
        table[i].prefix = inet_addr(prefix);
        table[i].mask = inet_addr(mask);
        table[i].next_hop = inet_addr(next_hop);
        table[i].interface = interface;
		// citim variabilele care se afla in fisier
    }
}

// functie pentru a cauta cea mai buna ruta pe tabela de routare
int binarySearch(int left, int right, __u32 dest, rtable_struct *table) {
    if (left > right) {
        return -1;
    } else {
        if (table[(left + right)/2].prefix == dest) {
            return (left + right)/2;
        } else if (table[(left + right)/2].prefix > dest) {
            binarySearch(left, (left + right)/2 - 1, dest, table);
        } else {
            binarySearch((left + right)/2 + 1, right, dest, table);
        }
    }
    return -1;
}

//functia de cautare a routei cea mai bune
rtable_struct *get_best_route(__u32 dest, int dim, rtable_struct *table) {
    rtable_struct *best = NULL;
	//  get_best_route realizeaza o cautare in timp O(logn)

	int idx = binarySearch(0, dim, dest, table);
	for (int i = idx; i < dim; i++){
		int x = dest & table[i].mask;
		if(x == table[i].prefix){
			if(best == NULL)
				best = &table[i];
			else if(best->mask < table[i].mask)
				best = &table[i];
		}
	}
    return best;
}

struct arp_struct *get_arp_entry(arp_struct *arptable, int arptable_size, uint32_t dest) {
  	// searching ip address
  	for (int i = 0; i < arptable_size; i++){
		if (arptable[i].ip == dest)
			return &arptable[i];
  	}

  	return NULL;
}

int main(int argc, char *argv[]) {
    packet m;
	int rc;
    FILE *file  = fopen(argv[1], "r");

	// retinem numarul de linii din fisier ca sa putem aloca memoria tabelei de
	// routare
	int rSize = 0;
	for (char c = getc(file); c != EOF; c = getc(file)) {
        if (c == '\n') {
            rSize++;
        }
    }
    if (fseek(file, 0L, SEEK_SET) != 0) {
        printf("File error");
    }

	arp_struct *arptable = malloc(sizeof(arp_struct) * rSize);
    int arptable_size = 0;
   	rtable_struct *r_table_entry = (rtable_struct *) malloc(rSize *
	   								 sizeof(rtable_struct));

	queue q = queue_create();
  	int queue_length = 0;
    parse_routable(file, r_table_entry);
    //parse_arp_table(arp_table);

    setvbuf(stdout, NULL, _IONBF, 0);

    init(argc - 2, argv + 2);
    while (1) {
        rc = get_packet(&m);
        DIE(rc < 0, "get_message");
        /* Students will write code here */

		rtable_struct *r_table;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
    	struct icmphdr *icmp = (struct icmphdr *)(m.payload +
					sizeof(struct ether_header) + sizeof(struct iphdr));
    	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct ether_arp *eth_arp =
          	(struct ether_arp *)(m.payload + sizeof(struct ether_header));

		/// TODO: MODIFICA DE AICI
 		/* am primit arp request, trimitem reply*/
 	    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			// // actualizam tabela arp si trimitem ceea ce se afla in coada/
      		if (ntohs(eth_arp->arp_op) == ARPOP_REQUEST) {

        		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,
               	sizeof(eth_hdr->ether_shost));
        		get_interface_mac(m.interface, eth_hdr->ether_shost);

				memcpy(eth_arp->arp_tha, eth_arp->arp_sha, sizeof(eth_arp->arp_sha));
				get_interface_mac(m.interface, eth_arp->arp_sha);
				eth_arp->arp_op = htons(ARPOP_REPLY);

				char aux3[6];
				memcpy(aux3, eth_arp->arp_spa, sizeof(eth_arp->arp_spa));
				memcpy(eth_arp->arp_spa, eth_arp->arp_tpa,
					sizeof(eth_arp->arp_tpa));  // arp sender protocol (ip)
				memcpy(eth_arp->arp_tpa, aux3,
					sizeof(eth_arp->arp_spa));  // arp target protocol(ip)
				send_packet(m.interface, &m);
				continue;
      		}

			/* received arp reply, updating arp table and sending packets*/
			if (ntohs(eth_arp->arp_op) == ARPOP_REPLY) {
				// creeaza intrarea in tabel
				//////////////////////////////////////////////////////////////////////
				// obtine sender protocol address sub forma uint32_t
				uint32_t arp_spa = 0;
				for(int i = 0; i < 4; i++){
					arp_spa = (arp_spa << 8) ^ eth_arp->arp_spa[i];
				}
				///////////////////////////////////////////////////////////////////
				arptable[arptable_size].ip = arp_spa;
				arptable_size++;

				// sending packets from queue
				int i = 0;
				for(i = 0; i < queue_length; i++) {
					packet *left = queue_deq(q);
					struct ether_header *eth = (struct ether_header *)left->payload;
					get_interface_mac(left->interface, eth->ether_shost);
					memcpy(eth->ether_dhost, eth_arp->arp_sha, sizeof(eth_arp->arp_sha));
					send_packet(left->interface, left);
					free(left);
					queue_length--;
				}
				continue;
			}
		}
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
				memcpy(eth_hdr->ether_shost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_shost));
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				eth_hdr->ether_type = htons(ETHERTYPE_IP);
				icmp->type = ICMP_ECHOREPLY;
				// echoreply

				icmp->code = 0;
				icmp->un.echo.id = htons(getpid());

				icmp->checksum = 0;
				icmp->checksum = ip_checksum(icmp, sizeof(struct icmphdr));

				uint32_t s_addr = ip_hdr->saddr;
				ip_hdr->saddr = ip_hdr->daddr;
				ip_hdr->daddr = s_addr;
				ip_hdr->tos = 0;
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->id = htons(getpid());
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));
				m.len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct ether_header);
				//send_icmp(s_addr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, m.interface, htons(getpid()), 50);

			}
		}
		if ( ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
            /* if there is a packet with the wrong checksum, throw the packet */
            continue;
        }
        if (ip_hdr->ttl <= 1) {
            //icmpType(11);
			uint32_t s_addr = ip_hdr->saddr;
			send_icmp(s_addr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 11, 0, m.interface, htons(getpid()), 50);

            continue;
        }
		rtable_struct *next_ip = get_best_route(ip_hdr->daddr, rSize, r_table_entry);
        if (next_ip == NULL) {
            //icmpType(3);
			uint32_t s_addr = ip_hdr->saddr;
			send_icmp(s_addr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 3, 0, m.interface, htons(getpid()), 50);
            continue;
        }

        // decrement ttl, update checksum
        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

        /* create a new structure route_table_ent [struct rtable_struct *r_table]
        from which i will get the best route */
        r_table = get_best_route(ip_hdr->daddr, rSize, r_table_entry);
		arp_struct * dest = get_arp_entry(arptable, arptable_size, r_table->next_hop);

		// if (dest == NULL) {
		// 	queue_length++;
		// 	packet req;

		// 	struct ether_header *req_hdr = (struct ether_header *)req.payload;
		// 	struct ether_arp *eth_arp =
		// 		(struct ether_arp *)(req.payload + sizeof(struct ether_header));


		// 	req.interface = next_ip->interface;
		// 	get_interface_mac(req.interface, req_hdr->ether_shost);
		// 	hwaddr_aton("ff:ff:ff:ff:ff:ff", req_hdr->ether_dhost);

		// 	eth_arp->arp_op = htons(ARPOP_REQUEST);
		// 	eth_arp->arp_hrd = htons(ARPHRD_ETHER);
		// 	eth_arp->arp_pro = htons(ETHERTYPE_IP);
		// 	eth_arp->arp_hln = 6;
		// 	eth_arp->arp_pln = 4;
		// 	req_hdr->ether_type = htons(0x0806);

		// 	get_interface_mac(next_ip->interface,
		// 						eth_arp->arp_sha);  // arp frame sender
		// 	memcpy(eth_arp->arp_spa, get_interface_ip(next_ip->interface),
		// 			sizeof(get_interface_ip(
		// 				next_ip->interface)));  // arp sender protocol (ip)
		// 	hwaddr_aton("00:00:00:00:00:00", eth_arp->arp_tha);
		// 	// arp frame target address
		// 	memcpy(eth_arp->arp_tpa, &next_ip->next_hop,
		// 			sizeof(next_ip->next_hop));  // arp target protocol(ip)
		// 	req.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
		// 	send_packet(req.interface, &req);

		// 	get_interface_mac(next_ip->interface, eth_hdr->ether_shost);
		// 	m.interface = next_ip->interface;
		// 	packet other = m;
		// 	queue_enq(q, &other);

		// 	continue;
		//  }


		get_interface_mac(next_ip->interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, arptable->mac, sizeof(eth_hdr->ether_dhost));
		send_packet(next_ip->interface, &m);
    }
    return 0;
}


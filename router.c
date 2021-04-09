#include <queue.h>
#include "skel.h"
#include <netinet/if_ether.h>

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

void parse_arp_table(arp_struct *arpTable) {
    FILE *fin = fopen("arp_table.txt", "r");

    int lines = 0;
	for (char c = getc(fin); c != EOF; c = getc(fin)) {
        if (c == '\n') {
            lines++;
        }
    }
    if (fseek(fin, 0L, SEEK_SET) != 0) {
        printf("File error");
    }
	arpTable = malloc (lines * sizeof(arp_struct));

	char ip[100], mac[100];

    for (int i = 0; i < lines; i++) {
        fscanf(fin, "%s %s\n", ip, mac);
		// citim din fisier variabilele
		// folosim: -functia inet_addr() pentru a transforma variabilele
		// din string in format IPv4
		// -functia hwaddr_aton() converteste ascii in adresa mac
	   	arpTable[i].ip = inet_addr(ip);
        hwaddr_aton(mac, arpTable[i].mac);
    }
}

// functie pentru a cauta cea mai buna ruta pe tabela de routare
int binarySearch(int left, int right, __u32 dest_ip,
                rtable_struct *table) {
    if (left > right) {
        return -1;
    } else {
        int mid = (left + right)/2;// >> 1;
        if (table[mid].prefix == dest_ip) {
            return mid;
        } else if (table[mid].prefix > dest_ip) {
            binarySearch(left, mid - 1, dest_ip, table);
        } else {
            binarySearch(mid + 1, right, dest_ip, table);
        }
    }
    return -1;
}

//functia de cautare a routei cea mai bune
rtable_struct *get_best_route(
    __u32 dest_ip, int lines, rtable_struct *table) {
    rtable_struct *best = NULL;
	//  get_best_route realizeaza o cautare in timp O(logn)

	int idx = binarySearch(0, lines, dest_ip, table);
	for (int i = idx; i < lines; i++){
		int x = dest_ip & table[i].mask;
		if(x == table[i].prefix){
			if(best == NULL)
				best = &table[i];
			else if(best->mask < table[i].mask)
				best = &table[i];
		}
	}
    return best;
}


// 2. Protocolul Arp

// Cand primesc un pachet verific daca ether_type este de tip Arp
// dupa care daca este Arp request caz in care modific pachetul primit
// completand macul routerului si inversand ether_shost cu ether_dhost
// si arp_tpa cu arp_spa.

// Daca am primit un Arp reply completez tabela mea arp cu macul.ul primit
// si parcurg coada pentru a trimite pachetele din acestea.

// Daca am primit un pachet pentru care nu cunosc adresa mac fac un pachet nou
// de tip Arp request, completez adresa broadcast si celelalte campuri necesare
// (arp_spa pentru ip-ul a carui mac il caut, arp_op pentru tipul operatiei...).
// Mesajul il bag in coada si trimit requestul.

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

	arp_struct *arptable = malloc(sizeof(arp_struct) * 100000);
    int arptable_size = 0;
   	rtable_struct *r_table_ent = (rtable_struct *) malloc(rSize *
	   								 sizeof(rtable_struct));
   // arp_struct *arp_table = (arp_struct *) malloc(sizeof(arp_struct));

	queue to_send = queue_create();
  	int size_q = 0;
    parse_routable(file, r_table_ent);
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
	//////////////////////////////////////////////////////////////////////////////
    	struct ether_header *eth_hdr = (struct ether_header *)m.payload;


		  /*received an arp packet*/
	    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
    	  	struct ether_arp *arp_eth =
          	(struct ether_arp *)(m.payload + sizeof(struct ether_header));
      		/* received arp request and sending arp reply*/
      		if (ntohs(arp_eth->arp_op) == ARPOP_REQUEST) {
        		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,
               	sizeof(eth_hdr->ether_shost));
        		get_interface_mac(m.interface, eth_hdr->ether_shost);

				memcpy(arp_eth->arp_tha, arp_eth->arp_sha, sizeof(arp_eth->arp_sha));
				get_interface_mac(m.interface, arp_eth->arp_sha);
				arp_eth->arp_op = htons(ARPOP_REPLY);

				char aux3[6];
				memcpy(aux3, arp_eth->arp_spa, sizeof(arp_eth->arp_spa));
				memcpy(arp_eth->arp_spa, arp_eth->arp_tpa,
					sizeof(arp_eth->arp_tpa));  // arp sender protocol (ip)
				memcpy(arp_eth->arp_tpa, aux3,
					sizeof(arp_eth->arp_spa));  // arp target protocol(ip)
				send_packet(m.interface, &m);
				continue;
      		}

			/* received arp reply, updating arp table and sending packets*/
			if (ntohs(arp_eth->arp_op) == ARPOP_REPLY) {
				//arptable[arptable_size].ip = inet_addr(arp_eth->arp_spa);
				//hwaddr_aton(arp_eth->arp_sha, arptable[arptable_size].mac);
				arptable_size++;

				// sending packets from queue
				int i = 0;
				for(i = 0; i < size_q; i++) {
				packet *x = queue_deq(to_send);
				struct ether_header *eth = (struct ether_header *)x->payload;
				get_interface_mac(x->interface, eth->ether_shost);
				memcpy(eth->ether_dhost, arp_eth->arp_sha, sizeof(arp_eth->arp_sha));
				send_packet(x->interface, x);

				}
				size_q = 0;
				continue;
			}
		}

        if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
            icmp->type = ICMP_ECHOREPLY;
			// echoreply

			icmp->code = 0;
			icmp->un.echo.id = htons(getpid());
			// unic

			icmp->checksum = 0;
			icmp->checksum = ip_checksum(icmp, sizeof(struct icmphdr));
			//Inițializați headerul de ICMP si IPV4 cu informațiile necesare.

			uint32_t s_addr = ip_hdr->saddr;
	        ip_hdr->saddr = ip_hdr->daddr;
	        ip_hdr->daddr = s_addr;
			ip_hdr->tos = 0;
			// serviciu de tip ip
			ip_hdr->protocol = IPPROTO_ICMP;
			// Procotol => ICMP
			ip_hdr->id = htons(getpid());
			// Unic
			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));
			m.len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct ether_header);
			//lungimea totala
			//send_icmp(s_addr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, ICMP_ECHOREPLY, 0, m.interface, htons(getpid()), 50);

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
        if (get_best_route(ip_hdr->daddr, rSize, r_table_ent) == NULL) {
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
        r_table = get_best_route(ip_hdr->daddr, rSize, r_table_ent);
        // update the interface from the packet
        m.interface = r_table->interface;
        // send packet to other hosts
        send_packet(m.interface, &m);
    }
    return 0;
}
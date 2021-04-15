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
void parse_routable(FILE *fin, rtable_struct *table, int rSize) {
	char prefix[25], next_hop[25], mask[25];
	int interface;
    for (int i = 0; i < rSize; i++) {
		fscanf(fin, "%s", prefix);
        table[i].prefix = inet_addr(prefix);
		fscanf(fin, "%s", next_hop);
        table[i].next_hop = inet_addr(next_hop);
		fscanf(fin, "%s", mask);
		table[i].mask = inet_addr(mask);
		fscanf(fin, "%d", &interface);
        table[i].interface = interface;
		// citim variabilele care se afla in fisier
    }
	fclose(fin);
}

// functie pentru a cauta cea mai buna ruta pe tabela de routare
int binarySearch(int left, int right, __u32 dest, rtable_struct *table) {
    if (left <= right) {
        if (table[(left + right)/2].prefix == (table[(left + right)/2].mask & dest))
            return (left + right)/2;
        else if (table[(left + right)/2].prefix >(table[(left + right)/2].mask & dest))
            binarySearch(left, (left + right)/2 - 1, dest, table);
        else
            binarySearch((left + right)/2 + 1, right, dest, table);
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
			if(best == NULL || (best->mask < table[i].mask))
				best = &table[i];
		}
	}
    return best;
}

// functia de cautare a unei rute arp in functie de ip
arp_struct *get_arp_entry(arp_struct *arptable, int arptable_size, uint32_t dest) {
  	for (int i = 0; i < arptable_size; i++){
		if (arptable[i].ip == dest)
			return &arptable[i];
  	}

  	return NULL;
}

// functia ajutatoare pentru qsort
int compare (const void *a, const void *b) {
	uint32_t pref_a = ((rtable_struct *)a)->prefix;
	uint32_t pref_b = ((rtable_struct *)b)->prefix;
	if(pref_a == pref_b)
		return (int)(((rtable_struct *)a)->mask - ((rtable_struct *)b)->mask);
	else
		return (pref_a - pref_b);
}

// functie pentru completarea icmphdr-ului
void build_icmphdr(struct icmphdr *icmp, uint8_t type) {
	icmp->type = type;
	icmp->un.echo.id = htons(getpid());
	icmp->checksum = ip_checksum(icmp, sizeof(struct icmphdr));
}

// functie pentru completarea ip_hdr
void build_ip_hdr(struct iphdr *ip_hdr, uint8_t protocol, uint32_t saddr, uint32_t daddr) {
	ip_hdr->protocol = protocol;
	ip_hdr->id = htons(getpid());
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
	ip_hdr->saddr = daddr;
	ip_hdr->daddr = saddr;
}

// functie pentru completarea eth_arp
void build_eth_arp(struct ether_arp *eth_arp, int interface, uint16_t aux) {
	memcpy(eth_arp->arp_tha, eth_arp->arp_sha, sizeof(eth_arp->arp_sha));
	get_interface_mac(interface, eth_arp->arp_sha);
	memcpy(eth_arp->arp_spa, eth_arp->arp_tpa, 4);
	memcpy(eth_arp->arp_tpa, eth_arp->arp_spa, 4);
	eth_arp->arp_op = aux;
}

int main(int argc, char *argv[]) {
    packet m;
	int rc;
    FILE *file  = fopen(argv[1], "r");

	// retinem numarul de linii din fisier ca sa putem aloca memoria tabelei de
	// routare
	int rSize = 0;
	char chr;
	while((chr = getc(file)) != EOF) {
		if (chr == '\n')
            rSize++;
	}

	DIE(fseek(file, 0L, SEEK_SET) != 0, "ERROR");

	arp_struct *arptable = (arp_struct *) malloc(sizeof(arp_struct) * rSize);
    int arptable_size = 0;
   	rtable_struct *rtable = (rtable_struct *) malloc(rSize * sizeof(rtable_struct));

	queue q = queue_create();
  	int queue_length = 0;
    parse_routable(file, rtable, rSize);
	qsort(rtable, rSize, sizeof(rtable_struct), compare);

    setvbuf(stdout, NULL, _IONBF, 0);

    init(argc - 2, argv + 2);
    while (1) {
        rc = get_packet(&m);
        DIE(rc < 0, "get_message");
        /* Students will write code here */

		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
    	struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		// am primit un pachet ip
		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP &&
			ip_hdr->protocol == IPPROTO_ICMP){
			struct icmphdr *icmp = (struct icmphdr *)(m.payload +
					sizeof(struct ether_header) + sizeof(struct iphdr));
			// trimitem echo reply daca pachetul este destinat router-ului
			if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))
				&& icmp->type == ICMP_ECHO) {
				build_ethhdr(eth_hdr, eth_hdr->ether_dhost, eth_hdr->ether_shost, htons(ETHERTYPE_IP));
				build_icmphdr(icmp, ICMP_ECHOREPLY);
				build_ip_hdr(ip_hdr, IPPROTO_ICMP, ip_hdr->saddr, ip_hdr->daddr);
				m.len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct ether_header);
				send_packet(m.interface, &m);
				continue;
			}
		}

 		// am primit arp request, trimitem reply
 	    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct ether_arp *eth_arp = (struct ether_arp *)(m.payload +
							sizeof(struct ether_header));
      		if (ntohs(eth_arp->arp_op) == ARPOP_REQUEST) {
				// trimitem arp reply
				build_ethhdr(eth_hdr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
					eth_hdr->ether_type);
        		get_interface_mac(m.interface, eth_hdr->ether_shost);
				build_eth_arp(eth_arp, m.interface, htons(ARPOP_REPLY));
				send_packet(m.interface, &m);

				continue;
      		}

			// am primit arp reply, actualizam tabela arp si trimitem pachete
			if (ntohs(eth_arp->arp_op) == ARPOP_REPLY) {
				// creeaza intrarea in tabel
				for(int i = 0; i < 4; i++){
					arptable[arptable_size].ip = (arptable[arptable_size].ip << 8)
												 ^ eth_arp->arp_spa[i];
				}
				arptable_size++;
				// trimitem pachetele din coada
				while(queue_length != 0) {
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


		// daca pachetul contine checksum gresit, il aruncam
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
            continue;
        }

		//trimitem time exceed daca ttl <= 1
        if (ip_hdr->ttl <= 1) {
			send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 11,
						0, m.interface, htons(getpid()), 50);
            continue;
        }

        // decrementam ttl-ul, actualiam checksum-ul
        ip_hdr->ttl--;
        ip_hdr->check = 0;
        ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		// trimitem host unreachable daca nu gasim cea mai buna ruta
		rtable_struct *best_route = get_best_route(ip_hdr->daddr, rSize, rtable);
        if (best_route == NULL) {
			send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost,
						ICMP_DEST_UNREACH, 0, m.interface, htons(getpid()), 50);
            continue;
        }

		// daca nu exitsa intrarea nexthop-ului, trimit arp request si salvez pachetul intr-o coada
		arp_struct * arp_entry = get_arp_entry(arptable, arptable_size, best_route->next_hop);
		if (arp_entry == NULL) {
			struct ether_arp *eth_arp2 = (struct ether_arp *)(m.payload + sizeof(struct ether_header));

			queue_length++;
			m.interface = best_route->interface;
			packet wait = m;
			queue_enq(q, &wait);

			m.interface = best_route->interface;
			get_interface_mac(m.interface, eth_hdr->ether_shost);
			memset(eth_hdr->ether_dhost, 255, 6);
			eth_hdr->ether_type = htons(ETHERTYPE_ARP);

			eth_arp2->arp_op = htons(1);
			eth_arp2->arp_hrd = 256;
			eth_arp2->arp_pro = 8;
			eth_arp2->arp_hln = 6;
			eth_arp2->arp_pln = 4;

			get_interface_mac(best_route->interface, eth_arp2->arp_sha);
			memcpy(eth_arp2->arp_spa, get_interface_ip(best_route->interface), 4);
			memcpy(eth_arp2->arp_tpa, &best_route->next_hop, 4);
			m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
			send_packet(m.interface, &m);
			continue;
		}
    }
    return 0;
}
#include "skel.h"
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "queue.h"

typedef struct { // structura routing table entry
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} rt_entry;

rt_entry *rt_table;

typedef struct { // structura arp table entry
	uint32_t ip;
	uint8_t mac[6];
} arp_entry;

arp_entry *arp_table;

#define START_CAPACITY 5 // capacitatea de start a rt_table cat si a lui arp_table
int curr_size = 0, arp_size = 0; // cate intrari sunt in fiecare table la inceput

// functia de checksum din lab
uint16_t ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

// functia de checksum de la bonus
void checksum_incremental(uint16_t* check, uint16_t* old_value, uint16_t new_value){
  	uint32_t sum;

   	sum = ~ntohs(*check) & 0xffff;
 	sum += (~ntohs(*old_value) & 0xffff) + (new_value & 0xffff);
  	sum = (sum >> 16) + (sum & 0xffff);
  	sum += (sum >> 16);

  	*check = htons(~sum & 0xffff);
  	*old_value = htons(new_value);
}

// obtine o adresa de tip uint32_t dintr-o adresa de forma "123.123.123.123"
uint32_t convert_string_to_ip_addr(char ip_string[]){
   char *token;
   uint32_t builder = 0;
   uint32_t builder_mask;

   token = strtok(ip_string, ".");

   while( token != NULL ) {
	  builder_mask = atoi(token);
	  builder = (builder << 8) ^ builder_mask;
      token = strtok(NULL, ".");
   }

   return builder;
}

// parsarea fisierului rtable.txt si adaugarea intrarilor in tabel
void parse_rt_table(char file_name[]){
	FILE *fp = fopen(file_name, "r");
	DIE(fp == NULL, "nu s-a putut citi din fisier sau el nu exista");

	int capacity = START_CAPACITY;

	char line[100], prefix[25], next_hop[25], mask[25];
	int interface;

	while(fgets(line, 99, fp) != NULL){
		if(curr_size == capacity){
			capacity += curr_size;
			rt_table = realloc (rt_table, sizeof(rt_entry) * capacity);
		}

		sscanf(line, "%s%s%s%i", prefix, next_hop, mask, &interface);

		rt_table[curr_size].prefix = convert_string_to_ip_addr(prefix);
		rt_table[curr_size].next_hop = convert_string_to_ip_addr(next_hop);
		rt_table[curr_size].mask = convert_string_to_ip_addr(mask);
		rt_table[curr_size].interface = interface;

		curr_size++;
	}
	fclose(fp);
}

// functia de comparare folosita pentru a sorta rt_table
int cmp_func (const void *a, const void *b){
	rt_entry rta = *(rt_entry *)a;
	rt_entry rtb = *(rt_entry *)b;
	if(rta.prefix == rtb.prefix){
		return (int)(rtb.mask - rta.mask);
	}
	else{
		return (int)(rta.prefix - rtb.prefix);
	}
}


// functia de cautare in rt_table folosind binary search modificata dupa masca si prefix
rt_entry *search(rt_entry key, int left, int right){
	int mid = (left + right) / 2;
	uint32_t prefix = rt_table[mid].prefix, mask = rt_table[mid].mask;
	if ((key.prefix & mask) == prefix){
		// daca am ajuns intr-un punct terminal, adica exista o singura valoare sau alte valori nu se potrivesc
		// intorc ce am gasit
		if(mid == 0 || rt_table[mid - 1].prefix != (key.prefix & mask))
			return &rt_table[mid];
		// daca am gasit o masca mai buna continuam cautarea, poate se va gasi una mai buna
		if(rt_table[mid].mask > key.mask){
			key.mask = rt_table[mid].mask;
			return search(key, left, mid - 1);
		}
		// in caz contrar am gasit cea mai bun masca
		else{
			if(rt_table[mid].mask == key.mask)
				return &rt_table[mid];
		}
	}
	// opreste cautarea cand nu s-a gasit intrarea cautata
	if(right <= left){
		return NULL;
	}
	// continua cautarea dupa prefix
	if((key.prefix & mask) < rt_table[mid].prefix){
		return search(key, left, mid - 1);
	}
	if((key.prefix & mask) > rt_table[mid].prefix){
		return search(key, mid + 1, right);
	}
	return NULL;
}

// cauta intrarea din arp_table care se potriveste cu ip-ul next-hopului
arp_entry *get_arp_entry(uint32_t dest_ip){
	for(int i = 0; i < arp_size; i++){
		if(dest_ip == arp_table[i].ip){
			return &arp_table[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet received, replied;
	int rc;

	queue packet_q;
	packet_q = queue_create();

	init();

	rt_table = calloc (START_CAPACITY, sizeof(rt_entry));
	arp_table = calloc (START_CAPACITY, sizeof(arp_entry));
	int arp_capacity = START_CAPACITY;

	parse_rt_table("rtable.txt");
	qsort(rt_table, curr_size, sizeof(rt_entry), cmp_func);

	while (1) {
		rc = get_packet(&received);
		DIE(rc < 0, "get_message");

		// Students will write code here

		// headerele pentru pachetul primit
		struct ether_header *eth_hdr_received = (struct ether_header *)received.payload;
		struct iphdr *ip_hdr_received = (struct iphdr *)(received.payload + sizeof(struct ether_header));
		struct ether_arp *arp_hdr_received = (struct ether_arp *)(received.payload + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr_received = (struct icmphdr *)(received.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

		// headerele pentru pachetul trimis
		struct ether_header *eth_hdr_replied = (struct ether_header *)replied.payload;
		struct ether_arp *arp_hdr_replied = (struct ether_arp *)(replied.payload + sizeof(struct ether_header));
		struct iphdr *ip_hdr_replied = (struct iphdr *)(replied.payload + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr_replied = (struct icmphdr *)(replied.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

		// Variabile folosite la cautarea in tabele
		rt_entry *rt_table_entry = NULL;
		arp_entry *arp_table_entry = NULL;

		// daca am primit un pachet de tip IP
		if(ntohs(eth_hdr_received->ether_type) == ETHERTYPE_IP){
			// daca am primit un pachet destinat routerului trimite inapoi echo reply
			if((ntohl(ip_hdr_received->daddr) == convert_string_to_ip_addr(get_interface_ip(received.interface)))){
				if(icmp_hdr_received->type == ICMP_ECHO){
					memcpy(eth_hdr_replied->ether_shost, eth_hdr_received->ether_shost, sizeof(eth_hdr_replied->ether_shost));
					memcpy(eth_hdr_received->ether_shost, eth_hdr_received->ether_dhost, sizeof(eth_hdr_received->ether_shost));
					memcpy(eth_hdr_received->ether_dhost, eth_hdr_replied->ether_shost, sizeof(eth_hdr_received->ether_dhost));
					eth_hdr_received->ether_type = htons(ETHERTYPE_IP);

					uint32_t aux;
					memcpy(&aux, &ip_hdr_received->saddr, sizeof(ip_hdr_received->saddr));
					memcpy(&ip_hdr_received->saddr, &ip_hdr_received->daddr,sizeof(ip_hdr_received->saddr));
					memcpy(&ip_hdr_received->daddr, &aux, sizeof(ip_hdr_received->daddr));
					ip_hdr_received->check = 0;
					ip_hdr_received->check = ip_checksum(ip_hdr_received, sizeof(struct iphdr));

					icmp_hdr_received->code = 0;
					icmp_hdr_received->type = ICMP_ECHOREPLY;
					icmp_hdr_received->checksum = 0;
					icmp_hdr_received->checksum = ip_checksum(icmp_hdr_received, sizeof(struct icmphdr));

					send_packet(received.interface, &received);
				}
				continue; // daca e destinat routerului si nu este un ECHO REQUEST skip it
			}
		}

		// daca am primit un pachet de tip ARP
		if(ntohs(eth_hdr_received->ether_type) == ETHERTYPE_ARP){
			// daca este un pachet de tip ARP REQUEST
			if(ntohs(arp_hdr_received->arp_op) == ARPOP_REQUEST){

				uint32_t ip = convert_string_to_ip_addr(get_interface_ip(received.interface));

				uint32_t tpa = 0, helper; // obtin target protocol address sub forma uint32_t
				for(int i = 0; i < 4; i++){
					helper = arp_hdr_received->arp_tpa[i];
					tpa = (tpa << 8) ^ helper;
				}

				if(ip == tpa){ // daca e destinat routerului trimit inapoi ARP_REPLY

					replied.interface = received.interface;
					replied.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

					memcpy(eth_hdr_replied->ether_dhost, eth_hdr_received->ether_shost, sizeof(eth_hdr_replied->ether_dhost));
					get_interface_mac(received.interface, eth_hdr_replied->ether_shost);
					eth_hdr_replied->ether_type = htons(ETHERTYPE_ARP);

					memcpy(arp_hdr_replied, arp_hdr_received, sizeof(*arp_hdr_replied));
					arp_hdr_replied->arp_op = htons(ARPOP_REPLY);


					memcpy(arp_hdr_replied->arp_tha, eth_hdr_received->ether_shost, sizeof(arp_hdr_replied->arp_tha));
					memcpy(arp_hdr_replied->arp_tpa, arp_hdr_received->arp_spa, sizeof(arp_hdr_replied->arp_tpa));
					get_interface_mac(received.interface, arp_hdr_replied->arp_sha);
					memcpy(arp_hdr_replied->arp_spa, arp_hdr_received->arp_tpa, sizeof(arp_hdr_replied->arp_spa));

					send_packet(received.interface, &replied);
				}
				continue; // daca nu este destinat routerului atunci arunca pachetul
			}

			// in cazul in care va urma sa primim un ARP REPLY verificam capacitatea tabelei arp
			if(arp_size == arp_capacity){
				arp_capacity += arp_size;
				arp_table = realloc(arp_table, arp_capacity * sizeof(arp_entry));
			}

			// daca este un pachet ARP REPLY adaugam intrarea arp in tabela si trimitem mesajele din coada
			if(ntohs(arp_hdr_received->arp_op) == ARPOP_REPLY){

				// creeaza intrarea in tabel
				arp_entry entry;

				// obtine sender protocol address sub forma uint32_t
				uint32_t spa = 0, spa_helper;
				for(int i = 0; i < 4; i++){
					spa_helper = arp_hdr_received->arp_spa[i];
					spa = (spa << 8) ^ spa_helper;
				}

				entry.ip = spa;
				memcpy(entry.mac, eth_hdr_received->ether_shost, sizeof(entry.mac));
				arp_table[arp_size++] = entry;

				while(!queue_empty(packet_q)){ // cat timp mai sunt pachete de trimis, trimite-le
					packet *helper = queue_deq(packet_q);
					rt_table_entry = queue_deq(packet_q);
					struct ether_header *eth_hdr_helper = (struct ether_header *)helper->payload;

					get_interface_mac(rt_table_entry->interface, eth_hdr_helper->ether_shost);
					memcpy(eth_hdr_helper->ether_dhost, eth_hdr_received->ether_shost, sizeof(eth_hdr_helper->ether_dhost));

					send_packet(rt_table_entry->interface, helper);
					free(helper);
				}
			}
			continue;
		}

		// daca am primit un pachet cu TTL <= 1 trimite inapoi TIME EXCEEDED
		if(ip_hdr_received->ttl <= 1){
			// creaza pachetul trimis inapoi

			replied.interface = received.interface;
			replied.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

			memcpy((icmp_hdr_replied + 1), ip_hdr_received, sizeof(struct iphdr) + 8);

			memcpy(eth_hdr_replied->ether_dhost, eth_hdr_received->ether_shost, sizeof(eth_hdr_replied->ether_dhost));
			get_interface_mac(received.interface, eth_hdr_replied->ether_shost);
			eth_hdr_replied->ether_type = htons(ETHERTYPE_IP);

			memcpy(&ip_hdr_replied->saddr, &ip_hdr_received->daddr, sizeof(ip_hdr_replied->saddr));
			memcpy(&ip_hdr_replied->daddr, &ip_hdr_received->saddr, sizeof(ip_hdr_replied->daddr));
			ip_hdr_replied->version = IPVERSION;
			ip_hdr_replied->ihl = 5;
			ip_hdr_replied->tos = 0;
			ip_hdr_replied->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
			ip_hdr_replied->id = htons(getpid());
			ip_hdr_replied->frag_off = 0;
			ip_hdr_replied->ttl = MAXTTL;
			ip_hdr_replied->protocol = IPPROTO_ICMP;
			ip_hdr_replied->check = 0;
			ip_hdr_replied->check = ip_checksum(ip_hdr_replied, sizeof(struct iphdr));

			icmp_hdr_replied->code = 0;
			icmp_hdr_replied->type = ICMP_TIME_EXCEEDED;
			icmp_hdr_replied->checksum = 0;
			icmp_hdr_replied->checksum = ip_checksum(icmp_hdr_replied, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

			send_packet(received.interface, &replied);
			continue; // dupa ce am trimis pachetul treci la urmatorul
		}

		// daca checksum-ul pachetului este gresit, atunci arunca pachetul
		__u16 sum = ip_hdr_received->check;
		ip_hdr_received->check = 0;
		if(sum != ip_checksum(ip_hdr_received, sizeof(struct iphdr))){
			continue;
		}
		ip_hdr_received->check = ip_checksum(ip_hdr_received, sizeof(struct iphdr));

		// decrementeaza ttl si actualizeaza checksum-ul folosind metoda de la bonus

		checksum_incremental(&ip_hdr_received->check, (uint16_t *)&ip_hdr_received->ttl, ((uint16_t)(ip_hdr_received->ttl-1) << 8) | (uint16_t)ip_hdr_received->protocol);

		// creeaza cheia folosita pentru cautarea next-hop - ului
		rt_entry key;
		key.prefix = ntohl(ip_hdr_received->daddr);
		key.mask = 0;

		rt_table_entry = search(key, 0, curr_size);

		// daca nu am gasit intrarea, inseamna ca nu exista acel host
		// intoarce ICMP HOST UNREACHABLE
		if(rt_table_entry == NULL){
			replied.interface = received.interface;
			replied.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

			memcpy((icmp_hdr_replied + 1), ip_hdr_received, sizeof(struct iphdr) + 8);

			memcpy(eth_hdr_replied->ether_dhost, eth_hdr_received->ether_shost, sizeof(eth_hdr_replied->ether_dhost));
			get_interface_mac(received.interface, eth_hdr_replied->ether_shost);
			eth_hdr_replied->ether_type = htons(ETHERTYPE_IP);

			uint32_t ip = htonl(convert_string_to_ip_addr(get_interface_ip(received.interface)));
			memcpy(&ip_hdr_replied->saddr, &ip, sizeof(ip_hdr_replied->saddr));
			memcpy(&ip_hdr_replied->daddr, &ip_hdr_received->saddr, sizeof(ip_hdr_replied->daddr));
			ip_hdr_replied->version = IPVERSION;
			ip_hdr_replied->ihl = 5;
			ip_hdr_replied->tos = 0;
			ip_hdr_replied->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
			ip_hdr_replied->id = htons(getpid());
			ip_hdr_replied->frag_off = 0;
			ip_hdr_replied->ttl = MAXTTL;
			ip_hdr_replied->protocol = IPPROTO_ICMP;
			ip_hdr_replied->check = 0;
			ip_hdr_replied->check = ip_checksum(ip_hdr_replied, sizeof(struct iphdr));

			icmp_hdr_replied->code = 0;
			icmp_hdr_replied->type = ICMP_DEST_UNREACH;
			icmp_hdr_replied->checksum = 0;
			icmp_hdr_replied->checksum = ip_checksum(icmp_hdr_replied, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

			send_packet(received.interface, &replied);
			continue;
		}

		// ia intrarea specifica next hop-ului din arp_table
		arp_table_entry = get_arp_entry(rt_table_entry->next_hop);

		// daca nu exista in tabela, atunci trimite ARP REQUEST pentru adresa si salveaza pachetul + intrarea din rt_table
		if(arp_table_entry == NULL){

			packet *saved = malloc(sizeof(packet)); // salveaza pachetul in memorie
			memcpy(saved, &received, sizeof(received));
			queue_enq(packet_q, saved); // pune pachetul in coada
			queue_enq(packet_q, rt_table_entry); // pune intrarea din rt_table in coada

			// trimite ARP REQUEST
			replied.interface = rt_table_entry->interface;
			replied.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

			hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr_replied->ether_dhost);
			get_interface_mac(rt_table_entry->interface, eth_hdr_replied->ether_shost);
			eth_hdr_replied->ether_type = htons(ETHERTYPE_ARP);

			arp_hdr_replied->arp_hrd = htons(ARPHRD_ETHER);
			arp_hdr_replied->arp_pro = 8;
			arp_hdr_replied->arp_hln = 6;
			arp_hdr_replied->arp_pln = 4;
			arp_hdr_replied->arp_op = htons(ARPOP_REQUEST);

			uint32_t ip = ntohl(convert_string_to_ip_addr(get_interface_ip(rt_table_entry->interface)));
			uint32_t hop = ntohl(rt_table_entry->next_hop);
			get_interface_mac(rt_table_entry->interface, arp_hdr_replied->arp_sha);
			memcpy(arp_hdr_replied->arp_spa, &ip, sizeof(arp_hdr_replied->arp_spa));
			hwaddr_aton("00:00:00:00:00:00",arp_hdr_replied->arp_tha);
			memcpy(arp_hdr_replied->arp_tpa, &hop, sizeof(arp_hdr_replied->arp_tpa));

			send_packet(rt_table_entry->interface, &replied);
			continue;
		}

		// actualizez adresele MAC sursa si destinatie pentru a trimite mai departe pachetul
		get_interface_mac(rt_table_entry->interface, eth_hdr_received->ether_shost);
		memcpy(eth_hdr_received->ether_dhost, arp_table_entry->mac, sizeof(eth_hdr_received->ether_dhost));

		// trimite mai departe pachetul
		send_packet(rt_table_entry->interface, &received);
	}
}

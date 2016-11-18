/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens com struct          */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include "dhcp.h"
#include <pthread.h>

unsigned char buff[1500];
uint8_t mensagemNaMao[1500];
struct ip *sIP;
struct udphdr *sUDP;
struct dhcp_message *sDhcp;

// Para Referencia CHUPA
//**********************************************************************************//
// struct ether_header
// {
//   u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
//   u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
//   u_int16_t ether_type;		        /* packet type ID field	*/
// } __attribute__ ((__packed__));
//**********************************************************************************//
// struct ip
//   {
// #if __BYTE_ORDER == __LITTLE_ENDIAN
//     unsigned int ip_hl:4;		/* header length */
//     unsigned int ip_v:4;		/* version */
// #endif
// #if __BYTE_ORDER == __BIG_ENDIAN
//     unsigned int ip_v:4;		/* version */
//     unsigned int ip_hl:4;		/* header length */
// #endif
//     u_int8_t ip_tos;			/* type of service */
//     u_short ip_len;			/* total length */
//     u_short ip_id;			/* identification */
//     u_short ip_off;			/* fragment offset field */
// #define	IP_RF 0x8000			/* reserved fragment flag */
// #define	IP_DF 0x4000			/* dont fragment flag */
// #define	IP_MF 0x2000			/* more fragments flag */
// #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
//     u_int8_t ip_ttl;			/* time to live */
//     u_int8_t ip_p;			/* protocol */
//     u_short ip_sum;			/* checksum */
//     struct in_addr ip_src, ip_dst;	/* source and dest address */
//   };
//**********************************************************************************//
// struct udphdr
// {
//   __extension__ union
//   {
//     struct
//     {
//       u_int16_t uh_sport;		/* source port */
//       u_int16_t uh_dport;		/* destination port */
//       u_int16_t uh_ulen;		 udp length 
//       u_int16_t uh_sum;		/* udp checksum */
//     };
//     struct
//     {
//       u_int16_t source;
//       u_int16_t dest;
//       u_int16_t len;
//       u_int16_t check;
//     };
//   };
// };
//**********************************************************************************//
// struct dhcp_packet {
//  	u_int8_t  op;		/* 0: Message opcode/type */
// 	u_int8_t  htype;	/* 1: Hardware addr type (net/if_types.h) */
// 	u_int8_t  hlen;		/* 2: Hardware addr length */
// 	u_int8_t  hops;		/* 3: Number of relay agent hops from client */
// 	u_int32_t xid;		/* 4: Transaction ID */
// 	u_int16_t secs;		/* 8: Seconds since client started looking */
// 	u_int16_t flags;	/* 10: Flag bits */
// 	struct in_addr ciaddr;	/* 12: Client IP address (if already in use) */
// 	struct in_addr yiaddr;	/* 16: Client IP address */
// 	struct in_addr siaddr;	/* 18: IP address of next server to talk to */
// 	struct in_addr giaddr;	/* 20: DHCP relay agent IP address */
// 	unsigned char chaddr [16];	/* 24: Client hardware address */
// 	char sname [DHCP_SNAME_LEN];	/* 40: Server name */
// 	char file [DHCP_FILE_LEN];	/* 104: Boot filename */
// 	unsigned char options [DHCP_MAX_OPTION_LEN];
// 				/* 212: Optional parameters
// 			  (actual length dependent on MTU). */
// };
//**********************************************************************************//
void criaAPohaDoPacoteInteiro(){
	struct ether_header *headerEthernet;
	struct ip *headerIP;
	struct in_addr *ip_src;
	struct in_addr *ip_dst;
	struct udphdr *headerUDP;
	struct sDhcp *pacoteDHCP;

	//configura pacote ethernet
	ether_header->ether_shost = {0x00, 0x0a,0xf7,0x16,0xe0,0x93};
	ether_header->ether_dhost = {0xff, 0xff,0xff,0xff,0xff,0xff};
	ether_header->ether_type = 0x0800;

	//configura o pacote ip
	headerIP->ip_v = 0x04;
	// tem que ver o tamamnho dos pacotes...
	headerIP-> ip_hl = 0xff;
	headerIP->ip_ttl = 0x80;
	headerIP->ip_p = 0x11;
	headerIP->ip_src = ip_src;
	headerIP->ip_dst = ip_dst;
//     u_int8_t ip_tos;			/* type of service */
//     u_short ip_len;			/* total length */
//     u_short ip_id;			/* identification */
//     u_short ip_off;			/* fragment offset field */
// #define	IP_RF 0x8000			/* reserved fragment flag */
// #define	IP_DF 0x4000			/* dont fragment flag */
// #define	IP_MF 0x2000			/* more fragments flag */
// #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
//     u_short ip_sum;			/* checksum */
//     struct in_addr ip_src, ip_dst;	/* source and dest address */

}



void monta_pacote()
{
	// as struct estao descritas nos seus arquivos .h
	// por exemplo a ether_header esta no net/ethert.h
	// a struct ip esta descrita no netinet/ip.h
	struct ether_header *eth;

	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	eth = (struct ether_header *) &buff[0];

	
	//Endereco Mac Destino
	eth->ether_dhost[0] = 0xff;
	eth->ether_dhost[1] = 0xff;
	eth->ether_dhost[2] = 0xff;
	eth->ether_dhost[3] = 0xff;
	eth->ether_dhost[4] = 0xff;
	eth->ether_dhost[5] = 0xff;


	//MAquina ao lado
	//Endereco Mac Destino
	eth->ether_dhost[0] = 0Xa4;
	eth->ether_dhost[1] = 0X1f;
	eth->ether_dhost[2] = 0X72;
	eth->ether_dhost[3] = 0Xf5;
	eth->ether_dhost[4] = 0X90;
	eth->ether_dhost[5] = 0Xb7;
	
/*
	//Endereco Mac Origem
	eth->ether_shost[0] = 0Xa4;
	eth->ether_shost[1] = 0X1f;
	eth->ether_shost[2] = 0X72;
	eth->ether_shost[3] = 0Xf5;
	eth->ether_shost[4] = 0X90;
	eth->ether_shost[5] = 0X80;
/*

*/
 	eth->ether_type = htons(0X800);

}

void monta_ip(){
	struct in_addr *ip_src;
	struct in_addr *ip_dst;

	//htons se maior que 8 bytes usar se nao nao usar
	sIP = (struct ip *) &buff[14];
	sIP->ip_v = 0x04;
	sIP->ip_hl = 0x05;	
	sIP->ip_tos = 0x0;
	// printf("%x Versao \n" , sIP->ip_v); 
	// printf("%x Header Len \n" , sIP->ip_hl); 
	// printf("%x TYpe OF Service \n" , sIP->ip_tos); 
	// printf("%x Lenght \n" ,htons(sIP->ip_len));
	// printf("%x Identificacao \n" ,htons(sIP->ip_id));
	// printf("%x OffSet \n" ,htons(sIP->ip_off));
	// printf("%x  Tll \n" ,sIP->ip_ttl);
	// printf("%x protocol \n" ,sIP->ip_p);
	// printf("%x CheckSUm\n" ,htons(sIP->ip_sum));
	//printf("%x Source IP \n ",sIP->ip_src = "10.32.143.202");
	//printf("%x Destino IP \n ",sIP->ip_dst="10.32.143.153"); 
	//inet_aton("10.32.143.188", &iph->ip_src);
	//inet_aton("10.32.143.205", &iph->ip_dst);

	//inet_aton("10.32.143.202", sIP->&ip_src);
	//inet_aton("10.32.143.153", sIP->&ip_dst);


}


void montaUDP(){
	// as struct estao descritas nos seus arquivos .h
	// por exemplo a ether_header esta no net/ethert.h
	// a struct ip esta descrita no netinet/ip.h
	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	sUDP = (struct udphdr *) &buff[34];
	/*
		printf("%x UDP SORUCE PORT \n" ,htons(sUDP->uh_sport));	
		printf("%x UDP DEST PORT \n" ,htons(sUDP->uh_dport));	
		printf("%x UDP Len \n" ,htons(sUDP->uh_ulen));	
		printf("%x UDP SUM \n" ,htons(sUDP->uh_sum));	
	*/
}



void montaDHCP(){
	sDhcp = (struct sDhcp *) &buff[42];
}


void * thread_offer(void *args)
{
	int i;
	long tid;
	tid = (long) args;
	
	for (i = 0; i < 10; i++) {
		printf("Ola mundo! Eu sou a thread %ld.\n", tid);
		sleep(1);
	}

	pthread_exit(NULL);
}

void * thread_ack(void *args)
{
	int i;
	long tid;
	tid = (long) args;
	
	for (i = 0; i < 10; i++) {
		printf("Ola mundo! Eu sou a thread %ld.\n", tid);
		sleep(1);
	}

	pthread_exit(NULL);
}


int main(int argc,char *argv[])
{
	int sock, i;
	struct ifreq ifr;
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

    /* Inicializa com 0 os bytes de memoria apontados por ifr. */
	memset(&ifr, 0, sizeof(ifr));

    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. D� um "man" para ver os par�metros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}
	while(1){
		recv(sock,(char *) &buff, sizeof(buff), 0x0);
		/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
		to.sll_protocol= htons(ETH_P_ALL);
		to.sll_ifindex = 2; /* indice da interface pela qual os pacotes serao enviados */

		addr[0]=0Xa4;
		addr[0]=0X1f;
		addr[0]=0X72;
		addr[0]=0Xf5;
		addr[0]=0X90;
		addr[0]=0Xb7;
		memcpy (to.sll_addr, addr, 6);
		len = sizeof(struct sockaddr_ll);

		monta_pacote();
		//printf("\n");
		monta_ip();
		//printf("COISA ENCONTRADA, VERSAO: %x \n", sIP->ip_v);
		//printf("COISA ENCONTRADA, PROTOCOLO: %x \n", sIP->ip_p);
		if( sIP->ip_p == 17 ){
			montaUDP();
			//printf("DESTINATION: %x\n", sUDP->uh_dport);
			//printf("SOURCE: %x\n", sUDP->uh_sport);
			if(sUDP->uh_sport == 67 || sUDP->uh_sport == 68 || sUDP->uh_dport == 67 || sUDP->uh_dport == 68 ){
				montaDHCP();
				//printf("achei  um ");
				if(sUDP->options[0]){}
			}
		}else{
			continue;
		}
		
		if(!sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
			printf("sendto maquina destino.\n");
	}	
}

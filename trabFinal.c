/*-------------------------------------------------------------*/
/* Hariel G. & Lucas Schuler       */
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
#include <stdlib.h>
#include "dhcp.h"

unsigned char buffer[350];
unsigned char buff1[350];
unsigned char headerIP[20];
unsigned char headerIPAck[20];

#define MAC_SRC1 0xa4
#define MAC_SRC2 0x1f
#define MAC_SRC3 0x72
#define MAC_SRC4 0xf5
#define MAC_SRC5 0x90
#define MAC_SRC6 0xb7
#define MAC_DEST1 0xa4
#define MAC_DEST2 0x1f
#define MAC_DEST3 0x72
#define MAC_DEST4 0xf5
#define MAC_DEST5 0x90
#define MAC_DEST6 0x80
#define IP_HEX1	0X0a
#define IP_HEX2	0X20
#define IP_HEX3	0X8F
#define IP_HEX4	0XB4


const char* ip_src="10.32.143.202";
const char* ip_dst="10.32.143.210";

unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}


void pacoteOffer()
{

	struct ether_header *eth;
	struct ether_header *ethOri;

	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	eth = (struct ether_header *) &buffer[0];
	ethOri = (struct ether_header *) &buff1[0];

	//Endereco Mac Destino
	eth->ether_dhost[0] = MAC_DEST1;
	eth->ether_dhost[1] = MAC_DEST2;
	eth->ether_dhost[2] = MAC_DEST3;
	eth->ether_dhost[3] = MAC_DEST4;
	eth->ether_dhost[4] = MAC_DEST5;
	eth->ether_dhost[5] = MAC_DEST6;

	//Endereco Mac Origem
	eth->ether_shost[0] = MAC_SRC1;
	eth->ether_shost[1] = MAC_SRC2;
	eth->ether_shost[2] = MAC_SRC3;
	eth->ether_shost[3] = MAC_SRC4;
	eth->ether_shost[4] = MAC_SRC5;
	eth->ether_shost[5] = MAC_SRC6;

 	eth->ether_type = htons(0X800);

	struct ip *sIP;
	//htons se maior que 8 bytes usar e nao nao usar
	sIP = (struct ip *) &buffer[14];
	sIP->ip_v = 0x04;
	sIP->ip_hl = 0x05;	
	sIP->ip_tos = 0x0;
	sIP->ip_len= htons(0x150);

	sIP->ip_id=htons(0x00);
	//sIP->ip_id = htons(54321);
	
	sIP->ip_off=htons(0x00);
	sIP->ip_ttl = 0x10;
	sIP->ip_p = 0x11;	
	
	inet_aton(ip_src, &sIP->ip_src);//MEU IP
	inet_aton(ip_dst, &sIP->ip_dst);//IP PARA DAR PARA A MAQUINA
	
	
	memcpy(headerIP, &buffer[14], 20); //ou  memcpy(headerIP, buff+14, 20); 
	sIP->ip_sum = in_cksum((unsigned short *)&headerIP, sizeof(struct ip));

	struct udphdr *sUDP;

	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	sUDP = (struct udphdr *) &buffer[14+20];
	//htons(sUDP->uh_sport=67);
	sUDP->uh_sport = htons(0x43);

	sUDP->uh_dport=htons(0x44);

	sUDP->uh_ulen=htons(0x13c);
	sUDP->uh_sum=htons(0x00);

	//tem que ver checksum
	struct dhcp_packet *sDhcp;
	struct dhcp_packet *sDhcpAux;
	sDhcp = (struct dhcp_packet *) &buffer[14+20+8];
	sDhcpAux = (struct dhcp_packet *) &buff1[14+20+8];

	sDhcp->op = 0x02;
		sDhcp->htype=0x01;
	sDhcp->hlen=0x06;
	sDhcp->hops=0x0;
	sDhcp->xid=	sDhcpAux->xid;
	sDhcp->secs=htons(0x0000);
	sDhcp->flags=htons(0x0000);
	inet_aton("0.0.0.0", &sDhcp->ciaddr);
	inet_aton(ip_dst, &sDhcp->yiaddr);//IP OFERDADO
	inet_aton("0.0.0.0", &sDhcp->siaddr);
	inet_aton("0.0.0.0", &sDhcp->giaddr);
	
	//MAC DESTINO
	sDhcp->chaddr[0]= MAC_DEST1;
	sDhcp->chaddr[1]= MAC_DEST2;
	sDhcp->chaddr[2]= MAC_DEST3;	
	sDhcp->chaddr[3]= MAC_DEST4;
	sDhcp->chaddr[4]= MAC_DEST5;
	sDhcp->chaddr[5]= MAC_DEST6;

	/*Magic COokie*/
	sDhcp->options[0]=0x63;
	sDhcp->options[1]=0x82;
	sDhcp->options[2]=0x53;
	sDhcp->options[3]=0x63;

	//DHCP Message TYoe (Offer)
	sDhcp->options[4]=0x35;
	sDhcp->options[5]=0x01;
	sDhcp->options[6]=0x02;
	
	
	//DHCP Server Identifer (9 AO 12IP EM HEX)(MEU IP)(MAQUINA HOST)
	sDhcp->options[7]=0x36;
	sDhcp->options[8]=0x04;
	sDhcp->options[9]=IP_HEX1;
	sDhcp->options[10]=IP_HEX2;
	sDhcp->options[11]=IP_HEX3;
	sDhcp->options[12]=IP_HEX4;

	//IP Address Lease Time 

	sDhcp->options[13]=0x33;
	sDhcp->options[14]=0x04;
	sDhcp->options[15]=0x00;
	sDhcp->options[16]=0x01;
	sDhcp->options[17]=0x38;
	sDhcp->options[18]=0x80;

	
	//Subnet Mask  (MASCARA PADRÃO 255.255.255.0)

	sDhcp->options[19]=0x01; // NUMERO
	sDhcp->options[20]=0x04; // TAMANHO
	sDhcp->options[21]=0xff; 
	sDhcp->options[22]=0xff;
	sDhcp->options[23]=0xff;
	sDhcp->options[24]=0x00;

	//Router (27 AO 30 MEU IP)(MEU IP)(MAQUINA HOST) EM HEX

	sDhcp->options[25]=0x03;
	sDhcp->options[26]=0x04;
	sDhcp->options[27]=IP_HEX1;
	sDhcp->options[28]=IP_HEX2;
	sDhcp->options[29]=IP_HEX3;
	sDhcp->options[30]=IP_HEX4;

	//dns denovo
	sDhcp->options[31]=0x06;
	sDhcp->options[32]=0X04;
	sDhcp->options[33]=IP_HEX1;
	sDhcp->options[34]=IP_HEX2;
	sDhcp->options[35]=IP_HEX3;
	sDhcp->options[36]=IP_HEX4;

	//fim
	sDhcp->options[37]=0xff;
}

void pacoteack()
{
	// as struct estao descritas nos seus arquivos .h
	// por exemplo a ether_header esta no net/ethert.h
	// a struct ip esta descrita no netinet/ip.h
	struct ether_header *eth;

	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	eth = (struct ether_header *) &buffer[0];

	//Endereco Mac Destino
	eth->ether_dhost[0] = MAC_DEST1;
	eth->ether_dhost[1] = MAC_DEST2;
	eth->ether_dhost[2] = MAC_DEST3;
	eth->ether_dhost[3] = MAC_DEST4;
	eth->ether_dhost[4] = MAC_DEST5;
	eth->ether_dhost[5] = MAC_DEST6;

	//Endereco Mac Origem
	eth->ether_shost[0] = MAC_SRC1;
	eth->ether_shost[1] = MAC_SRC2;
	eth->ether_shost[2] = MAC_SRC3;
	eth->ether_shost[3] = MAC_SRC4;
	eth->ether_shost[4] = MAC_SRC5;
	eth->ether_shost[5] = MAC_SRC6;

 	eth->ether_type = htons(0X800);

	struct ip *sIP;
	//htons se maior que 8 bytes usar e nao nao usar
	sIP = (struct ip *) &buffer[14];
	sIP->ip_v = 0x04;
	sIP->ip_hl = 0x05;	
	sIP->ip_tos = 0x0;
	sIP->ip_len= htons(0x150);
    sIP->ip_id=htons(0x00);
    //sIP->ip_id = htons(54321);
	sIP->ip_off=htons(0x00);
	sIP->ip_ttl = 0x10;
	sIP->ip_p = 0x11;	
	
	inet_aton(ip_src, &sIP->ip_src);//MEU IP
	inet_aton(ip_dst, &sIP->ip_dst);//IP PARA DAR PARA A MAQUINA
	
	memcpy(headerIPAck, &buffer[14], 20); //ou  memcpy(headerIP, buff+14, 20); 
	sIP->ip_sum = in_cksum((unsigned short *)&headerIP, sizeof(struct ip));


	// as struct estao descritas nos seus arquivos .h
	// por exemplo a ether_header esta no net/ethert.h
	// a struct ip esta descrita no netinet/ip.h
	struct udphdr *sUDP;

	// coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
	// onde inicia o header do ethernet.
	sUDP = (struct udphdr *) &buffer[14+20];
	//htons(sUDP->uh_sport=67);
	sUDP->uh_sport = htons(0x43);

	sUDP->uh_dport=htons(0x44);

	sUDP->uh_ulen=htons(0x13c);
	sUDP->uh_sum=htons(0x00);
	//Usar metodo checsum para calculoar

	struct dhcp_packet *sDhcp;
	struct dhcp_packet *sDhcpAux;
	
	sDhcp = (struct dhcp_packet *) &buffer[14+20+8];
	sDhcpAux = (struct dhcp_packet *) &buff1[14+20+8];

	sDhcp->op = 0x02;
		sDhcp->htype=0x01;
	sDhcp->hlen=0x06;
	sDhcp->hops=0x0;
	sDhcp->xid=	sDhcpAux->xid;
	sDhcp->secs=htons(0x0000);
	sDhcp->flags=htons(0x0000);
	inet_aton("0.0.0.0", &sDhcp->ciaddr);
	inet_aton(ip_dst, &sDhcp->yiaddr);
	inet_aton("0.0.0.0", &sDhcp->siaddr);
	inet_aton("0.0.0.0", &sDhcp->giaddr);

	sDhcp->chaddr[0]= MAC_DEST1;
	sDhcp->chaddr[1]= MAC_DEST2;
	sDhcp->chaddr[2]= MAC_DEST3;	
	sDhcp->chaddr[3]= MAC_DEST4;
	sDhcp->chaddr[4]= MAC_DEST5;
	sDhcp->chaddr[5]= MAC_DEST6;

	/*ainda não sei porquê mas tem que ter*/
	sDhcp->options[0]=0x63;
	sDhcp->options[1]=0x82;
	sDhcp->options[2]=0x53;
	sDhcp->options[3]=0x63;

	//DHCP Message 
	sDhcp->options[4]=0x35;
	sDhcp->options[5]=0x01;
	sDhcp->options[6]=0x05;
	
	//DHCP server
	sDhcp->options[7]=0x36;
	sDhcp->options[8]=0x04;
	sDhcp->options[9]=IP_HEX1;
	sDhcp->options[10]=IP_HEX2;
	sDhcp->options[11]=IP_HEX3;
	sDhcp->options[12]=IP_HEX4;

	//release time

	sDhcp->options[13]=0x33;
	sDhcp->options[14]=0x04;
	sDhcp->options[15]=0x00;
	sDhcp->options[16]=0x01;
	sDhcp->options[17]=0x38;
	sDhcp->options[18]=0x80;

	//mascara

	sDhcp->options[19]=0x01; // opção
	sDhcp->options[20]=0x04; // length
	sDhcp->options[21]=0xff; 
	sDhcp->options[22]=0xff;
	sDhcp->options[23]=0xff;
	sDhcp->options[24]=0x00;

	//router

	sDhcp->options[25]=0x03;
	sDhcp->options[26]=0x04;
	sDhcp->options[27]=IP_HEX1;
	sDhcp->options[28]=IP_HEX2;
	sDhcp->options[29]=IP_HEX3;
	sDhcp->options[30]=IP_HEX4;

	//DNS

	sDhcp->options[31]=0x06;
	sDhcp->options[32]=0X04;
	sDhcp->options[33]=IP_HEX1;
	sDhcp->options[34]=IP_HEX2;
	sDhcp->options[35]=IP_HEX3;
	sDhcp->options[36]=IP_HEX4;

	//cabô
	sDhcp->options[37]=0xff;
	}


int main(int argc,char *argv[])
{
    int i=0;
	int sock;
	int flag=0;
	struct ifreq ifr;
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

    /* Inicializa com 0 os bytes de memoria apontados por ifr. */
	memset(&ifr, 0, sizeof(ifr));

    /* Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. D� um "man" para ver os par�metros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro ao abrir socket\n");
        exit(1);
 	}

	
	/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_halen = 6;
	strcpy(ifr.ifr_name, "enp4s0");

	if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		printf("pau no ioctl!");

		to.sll_ifindex = ifr.ifr_ifindex; /* indice da interface pela qual os pacotes serao enviados */
		len = sizeof(struct sockaddr_ll);

	for(;;)
	{
		recv(sock,(char *) &buff1, sizeof(buff1), 0x0);
		if(buff1[23]==0x11)
		{
			if(buff1[35]=0X44 && buff1[37] == 0x43)
			{
				if(buff1[282]==0x35 && buff1[283]==0x01 && buff1[284]==0x01)
				{					
													
							printf("vou mandar offer");						
							pacoteOffer();
							if(sendto(sock, (char *) buffer, sizeof(buffer), 0, (struct sockaddr*) &to, len)<0){
															printf("\nOffer");
							}
				}
				else if(buff1[282]==0x35 && buff1[283]==0x01 && buff1[284]==0x03)
				{				
					printf("vou mandar ack");	
							pacoteack();
							if(sendto(sock, (char *) buffer, sizeof(buffer), 0, (struct sockaddr*) &to, len)<0){
								printf("\nAck");
							}
				}
			}
		}
	}
	printf("\n sai");
}


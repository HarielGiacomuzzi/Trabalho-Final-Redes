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


void superMontaPacote(int option)
{

    struct ether_header *eth;
    struct ether_header *ethOri;
    struct ip *sIP;
    struct udphdr *sUDP;
    struct dhcp_packet *sDhcp;
    struct dhcp_packet *sDhcpAux;

    if(option){
        
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

        
        //htons se maior que 8 bytes usar e nao nao usar
        sIP = (struct ip *) &buffer[14];
        sIP->ip_v = 0x04;
        sIP->ip_hl = 0x05;	
        sIP->ip_tos = 0x0;
        sIP->ip_len= htons(0x150);

        sIP->ip_id=htons(0x00);
        
        sIP->ip_off=htons(0x00);
        sIP->ip_ttl = 0x10;
        sIP->ip_p = 0x11;	
        
        inet_aton(ip_src, &sIP->ip_src);//quem eu sou
        inet_aton(ip_dst, &sIP->ip_dst);//IP que vou oferecer
        
        
        memcpy(headerIP, &buffer[14], 20); //ou  memcpy(headerIP, buff+14, 20); 
        sIP->ip_sum = in_cksum((unsigned short *)&headerIP, sizeof(struct ip));

        
        sUDP = (struct udphdr *) &buffer[14+20];
        sUDP->uh_sport = htons(0x43);

        sUDP->uh_dport=htons(0x44);

        sUDP->uh_ulen=htons(0x13c);
        sUDP->uh_sum=htons(0x00);

        //tem que ver checksum
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
        inet_aton(ip_dst, &sDhcp->yiaddr);//IP que eu tentei dar
        inet_aton("0.0.0.0", &sDhcp->siaddr);
        inet_aton("0.0.0.0", &sDhcp->giaddr);
        
        //mac destino
        sDhcp->chaddr[0]= MAC_DEST1;
        sDhcp->chaddr[1]= MAC_DEST2;
        sDhcp->chaddr[2]= MAC_DEST3;	
        sDhcp->chaddr[3]= MAC_DEST4;
        sDhcp->chaddr[4]= MAC_DEST5;
        sDhcp->chaddr[5]= MAC_DEST6;

        /*Magic*/
        sDhcp->options[0]=0x63;
        sDhcp->options[1]=0x82;
        sDhcp->options[2]=0x53;
        sDhcp->options[3]=0x63;

        //configura DHCP (Offer)
        sDhcp->options[4]=0x35;
        sDhcp->options[5]=0x01;
        sDhcp->options[6]=0x02;
        
        
        //DHCP Server Identifer
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

        
        //usando mascara padrão 255.255.255.0

        sDhcp->options[19]=0x01; // NUMERO
        sDhcp->options[20]=0x04; // TAMANHO
        sDhcp->options[21]=0xff; 
        sDhcp->options[22]=0xff;
        sDhcp->options[23]=0xff;
        sDhcp->options[24]=0x00;

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
    else{
        
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
        
        
        //htons se maior que 8 bytes usar e nao nao usar
        sIP = (struct ip *) &buffer[14];
        sIP->ip_v = 0x04;
        sIP->ip_hl = 0x05;
        sIP->ip_tos = 0x0;
        sIP->ip_len= htons(0x150);
        sIP->ip_id=htons(0x00);
        sIP->ip_off=htons(0x00);
        sIP->ip_ttl = 0x10;
        sIP->ip_p = 0x11;
        
        inet_aton(ip_src, &sIP->ip_src);//MEU IP
        inet_aton(ip_dst, &sIP->ip_dst);//IP que tô oferecendo
        
        memcpy(headerIPAck, &buffer[14], 20);
        sIP->ip_sum = in_cksum((unsigned short *)&headerIP, sizeof(struct ip));
        

        sUDP = (struct udphdr *) &buffer[14+20];
        sUDP->uh_sport = htons(0x43);
        
        sUDP->uh_dport=htons(0x44);
        
        sUDP->uh_ulen=htons(0x13c);
        sUDP->uh_sum=htons(0x00);
        
        //Usar metodo checsum para calculoar
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

    // seta tudo pra 0 pra garantir que não dê bostinha
	memset(&ifr, 0, sizeof(ifr));

    // cria o descritor de arquivo que é o socket
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro ao abrir socket\n");
        exit(1);
 	}

	
	// seta a interface
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_halen = 6;
	strcpy(ifr.ifr_name, "enp4s0");

    // verifica se não deu ruin
	if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		printf("pau no ioctl!");

		to.sll_ifindex = ifr.ifr_ifindex;
		len = sizeof(struct sockaddr_ll);

    // agora é só diversão
	for(;;)
	{
		recv(sock,(char *) &buff1, sizeof(buff1), 0x0);
		// filtra pra não pegar qualquer pacote
        if(buff1[23]==0x11)
		{
            // será que é dhcp
			if(buff1[35]=0X44 && buff1[37] == 0x43)
			{
                // xô ver se é discover
				if(buff1[282]==0x35 && buff1[283]==0x01 && buff1[284]==0x01)
				{					
													
							printf("vou mandar offer");						
							superMontaPacote(1);
							if(sendto(sock, (char *) buffer, sizeof(buffer), 0, (struct sockaddr*) &to, len)<0){
															printf("\nOffer");
							}
				}
				else if(buff1[282]==0x35 && buff1[283]==0x01 && buff1[284]==0x03)
				{				
					printf("vou mandar ack");	
							superMontaPacote(0);
							if(sendto(sock, (char *) buffer, sizeof(buffer), 0, (struct sockaddr*) &to, len)<0){
								printf("\nAck");
							}
				}
			}
		}
	}
	printf("\n feitoria");
}


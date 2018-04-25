/* PHoss (PHenoelit's own security sniffer */
/* $Id: main.c,v 1.13 2000/06/20 14:21:38 fx Exp fx $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>                 // for IPPROTO_bla consts
#include <sys/socket.h>                 // for inet_ntoa()
#include <arpa/inet.h>                  // for inet_ntoa()  

#include <pcap.h>                       // for the Berkeley Packet Filter 
#include <net/bpf.h>

#include "MIME.h"
#include "list.h"
#include "subprotocols.h"

#define PROGRAM_NAME "PHoss (Phenoelit's own security sniffer)\n(c) 1999 by Phenoelit (http://www.phenoelit.de)"
#define PROGRAM_VERSION "$Revision: 1.13 $"

#define DEF_CAPLENGTH 1525

#define ETHLENGTH 14
#define IP_MIN_LENGTH 20

#define HTTP_PORT 80
#define POP3_PORT 110
#define FTP_PORT 21
#define LDAP_PORT 389
#define IMAP4_PORT 143
#define TELNET_PORT 23
#define VNC_PORT 5900

#define VERBOSE(x,y) ((verbose>=(x))?printf("%s",y):0);

struct iphdr {
        u_char  ihl:4,        /* header length */
        version:4;              /* version */
        u_char  tos;          /* type of service */
        short   tot_len;      /* total length */
        u_short id;           /* identification */
        short   off;          /* fragment offset field */
#define IP_DF   0x4000  /* dont fragment flag */
#define IP_MF   0x2000  /* more fragments flag */
        u_char  ttl;          /* time to live */
        u_char  protocol;     /* protocol */
        u_short check;        /* checksum */
        struct  in_addr saddr;
	struct  in_addr daddr;  /* source and dest address */
};

struct tcphdr {
        unsigned short int src_port;
	unsigned short int dest_port;
        unsigned long int   seq_num;
        unsigned long int   ack_num;
	unsigned short int	rawflags;
        unsigned short int   window;
        long int   crc_a_urgent;
        long int   options_a_padding;
};

typedef struct t_protocol {
    char *name;
    SupportedProtos	type;
    int	(* handler) (char *tcp_data, unsigned int length);
} Protocols;

/* global variables */
static int verbose=0;
static char *filter=NULL;
static int cap_interrupted;
static int use_port=1;
static int use_pattern=1;

/* global bpf vars */
static char pcap_err[PCAP_ERRBUF_SIZE];        // buffer for pcap errors
static pcap_t *cap;                            // capture handler
static bpf_u_int32 network,netmask;            // network and netmask for filter
struct pcap_pkthdr *phead;	//packet information header copy
static struct pcap_pkthdr *pcap_head;	//packet information header
static struct bpf_program cfilter;	// the compiled filter
struct iphdr *ip;			// pointer for actual header(s)
struct tcphdr *tcp;			// pointer for actual header(s)

/* this is what a bad programmer does ... */
char *tcp_data;
unsigned int tcp_data_length;


/* functions */
void print_found(SupportedProtos prot, char *cleardata);

// error handler (=!) for pcap lib
void capterror(pcap_t *caps, char *message) {
            pcap_perror(caps,message);
            exit (-1);
}

void *smalloc(size_t size) {
    void *ptr;
    if ((ptr=malloc(size))==NULL) {
	fprintf(stderr,"malloc(): failed. Memory full ?\n");
	exit (-1);
    } else {
	memset(ptr,0,size);
	return (ptr);
    }
}

void SIG_INT_handler(int signalnr) {
    VERBOSE(1,"closing capture ... ");
    pcap_close(cap);
    cap_interrupted++;
}

int init_capture(char *device,unsigned int snaplength) {

    if (device==NULL) {
	VERBOSE(1,"device not set. Looking up ...\n");
	if ((device=pcap_lookupdev(pcap_err))==NULL) {
	    fprintf(stderr,"init_capture(): %s\n",pcap_err);
	    return (-1);
	}
    }
    if (verbose) printf("Device: %s\n",device);

    VERBOSE(2,"Looking up network ...\n");
    if (pcap_lookupnet(device,&network,&netmask,pcap_err)!=0) {
	fprintf(stderr,"init_capture(): %s\n",pcap_err);
	return (-1);
    }

    /* 1 = promiscuous mode , 0 = timeout */
    VERBOSE(2,"opening network ...\n");
    if ((cap=pcap_open_live(device,snaplength,1,0,pcap_err))==NULL) {
	fprintf(stderr,"init_capture(): %s\n",pcap_err);
	return (-1);
    }

    VERBOSE(2,"compiling filter ...\n");
    if (pcap_compile(cap,&cfilter,filter,0/*no optim*/,netmask)!=0) {
	capterror(cap,"compiler");
    }

    VERBOSE(2,"setting filter ...\n");
    if (pcap_setfilter(cap,&cfilter)!=0) {
	capterror(cap,"setfilter");
    }

    VERBOSE(2,"Checking link layer type ...\n");
    if (pcap_datalink(cap)!=DLT_EN10MB) {
	fprintf(stderr,"\nAt the moment - we just support 10Mb Ethernet.\n");
	return (-1);
    }

    pcap_head=(struct pcap_pkthdr *)smalloc(sizeof(struct pcap_pkthdr));

    VERBOSE(1,"initialization successfull.\n");
    return (0);
}


/* suplementary functions */

/* mempos:
 * 	searches the memory beginning at 'memp' (l bytes long) for needle
 * RETURNS: porter to the position of 'needle' or NULL if not found
 */
char *mempos(char *memp, unsigned int l,char *needle) {
    int i;
    char *n2,*p;

    if (l==0) return (NULL);
    if (strlen(needle)>l) return (NULL);

    p=memp;
    n2=smalloc(strlen(needle)+1);
    for (i=0;i<(l-strlen(needle));i++) {
	memset(n2,0,strlen(needle)+1);
	memcpy(n2,p,strlen(needle));
	if (!strcasecmp(n2,needle)) {
		free(n2);
		return (p);
	} else {
	    p++;
	}
    }
    return (NULL);
}

/* memduptil:
 * 	copies everything from src to its resulting pointer i
 * 	until (excluding) the stop_char is found.
 * RETURNS
 * pointer to the new string or NULL on error
 */
char * memduptil(char *src,char stop_char) {
    int i;
    char *p;

    i=0;
    while (src[i]!=stop_char) { i++; }
    if (i==0) return (NULL);
    p=smalloc(i+1);
    memcpy(p,src,i);
    return (p);
}
	
/* ============================== */
/* handler for the supported protos */

int handle_http(char *tcpd, unsigned int length) {

#define AUTH_STRING "Authorization: Basic "
    char *auth_pos;
    char *b64str;
    char *clear_password;

    if ((auth_pos=mempos(tcpd,length,AUTH_STRING))!=NULL) {
	VERBOSE(1,"HTTP: Basic authorization found\n");
	auth_pos+=sizeof(char)*strlen(AUTH_STRING);
	b64str=memduptil(auth_pos,'\n');
	clear_password=decode64(b64str);
	print_found(PROTO_HTTP,clear_password);
	free(clear_password);
	free(b64str);
    }
    return (0);
}

int handle_ldap(char *tcpd, unsigned int length) {

    unsigned long int MessageID;
    // for all the length calculations
    unsigned char l,pl;
    unsigned char choice;
    char *username;
    char *password;
    char *fullstring;

    choice=0;
    memcpy(&choice,&tcpd[5],1);
    l=tcpd[11];
    memcpy(&pl,(void *)(&tcpd[12]+l+1),1);
    
    if (verbose>=3) {
	memcpy(&MessageID,tcpd,4);
	printf("LDAP Message ID: %d\n",MessageID);
	printf("Choice: %x\n",(int)choice);
	printf("LDAP Protocol Version: %d\n",tcpd[9]);
	printf("Length of DN: %d\n",l);
	printf("Length of Password: %d\n",pl);
    }

    if ((choice==0x60)||(choice==0x00)) {
	VERBOSE(1,"LDAP: Bind request found\n");
    } else { 
	return (0); 
    }

    if (l==0) {
	VERBOSE(1,"LDAP: Anonymous bind\n");
	return (0);
    }
    
    username=(char *)smalloc(l+1);
    memcpy(username,&tcpd[12],l);
    password=(char *)smalloc(pl+1);
    memcpy(password,&tcpd[12]+l+2,pl);
    
    if (pl==0) {
	fullstring=(char *)smalloc(strlen(username)+2);
	strcpy(fullstring,username);
	strcat(fullstring,":");
    } else {
	fullstring=(char *)smalloc(strlen(username)+strlen(password)+2);
	strcpy(fullstring,username);
	strcat(fullstring,":");
	strcat(fullstring,password);
    }
    print_found(PROTO_LDAP,fullstring);

    free(username);
    free(password);
    return (0);
}

int handle_pop(char *tcpd, unsigned int length) {

#define USERNAME "USER "
#define PASSWORD "PASS "
    char *user, *pass;
    char *clear;
    char *fullstring;

    if ((user=mempos(tcpd,length,USERNAME))!=NULL) {
	VERBOSE(1,"POP3: Username found\n");
	user+=sizeof(char)*strlen(USERNAME);
	clear=memduptil(user,'\r');
	if (verbose>=1) print_found(PROTO_POP3,clear);
	// add the username to the list, if not existing
	if (list_find(clear,PROTO_POP3)==0) {
	    list_append();
	    current->username=smalloc(strlen(clear)+1);
	    strcpy(current->username,clear);
	    current->saddr=(struct in_addr)ip->saddr;
	    current->daddr=(struct in_addr)ip->daddr;
	    current->sport=(unsigned short int)tcp->src_port;
	    current->dport=(unsigned short int)tcp->dest_port;
	    current->type=PROTO_POP3;
	}
	free(clear);
    }

    if ((pass=mempos(tcpd,length,PASSWORD))!=NULL) {
	VERBOSE(1,"POP3: Password found\n");
	pass+=sizeof(char)*strlen(PASSWORD);
	clear=memduptil(pass,'\r');
	if (verbose>=1) print_found(PROTO_POP3,clear);

	// look up src and dest IP addr and guess this combi
	list_rewind();
	while (!(list_next())) {
	    if ( 
		    (!memcmp((void *)&current->saddr,(void *)&ip->saddr,4)) &&
		    (!memcmp((void *)&current->daddr,(void *)&ip->daddr,4)) &&
		    (current->sport==(unsigned short int)tcp->src_port) &&
		    (current->dport==(unsigned short int)tcp->dest_port) &&
		    (current->type==PROTO_POP3)
		    ) {

		VERBOSE(1,"POP3: Username match found ...\n");
		// there are NULL passwords outside !
		if (clear!=NULL) {
		    fullstring=(char *)
			smalloc(strlen(clear)+strlen(current->username)+2);
		    strcpy(fullstring,current->username);
		    strcat(fullstring,":");
		    strcat(fullstring,clear);
		} else {
		    fullstring=(char *)smalloc(strlen(current->username)+2);
		    strcpy(fullstring,current->username);
		    strcat(fullstring,":");
		}
		print_found(PROTO_POP3,fullstring);
		free(fullstring);
		list_delete();
	    }
	}
	free(clear);
    }
    return (0);
}
	    
int handle_ftp(char *tcpd, unsigned int length) {

#define USERNAME "USER "
#define PASSWORD "PASS "
    char *user, *pass;
    char *clear;
    char *fullstring;

    if ((user=mempos(tcpd,length,USERNAME))!=NULL) {
	VERBOSE(1,"FTP: Username found\n");
	user+=sizeof(char)*strlen(USERNAME);
	clear=memduptil(user,'\r');
	if (verbose>=1) print_found(PROTO_FTP,clear);
	// add the username to the list, if not existing
	if (list_find(clear,PROTO_FTP)==0) {
	    list_append();
	    current->username=smalloc(strlen(clear)+1);
	    strcpy(current->username,clear);
	    current->saddr=(struct in_addr)ip->saddr;
	    current->daddr=(struct in_addr)ip->daddr;
	    current->sport=(unsigned short int)tcp->src_port;
	    current->dport=(unsigned short int)tcp->dest_port;
	    current->type=PROTO_FTP;
	}
	free(clear);
    }

    if ((pass=mempos(tcpd,length,PASSWORD))!=NULL) {
	VERBOSE(1,"FTP: Password found\n");
	pass+=sizeof(char)*strlen(PASSWORD);
	clear=memduptil(pass,'\r');
	if (verbose>=1) print_found(PROTO_FTP,clear);

	// look up src and dest IP addr and guess this combi
	list_rewind();
	while (!(list_next())) {
	    if ( 
		    (!memcmp((void *)&current->saddr,(void *)&ip->saddr,4)) &&
		    (!memcmp((void *)&current->daddr,(void *)&ip->daddr,4)) &&
		    (current->sport==(unsigned short int)tcp->src_port) &&
		    (current->dport==(unsigned short int)tcp->dest_port) &&
		    (current->type==PROTO_FTP)
		    ) {

		VERBOSE(1,"FTP: Username match found ...\n");
		if (clear!=NULL) {
		    fullstring=(char *)
			smalloc(strlen(clear)+strlen(current->username)+2);
		    strcpy(fullstring,current->username);
		    strcat(fullstring,":");
		    strcat(fullstring,clear);
		} else {
		    fullstring=(char *)smalloc(strlen(current->username)+2);
		    strcpy(fullstring,current->username);
		    strcat(fullstring,":");
		}
		print_found(PROTO_FTP,fullstring);
		free(fullstring);
		list_delete();
	    } // end of if matching username found
	} // end of list loop
	free(clear);
    }
    return (0);
}

int handle_vnc(char *tcpd, unsigned int length) {
#define RFB_INITIAL_LENGTH	12
#define RFB_INITIAL		"RFB "
#define RFB_CHALLANGE_LENGTH	16
    int	i;
    char	ts1[9];
    char	*ops;

    /* check, if the length of this payload is 12 and begins with RFB
     * because this will be the initial protocol handshake */
    if (
	    (memcmp(tcpd,RFB_INITIAL,4)==0)
	    &&(length==RFB_INITIAL_LENGTH)
	    ) {
	if (ntohs((unsigned short int)tcp->dest_port)==VNC_PORT) {
	    /* this is the client->server packet (means packet 2) */
	    VERBOSE(1,"VNC: handshake packet to server\n");
	    if (!list_find_connection(ip->saddr,ip->daddr,
			tcp->src_port,tcp->dest_port,PROTO_VNC)) {
		VERBOSE(1,"VNC: looks like we missed the initial packet\n");
		/* save this in original order */
		list_append();
		current->username=NULL;
		current->saddr=(struct in_addr)ip->saddr;
		current->daddr=(struct in_addr)ip->daddr;
		current->sport=(unsigned short int)tcp->src_port;
		current->dport=(unsigned short int)tcp->dest_port;
		current->type=PROTO_VNC;
	    } else {
		VERBOSE(2,"VNC: already in list\n");
	    }
	} else {
	    /* this is the initial server->client proto handshake */
	    VERBOSE(1,"VNC: handshake packet to client\n");
	    /* save this in reverse order (server<>client) */
	    list_append();
	    current->username=NULL;
	    current->saddr=(struct in_addr)ip->daddr;
	    current->daddr=(struct in_addr)ip->saddr;
	    current->sport=(unsigned short int)tcp->dest_port;
	    current->dport=(unsigned short int)tcp->src_port;
	    current->type=PROTO_VNC;
	}

    } else {
	/* it is not in initial handshake state, so it may continue */
	if (ntohs((unsigned short int)tcp->src_port)==VNC_PORT) {
	    /* generally, this is a server->client packet */
	    /* may be it's the authentication challange */
	    if ((list_find_connection(ip->daddr,ip->saddr,
			tcp->dest_port,tcp->src_port,PROTO_VNC))
		    &&(current->username==NULL)
		    &&(length==RFB_CHALLANGE_LENGTH)) {
		/* we have it in list (reverse order) */
		current->username=(char *)smalloc(length+2);
		memcpy(current->username,tcpd,RFB_CHALLANGE_LENGTH);
		if (verbose) {
		    printf("VNC: challange is ");
		    for (i=0;i<RFB_CHALLANGE_LENGTH;i++) { 
			printf("%x",(unsigned char) current->username[i]); 
		    }
		    printf("\n");
		}
		return (0);
	    } /* it's not a known challange */
	} else {
	    /* generally, this is a client to server packet */
	    /* may be it's the authentication response */
	    if ((list_find_connection(ip->saddr,ip->daddr,
			tcp->src_port,tcp->dest_port,PROTO_VNC))
		    &&(current->username!=NULL)
		    &&(length==RFB_CHALLANGE_LENGTH)) {
		    
		if (!memcmp(current->username,"같같같같",8)) // death
		    return 0;

		/* it IS the response and we have the challange ! */
		ops=(char *)smalloc((RFB_CHALLANGE_LENGTH*6)+5);
		for (i=0;i<RFB_CHALLANGE_LENGTH;i++) { 
		    memset(ts1,0,9);
		    sprintf(ts1,"%x",(unsigned char) current->username[i]); 
		    if (ts1[1]=='\0') { ts1[1]=ts1[0]; ts1[0]='0'; }
		    strcat(ops,ts1);
		}
		strcat(ops,"\n\t\t");
		for (i=0;i<RFB_CHALLANGE_LENGTH;i++) { 
		    memset(ts1,0,9);
		    sprintf(ts1,"%x",(unsigned char) tcpd[i]); 
		    if (ts1[1]=='\0') { ts1[1]=ts1[0]; ts1[0]='0'; }
		    strcat(ops,ts1);
		}
		print_found(PROTO_VNC,ops);
		free(ops);
		memset(current->username,'�',RFB_CHALLANGE_LENGTH);
		return (0);
	    } // that's it. we are done !
	}
    }
    VERBOSE(3,"VNC: some data packet\n");

    return (0);
}
    
int handle_imap4(char *tcpd, unsigned int length) {
#define AUTH_REQ "authenticate login"
#define MICROSOFT_LOGIN "login "
    char *clear,*msp;
    char *b64;
    char *fullstring;

    // first request should be the AUTH_REQ ..
    if (mempos(tcpd,length,AUTH_REQ)!=NULL) {
	VERBOSE(1,"IMAP4: Authentication request found\n");
	list_append();
	current->username=(char *)smalloc(strlen(AUTH_REQ)+1);
	strcpy(current->username,AUTH_REQ);
	current->saddr=(struct in_addr)ip->saddr;
	current->daddr=(struct in_addr)ip->daddr;
	current->sport=(unsigned short int)tcp->src_port;
	current->dport=(unsigned short int)tcp->dest_port;
	current->type=PROTO_IMAP4;
	// EXIT - there should be no authentication in this packet
	return (0);
    }

    list_rewind();
    while (!(list_next())) {
	// if we allready found a packet containing the auth req from
	// this client to this server, we should try to extract
	// the username, save this one in current->username and wait for 
	// the password packet ...
	//
	// first - look for a completly unknown user
	if ( 
		(!memcmp((void *)&current->saddr,(void *)&ip->saddr,4)) &&
		(!memcmp((void *)&current->daddr,(void *)&ip->daddr,4)) &&
		(current->sport==(unsigned short int)tcp->src_port) &&
		(current->dport==(unsigned short int)tcp->dest_port) &&
		(current->type==PROTO_IMAP4) &&
		(strcmp(current->username,AUTH_REQ)==0)
		) {

	    VERBOSE(1,"IMAP4: suspecting username packet\n");

	    // there should be no identification tag in the username and 
	    // the password packet ...
	    if ((b64=memduptil(tcpd,'\r'))==NULL) {
		VERBOSE(1,"suspected username packet enpty\n");
		continue;
	    }
	    clear=decode64(b64);
	    if (verbose>=1) {
		print_found(PROTO_IMAP4,clear);
	    }
	    // we copy the username in the current record ...
	    free(current->username);
	    current->username=(char *)smalloc(strlen(clear)+1);
	    strcpy(current->username,clear);
	    free(clear);
	    // that's all for now, because in the NEXT packet should be 
	    // the password - therefor we exit here
	    return (0);
	} // end of if 
    } // end of while

    // the password section ...
    list_rewind();
    while (!(list_next())) {

	// if we find a packet from this host, containing data and we allready
	// found a username should be this the password
	if ( 
		(!memcmp((void *)&current->saddr,(void *)&ip->saddr,4)) &&
		(!memcmp((void *)&current->daddr,(void *)&ip->daddr,4)) &&
		(current->sport==(unsigned short int)tcp->src_port) &&
		(current->dport==(unsigned short int)tcp->dest_port) &&
		(current->type==PROTO_IMAP4) &&
		(strcmp(current->username,AUTH_REQ)!=0)
		) {

	    VERBOSE(1,"IMAP4: suspecting password packet\n");
	    // there should be no identification tag in the username and 
	    // the password packet ...
	    if ((b64=memduptil(tcpd,'\r'))==NULL) {
		VERBOSE(1,"suspected password packet enpty\n");
		continue;
	    }
	    clear=decode64(b64);
	    if (verbose>=1) {
		print_found(PROTO_IMAP4,clear);
	    }
	    if (clear==NULL) {
		fullstring=(char *)smalloc(strlen(current->username)+2);
		strcpy(fullstring,current->username);
		strcat(fullstring,":");
		print_found(PROTO_IMAP4,fullstring);
	    } else {
		fullstring=(char *)smalloc(strlen(current->username)+
			strlen(clear)+2);
		strcpy(fullstring,current->username);
		strcat(fullstring,":");
		strcat(fullstring,clear);
		print_found(PROTO_IMAP4,fullstring);
	    }
	    free(clear);
	    free(fullstring);
	    // we found it - therefor we should delete this entry in the list
	    // and exit right here
	    list_delete();
	    return(0);
	} // end of if
    } //end of while

    // if all of this fails we have one more option:
    // it could be a microsoft client running outlook...
    // they send the LOGIN in a different format:
    // 		A001 LOGIN "username" "password"
    // ---
    // the use of b64 is just saving - it contains clear text
    if ((b64=mempos(tcpd,length,MICROSOFT_LOGIN))!=NULL) {
	VERBOSE(1,"IMAP4: Microsoft Office login request found\n");
	b64+=sizeof(char)*strlen(MICROSOFT_LOGIN)+1;
	clear=memduptil(b64,'"');
	b64+=sizeof(char)*strlen(clear)+3;
	msp=memduptil(b64,'"');
	if (msp==NULL) {
	    fullstring=(char *)smalloc(strlen(clear)+2);
	    strcpy(fullstring,clear);
	    strcat(fullstring,":");
	} else {
	    fullstring=(char *)smalloc(strlen(clear)+strlen(msp)+2);
	    strcpy(fullstring,clear);
	    strcat(fullstring,":");
	    strcat(fullstring,msp);
	}
	free(msp);
	free(clear);
	print_found(PROTO_IMAP4,fullstring);
	free(fullstring);
    }

    return (0);
}

int handle_telnet(char *tcpd, unsigned int length) {
#define MAX_TELNET_LENGTH 50
#define MAX_LFS 4
    int i,j;
    char *buffer;

    if ( 
	    (!isprint(tcpd[0])) &&
	    (tcpd[0]!='\r') &&
	    (tcpd[0]!='\n') 
	    ) 
	return (0);

    list_rewind();
    while (!(list_next())) {
	if ( 
		(!memcmp((void *)&current->saddr,(void *)&ip->saddr,4)) &&
		(!memcmp((void *)&current->daddr,(void *)&ip->daddr,4)) &&
		(current->sport==(unsigned short int)tcp->src_port) &&
		(current->dport==(unsigned short int)tcp->dest_port) &&
		(current->type==PROTO_TELNET)
		) {
	    // we allready captured a packet from this host
	    VERBOSE(1,"TELNET: communication in progress ...\n");

	    // if the first caracter is � - then this is an death connection
	    if (current->username[0]=='�') return (0);

	    // everything in progress ...
	    // free the username, reallocate the new one and copy
	    buffer=(char *)smalloc(strlen(current->username)+1);
	    strcpy(buffer,current->username);
	    free(current->username);
	    current->username=(char *)smalloc(strlen(buffer)+length+1);
	    strcpy(current->username,buffer);
	    free(buffer);
	    buffer=current->username;
	    buffer+=sizeof(char)*(strlen(current->username));
	    j=0;
	    for (i=0;i<length;i++) {
		if (isprint(tcpd[i])||(tcpd[i]=='\n')) {
		    buffer[j]=tcpd[i];
		    j++;
		}
		if (tcpd[i]=='\r') {
		    buffer[j]='\n';
		    j++;
		}
	    }
	    buffer[j]='\0';
	    
	    // we count the number of line feeds in the username string
	    // - if they are more then MAX_LFS, then we stop the listening to
	    // this conversation here ...
	    j=0;
	    for (i=0;i<=strlen(current->username);i++) {
		if (current->username[i]=='\n') j++;
	    }
	    if (j>MAX_LFS) {
		print_found(PROTO_TELNET,"");
		printf("+++telnet+++\n%s\n---telnet---\n",current->username);
		current->username[0]='�';
		return (0);
	    }
	    
	    // my be we missed something or it is not real telnet or 
	    // whatever ...
	    // stop after MAX_TELNET_LENGTH chars 
	    if (strlen(current->username)>MAX_TELNET_LENGTH) {
		print_found(PROTO_TELNET,"");
		printf("+++telnet+++\n%s\n---telnet---\n",current->username);
		current->username[0]='�';
		return (0);
	    }

	    return (0);
	}
    }

    // looks like a new connection ...
    VERBOSE(1,"TELNET: New communication found\n");
    list_append();
    current->username=(char *)smalloc(length+1);
    j=0;
    for (i=0;i<length;i++) {
	if (isprint(tcpd[i])||(tcpd[i]=='\n')) {
	    current->username[j]=tcpd[i];
	    j++;
	}
	if (tcpd[i]=='\r') {
	    current->username[j]='\n';
	    j++;
	}
    }
    current->username[j]='\0';
    current->saddr=(struct in_addr)ip->saddr;
    current->daddr=(struct in_addr)ip->daddr;
    current->sport=(unsigned short int)tcp->src_port;
    current->dport=(unsigned short int)tcp->dest_port;
    current->type=PROTO_TELNET;
    return (0);
}

/* the array for callig appropriate functions for each protocol */
// NULL for the functions means "not yet supported"
static Protocols proto[] = {
    {"HTTP",PROTO_HTTP,handle_http},
    {"LDAP",PROTO_LDAP,handle_ldap},
    {"FTP",PROTO_FTP,handle_ftp},
    {"POP3",PROTO_POP3,handle_pop},
    {"IMAP4",PROTO_IMAP4,handle_imap4},
    {"Telnet",PROTO_TELNET,handle_telnet},
    {"VNC",PROTO_VNC,handle_vnc},
    {"unknown",PROTO_NONE,NULL}
};

/* tries to identify the protocol
 */
SupportedProtos identify(u_char *pdata) {

#define HTTP_PATTERN 7
    char *http_pattern[] = {"GET ","POST ","HEAD ","OPTIONS ","PUT ", 
	"DELETE ","TRACE "};
#define POP3_PATTERN 2
    char *pop3_pattern[] = {"USER ","PASS "};
#define FTP_PATTERN 2
    char  *ftp_pattern[] = {"USER ","PASS "};
#define LDAP_PATTERN 0
#define IMAP4_PATTERN 1
    char *imap4_pattern[] = {"authenticate login"};
    int i;

    ip=(struct iphdr *)(pdata+ETHLENGTH);
    if ((unsigned char)ip->version!=4) {
	return ((SupportedProtos)PROTO_NONE);
    }
    if (ip->protocol!=IPPROTO_TCP) {
	return ((SupportedProtos)PROTO_NONE);
    }

    tcp=(struct tcphdr *)(pdata+ETHLENGTH+((unsigned char)ip->ihl*4));
    if (verbose>=3) {
	printf("%s:%d -> ",
		inet_ntoa((struct in_addr)ip->saddr),
		ntohs((unsigned short int)tcp->src_port));
	printf("%s:%d\n",
		inet_ntoa((struct in_addr)ip->daddr),
		ntohs((unsigned short int)tcp->dest_port));
	printf("\tSeq: %u\n",(unsigned long int)ntohl(tcp->seq_num));
	printf("\tAck: %u\n",(unsigned long int)ntohl(tcp->ack_num));
    }
    if (
	    (phead->caplen-ETHLENGTH-
	     ((unsigned char)ip->ihl*4)-
	     (unsigned short int)((ntohs(tcp->rawflags)&0xF000)>>10))
	    ==0) {
	return ((SupportedProtos)PROTO_NONE);
    }
	
    // tcp_data is ...
    tcp_data=(pdata+
	    // .. ethernet length +
	    ETHLENGTH+
	    // .. IP header +
	    ((unsigned char)ip->ihl*4)+
	    // .. Dataoffset in TCP 
	    //      which is ((rawflags&0xF000)>>12)*4
	    //      which is (rawflags&0xF000)>>10 !
	    ((unsigned short int)(ntohs(tcp->rawflags)&0xF000)>>10));
    tcp_data_length=(phead->caplen-ETHLENGTH- 
	    ((unsigned char)ip->ihl*4)- 
	    (unsigned short int)((ntohs(tcp->rawflags)&0xF000)>>10));

    if (use_port) {
	switch (ntohs((unsigned short int)tcp->dest_port)) {
	    case HTTP_PORT: //guess it is HTTP
		return (PROTO_HTTP);
	    case POP3_PORT: //guess it is POP
		return (PROTO_POP3);
	    case FTP_PORT: //guess it is FTP
		return (PROTO_FTP);
	    case LDAP_PORT: //guess it is LDAP
		return (PROTO_LDAP);
	    case IMAP4_PORT: //guess it is LDAP
		return (PROTO_IMAP4);
	    case TELNET_PORT: //guess it is LDAP
		return (PROTO_TELNET);
	    case VNC_PORT: // guess it is VNC
		return (PROTO_VNC);
	} //switch end

	/* because we need both directions on VNC, check the source port too */
	if (ntohs((unsigned short int)tcp->src_port)==VNC_PORT) {
	    return (PROTO_VNC);
	}
    } // if use_port
    if (use_pattern) {
	// first check for HTTP
	for (i=0;i<HTTP_PATTERN;i++) {
	    if (tcp_data_length<=strlen(http_pattern[i])) continue;
	    if (memcmp(tcp_data,http_pattern[i],strlen(http_pattern[i]))==0) {
		return (PROTO_HTTP);
	    }
	}
	// then check for FTP
	for (i=0;i<FTP_PATTERN;i++) {
	    if (tcp_data_length<=strlen(ftp_pattern[i])) continue;
	    if (memcmp(tcp_data,ftp_pattern[i],strlen(ftp_pattern[i]))==0) {
		return (PROTO_FTP);
	    }
	}
	// then check for POP3
	for (i=0;i<POP3_PATTERN;i++) {
	    if (tcp_data_length<=strlen(pop3_pattern[i])) continue;
	    if (memcmp(tcp_data,pop3_pattern[i],strlen(pop3_pattern[i]))==0) {
		return (PROTO_POP3);
	    }
	}
	// then check for IMAP4
	for (i=0;i<IMAP4_PATTERN;i++) {
	    if (tcp_data_length<=strlen(imap4_pattern[i])) continue;
	    // here we use mempos because of the unknown length of the IMAP
	    // identifier tag
	    if (mempos(tcp_data,tcp_data_length,imap4_pattern[i])!=NULL) {
		return (PROTO_IMAP4);
	    }
	}
	/* 
	 * I disabled this one because a lot !!! of packets match these 
	 * criterias (like some netbios name requests !)
	 *
	// last check: LDAP
	if ( ((tcp_data[9]==2) || (tcp_data[9]==3)) &&
		((tcp_data[5]==0x60) || (tcp_data[5]==0x00)) ) {
	    // may be it is LDAP
	    return (PROTO_LDAP);
	} // end of if (LDAP)
	*/
    }

    return ((SupportedProtos)PROTO_NONE);
}


/* the main capture loop */
void capture_loop(void) {

    u_char *packet,*pcap_packet;
    SupportedProtos identification;

    while (cap_interrupted==0) {
	if ((pcap_packet=(u_char *)pcap_next(cap,pcap_head))==NULL) continue;

	/* make sure it is our own data */
	phead=smalloc(sizeof(struct pcap_pkthdr));
	memcpy(phead,pcap_head,sizeof(struct pcap_pkthdr));
	packet=smalloc(phead->caplen);
	memcpy(packet,pcap_packet,phead->caplen);

	
	if (phead->len<=(ETHLENGTH+IP_MIN_LENGTH)) {
	    VERBOSE(2,"Dwarf packet - skipping\n");
	    continue;
	}

	if ((identification=identify(packet))==PROTO_NONE) {
	    VERBOSE(3,"unknown protocol - skipping\n");
	} else {
	    // identification successfull
	    if (verbose>=3) printf("Proto: %s\n",proto[identification].name);
	    proto[identification].handler(tcp_data,tcp_data_length);
	}
	free(phead);
	free(packet);
    } // of while cap_interrupted

}

void usage(void) {
    printf("./PHoss [-Ppv] [-l XXXX] [-i interface ] [-f filter]\n"
           "\n-P\tDon't use destination ports for protocol identification\n"
           "-p\tDon't use pattern matching for protocol identification\n"
           "-v\tverbose (more increase information)\n"
           "-l XX\tSet capture length to this value (default 1525)\n"
           "-i int\tUse this interface\n"
           "-f xx\tSet packet filter. See tcpdump(1) for more\n"
           "-L \tmake output linebuffered\n");
    exit(0);
}

int main(int argc, char **argv) {

    // command line options
    char option;
    extern char *optarg;

    // command line args
    char *net_dev=NULL;
    unsigned int slength=DEF_CAPLENGTH;


    printf("%s\n%s\n",PROGRAM_NAME,PROGRAM_VERSION);

    while ((option=getopt(argc,argv,"PLpvl:i:f:"))!=EOF) {
	switch(option) {
	    case 'v': verbose++;
		      break;
	    case 'p': // don't use pattern for protocol guess
		      use_pattern=0;
		      VERBOSE(1,"Pattern matching packet identification\
		      disabled\n");
		      break;
	    case 'P': // don't use port for protocol guess
		      use_port=0;
		      VERBOSE(1,"Port matching packet identification\
		      disabled\n");
		      break;
	    case 'f': filter=(char *)smalloc(strlen(optarg)+1);
		      strcpy(filter,optarg);
		      break;
	    case 'L': // make stdout line buffered for output in a file
#ifdef HAVE_SETLINEBUF
			setlinebuf(stdout);
#else
			setvbuf(stdout, NULL, _IOLBF, 0);
#endif
			break;
	    case 'i': net_dev=(char *)smalloc(strlen(optarg)+1);
		      strcpy(net_dev,optarg);
		      break;
	    case 'l': if ((slength=atoi(optarg))<24) {
			  fprintf(stderr,"Useless capture length: %d - ignored\n",slength);
			  slength=DEF_CAPLENGTH;
		      }
	    default: usage();
	}
    }

    if (init_capture(net_dev,slength)==0) {
	// rest of the program
	
	// installing SIGN_INT handler
	signal(SIGINT,(void *)SIG_INT_handler);
	// setting up list
	list_create();
	
	// start the capture looping (til CTRL-C)
	capture_loop();

	list_destroy();
    }

    /* cleaning up */
    free(phead);
    free(filter);

    printf("Goodbye\n");
    return 0;
}


void print_found(SupportedProtos prot, char *cleardata) {
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    printf("Source: \t%s:%d\n",
	    inet_ntoa((struct in_addr)ip->saddr),
	    ntohs((unsigned short int)tcp->src_port));
    printf("Destination: \t%s:%d\n",
	    inet_ntoa((struct in_addr)ip->daddr),
	    ntohs((unsigned short int)tcp->dest_port));
    printf("Protocol: \t%s\n",proto[prot].name);
    printf("Data: \t\t%s\n",cleardata);
}

/* $Id: list.c,v 1.4 2000/06/01 13:49:20 fx Exp fx $ */
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>                 // for IPPROTO_bla consts
#include <sys/socket.h>                 // for inet_ntoa()
#include <arpa/inet.h>                  // for inet_ntoa()  

#include "list.h"

int list_next() {
    if (current->next==NULL) { 
	return (-1); 
    /* if (current==NULL) { 
	current=anchor;
	return (-1);  */
    } else {
	current=current->next;
	return 0;
    }
}

void list_delete() {
    if (current==anchor) {
	anchor=anchor->next;
	free(current);
	current=anchor;
    } else {
	help=anchor;
	while (help->next!=current) { help=help->next; }
	help->next=current->next;
	free(current);
	current=help;
	if (help->next==NULL) { 
	    last=help;
	}
    }
}

int list_create() {

    if (anchor!=NULL) {
	fprintf(stderr,"create_list(): WARING: anchor not NULL\n");
    }
    anchor=current=help=NULL;

    anchor=(struct T_LIST_MEMBER *)malloc(sizeof(struct T_LIST_MEMBER));
    current=anchor;
    help=anchor;
    current->next=NULL;
    last=anchor;

    return 0;
}

void list_rewind() {
    current=anchor;
}

int list_append(void) {

    // list_rewind();
    // while (current->next!=NULL) current=current->next;
    current=last;

    help=(struct T_LIST_MEMBER *)malloc(sizeof(struct T_LIST_MEMBER));
    current->next=help;
    help->next=NULL;

    last=help;
    current=help;
    return 0;
}

int list_destroy() {
    list_rewind();
    while (current!=NULL) {
	help=current;
	current=current->next;
	free(help);
    }
    return 0;
}

int list_find(char *a,SupportedProtos t) {
    list_rewind();
    current=current->next;
    while (current!=NULL) {
	if ((strcmp(current->username,a)==0)&&(current->type==t)) {
	    return 1;
	} else {
	    current=current->next;
	}
    }
    return 0;
}

int list_find_connection(
	struct in_addr s, struct in_addr d, 
	unsigned short int sp, unsigned short int dp, 
	SupportedProtos t) {
    
    list_rewind();
    current=current->next;
    while (current!=NULL) {
	if (
		(memcmp(&current->saddr,&s,4)==0)
		&&(memcmp(&current->daddr,&d,4)==0)
		&&(current->sport==sp)
		&&(current->dport==dp)
		&&(current->type==t)
		) {
	    return 1;
	} else {
	    current=current->next;
	}
    }
    return 0;
}



#ifndef _LIST_H_
#define _LIST_H_

/* $Id: list.h,v 1.3 2000/06/01 12:52:25 fx Exp fx $ */

#include "subprotocols.h"

struct T_LIST_MEMBER {
    char *username;
    struct in_addr saddr;
    struct in_addr daddr;
    unsigned short int sport;
    unsigned short int dport;
    SupportedProtos type;

    struct T_LIST_MEMBER *next;
};

// extern int list_verbose;
// extern struct T_LIST_MEMBER *current;
struct T_LIST_MEMBER *anchor,*current,*help,*last;
int list_verbose;

int list_create();
int list_append();
int list_destroy();
int list_next();
void list_rewind();
void list_delete();
int list_find(char *a,SupportedProtos t); 
int list_find_connection(struct in_addr s, struct in_addr d, unsigned short int sp, unsigned short int dp, SupportedProtos t);

#endif _LIST_H_

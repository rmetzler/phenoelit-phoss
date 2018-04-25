#ifndef _SUBPROTOCOLS_H_
#define _SUBPROTOCOLS_H_
/* $Id: subprotocols.h,v 1.4 2000/06/01 11:54:22 fx Exp fx $ */
typedef enum {
    PROTO_HTTP,
    PROTO_LDAP,
    PROTO_FTP,
    PROTO_POP3,
    PROTO_IMAP4,
    PROTO_TELNET,
    PROTO_VNC,
    PROTO_NONE
} SupportedProtos;
#endif _SUBPROTOCOLS_H_

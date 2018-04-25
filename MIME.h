/* MIME.h 
 * function for encoding a string in base64 format
 * $Id: MIME.h,v 1.1 1999/11/15 08:31:49 root Exp root $
 */

#ifndef _MIME_H_
#define _MIME_H_

extern char *encode64(const char *plainorig);
extern char *decode64(char *code);

#endif _MIME_H_

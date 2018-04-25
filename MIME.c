/* MIME.h 
 * function for encoding a string in base64 format
 * $Id: MIME.c,v 1.1 1999/11/15 08:31:59 root Exp root $
 */

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

// prototypes
#include "MIME.h"

const char dict[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *encode64(const char *plainorig)
{
static char *encoded;
static int encoded_l;

  // char dict[64];
  char dummy3[5];
  char *plain;
  int plain_length,padding;
  unsigned long block24;
  unsigned char l;

  /* per definition is encoded (resp. the returned var) freed by caller */
  encoded=NULL;
 
  /* take care of 0s and padding */ 
  if (!(strlen(plainorig)%3))
  { plain_length=strlen(plainorig); 
    padding=0;
  } else {
    plain_length=(strlen(plainorig)+(3-(strlen(plainorig)%3)));
    padding=(3-(strlen(plainorig)%3));
    // FOR DEBUG printf("Padding = %d\n",padding); 
  }
 
  /* calculate needed memory and get it */
  plain=(char *)malloc(plain_length);
  if (plain==NULL) { printf("encode64(): malloc for plain\n"); exit(-1); }
  bzero(plain,plain_length);
  strcpy(plain,plainorig);

  encoded=(char *)malloc((int)(plain_length*1.4)+1);
  if (encoded==NULL) { printf("encode64(): malloc for encoded, size: %d\n",(int)(plain_length*1.4)+1); exit(-1); }
  encoded_l=(int)(strlen(plain)*1.4)+1;

  bzero(encoded,encoded_l); 
  bzero(dummy3,sizeof(dummy3)); 

  for (l=0;l<plain_length;l+=3)
  {
    block24=(((unsigned char)plain[l])<<16)|(((unsigned char)plain[l+1])<<8)|((unsigned char)plain[l+2]);

    dummy3[0]=dict[(block24&16515072)>>18];
    dummy3[1]=dict[(block24&258048)>>12];
    dummy3[2]=dict[(block24&4032)>>6];
    dummy3[3]=dict[block24&63];
    if ((padding)&&((l+3)>=plain_length))
    { switch(padding)
      { case 1: dummy3[3]=61; break;
        case 2: dummy3[2]=dummy3[3]=61; break; }
    }
    strcat(encoded,dummy3);

  }  

  // FOR DEBUG printf("%s\n",encoded);
  free(plain);
  return encoded;
} 

char *decode64(char *code)
{
	char *sp,*decoded;
	char dummy[5];
	unsigned long int four;
	int padding,i;

	if ((code==NULL)||(strlen(code)==0)) return NULL;
	if ((decoded=(char *)malloc(strlen(code)))==NULL)
	{ printf("decode64: malloc() for decode\n"); return NULL; }
	bzero(decoded,strlen(code));

	if (code[strlen(code)-1]=='=')
	{
		if (code[strlen(code)-2]=='=') padding=2;
		else padding=1;
	}
	else padding=0;

	bzero(dummy,sizeof(dummy));
	sp=code;
	while (strlen(sp)>=4)
	{
		strncpy(dummy,sp,4);
		four=0;
		for (i=0;i<=63;i++)
			if (dummy[0]==dict[i]) break;
		four=i<<18;
		for (i=0;i<=63;i++)
			if (dummy[1]==dict[i]) break;
		four=four | (i<<12);

		// take care of padding 
		if (dummy[2]=='=') i=0;
		else 
		{
			for (i=0;i<=63;i++)
				if (dummy[2]==dict[i]) break;
		}
		four=four | (i<<6);
		if (dummy[3]=='=') i=0;
		else 
		{
			for (i=0;i<=63;i++)
				if (dummy[3]==dict[i]) break;
		}
		four=four | i;
		dummy[3]=(char )0;
		dummy[2]=(char )(four&0xFF);
		dummy[1]=(char )((four&0xFF00)>>8);
		dummy[0]=(char )((four&0xFF0000)>>16);
		strcat(decoded,dummy);	
		sp+=4;
	}

	return decoded;
}


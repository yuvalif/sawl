/*TODO: rewrite radius_hdr and radius_attr to remove GNU license*/

/* $Id: radius.h,v 1.1.1.1 2004/09/21 15:56:44 iscjonm Exp $
 *
 * Copyright (C) 2004 The Trustees of the University of Pennsylvania
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _RADIUS_H
#define _RADIUS_H

#include <openssl/sha.h>

struct radius_hdr {
  unsigned char code;       /* type of RADIUS packet */
  unsigned char ident;      /* "session" identifier */
  unsigned short len;       /* length in octets of entire packet including RADIUS header */
  unsigned char auth[16];   /* authenticator field */
};

struct radius_attr {
  unsigned char type;       /* attribute type */
  unsigned char len;        /* attribute length in octets, including type and length fields */
  unsigned char value[8];
  /* note that value can be arbitrary length, but we make it 8 bytes for alignment purposes */
};

#define RADIUS_ACCESS_REQUEST       1
#define RADIUS_ACCESS_ACCEPT        2
#define RADIUS_ACCESS_REJECT        3
#define RADIUS_ACCT_REQUEST         4
#define RADIUS_ACCT_RESPONSE        5
#define RADIUS_ACCESS_CHALLENGE    11
#define RADIUS_STATUS_SERVER       12
#define RADIUS_STATUS_CLIENT       13

struct radius_info
{
    int _has_name;
    int _has_ip;
    int _location_update;
    int _login_or_update;
    int _logout;
    char _name[SHA_DIGEST_LENGTH*2+1];
    unsigned int _cell_id;
    char _ip[16];
};

#define HI_NIBBLE(b) (((b) >> 4) & 0x0F)
#define LO_NIBBLE(b) ((b) & 0x0F)

extern void append_radius_info(struct radius_attr* ra, struct radius_info* info);
extern void print_radius_info(struct radius_info* info);

#endif


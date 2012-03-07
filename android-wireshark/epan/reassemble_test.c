/* Standalone program to test functionality of reassemble.h API
 *
 * These aren't particularly complete - they just test a few corners of
 * functionality which I was interested in. In particular, they only test the
 * fragment_add_seq_* (ie, FD_BLOCKSEQUENCE) family of routines. However,
 * hopefully they will inspire people to write additional tests, and provide a
 * useful basis on which to do so.
 *
 * December 2010:
 * 1. reassemble_test can be run under valgrind to detect any memory leaks in the
 *    Wireshark reassembly code.
 *    Specifically: code has been added to free dynamically allocated memory
 *     after each test (or at program completion) so that valgrind will report
 *     only actual memory leaks.
 *    The following command can be used to run reassemble_test under valgrind:
 *      env                               \
 *        G_DEBUG=gc-friendly             \
 *        G_SLICE=always-malloc           \
 *        WIRESHARK_DEBUG_EP_NO_CHUNKS=1  \
 *        WIRESHARK_DEBUG_SE_NO_CHUNKS=1  \
 *        WIRESHARK_DEBUG_SE_USE_CANARY=1 \
 *        WIRESHARK_EP_VERIFY_POINTERS=1  \
 *        WIRESHARK_SE_VERIFY_POINTERS=1  \
 *      valgrind --leak-check=full --show-reachable=yes ./reassemble_test
 *
 *  2. Debug functions have been added which will print information
 *     about the fd-chains associated with the fragment_table and the
 *     reassembled table.
 *     #define debug  to enable the code.
 *
 * $Id: reassemble_test.c 36132 2011-03-03 23:28:32Z morriss $
 *
 * Copyright (c) 2007 MX Telecom Ltd. <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/reassemble.h>

#include <epan/dissectors/packet-dcerpc.h>

#define ASSERT(b) do_test((b),"Assertion failed at line %i: %s\n", __LINE__, #b)
#define ASSERT_EQ(exp,act) do_test((exp)==(act),"Assertion failed at line %i: %s==%s (%i==%i)\n", __LINE__, #exp, #act, exp, act)
#define ASSERT_NE(exp,act) do_test((exp)!=(act),"Assertion failed at line %i: %s!=%s (%i!=%i)\n", __LINE__, #exp, #act, exp, act)

static int failure = 0;

static void
do_test(gboolean condition, const char *format, ...)
{
    va_list ap;

    if (condition)
        return;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    failure = 1;

    /* many of the tests assume this routine doesn't return on failure; if we
     * do, it may provide more information, but may cause a segfault. Uncomment
     * this line if you wish.
     */
    exit(1);
}

#define DATA_LEN 256

static char *data;
static tvbuff_t *tvb;
static packet_info pinfo;

/* fragment_table maps from datagram ids to head of fragment_data list
   reassembled_table maps from <packet number,datagram id> to head of
   fragment_data list */
static GHashTable *fragment_table = NULL;
static GHashTable *reassembled_table = NULL;

#ifdef debug
/*************************************************
 * Util fcns to display
 *   fragment_table & reassembled_table fd-chains
 ************************************************/

/* Must match the typedef in reassemble.c */
typedef struct _fragment_key {
	address src;
	address dst;
	guint32 id;
} fragment_key;

/* Must match the typedef in reassemble.c */
typedef struct _reassembled_key {
	guint32 id;
	guint32 frame;
} reassembled_key;

static struct _fd_flags {
    guint32 flag;
    gchar  *flag_name;
} fd_flags[] = {
    {FD_DEFRAGMENTED         ,"DF"},
    {FD_DATALEN_SET          ,"DS"},
    {FD_NOT_MALLOCED         ,"NM"},
    {FD_BLOCKSEQUENCE        ,"BS"},
    {FD_DATA_NOT_PRESENT     ,"NP"},
    {FD_PARTIAL_REASSEMBLY   ,"PR"},
    {FD_OVERLAP              ,"OL"},
    {FD_OVERLAPCONFLICT      ,"OC"},
    {FD_MULTIPLETAILS        ,"MT"},
    {FD_TOOLONGFRAGMENT      ,"TL"},
};
#define N_FD_FLAGS (signed)(sizeof(fd_flags)/sizeof(struct _fd_flags))

static void
print_fd(fragment_data *fd, gboolean is_head) {
    int i;

    g_assert(fd != NULL);
    printf("        %08x %08x %3d %3d %3d", fd, fd->next, fd->frame, fd->offset, fd->len);
    if (is_head) {
        printf(" %3d %3d", fd->datalen, fd->reassembled_in);
    } else {
        printf( "        ");
    }
    printf(" 0x%08x", fd->data);
    for (i=0; i<N_FD_FLAGS; i++) {
        printf(" %s", (fd->flags & fd_flags[i].flag) ? fd_flags[i].flag_name : "  ");
    }
    printf("\n");
}

static void
print_fd_chain(fragment_data *fd_head) {
    fragment_data *fdp;

    g_assert(fd_head != NULL);
    print_fd(fd_head, TRUE);
    for (fdp=fd_head->next; fdp != NULL; fdp=fdp->next) {
        print_fd(fdp, FALSE);
    }
}

static void
print_fragment_table_chain(gpointer k, gpointer v, gpointer ud) {
    fragment_key  *key     = (fragment_key*)k;
    fragment_data *fd_head = (fragment_data *)v;
    printf("  --> FT: %3d 0x%08x 0x%08x\n", key->id, *(guint32 *)(key->src.data), *(guint32 *)(key->dst.data));
    print_fd_chain(fd_head);
}

static void
print_fragment_table(void) {
    printf("\n Fragment Table -------\n");
    g_hash_table_foreach(fragment_table, print_fragment_table_chain, NULL);
}

static void
print_reassembled_table_chain(gpointer k, gpointer v, gpointer ud) {
    reassembled_key  *key  = (reassembled_key*)k;
    fragment_data *fd_head = (fragment_data *)v;
    printf("  --> RT: %5d %5d\n", key->id, key->frame);
    print_fd_chain(fd_head);
}

static void
print_reassembled_table(void) {
    printf("\n Reassembled Table ----\n");
    g_hash_table_foreach(reassembled_table, print_reassembled_table_chain, NULL);
}

static void
print_tables(void) {
    print_fragment_table();
    print_reassembled_table();
}
#endif

/**********************************************************************************
 *
 * fragment_add_seq
 *
 *********************************************************************************/

/* Simple test case for fragment_add_seq.
 * Adds three fragments (out of order, with one for a different datagram in between),
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       1    12     1     0    60   T       5
       0    13     2     0    60   T      15
       0    12     3     2    60   F       5
       0    12     4     1    60   F      15
*/
static void
test_simple_fragment_add_seq(void)
{
    fragment_data *fd_head, *fdh0;

    printf("Starting test test_simple_fragment_add_seq\n");

    pinfo.fd->num = 1;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* adding the same fragment again should do nothing, even with different
     * offset etc */
    pinfo.fd->flags.visited = 1;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             0, 60, TRUE);
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->flags.visited = 0;
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq(tvb, 15, &pinfo, 13, fragment_table,
                             0, 60, TRUE);
    ASSERT_EQ(2,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* now we add the terminal fragment of the first datagram */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             2, 60, FALSE);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(2,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* finally, add the missing fragment */
    pinfo.fd->num = 4;
    fd_head=fragment_add_seq(tvb, 15, &pinfo, 12, fragment_table,
                             1, 60, TRUE);

    ASSERT_EQ(2,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(170,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(4,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+15,60));
    ASSERT(!memcmp(fd_head->data+110,data+5,60));

#if 0
    print_fragment_table();
#endif

    /* what happens if we revisit the packets now? */
    fdh0 = fd_head;
    pinfo.fd->flags.visited = 1;
    pinfo.fd->num = 1;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, TRUE);
    /*
     * this api relies on the caller to check fd_head -> reassembled_in
     *
     * Redoing all the tests seems like overkill - just check the pointer
     */
    ASSERT_EQ(fdh0,fd_head);

    pinfo.fd->num = 3;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             2, 60, FALSE);
    ASSERT_EQ(fdh0,fd_head);

    pinfo.fd->num = 4;
    fd_head=fragment_add_seq(tvb, 15, &pinfo, 12, fragment_table,
                             1, 60, TRUE);
    ASSERT_EQ(fdh0,fd_head);

#if 0
    print_fragment_table();
#endif
}

/* XXX ought to have some tests for overlapping fragments */

/* This tests the functionality of fragment_set_partial_reassembly for
 * FD_BLOCKSEQUENCE reassembly.
 *
 * We add a sequence of fragments thus:
 *    seqno   frame  offset   len   (initial) more_frags
 *    -----   -----  ------   ---   --------------------
 *      0       1       10       50   false
 *      1       2        0       40   true
 *      1       3        0       40   true (a duplicate fragment)
 *      2       4       20      100   false
 *      3       5        0       40   false
 */
static void
test_fragment_add_seq_partial_reassembly(void)
{
    fragment_data *fd_head, *fd;

    printf("Starting test test_fragment_add_seq_partial_reassembly\n");

    /* generally it's probably fair to assume that we will be called with
     * more_frags=FALSE.
     */
    pinfo.fd->num = 1;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(50,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(1,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_EQ(NULL,fd_head->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));

    /* now we announce that the reassembly wasn't complete after all. */
    fragment_set_partial_reassembly(&pinfo,12,fragment_table);

    /* and add another segment. To mix things up slightly (and so that we can
     * check on the state of things), we're going to set the more_frags flag
     * here
     */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq(tvb, 0, &pinfo, 12, fragment_table,
                             1, 40, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    fd_head=fragment_get(&pinfo,12,fragment_table);
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);   /* unused */
    ASSERT_EQ(0,fd_head->offset);  /* unused */
    /* ASSERT_EQ(50,fd_head->len);     the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_NOT_MALLOCED,fd->flags);
    ASSERT_EQ(fd_head->data,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE(NULL,fd->data);
    ASSERT_EQ(NULL,fd->next);

    /* Another copy of the second segment.
     */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq(tvb, 0, &pinfo, 12, fragment_table,
                             1, 40, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);
    fd_head=fragment_get(&pinfo,12,fragment_table);
    ASSERT_NE(NULL,fd_head);
    ASSERT_EQ(0,fd_head->frame);   /* unused */
    ASSERT_EQ(0,fd_head->offset);  /* unused */
    /* ASSERT_EQ(50,fd_head->len);     the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_NOT_MALLOCED,fd->flags);
    ASSERT_EQ(fd_head->data,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE(NULL,fd->data);
    ASSERT_EQ(NULL,fd->next);



    /* have another go at wrapping things up */
    pinfo.fd->num = 4;
    fd_head=fragment_add_seq(tvb, 20, &pinfo, 12, fragment_table,
                             2, 100, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(190,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(2,fd->offset);  /* seqno */
    ASSERT_EQ(100,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_EQ(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data,40));
    ASSERT(!memcmp(fd_head->data+90,data+20,100));


    /* do it again (this time it is more complicated, with an overlap in the
     * reassembly) */

    fragment_set_partial_reassembly(&pinfo,12,fragment_table);

    pinfo.fd->num = 5;
    fd_head=fragment_add_seq(tvb, 0, &pinfo, 12, fragment_table,
                             3, 40, FALSE);

    fd_head=fragment_get(&pinfo,12,fragment_table);
    ASSERT_NE(NULL,fd_head);
    ASSERT_EQ(0,fd_head->frame);   /* unused */
    ASSERT_EQ(0,fd_head->offset);  /* unused */
    ASSERT_EQ(230,fd_head->len);   /* the length of data we have */
    ASSERT_EQ(3,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(5,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(2,fd->offset);  /* seqno */
    ASSERT_EQ(100,fd->len);   /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_NE(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(5,fd->frame);
    ASSERT_EQ(3,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ(NULL,fd->data);
    ASSERT_EQ(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data,40));
    ASSERT(!memcmp(fd_head->data+90,data+20,100));
    ASSERT(!memcmp(fd_head->data+190,data,40));
}

/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 1st one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     2    40   F      5
       0    12     4     0    50   T      10
*/
static void
test_fragment_add_seq_duplicate_first(void)
{
    fragment_data *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_first\n");

    pinfo.fd->num = 1;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             1, 60, TRUE);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Add the last fragment */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             2, 40, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* Add the first fragment again */
    pinfo.fd->num = 4;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, TRUE);

    /* Reassembly should have still succeeded */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(4,fd_head->next->next->frame);
    ASSERT_EQ(0,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next);

    ASSERT_EQ(2,fd_head->next->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+5,60));
    ASSERT(!memcmp(fd_head->data+110,data+5,40));

#if 0
    print_fragment_table();
#endif
}


/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     1    60   T      5
       0    12     4     3    40   F      5
*/
static void
test_fragment_add_seq_duplicate_middle(void)
{
    fragment_data *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_middle\n");

    pinfo.fd->num = 1;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             1, 60, TRUE);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame) */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             1, 60, TRUE);

    /* This duplicate fragment should have been ignored */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.fd->num = 4;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             2, 40, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(2,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd_head->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(4,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+5,60));
    ASSERT(!memcmp(fd_head->data+110,data+5,40));

#if 0
    print_fragment_table();
#endif
}

/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 3rd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     2    40   F      5
       0    12     4     2    40   F      5
*/
static void
test_fragment_add_seq_duplicate_last(void)
{
    fragment_data *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_last\n");

    pinfo.fd->num = 1;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             1, 60, TRUE);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Add the last fragment */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             2, 40, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* Add the last fragment again */
    pinfo.fd->num = 4;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             2, 40, FALSE);

    /* Reassembly should have still succeeded */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(2,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(4,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd_head->next->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+5,60));
    ASSERT(!memcmp(fd_head->data+110,data+5,40));

#if 0
    print_fragment_table();
#endif
}

/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data
 * where the retransmission "conflicts" with the original transmission
 * (contents are different).
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     1    60   T      15
       0    12     4     2    40   F      5
*/
static void
test_fragment_add_seq_duplicate_conflict(void)
{
    fragment_data *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_conflict\n");

    pinfo.fd->num = 1;
    fd_head=fragment_add_seq(tvb, 10, &pinfo, 12, fragment_table,
                             0, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             1, 60, TRUE);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame and with
     * different data)
     */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq(tvb, 15, &pinfo, 12, fragment_table,
                             1, 60, TRUE);

    /* This duplicate fragment should have been ignored */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.fd->num = 4;
    fd_head=fragment_add_seq(tvb, 5, &pinfo, 12, fragment_table,
                             2, 40, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP|FD_OVERLAPCONFLICT,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(2,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP|FD_OVERLAPCONFLICT,fd_head->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(4,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+5,60));
    ASSERT(!memcmp(fd_head->data+110,data+5,40));

#if 0
    print_fragment_table();
#endif
}

/**********************************************************************************
 *
 * fragment_add_dcerpc_dg
 *
 *********************************************************************************/

/* This can afford to be reasonably minimal, as it's just the same logic with a
 * different hash key to fragment_add_seq
 */
static void
test_fragment_add_dcerpc_dg(void)
{
    e_uuid_t act_id = {1,2,3,{4,5,6,7,8,9,10,11}};

    fragment_data *fd_head, *fdh0;
    GHashTable *fragment_table = NULL;

    printf("Starting test test_fragment_add_dcerpc_dg\n");

    /* we need our own fragment table */
    dcerpc_fragment_table_init(&fragment_table);
    fd_head=fragment_add_dcerpc_dg(tvb, 10, &pinfo, 12, &act_id, fragment_table,
                                   0, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->num = 2;
    fd_head=fragment_add_dcerpc_dg(tvb, 15, &pinfo, 13, &act_id, fragment_table,
                             0, 60, TRUE);
    ASSERT_EQ(2,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);

    /* another pdu, with the same fragment_id, but a different act_id, to the
     * first one */
    pinfo.fd->num = 3;
    act_id.Data1=2;
    fd_head=fragment_add_dcerpc_dg(tvb, 15, &pinfo, 12, &act_id, fragment_table,
                                   0, 60, TRUE);
    ASSERT_EQ(3,g_hash_table_size(fragment_table));
    ASSERT_EQ(NULL,fd_head);
    act_id.Data1=1;

    /* now we add the terminal fragment of the first datagram */
    pinfo.fd->num = 4;
    fd_head=fragment_add_dcerpc_dg(tvb, 5, &pinfo, 12, &act_id, fragment_table,
                                   1, 60, FALSE);

    ASSERT_EQ(3,g_hash_table_size(fragment_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(110,fd_head->len); /* the length of data we have */
    ASSERT_EQ(1,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+5,60));

    /* what happens if we revisit the packets now? */
    fdh0 = fd_head;
    pinfo.fd->flags.visited = 1;
    pinfo.fd->num = 1;
    fd_head=fragment_add_dcerpc_dg(tvb, 10, &pinfo, 12, &act_id, fragment_table,
                                   0, 50, TRUE);
    /*
     * this api relies on the caller to check fd_head -> reassembled_in
     *
     * Redoing all the tests seems like overkill - just check the pointer
     */
    ASSERT_EQ(fdh0,fd_head);
}

/**********************************************************************************
 *
 * fragment_add_seq_check
 *
 *********************************************************************************/


/* This routine is used for both fragment_add_seq_802_11 and
 * fragment_add_seq_check.
 *
 * Adds a couple of out-of-order fragments and checks their reassembly.
 */

/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    13     2     0    60   T      15
       0    12     3     2    60   F       5
       0    12     4     1    60   F      15
*/


static void
test_fragment_add_seq_check_work(fragment_data *(*fn)(tvbuff_t *, const int,
				 const packet_info *, const guint32, GHashTable *,
				 GHashTable *, const guint32, const guint32, const gboolean))
{
    fragment_data *fd_head;

    pinfo.fd -> num = 1;
    fd_head=fn(tvb, 10, &pinfo, 12, fragment_table,
               reassembled_table, 0, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->num = 2;
    fd_head=fn(tvb, 15, &pinfo, 13, fragment_table,
               reassembled_table, 0, 60, TRUE);
    ASSERT_EQ(2,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    /* add the terminal fragment of the first datagram */
    pinfo.fd->num = 3;
    fd_head=fn(tvb, 5, &pinfo, 12, fragment_table,
               reassembled_table, 2, 60, FALSE);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(2,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    /* finally, add the missing fragment */
    pinfo.fd->num = 4;
    fd_head=fn(tvb, 15, &pinfo, 12, fragment_table,
               reassembled_table, 1, 60, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(3,g_hash_table_size(reassembled_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(170,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(4,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_NE(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+15,60));
    ASSERT(!memcmp(fd_head->data+110,data+5,60));

#if 0
    print_tables();
#endif
}

/* Simple test case for fragment_add_seq_check
 */
static void
test_fragment_add_seq_check(void)
{
    printf("Starting test test_fragment_add_seq_check\n");

    test_fragment_add_seq_check_work(fragment_add_seq_check);
}


/* This tests the case that the 802.11 hack does something different for: when
 * the terminal segment in a fragmented datagram arrives first.
 */
static void
test_fragment_add_seq_check_1(void)
{
    fragment_data *fd_head;

    printf("Starting test test_fragment_add_seq_check_1\n");

    pinfo.fd->num = 1;
    fd_head=fragment_add_seq_check(tvb, 10, &pinfo, 12, fragment_table,
                                   reassembled_table, 1, 50, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    /* Now add the missing segment */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq_check(tvb, 5, &pinfo, 12, fragment_table,
                                   reassembled_table, 0, 60, TRUE);

    ASSERT_EQ(0,g_hash_table_size(fragment_table));
    ASSERT_EQ(2,g_hash_table_size(reassembled_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(110,fd_head->len); /* the length of data we have */
    ASSERT_EQ(1,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(2,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(2,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(1,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+5,60));
    ASSERT(!memcmp(fd_head->data+60,data+10,50));
}

/**********************************************************************************
 *
 * fragment_add_seq_802_11
 *
 *********************************************************************************/

/* Tests the 802.11 hack.
 */
static void
test_fragment_add_seq_802_11_0(void)
{
    fragment_data *fd_head;

    printf("Starting test test_fragment_add_seq_802_11_0\n");

    /* the 802.11 hack is that some non-fragmented datagrams have non-zero
     * fragment_number; test for this. */

    pinfo.fd->num = 1;
    fd_head=fragment_add_seq_802_11(tvb, 10, &pinfo, 12, fragment_table,
                                    reassembled_table, 10, 50, FALSE);

    ASSERT_EQ(0,g_hash_table_size(fragment_table));
    ASSERT_EQ(1,g_hash_table_size(reassembled_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(0,fd_head->len);    /* unused */
    ASSERT_EQ(0,fd_head->datalen); /* unused */
    ASSERT_EQ(1,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE,fd_head->flags);
    ASSERT_EQ(NULL,fd_head->data);
    ASSERT_EQ(NULL,fd_head->next);
}

/* Reuse the fragment_add_seq_check testcases */
static void test_fragment_add_seq_802_11_1(void)
{
    printf("Starting test test_fragment_add_seq_802_11_1\n");
    test_fragment_add_seq_check_work(fragment_add_seq_802_11);
}

/**********************************************************************************
 *
 * fragment_add_seq_check_multiple
 *
 *********************************************************************************/

/* Test 2 partial frags from 2 diff datagrams in the same frame */
/*
   datagram #1: frame 1 + first part of frame 2
   datagram #1: last part of frame 2 + frame 3

   Is this a valid scenario ?

   The result of calling fragment_add_seq_check() for these
   fragments is a reassembled_table with:
    id, frame 1 => first_datagram;  ["reassembled in" frame 2]
    id, frame 2 => second_datagram; ["reassembled in" frame 3]
    id, frame 3 => second_datagram;

    Note that the id, frame 2 => first datagram was overwritten
     by the entry for the second datagram.
   Is this OK ? IE: When dissected/displayed
      will the reassembled datagram 1 appear with frame 2 ??
*/

/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    20   F       5
       0    12     2     0    25   T      25
       0    12     3     1    60   F       0
*/

/*
   Is this a valid scenario ?
   Is this OK ? IE: When dissected/displayed:
      Will the reassembled datagram 1 appear with frame 2 ??
*/
#if 0
static void
test_fragment_add_seq_check_multiple(void) {
    fragment_data *fd_head;

    pinfo.fd -> num = 1;
    fd_head=fragment_add_seq_check(tvb, 10, &pinfo, 12, fragment_table,
                                   reassembled_table, 0, 50, TRUE);

    /* add the terminal fragment of the first datagram */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq_check(tvb, 5, &pinfo, 12, fragment_table,
                                   reassembled_table, 1, 20, FALSE);

    print_tables();

    /* Now: start a second datagram with the first fragment in frame #2 */
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq_check(tvb, 25, &pinfo, 12, fragment_table,
               reassembled_table, 0, 25, TRUE);

    /* add the terminal fragment of the second datagram */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq_check(tvb, 0, &pinfo, 12, fragment_table,
                                   reassembled_table, 1, 60, FALSE);

    print_tables();
}
#endif

/**********************************************************************************
 *
 * fragment_add_seq_next
 *
 *********************************************************************************/

/* Simple test case for fragment_add_seq_next.
 * Adds a couple of fragments (with one for a different datagram in between),
 * and checks that they are reassembled correctly.
 */
static void
test_simple_fragment_add_seq_next(void)
{
    fragment_data *fd_head;

    printf("Starting test test_simple_fragment_add_seq_next\n");

    pinfo.fd->num = 1;
    fd_head= fragment_add_seq_next(tvb, 10, &pinfo, 12, fragment_table,
                                  reassembled_table, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    /* adding the same fragment again should do nothing, even with different
     * offset etc */
    pinfo.fd->flags.visited = 1;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 12, fragment_table,
                                  reassembled_table, 60, TRUE);
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->flags.visited = 0;
    pinfo.fd->num = 2;
    fd_head=fragment_add_seq_next(tvb, 15, &pinfo, 13, fragment_table,
                                  reassembled_table, 60, TRUE);
    ASSERT_EQ(2,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);


    /* now we add the terminal fragment of the first datagram */
    pinfo.fd->num = 3;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 12, fragment_table,
                                  reassembled_table, 60, FALSE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(2,g_hash_table_size(reassembled_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(110,fd_head->len); /* the length of data we have */
    ASSERT_EQ(1,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE(NULL,fd_head->data);
    ASSERT_NE(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ(NULL,fd_head->next->data);
    ASSERT_NE(NULL,fd_head->next->next);

    ASSERT_EQ(3,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ(NULL,fd_head->next->next->data);
    ASSERT_EQ(NULL,fd_head->next->next->next);

    /* test the actual reassembly */
    ASSERT(!memcmp(fd_head->data,data+10,50));
    ASSERT(!memcmp(fd_head->data+50,data+5,60));
}


/* This tests the case where some data is missing from one of the fragments.
 * It should prevent reassembly.
 */
static void
test_missing_data_fragment_add_seq_next(void)
{
    fragment_data *fd_head;

    printf("Starting test test_missing_data_fragment_add_seq_next\n");

    /* attempt to add a fragment which is longer than the data available */
    pinfo.fd->num = 1;
    fd_head=fragment_add_seq_next(tvb, 10, &pinfo, 12, fragment_table,
                                  reassembled_table, DATA_LEN-9, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure. Reassembly failed so everything
     * should be null (meaning, just use the original tvb)  */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(0,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE,fd_head->flags & 0x1ff);
    ASSERT_EQ(NULL,fd_head->data);
    ASSERT_EQ(NULL,fd_head->next);

    /* add another fragment (with all data present) */
    pinfo.fd->num = 4;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 12, fragment_table,
                                  reassembled_table, 60, FALSE);

    /* XXX: it's not clear that this is the right result; however it's what the
     * code does...
     */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);


    /* check what happens when we revisit the packets */
    pinfo.fd->flags.visited = TRUE;
    pinfo.fd->num = 1;

    fd_head=fragment_add_seq_next(tvb, 10, &pinfo, 12, fragment_table,
                                  reassembled_table, DATA_LEN-9, TRUE);

    /* We just look in the reassembled_table for this packet. It never got put
     * there, so this always returns null.
     *
     * That's crazy, because it means that the subdissector will see the data
     * exactly once - on the first pass through the capture (well, assuming it
     * doesn't bother to check fd_head->reassembled_in); however, that's
     * what the code does...
     */
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    pinfo.fd->num = 4;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 12, fragment_table,
                                  reassembled_table, 60, FALSE);
    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);
}


/*
 * we're going to do something similar now, but this time it is the second
 * fragment which has something missing.
 */
static void
test_missing_data_fragment_add_seq_next_2(void)
{
    fragment_data *fd_head;

    printf("Starting test test_missing_data_fragment_add_seq_next_2\n");

    pinfo.fd->num = 11;
    fd_head=fragment_add_seq_next(tvb, 10, &pinfo, 24, fragment_table,
                                  reassembled_table, 50, TRUE);

    ASSERT_EQ(1,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    pinfo.fd->num = 12;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 24, fragment_table,
                                  reassembled_table, DATA_LEN-4, FALSE);

    /* XXX: again, i'm really dubious about this. Surely this should return all
     * the data we had, for a best-effort attempt at dissecting it?
     * And it ought to go into the reassembled table?
     */
    ASSERT_EQ(0,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    /* check what happens when we revisit the packets */
    pinfo.fd->flags.visited = TRUE;
    pinfo.fd->num = 11;

    fd_head=fragment_add_seq_next(tvb, 10, &pinfo, 24, fragment_table,
                                  reassembled_table, 50, TRUE);

    /* As before, this returns NULL because the fragment isn't in the
     * reassembled_table. At least this is a bit more consistent than before.
     */
    ASSERT_EQ(0,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

    pinfo.fd->num = 12;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 24, fragment_table,
                                  reassembled_table, DATA_LEN-4, FALSE);
    ASSERT_EQ(0,g_hash_table_size(fragment_table));
    ASSERT_EQ(0,g_hash_table_size(reassembled_table));
    ASSERT_EQ(NULL,fd_head);

}

/*
 * This time, our datagram only has one segment, but it has data missing.
 */
static void
test_missing_data_fragment_add_seq_next_3(void)
{
    fragment_data *fd_head;

    printf("Starting test test_missing_data_fragment_add_seq_next_3\n");

    pinfo.fd->num = 20;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 30, fragment_table,
                                  reassembled_table, DATA_LEN-4, FALSE);

    ASSERT_EQ(0,g_hash_table_size(fragment_table));
    ASSERT_EQ(1,g_hash_table_size(reassembled_table));
    ASSERT_NE(NULL,fd_head);

    /* check the contents of the structure. */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(0,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(20,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE|FD_DEFRAGMENTED,fd_head->flags);
    ASSERT_EQ(NULL,fd_head->data);
    ASSERT_EQ(NULL,fd_head->next);

    /* revisiting the packet ought to produce the same result. */
    pinfo.fd->flags.visited = TRUE;

    pinfo.fd->num = 20;
    fd_head=fragment_add_seq_next(tvb, 5, &pinfo, 30, fragment_table,
                                  reassembled_table, DATA_LEN-4, FALSE);

    ASSERT_EQ(0,g_hash_table_size(fragment_table));
    ASSERT_EQ(1,g_hash_table_size(reassembled_table));
    ASSERT_NE(NULL,fd_head);
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->offset); /* unused */
    ASSERT_EQ(0,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(20,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE|FD_DEFRAGMENTED,fd_head->flags);
    ASSERT_EQ(NULL,fd_head->data);
    ASSERT_EQ(NULL,fd_head->next);
}


/**********************************************************************************
 *
 * main
 *
 *********************************************************************************/

int
main(int argc _U_, char **argv _U_)
{
    frame_data fd;
    char src[] = {1,2,3,4}, dst[] = {5,6,7,8};
    unsigned int i;
    void (*tests[])(void) = {
        test_simple_fragment_add_seq,              /* frag table only   */
        test_fragment_add_seq_partial_reassembly,
        test_fragment_add_seq_duplicate_first,
        test_fragment_add_seq_duplicate_middle,
        test_fragment_add_seq_duplicate_last,
        test_fragment_add_seq_duplicate_conflict,
        test_fragment_add_dcerpc_dg,
        test_fragment_add_seq_check,               /* frag + reassemble */
        test_fragment_add_seq_check_1,
        test_fragment_add_seq_802_11_0,
        test_fragment_add_seq_802_11_1,
        test_simple_fragment_add_seq_next,
        test_missing_data_fragment_add_seq_next,
        test_missing_data_fragment_add_seq_next_2,
        test_missing_data_fragment_add_seq_next_3,
#if 0
        test_fragment_add_seq_check_multiple
#endif
    };

    /* initialise stuff */
    emem_init();
    tvbuff_init();
    reassemble_init();

    /* a tvbuff for testing with */
    data = g_malloc(DATA_LEN);
    /* make sure it's full of stuff */
    for(i=0; i<DATA_LEN; i++) {
        data[i]=i & 0xFF;
    }
    tvb = tvb_new_real_data(data, DATA_LEN, DATA_LEN*2);

    /* other test stuff */
    pinfo.fd = &fd;
    fd.flags.visited = 0;
    SET_ADDRESS(&pinfo.src,AT_IPv4,4,src);
    SET_ADDRESS(&pinfo.dst,AT_IPv4,4,dst);

    /*************************************************************************/
    for(i=0; i < sizeof(tests)/sizeof(tests[0]); i++ ) {
        /* re-init the fragment tables */
        fragment_table_init(&fragment_table);
        ASSERT(fragment_table != NULL);

        reassembled_table_init(&reassembled_table);
        ASSERT(reassembled_table != NULL);

        pinfo.fd->flags.visited = FALSE;

        tests[i]();

        /* Free memory used by the tables */
        fragment_table_init(&fragment_table);
        g_hash_table_destroy(fragment_table);
        fragment_table = NULL;

        reassembled_table_init(&reassembled_table);
        g_hash_table_destroy(reassembled_table);
        reassembled_table = NULL;
    }

    tvb_free(tvb);
    tvb = NULL;
    g_free(data);
    data = NULL;

    printf(failure?"FAILURE\n":"SUCCESS\n");
    return failure;
}


/* stubs */
void add_new_data_source(packet_info *pinfo _U_, tvbuff_t *tvb _U_,
                        const char *name _U_)
{}

proto_item *
proto_tree_add_uint(proto_tree *tree _U_, int hfindex _U_, tvbuff_t *tvb _U_,
                    gint start _U_, gint length _U_, guint32 value _U_)
{ return NULL; }

void proto_item_prepend_text(proto_item *ti _U_, const char *format _U_, ...)
{}

void proto_item_append_text(proto_item *ti _U_, const char *format _U_, ...)
{}

proto_item *proto_tree_add_uint_format(proto_tree *tree _U_, int hfindex _U_,
                                       tvbuff_t *tvb _U_, gint start _U_,
                                       gint length _U_, guint32 value _U_,
                                       const char *format _U_, ...)
{ return NULL; }

proto_tree* proto_item_add_subtree(proto_item *ti _U_, const gint idx _U_)
{ return NULL; }

proto_item *proto_tree_add_boolean(proto_tree *tree _U_, int hfindex _U_,
                                   tvbuff_t *tvb _U_, gint start _U_,
                                   gint length _U_, guint32 value _U_)
{ return NULL; }

proto_item *proto_tree_add_item(proto_tree *tree _U_, const int hfindex _U_,
                                tvbuff_t *tvb _U_, const gint start _U_,
                                gint length _U_,
                                const guint encoding _U_)
{ return NULL; }

gint check_col(column_info *cinfo _U_, const gint col _U_)
{ return 0; }

void col_add_fstr(column_info *cinfo _U_, const gint col _U_, const gchar *format _U_,
                       ...)
{}

const char* proto_registrar_get_name(const int n _U_)
{ return ""; }

void proto_item_set_text(proto_item *ti _U_, const char *format _U_, ...)
{ }

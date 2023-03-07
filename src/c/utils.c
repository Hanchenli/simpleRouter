/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains miscellaneous helper functions.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 *
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "protocols/ethernet.h"
#include "utils.h"

/* See utils.h */
uint16_t cksum (const void *_data, int len)
{
    const uint8_t *data = _data;
    uint32_t sum;

    for (sum = 0; len >= 2; data += 2, len -= 2) {
        sum += data[0] << 8 | data[1];
    }

    if (len > 0) {
        sum += data[0] << 8;
    }

    while (sum > 0xffff) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    sum = htons (~sum);

    return sum ? sum : 0xffff;
}

/* See utils.h */
bool ethernet_addr_is_equal(uint8_t *addr1, uint8_t *addr2)
{
    for (int i=0; i<ETHER_ADDR_LEN; i++) {
        if(addr1[i] != addr2[i])
            return false;
    }
    return true;
}

/*See utils.h*/
int send_ICMP_Packet(chirouter_ctx_t *ctx, ethernet_frame_t *frame,
                     uint8_t type, uint8_t code)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    iphdr_t* iphdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    chilog(DEBUG, "SENT IP DEST IS: %d, SRC IS: %d", iphdr->dst, iphdr->src);

    /*Only for echo*/
    int payload_len;
    if(type ==  ICMPTYPE_ECHO_REPLY) {
        payload_len = ntohs(iphdr->len) - sizeof(iphdr_t) - ICMP_HDR_SIZE;
        chilog(DEBUG, "calculated length is %d",payload_len);
    } else {
        payload_len = sizeof(iphdr_t) + 8;
    }

    int reply_len = sizeof(ethhdr_t) + sizeof(iphdr_t) 
                    + ICMP_HDR_SIZE + payload_len;

    uint8_t reply[reply_len];
    memset(reply, 0, reply_len);
    ethhdr_t *reply_ether_hdr = (ethhdr_t*) reply;
    iphdr_t *reply_iphdr = (iphdr_t*) (reply + sizeof(ethhdr_t));
    icmp_packet_t *reply_icmp = (icmp_packet_t *)(reply + sizeof(ethhdr_t)
                                + sizeof(iphdr_t));

    memcpy((void *)reply_ether_hdr->dst, (const void*)hdr->src, ETHER_ADDR_LEN);
    memcpy((void *)reply_ether_hdr->src, (const void*)frame->in_interface->mac,
           ETHER_ADDR_LEN);
    reply_ether_hdr->type = htons(ETHERTYPE_IP);

    reply_icmp->chksum = 0;
    reply_icmp->type = type;
    reply_icmp->code = code;
    /*get payload into this*/
    if(type == ICMPTYPE_DEST_UNREACHABLE) {
        memcpy((void *)reply_icmp->dest_unreachable.payload,
               (const void*)iphdr, sizeof(iphdr_t));
        memcpy((void *)reply_icmp->dest_unreachable.payload + sizeof(iphdr_t),
               (const void*)iphdr + sizeof(iphdr_t), sizeof(uint64_t));
    } else if(type == ICMPTYPE_TIME_EXCEEDED) {
        memcpy((void *)reply_icmp->time_exceeded.payload,
               (const void*)iphdr, sizeof(iphdr_t));
        memcpy((void *)reply_icmp->time_exceeded.payload + sizeof(iphdr_t),
               (const void*)iphdr + sizeof(iphdr_t), sizeof(uint64_t));
    } else if (type == ICMPTYPE_ECHO_REPLY) {
        icmp_packet_t *icmp = (icmp_packet_t*) (frame->raw + sizeof(ethhdr_t)
                                                + sizeof(iphdr_t));

        reply_icmp->echo.identifier = icmp->echo.identifier;
        reply_icmp->echo.seq_num = icmp->echo.seq_num;
        memcpy((void *)reply_icmp->echo.payload, icmp->echo.payload,
               payload_len);
    }
    reply_icmp->chksum = cksum(reply_icmp, ICMP_HDR_SIZE + payload_len);

    reply_iphdr->version = iphdr->version;
    reply_iphdr->ihl = iphdr->ihl;
    reply_iphdr->tos = 0;
    reply_iphdr->len = htons(sizeof(iphdr_t) + ICMP_HDR_SIZE + payload_len);
    reply_iphdr->id = iphdr->id;
    reply_iphdr->off = iphdr->off;
    reply_iphdr->ttl = TTL_DEFAULT;
    reply_iphdr->proto = IPPROTO_ICMP;
    reply_iphdr->cksum = 0;
    reply_iphdr->src = frame->in_interface->ip.s_addr;
    reply_iphdr->dst = iphdr->src;
    reply_iphdr->cksum = cksum(reply_iphdr, sizeof(iphdr_t));

    int ret = chirouter_send_frame(ctx, frame->in_interface, 
                                   (uint8_t *)reply, reply_len);
    iphdr_t* senthdr = (iphdr_t*) (reply + sizeof(ethhdr_t));
    struct in_addr debug;
    debug.s_addr = senthdr->dst;
    chilog(DEBUG, "SENT IP to DEST: %s", inet_ntoa(debug));
    return ret;
}

/*See utils.h*/
int send_arp_request(chirouter_ctx_t *ctx, struct in_addr *ipaddr,
                     chirouter_interface_t *out_interface)
{
    int ret;

    int reply_len = sizeof(ethhdr_t) + sizeof(arp_packet_t);
    uint8_t reply[reply_len];
    memset(reply, 0, reply_len);
    ethhdr_t *reply_ether_hdr = (ethhdr_t*) reply;
    arp_packet_t *reply_arp = (arp_packet_t*) (reply + sizeof(ethhdr_t));

    uint8_t all_one_byte = ALL_ONE_BYTE;
    memset((void *)reply_ether_hdr->dst, all_one_byte, ETHER_ADDR_LEN);
    memcpy((void *)reply_ether_hdr->src, (const void*)out_interface->mac,
           ETHER_ADDR_LEN);
    chilog(DEBUG, "src is: %lu",reply_ether_hdr->src);
    reply_ether_hdr->type = htons(ETHERTYPE_ARP);

    reply_arp->hrd = htons(ARP_HRD_ETHERNET);
    reply_arp->pro = htons(ETHERTYPE_IP);
    reply_arp->hln = ETHER_ADDR_LEN;
    reply_arp->pln = IPV4_ADDR_LEN;
    reply_arp->op = htons(ARP_OP_REQUEST);
    reply_arp->tpa = ipaddr->s_addr;
    memcpy((void*)reply_arp->sha, (const void*)out_interface->mac,
           ETHER_ADDR_LEN);
    reply_arp->spa = out_interface->ip.s_addr;

    chilog(DEBUG, "Sending arp with len: %d", reply_len);
    ret = chirouter_send_frame(ctx, out_interface, (uint8_t *)reply,
                               reply_len);
    return ret;
}
/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
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

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"

/*
 * get_routing_id - Obtains routing entry id in routing table
 *
 * ctx: Router context
 *
 * frame: Ethernet frame to forward
 *
 * Returns: The routing entry id, if not found, id is equal to size
 *
 */
uint16_t get_routing_id(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    uint16_t id = ctx->num_rtable_entries;
    uint32_t max_mask = 0;
    iphdr_t* iphdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));

    for(int i = 0; i < ctx->num_rtable_entries; i++) {
        struct in_addr debug;
        debug.s_addr = ctx->routing_table[i].mask.s_addr & iphdr->dst;
        chilog(DEBUG, "masked address: %s, mask: %s, destination: %s",
               inet_ntoa(debug), inet_ntoa(ctx->routing_table[i].mask),
               inet_ntoa(ctx->routing_table[i].dest));
        if((ctx->routing_table[i].mask.s_addr & iphdr->dst)
                == ctx->routing_table[i].dest.s_addr) {
            if (ctx->routing_table[i].mask.s_addr >= max_mask) {
                id = i;
                max_mask = ctx->routing_table[i].mask.s_addr;
            }
        }
    }

    return id;
}

/*
 * forward_ip - Forwards IP datagram with Arp Cache Entry
 *
 * ctx: Router context
 *
 * frame: Ethernet frame to forward
 *
 * arpcache_entry: ARP cache
 *
 * out_interface: Interface to send the datagram
 *
 * Returns:
 *
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 */
int forward_ip(chirouter_ctx_t *ctx, ethernet_frame_t *frame,
               chirouter_arpcache_entry_t* arpcache_entry,
               chirouter_interface_t *out_interface)
{

    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    iphdr_t* iphdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    int ret;
    if(iphdr->ttl == 1) {
        ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_TIME_EXCEEDED,
                               ICMP_CODE_PLACEHOLDER);
        return ret;
    }
    iphdr->ttl -= 1;
    iphdr->cksum = 0;
    iphdr->cksum = cksum(iphdr, sizeof(iphdr_t));

    chilog(DEBUG, "iphdr length is: %hu", ntohs(iphdr->len));
    int reply_len = sizeof(ethhdr_t) + ntohs(iphdr->len);
    uint8_t reply[reply_len];
    memset(reply, 0, reply_len);
    ethhdr_t *reply_ether_hdr = (ethhdr_t*) reply;
    iphdr_t *reply_ip = (iphdr_t*) (reply + sizeof(ethhdr_t));
    memcpy((void *)reply_ether_hdr->dst, (const void*)arpcache_entry->mac,
           ETHER_ADDR_LEN);
    memcpy((void *)reply_ether_hdr->src, (const void*)out_interface->mac,
           ETHER_ADDR_LEN);
    reply_ether_hdr->type = htons(ETHERTYPE_IP);
    memcpy((void *)reply_ip, (const void*)iphdr, ntohs(iphdr->len));

    chilog(DEBUG, "Packet Length is: %d", reply_len);
    ret = chirouter_send_frame(ctx, out_interface, (uint8_t *)reply,
                               reply_len);
    return ret;
}

/*
 * frame_need_wait_for_arp - Adds frame to ARP pending list or to witheld frames
 * and sends an ARP request only if needed
 *
 * ctx: Router context
 *
 * frame: Incoming Ethernet frame
 *
 * ipaddr: IP address
 *
 * out_interface: The interface to send the frame
 *
 * Returns:
 *
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 */
int frame_need_wait_for_arp(chirouter_ctx_t *ctx, ethernet_frame_t *frame,
                            struct in_addr *ipaddr, 
                            chirouter_interface_t *out_interface)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    iphdr_t* iphdr = (iphdr_t*) frame->raw + sizeof(ethhdr_t);
    int ret;

    pthread_mutex_lock(&ctx->lock_arp);
    chirouter_pending_arp_req_t* req_entry
        = chirouter_arp_pending_req_lookup(ctx, ipaddr);
    if(req_entry != NULL) {
        ret = chirouter_arp_pending_req_add_frame(ctx, req_entry, frame);
        pthread_mutex_unlock(&ctx->lock_arp);
        return ret;
    }
    req_entry = chirouter_arp_pending_req_add(ctx, ipaddr, out_interface);
    ret = chirouter_arp_pending_req_add_frame(ctx, req_entry, frame);
    pthread_mutex_unlock(&ctx->lock_arp);
    if(ret != 0) return ret;

    ret = send_arp_request(ctx, ipaddr, out_interface);
    return ret;
}

/*
 * send_withheld_frame - Sends a withheld frames to the destination MAC
 *
 * ctx: Router context
 *
 * frame: Incoming Ethernet frame
 *
 * out_interface: The interface to send the frame
 *
 * mac: Destination MAC address
 *
 * Returns:
 *
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 */
int send_withheld_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame,
                        chirouter_interface_t *out_interface, uint8_t *mac)
{
    int reply_len = frame->length;
    uint8_t reply[reply_len];
    memcpy((void *)reply, (const void *)frame->raw, reply_len);
    ethhdr_t* reply_hdr = (ethhdr_t*) reply;
    iphdr_t* reply_iphdr = (iphdr_t*) (reply + sizeof(ethhdr_t));

    int ret;

    if(reply_iphdr->ttl == 1) {
        ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_TIME_EXCEEDED,
                               ICMP_CODE_PLACEHOLDER);
        return ret;
    }
    reply_iphdr->ttl -= 1;
    reply_iphdr->cksum = 0;
    reply_iphdr->cksum = cksum(reply_iphdr, sizeof(iphdr_t));

    memcpy((void *)reply_hdr->dst, (const void*)mac, ETHER_ADDR_LEN);
    memcpy((void *)reply_hdr->src, (const void*)out_interface->mac,
           ETHER_ADDR_LEN);

    ret = chirouter_send_frame(ctx, out_interface, (uint8_t *)reply_hdr,
                               reply_len);

    return ret;
}

/*
 * process_arp_request:
 * receives an arp request from the interface and sends arp reply if available
 *
 * ctx: Router context
 *
 * frame: Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 */
int process_arp_request(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    arp_packet_t* arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));

    /*Check if the arp request is for the router*/
    if(ntohl(arp->tpa) != ntohl(frame->in_interface->ip.s_addr)) {
        return 1;
    }

    int reply_len = sizeof(ethhdr_t) + sizeof(arp_packet_t);
    uint8_t reply[reply_len];
    memset(reply, 0, reply_len);
    ethhdr_t *reply_ether_hdr = (ethhdr_t*) reply;
    arp_packet_t *reply_arp = (arp_packet_t*) (reply + sizeof(ethhdr_t));
    memcpy((void *)reply_ether_hdr->dst, (const void*)hdr->src, ETHER_ADDR_LEN);
    memcpy((void *)reply_ether_hdr->src, (const void*)frame->in_interface->mac,
           ETHER_ADDR_LEN);
    reply_ether_hdr->type = htons(ETHERTYPE_ARP);

    reply_arp->hrd = arp->hrd;
    reply_arp->pro = arp->pro;
    reply_arp->hln = arp->hln;
    reply_arp->pln = arp->pln;
    reply_arp->op = htons(ARP_OP_REPLY);
    memcpy((void*)reply_arp->tha, (const void*)arp->sha, ETHER_ADDR_LEN);
    reply_arp->tpa = arp->spa;
    /*Set Arp Reply MAC Address*/
    memcpy((void*)reply_arp->sha, (const void*)frame->in_interface->mac,
           ETHER_ADDR_LEN);
    reply_arp->spa = frame->in_interface->ip.s_addr;

    int ret = chirouter_send_frame(ctx, frame->in_interface, (uint8_t *)reply,
                                   reply_len);
    return ret;
}

/*
 * process_arp_reply - Adds reply to ARP cache and sends pending ARP packets
 *
 * ctx: Router context
 *
 * frame: Arp Reply Ethernet frame to process
 *
 * Returns: 0 on success, 1 on non-critical error
 *
 */
int process_arp_reply(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    arp_packet_t* arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));

    pthread_mutex_lock(&ctx->lock_arp);
    struct in_addr arp_ip_addr;
    arp_ip_addr.s_addr = arp->spa;
    int ret = chirouter_arp_cache_add(ctx, &arp_ip_addr, arp->sha);
    if (ret != 0) {
        pthread_mutex_unlock(&ctx->lock_arp);
        return ret;
    }

    chirouter_pending_arp_req_t* chirouter_arp_req;

    chirouter_arp_req = chirouter_arp_pending_req_lookup(ctx, &arp_ip_addr);

    if(chirouter_arp_req == NULL) {
        pthread_mutex_unlock(&ctx->lock_arp);
        return ret;
    }

    withheld_frame_t *iter = chirouter_arp_req->withheld_frames;
    while(iter != NULL) {
        ret = send_withheld_frame(ctx, iter->frame,
                                  chirouter_arp_req->out_interface, arp->sha)
                                 | ret;
        iter = iter->next;
    }
    /*remove pending arp request*/
    ret = chirouter_arp_pending_req_free_frames(chirouter_arp_req);
    DL_DELETE(ctx->pending_arp_reqs, chirouter_arp_req);
    pthread_mutex_unlock(&ctx->lock_arp);
    return ret;
}

/*
 * process_ip - Wrapper function for processing IP Datagram
 *
 * Reply an ICMP message or forward the datagram
 *
 * ctx: Router context
 *
 * frame: Ethernet frame(IP) to process
 *
 * Returns: 0 on success, 1 on non-critical error
 *
 */
int process_ip(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /*Uses send_ICMP_Packet to send ICMP, get_routing_id to get routing entry,
    forward_ip to forward ip to entry, frame_need_wait_for_arp to handle
    unknown-mac packets*/
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    iphdr_t* iphdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    if(iphdr->dst == frame->in_interface->ip.s_addr) {
        /*If Destination IP matches the IP of interface*/
        int ret = 0;
        if (iphdr->proto == IPPROTO_TCP
                || iphdr->proto == IPPROTO_UDP) {
            ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_DEST_UNREACHABLE,
                                   ICMPCODE_DEST_PORT_UNREACHABLE);
        } else if (iphdr->ttl == TTL_MINIMUM) {
            ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_TIME_EXCEEDED,
                                   ICMP_CODE_PLACEHOLDER);
        } else if(iphdr->proto == IPPROTO_ICMP) {
            icmp_packet_t* icmp = (icmp_packet_t *)
                                  (frame->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));
            if(icmp->type == ICMPTYPE_ECHO_REQUEST) {
                ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_ECHO_REPLY,
                                       ICMP_CODE_PLACEHOLDER);
            }
        } else {
            ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_DEST_UNREACHABLE,
                                   ICMPCODE_DEST_PROTOCOL_UNREACHABLE);
        }

        return ret;
    }

    /*Check if ip is in another interface*/
    bool ip_in_router = false;
    for(int i = 0; i < ctx->num_interfaces; i++) {
        if (ntohl(iphdr->dst) == ntohl((ctx->interfaces)[i].ip.s_addr)) {
            ip_in_router = true;
            break;
        }
    }
    if(ip_in_router) {
        int ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_DEST_UNREACHABLE,
                                   ICMPCODE_DEST_HOST_UNREACHABLE);
        return ret;
    }

    /*Otherwise try to forward the packet*/
    uint16_t id_routing = get_routing_id(ctx, frame);
    if(id_routing == ctx->num_rtable_entries) {
        int ret = send_ICMP_Packet(ctx, frame, ICMPTYPE_DEST_UNREACHABLE,
                                   ICMPCODE_DEST_NET_UNREACHABLE);
        return ret;
    }

    struct in_addr arp_ip_address;
    arp_ip_address.s_addr = iphdr->dst;
    if(ctx->routing_table[id_routing].gw.s_addr != 0) {
        arp_ip_address = ctx->routing_table[id_routing].gw;
    }
    /*Search for arp cache before deciding to send arp request*/
    pthread_mutex_lock(&ctx->lock_arp);
    chirouter_arpcache_entry_t* arpcache_entry;
    arpcache_entry = chirouter_arp_cache_lookup(ctx, &arp_ip_address);

    if(arpcache_entry != NULL) {
        chilog(DEBUG, "FOUND in ARP Cache");
        int ret = forward_ip(ctx, frame, arpcache_entry,
                             ctx->routing_table[id_routing].interface);
        pthread_mutex_unlock(&ctx->lock_arp);
        return ret;
    }

    pthread_mutex_unlock(&ctx->lock_arp);
    /*Send arp request & add to pending or append to existing cache*/
    chilog(DEBUG, "Not in ARP Cache");
    int ret = frame_need_wait_for_arp(ctx, frame, &arp_ip_address,
                                      ctx->routing_table[id_routing].interface);
    chilog(DEBUG, "OUT of pending arp");

    return ret;
}

/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame.
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;
    if (ntohs(hdr->type) == ETHERTYPE_ARP) {
        arp_packet_t* arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));
        int rt;
        if (ntohs(arp->op) == ARP_OP_REQUEST) {
            rt = process_arp_request(ctx, frame);
        } else {
            rt = process_arp_reply(ctx, frame);
        }
        return rt;
    }

    if (ntohs(hdr->type) == ETHERTYPE_IP) {
        iphdr_t* ip_hdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
        int rt = process_ip(ctx, frame);
    }

    if(ntohs(hdr->type) == ETHERTYPE_IPV6) {
        chilog(ERROR, "IPV6 USED");
        return 1;
    }

    return 0;
}



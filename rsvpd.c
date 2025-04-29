/*
 * Copyright (c) 2025, Spanidea. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include "socket.h"
#include "log.h"
#include "rsvp_sh.h"

#define SOCKET_PATH "/tmp/rsvp_socket"
#define LOG_FILE_PATH "/tmp/rsvpd.log"

struct src_dst_ip *ip = NULL;

extern struct session* path_head;
extern struct session* resv_head;
extern db_node *path_tree;
extern db_node *resv_tree;

extern pthread_mutex_t path_tree_mutex;
extern pthread_mutex_t resv_tree_mutex;
extern pthread_mutex_t path_list_mutex;
extern pthread_mutex_t resv_list_mutex;

int sock = 0;
int ipc_sock = 0;

#define MAX_HOPS 30
#define TIMEOUT 1
#define DEST_PORT 33434

// Calculate checksum for ICMP packet
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void trace(char *ip) {

    uint8_t first = 0;
    int  count = 0;
    char *dest_ip = ip;

    char srcip[16], dstip[16], nhip[16], sender_ip[16], receiver_ip[16];;
    uint16_t tunnel_id;
    struct sockaddr_in addr;
    struct in_addr send_ip, rece_ip;
    uint32_t ifh;
    uint8_t prefix_len = 0;
    char dev[16];

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);

    struct sub_object *explicit = (struct sub_object*)malloc(sizeof(struct sub_object));
    if(explicit == NULL){
	printf("dynamic memory allocation failed\n");
	return;
    }
    first = 1;
	
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        // Set TTL
        if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("setsockopt");
            return 1;
        }

        // Set socket timeout
        //struct timeval timeout = {TIMEOUT, 0};
        //setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        // Build ICMP Echo Request
        char sendbuf[64];
        struct icmp *icmp_hdr = (struct icmp *)sendbuf;
        memset(sendbuf, 0, sizeof(sendbuf));
        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = getpid();
        icmp_hdr->icmp_seq = ttl;
        icmp_hdr->icmp_cksum = checksum(sendbuf, sizeof(sendbuf));

        //struct timeval start, end;
        //gettimeofday(&start, NULL);

        sendto(sock, sendbuf, sizeof(sendbuf), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // Receive ICMP reply
        char recvbuf[1024];
        struct sockaddr_in reply_addr;
        socklen_t addrlen = sizeof(reply_addr);

        int n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                         (struct sockaddr *)&reply_addr, &addrlen);

	if(first) {
		explicit->hop_type = htons(1);
		explicit->length = htons(8);
		explicit->nexthop_ip = reply_addr.sin_addr;
		explicit->prefix_len = htons(32);
		explicit->reserved = 0;
		first = 0;
	} else {
		explicit = (struct sub_object*)realloc(explicit, sizeof(struct sub_object));
		if(explicit == NULL){
			printf("realloc dynamic memory allocation failed\n");
			return;
		}
		explicit->hop_type = htons(1);
                explicit->length = htons(8);
                explicit->nexthop_ip = reply_addr.sin_addr;
                explicit->prefix_len = htons(32);
                explicit->reserved = 0;
	}
	count++;

        //gettimeofday(&end, NULL);

        //double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
        //             (end.tv_usec - start.tv_usec) / 1000.0;

        if (n < 0) {
            printf("%2d  *\n", ttl);
        } else {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &reply_addr.sin_addr, addr_str, sizeof(addr_str));

            struct ip *ip_hdr = (struct ip *)recvbuf;
            struct icmp *icmp_resp = (struct icmp *)(recvbuf + (ip_hdr->ip_hl << 2));

            printf("%2d  %-15s  /*%.2f ms*/\n", ttl, addr_str/*, rtt*/);

            // ICMP_ECHOREPLY means we reached the destination
            if (icmp_resp->icmp_type == ICMP_ECHOREPLY) {
                break;
            }
        }
    }

    printf("no of nexthop to destination = size = %d count =%d %ld\n", sizeof(struct sub_object), count, (sizeof(struct sub_object)*count)/sizeof(struct sub_object));

	

    close(sock);
    return 0;
}



int main() {
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    char buffer[512];
    int reached = 0;
    struct session* temp = NULL;


    char srcip[16], dstip[16], nhip[16], sender_ip[16], receiver_ip[16];;
    uint16_t tunnel_id;
    int explicit = 0;
    struct sockaddr_in addr;
    struct in_addr send_ip, rece_ip;
    uint32_t ifh;
    uint8_t prefix_len = 0;
    char dev[16];


    sock = socket(AF_INET, SOCK_RAW, RSVP_PROTOCOL);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("binding failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // only in PE1 or PE2 where we configure the tunnel for RSVP.
    // ------------------------------------------------------

    for (int i  = 0; i < 1; i++){
        printf("Enter tunnel_id: \n");
        scanf("%hd",&tunnel_id);
        getchar();

	printf("Enter src ip : \n");
        fgets(srcip, 16, stdin);

        printf("Enter dst ip: \n");
        fgets(dstip, 16, stdin);

        int len = strlen(srcip);
        if(srcip[len-1] == '\n')
            srcip[len-1] = '\0';

        len = strlen(dstip);
        if(dstip[len-1] == '\n')
            dstip[len-1] = '\0';

	//trace(dstip);
    
        path_msg *path = malloc(sizeof(path_msg));

        //get and assign nexthop
        if(get_nexthop(dstip, nhip, &prefix_len, dev, &ifh)) {
            strcpy(path->dev, dev);
            path->IFH = ifh;
            path->prefix_len = prefix_len;
            if(strcmp(nhip, " ") == 0) {
                inet_pton(AF_INET, "0.0.0.0", &path->nexthop_ip);
            } else {
		inet_pton(AF_INET, nhip, &path->nexthop_ip);
		inet_pton(AF_INET, "0.0.0.0", &path->p_srcip);
  		if(get_srcip(nhip, srcip, &ifh)) {
                	inet_pton(AF_INET, srcip, &path->e_srcip);
			path->IFH = ifh;
		}
            }
        } else {
                printf("no route to destination\n");
                continue;
        }
	//path_msg path;
        path->tunnel_id = tunnel_id;
        inet_pton(AF_INET, srcip, &path->src_ip);
        inet_pton(AF_INET, dstip, &path->dest_ip);


        path->interval = 30;
        path->setup_priority = 7;
        path->hold_priority = 7;
        path->flags = 0;
        path->lsp_id = 1;
        path->IFH = ifh;
        strncpy(path->name, "Path1", sizeof(path->name) - 1);
        path->name[sizeof(path->name) - 1] = '\0';

        path_tree = insert_node(path_tree, (void*)path, compare_path_insert, 1);
        display_tree_debug(path_tree, 1);

        inet_pton(AF_INET, srcip, &send_ip);
        inet_pton(AF_INET, dstip, &rece_ip);

        if(resv_head == NULL) {
            resv_head = insert_session(resv_head, tunnel_id, srcip, dstip, 1);
        } else {
            insert_session(resv_head, tunnel_id, srcip, dstip, 1);
        }

        // Send RSVP-TE PATH Message
        send_path_message(sock, path->tunnel_id);
    }
    //---------------------------------------------------------
    path_event_handler(); //send path msg

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&sender_addr, &addr_len);
        if (bytes_received < 0) {
            log_message("Receive failed");
            continue;
        }
        log_message("Received bytes in receive_thread");
        struct rsvp_header* rsvp = (struct rsvp_header*)(buffer + IP);
        char sender_ip[16], receiver_ip[16];
        uint16_t tunnel_id;

        log_message("Mutex locked in receive_thread");
        switch (rsvp->msg_type) {
            case PATH_MSG_TYPE:

                //Receive PATH Message
                resv_event_handler();

                // get ip from the received path packet
                log_message(" in path msg type\n");
                get_ip(buffer, sender_ip, receiver_ip, &tunnel_id);
		if((reached = dst_reached(receiver_ip)) == -1) {
                	log_message(" No route to destiantion %s\n",receiver_ip);
                        return;
                }

		pthread_mutex_lock(&path_list_mutex);
                temp = search_session(path_head, tunnel_id);
                pthread_mutex_unlock(&path_list_mutex);
		if(temp == NULL) {
			pthread_mutex_lock(&path_list_mutex);
	               	path_head = insert_session(path_head, tunnel_id, sender_ip, receiver_ip, reached);
 			pthread_mutex_unlock(&path_list_mutex);
			if(path_head == NULL) {
				log_message("insert for tunnel %d failed", tunnel_id);
				return;
			}
		}
		temp = NULL;
                
                receive_path_message(sock,buffer,sender_addr);
               
		break;

            case RESV_MSG_TYPE:

                // Receive RSVP-TE RESV Message	
                path_event_handler();

                //get ip from the received resv msg
                log_message(" in resv msg type\n");
		/*get_ip(buffer, sender_ip, receiver_ip, &tunnel_id);
		if((reached = dst_reached(sender_ip)) == -1) {
	                log_message(" No route to destiantion %s\n",sender_ip);
                        return;
                }
                
		pthread_mutex_lock(&resv_list_mutex);
                temp = search_session(resv_head, tunnel_id);
                if(temp == NULL) {
                        resv_head = insert_session(resv_head, tunnel_id, sender_ip, receiver_ip, reached);
			if(resv_head == NULL) {
				log_message("insert for tunnel %d failed", tunnel_id);
                               	return;	
			}
                }
		temp = NULL;
 	        pthread_mutex_unlock(&resv_list_mutex);
               	*/ 
                receive_resv_message(sock,buffer,sender_addr);
                
 		break;

            default: {

                char msg[64];
                snprintf(msg, sizeof(msg), "Unknown RSVP message type: %d", rsvp->msg_type);
                log_message(msg);
	    }
        }
        log_message("Mutex unlocking in receive_thread");
    }
    return NULL;
}


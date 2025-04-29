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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include "rsvp_msg.h"
#include "rsvp_db.h"

//char nhip[16];
//extern char src_ip[16], route[16];
extern db_node* path_tree;
extern db_node* resv_tree;

extern pthread_mutex_t path_tree_mutex;
extern pthread_mutex_t resv_tree_mutex;
extern pthread_mutex_t path_list_mutex;
extern pthread_mutex_t resv_list_mutex;

// Function to send an RSVP-TE RESV message with label assignment
void send_resv_message(int sock, uint16_t tunnel_id) {
    struct sockaddr_in dest_addr;
    char resv_packet[RESV_PACKET_SIZE];
    char nhip[16];

    struct in_addr p_srcip;
    char srcip[16];
    uint32_t ifh;

    struct rsvp_header *resv = (struct rsvp_header*)resv_packet;
    //    struct class_obj *class_obj = (struct class_obj*)(resv_packet + sizeof(struct rsvp_header));
    struct session_object *session_obj = (struct session_object*)(resv_packet + START_SENT_SESSION_OBJ);
    struct hop_object *hop_obj = (struct hop_object*)(resv_packet + START_SENT_HOP_OBJ);
    struct time_object *time_obj = (struct time_object*)(resv_packet + START_SENT_TIME_OBJ);
    struct Filter_spec_object *spec_obj = (struct Filter_spec_object*)(resv_packet + START_SENT_FILTER_SPEC_OBJ);
    struct label_object *label_obj = (struct label_object*)(resv_packet + START_SENT_LABEL);

    pthread_mutex_lock(&resv_tree_mutex);
    db_node *resv_node = search_node(resv_tree, tunnel_id, compare_resv_del);
    pthread_mutex_unlock(&resv_tree_mutex);
    if (resv_node == NULL) {
	log_message("tunnel id %d not found\n", tunnel_id);
	return;
    }
    resv_msg *p = (resv_msg*)resv_node->data;
 
    // Populate RSVP RESV header
    resv->version_flags = 0x10;  // RSVP v1
    resv->msg_type = RESV_MSG_TYPE;
    resv->length = htons(sizeof(resv_packet));
    resv->checksum = 0;
    resv->ttl = 255;
    resv->reserved = 0;

    //session object for RESV msg
    session_obj->class_obj.class_num = 1;
    session_obj->class_obj.c_type = 7;
    session_obj->class_obj.length = htons(sizeof(struct session_object));
    session_obj->dst_ip = p->dest_ip;
    session_obj->tunnel_id = htons(p->tunnel_id);
    session_obj->src_ip = p->src_ip;

    //hop object for PATH?RESV msg
    hop_obj->class_obj.class_num = 3;
    hop_obj->class_obj.c_type = 1;
    hop_obj->class_obj.length = htons(sizeof(struct hop_object));
    hop_obj->next_hop = p->e_srcip;
    hop_obj->IFH = htonl(p->IFH);

    time_obj->class_obj.class_num = 5;
    time_obj->class_obj.c_type = 1;
    time_obj->class_obj.length = htons(sizeof(struct time_object));
    time_obj->interval = htonl(p->interval); 

    spec_obj->class_obj.class_num = 16;
    spec_obj->class_obj.c_type = 1;
    spec_obj->class_obj.length = htons(sizeof(struct Filter_spec_object));
    spec_obj->src_ip = p->src_ip;
    spec_obj->Reserved = 0;
    spec_obj->LSP_ID = 1;

    // Populate Label Object
    label_obj->class_obj.class_num = 16;  // Label class
    label_obj->class_obj.c_type = 1;  // Generic Label
    label_obj->class_obj.length = htons(sizeof(struct label_object));
    label_obj->label = htonl(p->in_label);

    // Set destination (ingress router)
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = p->nexthop_ip;
    dest_addr.sin_port = 0;

    // Send RESV message
    if (sendto(sock, resv_packet, sizeof(resv_packet), 0, 
                (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Send failed");
    } else {
        log_message("Sent RESV message to %s with Label %d\n", inet_ntoa(p->nexthop_ip), p->in_label);
    }
}

void get_path_class_obj(int class_obj_arr[]) {
    log_message("getting calss obj arr\n");
    class_obj_arr[0] = START_RECV_SESSION_OBJ;
    class_obj_arr[1] = START_RECV_HOP_OBJ;
    class_obj_arr[2] = START_RECV_TIME_OBJ;
    class_obj_arr[3] = START_RECV_LABEL_REQ;
    class_obj_arr[4] = START_RECV_SESSION_ATTR_OBJ;
    class_obj_arr[5] = START_RECV_SENDER_TEMP_OBJ;
}

// Function to receive RSVP-TE PATH messages
void receive_path_message(int sock, char buffer[], struct sockaddr_in sender_addr) {
    //char buffer[1024];
    struct class_obj *class_obj;
    int class_obj_arr[10]; 
    int i = 0;
    char src_ip[16], dst_ip[16];
    struct in_addr sender_ip, receiver_ip;
    uint16_t tunnel_id;
    db_node *temp = NULL;

    log_message("Received PATH message from %s\n", inet_ntoa(sender_addr.sin_addr));

    struct rsvp_header *rsvp = (struct rsvp_header*)(buffer+20);
    struct session_object *session_obj = (struct session_object*)(buffer + START_RECV_SESSION_OBJ);

    pthread_mutex_lock(&path_tree_mutex);
    db_node *path_node = search_node(path_tree, ntohs(session_obj->tunnel_id), compare_path_del);
    pthread_mutex_unlock(&path_tree_mutex);
    if(path_node == NULL){
        temp = path_tree_insert(path_tree, buffer);//, sender_addr.sin_addr);
        if(temp != NULL) {
            path_tree = temp;
            path_node = search_node(path_tree, ntohs(session_obj->tunnel_id), compare_path_del);
        }
    }
    display_tree_debug(path_tree, 1);
    pthread_mutex_unlock(&path_tree_mutex);

    if(path_node != NULL) {
        path_msg *p = (path_msg*)path_node->data;
        if(strcmp(inet_ntoa(p->nexthop_ip), "0.0.0.0") == 0) {
            log_message("****reached the destiantion, end oF rsvp tunnel***\n");

            pthread_mutex_lock(&resv_tree_mutex);
            db_node *resv_node = search_node(resv_tree, ntohs(session_obj->tunnel_id), compare_resv_del);
            if(resv_node == NULL){
                temp = resv_tree_insert(resv_tree, buffer, p->p_srcip, 1);
                if(temp != NULL) {
                    resv_tree = temp;
		    display_tree_debug(resv_tree, 0);
                }
            }
	    pthread_mutex_unlock(&resv_tree_mutex);

            send_resv_message(sock, ntohs(session_obj->tunnel_id));
        } else {
            log_message("send path msg to nexthop \n");
            send_path_message(sock, ntohs(session_obj->tunnel_id));
        }
    }
}

//Function to send PATH message for label request
void send_path_message(int sock, uint16_t tunnel_id) {
    struct sockaddr_in dest_addr;
    struct in_addr p_srcip;
    char srcip[16];
    char path_packet[PATH_PACKET_SIZE];
    uint32_t ifh;
    //char path_packet = (char *)malloc(PATH_PACKET_SIZE+sizeof(class_obj)+(sizeof(sub_object) * sizeof(explicit)/20);
    char nhip[16];

    struct rsvp_header *path = (struct rsvp_header*)path_packet;
    //struct class_obj *class_obj = (struct class_obj*)(path_packet + START_SENT_CLASS_OBJ); 
    struct session_object *session_obj = (struct session_object*)(path_packet + START_SENT_SESSION_OBJ);
    struct hop_object *hop_obj = (struct hop_object*)(path_packet + START_SENT_HOP_OBJ);
    struct time_object *time_obj = (struct time_object*)(path_packet + START_SENT_TIME_OBJ);
    struct label_req_object *label_req_obj = (struct label_req_object*)(path_packet + START_SENT_LABEL_REQ); 
    struct session_attr_object *session_attr_obj = (struct session_attr_object*)(path_packet + START_SENT_SESSION_ATTR_OBJ); 
    struct sender_temp_object *sender_temp_obj = (struct sender_temp_object*)(path_packet + START_SENT_SENDER_TEMP_OBJ);


    log_message("inside send path message");

    pthread_mutex_lock(&path_tree_mutex);
    db_node *path_node = search_node(path_tree, tunnel_id, compare_path_del);
    pthread_mutex_unlock(&path_tree_mutex);
    if (path_node == NULL) {
	log_message("tunnel id %d not found\n", tunnel_id);
	return;
    }
    path_msg *p = (path_msg*)path_node->data;

    log_message("PATH message next hop %s   \n", inet_ntoa(p->nexthop_ip));

    // Populate RSVP PATH header
    path->version_flags = 0x10;  // RSVP v1
    path->msg_type = PATH_MSG_TYPE;
    path->length = htons(sizeof(path_packet));
    path->checksum = 0;
    path->ttl = 255;
    path->reserved = 0;

    //session object for PATH msg
    session_obj->class_obj.class_num = 1;
    session_obj->class_obj.c_type = 7;
    session_obj->class_obj.length = htons(sizeof(struct session_object));
    session_obj->dst_ip = p->dest_ip;
    session_obj->tunnel_id = htons(p->tunnel_id);
    session_obj->src_ip = p->src_ip;

    //hop object for PATH and RESV msg
    hop_obj->class_obj.class_num = 3;
    hop_obj->class_obj.c_type = 1;
    hop_obj->class_obj.length = htons(sizeof(struct hop_object));
    hop_obj->next_hop = p->e_srcip;
    hop_obj->IFH = htonl(p->IFH);

    time_obj->class_obj.class_num = 5;
    time_obj->class_obj.c_type = 1;
    time_obj->class_obj.length = htons(sizeof(struct time_object));
    time_obj->interval = htonl(p->interval);

    /*explicit_object->class_obj.class_num = 20;
    explicit_object->class_obj.c_type = 1;
    explicit_object->class_obj.length = 36
    memcpy(explcit_object->sub_object,explicit, sizeof(explicit));
    */
    

    // Populate Label Object                                        
    label_req_obj->class_obj.class_num = 19;  // Label Request class
    label_req_obj->class_obj.c_type = 1;  // Generic Label                   
    label_req_obj->class_obj.length = htons(sizeof(struct label_req_object));
    label_req_obj->L3PID = htons(0x0800);  // Assigned Label (1001)

    //session attribute object for PATH msg
    session_attr_obj->class_obj.class_num = 207;
    session_attr_obj->class_obj.c_type = 7;
    session_attr_obj->class_obj.length = htons(sizeof(struct session_attr_object));
    session_attr_obj->setup_prio = p->setup_priority;
    session_attr_obj->hold_prio = p->hold_priority;
    session_attr_obj->flags = p->flags;
    session_attr_obj->name_len = sizeof("PE1");
    //strcpy("PE1", session_attr_obj->Name);

    //Sender template object for PATH msg
    sender_temp_obj->class_obj.class_num = 11;
    sender_temp_obj->class_obj.c_type = 7;
    sender_temp_obj->class_obj.length = htons(sizeof(struct sender_temp_object));    
    sender_temp_obj->src_ip = p->src_ip;
    sender_temp_obj->Reserved = 0;
    sender_temp_obj->LSP_ID = htons(p->lsp_id);

    // Set destination (egress router)
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = p->nexthop_ip;
    dest_addr.sin_port = 0;

    // Send PATH message
    if (sendto(sock, path_packet, sizeof(path_packet), 0, 
                (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
	log_message("PATH message failed to send to %s\n", inet_ntoa(hop_obj->next_hop));
        perror("Send failed");
    } else {
        log_message("Sent PATH message to %s\n", inet_ntoa(p->nexthop_ip));
    }
}



void get_resv_class_obj(int class_obj_arr[]) {
    log_message("getting calss obj arr\n");
    class_obj_arr[0] = START_RECV_SESSION_OBJ;
    class_obj_arr[1] = START_RECV_HOP_OBJ;
    class_obj_arr[2] = START_RECV_TIME_OBJ;
    class_obj_arr[3] = START_RECV_FILTER_SPEC_OBJ;
    class_obj_arr[4] = START_RECV_LABEL;
}


// Function to receive an RSVP-TE RESV message
void receive_resv_message(int sock, char buffer[], struct sockaddr_in sender_addr) {

    struct class_obj *class_obj;
    int class_obj_arr[10]; 
    int i = 0;
    char src_ip[16], dst_ip[16];
    struct in_addr sender_ip, receiver_ip;
    char d_ip[16], n_ip[16];
    uint16_t tunnel_id;
    db_node *temp = NULL;
    uint8_t new_insert;

    struct session_object *session_obj = (struct session_object*)(buffer + START_RECV_SESSION_OBJ);
    struct label_object *label_obj = (struct label_object*)(buffer + START_RECV_LABEL);

    log_message("Received RESV message from %s with Label %d\n",
            inet_ntoa(sender_addr.sin_addr), ntohl(label_obj->label));

    path_msg *pa = NULL;
    pthread_mutex_lock(&path_tree_mutex);
    db_node *path_node = search_node(path_tree, ntohs(session_obj->tunnel_id), compare_path_del);
    pthread_mutex_unlock(&path_tree_mutex);
    if(path_node == NULL){
	log_message(" not found path table entry for tunnel id  = %d\n", ntohs(session_obj->tunnel_id));
	log_message(" return as we cannot get nexthop for the resv\n");
	return;
    } else {
	log_message("tunnel id  %d found in the path table \n",ntohs(session_obj->tunnel_id));
	pa = (path_msg*)path_node->data;
	insert(buffer, 0);
    }

    pthread_mutex_lock(&resv_tree_mutex);
    db_node *resv_node = search_node(resv_tree, ntohs(session_obj->tunnel_id), compare_resv_del);
    if(resv_node == NULL){
        temp = resv_tree_insert(resv_tree, buffer, pa->p_srcip, 0);
        if(temp != NULL) {
	    new_insert = 1;
            resv_tree = temp;
            resv_node = search_node(resv_tree, ntohs(session_obj->tunnel_id), compare_resv_del);
	    display_tree_debug(resv_tree, 0);
        }
    }
    pthread_mutex_unlock(&resv_tree_mutex);

    //check whether we have reached the head of RSVP tunnel
    //If not reached continue distributing the label  
 
    char command[200];
    if(resv_node != NULL && new_insert) {
        resv_msg *p = (resv_msg*)resv_node->data;
	
	log_message("send resv tunnel id  %d next hop is %s \n",ntohs(session_obj->tunnel_id), inet_ntoa(p->nexthop_ip));


    struct in_addr net, mask;
        char network[16];
        mask.s_addr = htonl(~((1 << (32 - pa->prefix_len)) - 1));
        net.s_addr = pa->dest_ip.s_addr & mask.s_addr;

        inet_ntop(AF_INET, &net, network, 16);
        inet_ntop(AF_INET, &pa->nexthop_ip, n_ip, 16);

        if(strcmp(inet_ntoa(p->nexthop_ip),"0.0.0.0") == 0) {
            log_message("****reached the source, end oF rsvp tunnel***\n");

            snprintf(command, sizeof(command), "ip route add %s/%d encap mpls %d via %s dev %s",
                    network, pa->prefix_len, (p->out_label), n_ip, pa->dev);

            printf(" ========== 1 %s \n", command);
            system(command);
        } else {
            if(p->out_label == 3) {
                snprintf(command, sizeof(command), "ip -M route add %d via inet %s dev %s",
                        (p->in_label), n_ip, pa->dev);
                log_message(" ========== 2 %s ", command);
                system(command);
            } else {
                snprintf(command, sizeof(command), "ip -M route add %d as %d via inet %s",
                        (p->in_label), (p->out_label), n_ip);
                log_message(" ========== 3 %s ", command);
                system(command);
            }
            log_message("send resv msg to nexthop \n");
            send_resv_message(sock, ntohs(session_obj->tunnel_id));
        }
    }
    new_insert = 0;
}



int dst_reached(char ip[]) {

    char nhip[16];
    uint32_t ifh = 0;
    uint8_t prefix_len = 0;
    char dev[16];

    if(get_nexthop(ip, nhip, &prefix_len, dev, &ifh)) { 
    //log_message("next hop is %s\n", nhip);
    	if(strcmp(nhip, " ") == 0)
        	return 1;
    	else 
        	return 0;
    } else {
	return -1;
    } 
}


void get_ip(char buffer[], char sender_ip[], char receiver_ip[], uint16_t *tunnel_id) {

    struct session_object *temp = (struct session_object*)(buffer+START_RECV_SESSION_OBJ);

    inet_ntop(AF_INET, &temp->src_ip, sender_ip, 16);
    inet_ntop(AF_INET, &temp->dst_ip, receiver_ip, 16); 
    *tunnel_id = ntohs(temp->tunnel_id);

    //log_message(" src ip is %s \n",sender_ip);
    //log_message(" dst ip is %s \n", receiver_ip);
}


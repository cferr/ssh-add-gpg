// Copyright 2017 - Corentin Ferry
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "crypto.h"
#include "common.h"

int resolve(char * hostname, struct sockaddr** target_addr);

int main(int argc, char* argv[])
{
    init_gpg();
    
    // iterate through the arguments
    int i;
    char* hostname = NULL;
    uint32_t port = 0;
    enum ipmode ipm = IP_AUTO;
    char* gpg_key_id = NULL;
    char* ssh_key_file = NULL;
    for(i = 1; i < argc; i++) {
        if(i < argc - 1 && strlen(argv[i]) == 6 && strncmp(argv[i], "--addr", 6) == 0) {
            i++;
            uint32_t len = strlen(argv[i]);
            hostname = (char*)malloc((1 + len) * sizeof(char));
            strncpy(hostname, argv[i], len);
            hostname[len] = 0;
        } else if(i < argc - 1 && strlen(argv[i]) == 9 && strncmp(argv[i], "--gpg-key", 9) == 0) {
            i++;
            uint32_t len = strlen(argv[i]);
            gpg_key_id = (char*)malloc((1 + len) * sizeof(char));
            strncpy(gpg_key_id, argv[i], len);
            gpg_key_id[len] = 0;
        } else if(i < argc - 1 && strlen(argv[i]) == 6 && strncmp(argv[i], "--port", 6) == 0) {
            i++;
            port = (uint32_t)atoi(argv[i]);
        } else if(strlen(argv[i]) == 5 && strncmp(argv[i], "--ip4", 5) == 0) {
            ipm = IP_4;
        } else if(strlen(argv[i]) == 5 && strncmp(argv[i], "--ip6", 5) == 0) {
            ipm = IP_6; // unimplemented
        } else if(strlen(argv[i]) == 9 && strncmp(argv[i], "--ip-auto", 9) == 0) {
            ipm = IP_AUTO;
        } else {
            uint32_t len = strlen(argv[i]);
            ssh_key_file = (char*)malloc((1 + len) * sizeof(char));
            strncpy(ssh_key_file, argv[i], len);
            ssh_key_file[len] = 0;
            break;
        }
    }
    
    if(hostname == NULL || port == 0 || gpg_key_id == NULL || ssh_key_file == NULL) {
        printf("Usage: %s (--ip4 | --ip6 | --ip-auto) --addr [server_addr] --port [server_port] --gpg-key [key_id] ssh_key\n", argv[0]);
        return -1;
    }
    
    // IPv4 for the moment
    struct sockaddr_in si_other;
    int s, slen=sizeof(si_other);
    char buf[DGRAM_SIZE];

    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
        diep("socket");

    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET; // For the moment
    si_other.sin_port = htons(port);
    
    struct sockaddr* ip_addr;
    
   if(resolve(hostname, &ip_addr)) 
       diep("resolve()");
    si_other.sin_addr = ((struct sockaddr_in*)ip_addr)->sin_addr;
    
    FILE* keyf = fopen(ssh_key_file, "r");
    if(!keyf) {
        diep("fopen()");
    }
    
    struct stat keyf_stat;
    if(fstat(fileno(keyf), &keyf_stat))
        diep("fstat()");
    
    
    char* keybuf = malloc(MAX_KEY_LENGTH * sizeof(char));
    char* keybuf_ptr = keybuf;
    
    while(!feof(keyf)) {
        if(keybuf_ptr >= keybuf + MAX_KEY_LENGTH)
            diep("Key too long");
        size_t nbRead = fread(buf + 1, sizeof(char), DGRAM_SIZE - 1, keyf);
        buf[0] = (uint8_t) nbRead;
        memcpy(keybuf_ptr, buf + 1, nbRead);
        keybuf_ptr += nbRead;
    }
    *keybuf_ptr = 0x00;
    
    char* sigbuf;
    
    // Sign the key
    uint64_t outSize = 0;
    sign(keybuf, &sigbuf, (uint32_t)(keybuf_ptr - keybuf), &outSize, gpg_key_id);
    
    // Send a 0-size buffer to clear everything
    buf[0] = 0x00;
    if (sendto(s, buf, 1, 0, (struct sockaddr *) &si_other, slen) == -1)
        diep("sendto()");
    
    // Send the size
    *buf = (uint8_t)sizeof(uint64_t);
    *((off_t*)(buf + 1)) = (uint64_t)keyf_stat.st_size;
    //*(buf + sizeof(uint64_t) + 1) = 0x00;
    
    if (sendto(s, buf, DGRAM_SIZE, 0, (struct sockaddr *) &si_other, slen) == -1)
        diep("sendto()");
    
    // Send the text and the signature if the signature operation succeeded
    char* keybuf_ptr_send = keybuf;
    while(keybuf_ptr_send < keybuf_ptr) {
        if(keybuf_ptr - keybuf_ptr_send <= DGRAM_SIZE - 1) {
            buf[0] = keybuf_ptr - keybuf_ptr_send;
            memcpy(buf + 1, keybuf_ptr_send, keybuf_ptr - keybuf_ptr_send);
        } else {
            buf[0] = DGRAM_SIZE - 1;
            memcpy(buf + 1, keybuf_ptr_send, DGRAM_SIZE - 1);
        }
        if (sendto(s, buf, DGRAM_SIZE, 0, (struct sockaddr *) &si_other, slen) == -1)
            diep("sendto()");
        
        memset(buf, 0, sizeof(buf));
        
        keybuf_ptr_send += DGRAM_SIZE - 1;
    }
    
    char* sigptr;
    for(sigptr = sigbuf; sigptr < sigbuf + outSize; sigptr += DGRAM_SIZE - 1) {
        if(sigptr + DGRAM_SIZE - 1 >= sigbuf + outSize) {
            memset(buf, 0, sizeof(buf));
            buf[0] = (uint8_t)(outSize - (sigptr - sigbuf));
            memcpy(buf + 1, sigptr, (uint8_t)buf[0]);
        } else {
            buf[0] = DGRAM_SIZE - 1;
            memcpy(buf + 1, sigptr, DGRAM_SIZE - 1);
        }
        if (sendto(s, buf, DGRAM_SIZE, 0, (struct sockaddr *) &si_other, slen) == -1)
            diep("sendto()");
    }
    
    // Send a 0 that triggers key & signature verification
    buf[0] = 0x00;
    if (sendto(s, buf, 1, 0, (struct sockaddr *) &si_other, slen) == -1)
        diep("sendto()");
    
    //free(keybuf);
    free(sigbuf);
    
    close(s);
    return 0;
}


int resolve(char * hostname, struct sockaddr** target_addr)
{
    int retval = 1;
    struct addrinfo* ad;
    if(getaddrinfo(hostname, NULL, NULL, &ad) == 0)
    {
        if(ad) {
            retval = 0;
            *target_addr = malloc(sizeof(struct sockaddr*));
            memcpy(*target_addr, ad->ai_addr, sizeof(struct sockaddr*));
            
            freeaddrinfo(ad);
        }
    } else diep("getaddrinfo");
    
    return retval;
}

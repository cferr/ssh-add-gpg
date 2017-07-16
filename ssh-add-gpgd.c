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
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "crypto.h"

int main(int argc, char* argv[])
{
    init_gpg();
    
    // iterate through the arguments
    int i;
    char* bind_addr = NULL;
    uint32_t bind_port = 0;
    enum ipmode ipm = IP_AUTO;
    char* gpg_key_id = NULL;
    char* auth_keys_file = NULL;
    for(i = 1; i < argc; i++) {
        if(i < argc - 1 && strlen(argv[i]) == 6 && strncmp(argv[i], "--addr", 6) == 0) {
            i++;
            uint32_t len = strlen(argv[i]);
            bind_addr = (char*)malloc((1 + len) * sizeof(char));
            strncpy(bind_addr, argv[i], len);
            bind_addr[len] = 0;
        } else if(i < argc - 1 && strlen(argv[i]) == 9 && strncmp(argv[i], "--gpg-key", 9) == 0) {
            i++;
            uint32_t len = strlen(argv[i]);
            gpg_key_id = (char*)malloc((1 + len) * sizeof(char));
            strncpy(gpg_key_id, argv[i], len);
            gpg_key_id[len] = 0;
        } else if(i < argc - 1 && strlen(argv[i]) == 6 && strncmp(argv[i], "--port", 6) == 0) {
            i++;
            bind_port = (uint32_t)atoi(argv[i]);
        } else if(strlen(argv[i]) == 5 && strncmp(argv[i], "--ip4", 5) == 0) {
            ipm = IP_4;
        } else if(strlen(argv[i]) == 5 && strncmp(argv[i], "--ip6", 5) == 0) {
            ipm = IP_6;
        } else if(strlen(argv[i]) == 9 && strncmp(argv[i], "--ip-auto", 9) == 0) {
            ipm = IP_AUTO;
        } else {
            uint32_t len = strlen(argv[i]);
            auth_keys_file = (char*)malloc((1 + len) * sizeof(char));
            strncpy(auth_keys_file, argv[i], len);
            auth_keys_file[len] = 0;
            break;
        }
    }
    
    if(bind_addr == NULL || bind_port == 0 || gpg_key_id == NULL || auth_keys_file == NULL) {
        printf("Usage: %s (--ip4 | --ip6 | --ip-auto) --addr [bind_addr] --port [bind_port] --gpg-key [key_id] auth_keys_file\n", argv[0]);
        return -1;
    }
    
    // Weak protection
    FILE* fd = fopen(auth_keys_file, "a");
    if(!fd)
        diep("fopen");
    
    struct sockaddr_in si_me, si_other;
    int s, slen=sizeof(si_other);
    char buf[DGRAM_SIZE];
    char* keybuf = (char*)malloc(SRV_BUF_SIZE * sizeof(char));
    char* curpointer = keybuf;
    char* endpointer = keybuf + SRV_BUF_SIZE;

    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
        diep("socket");

    char* gpg_key_fp = publicKeyId(gpg_key_id);
    printf("GPG fingerprint to check against is %s\n", gpg_key_fp);
    
    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(bind_port);

    if(inet_aton(bind_addr, &si_me.sin_addr) != 1)
        diep("inet_aton");
    
    if (bind(s, (struct sockaddr *) &si_me, sizeof(si_me))==-1)
        diep("bind");

    struct in_addr prev_sin_addr;
    while(1) {
        if(recvfrom(s, buf, DGRAM_SIZE, 0, (struct sockaddr *) &si_other, &slen)>0) {
            if(prev_sin_addr.s_addr != si_other.sin_addr.s_addr) {
                // Flush the buffer
                memset(keybuf, 0, SRV_BUF_SIZE * sizeof(char));
                curpointer = keybuf;
                prev_sin_addr = si_other.sin_addr;
            }
            uint8_t size = buf[0];
            memcpy(curpointer, buf + 1, size);
            curpointer += size;
            if(curpointer >= endpointer) {
                // Overflow - reset everything
                memset(keybuf, 0, SRV_BUF_SIZE * sizeof(char));
                curpointer = keybuf;
                continue;
            }
            
            if(size == 0) {
                // Trigger
                // Get the sizes - unsigned
                uint64_t totalSize = (uint64_t)(curpointer - keybuf);
                uint64_t keySize = *((uint64_t*)keybuf);
                uint64_t signatureSize = totalSize - keySize - sizeof(uint64_t);

                if(keySize >= SRV_BUF_SIZE || keySize == 0 || signatureSize == 0) {
                    memset(keybuf, 0, SRV_BUF_SIZE * sizeof(char));
                    curpointer = keybuf;
                    continue;
                }
                
                // Create a buffer containing the key
                char* key = malloc(1 + keySize * sizeof(char));
                memcpy(key, keybuf + sizeof(uint64_t), keySize);
                key[keySize] = 0x00;
                
                // Set the remainder as the signature
                unsigned char* sig = malloc(1 + signatureSize * sizeof(unsigned char));
                memcpy(sig, keybuf + sizeof(uint64_t) + keySize, signatureSize);
                sig[signatureSize] = 0x00;
                
                // Check the signature
                if(!check(key, keySize, sig, signatureSize, gpg_key_fp, strlen(gpg_key_fp))) {
                    FILE* fd = fopen(auth_keys_file, "a");
                    if(!fd)
                        diep("fopen");
                    
                    fwrite(key, sizeof(char), keySize, fd);
                    
                    fclose(fd);
                }
                
                // Reset
                memset(keybuf, 0, SRV_BUF_SIZE * sizeof(char));
                curpointer = keybuf;
                free(key);
                free(sig);
            }
        }
    }
    
    free(keybuf);
    close(s);
    return 0;
}

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

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>

#define DGRAM_SIZE 256
#define NPACK 10
#define PORT 9930
// length in chars, although converted to base64
#define MAX_KEY_LENGTH 4096 / 8
// "ssh-rsa KEY NAME SIGNATURE"
#define MAX_NAME_LENGTH 128 + 3 + 7
#define DIGEST_ALG "SHA256"
#define MAX_ENC_DIGEST_LENGTH 4096
#define SRV_BUF_SIZE MAX_ENC_DIGEST_LENGTH + MAX_KEY_LENGTH + MAX_NAME_LENGTH

enum ipmode {
    IP_AUTO, IP_4, IP_6
};

void diep(char *s)
{
    perror(s);
    exit(1);
}

#endif

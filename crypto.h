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

#ifndef CRYPTO_H
#define CRYPTO_H
#include <sys/types.h>
#include <stdint.h>

void init_gpg();
char* publicKeyId(char* hint);
void sign(char* ssh_key, char** out, uint32_t ssh_key_length, size_t* out_length, char* key_filter);
int check(char* ssh_key, uint32_t ssh_key_length, char* signature, uint32_t signature_length, const char* gpg_key, const uint32_t gpg_key_length);

#endif

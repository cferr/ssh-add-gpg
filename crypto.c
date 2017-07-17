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

#include "crypto.h"
#include <gpgme.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void diegpg(const char* fun, gpgme_error_t err) {
    printf("%s: %s -> %s\n", fun, gpgme_strsource(err), gpgme_strerror(err));
    exit(1);
}

void init_gpg() {
    gpgme_check_version(NULL);

    gpgme_error_t err;
    gpgme_ctx_t context;
    if((err = gpgme_new(&context)))
        diegpg("gpgme_new", err);

    gpgme_release(context);
}


char* publicKeyId(char* hint) {
    gpgme_error_t err;
    gpgme_ctx_t context;

    if((err = gpgme_new(&context)))
        diegpg("gpgme_new", err);

    gpgme_op_keylist_start(context, hint, 0);

    // Get the signer key
    gpgme_key_t gpg_key;
    if((err = gpgme_op_keylist_next(context, &gpg_key))) {
        if(gpgme_err_source(err) == GPG_ERR_SOURCE_GPGME &&
                gpgme_err_code(err) == GPG_ERR_EOF)
        {
            fprintf(stderr, "No key matching filter %s\n", hint);
            exit(1);
        }
        else diegpg("gpgme_op_keylist_next", err);
    }

    uint32_t keyid_len = strlen(gpg_key->fpr);
    char* ret = malloc(1 + keyid_len);
    memcpy(ret, gpg_key->fpr, keyid_len);
    ret[keyid_len] = 0x00;

    gpgme_op_keylist_end(context);
    gpgme_release(context);

    return ret;
}

void sign(char* ssh_key, char** out, uint32_t ssh_key_length, size_t* out_length, char* key_filter) {
    gpgme_error_t err;
    gpgme_ctx_t context;

    if((err = gpgme_new(&context)))
        diegpg("gpgme_new", err);

    // ASCII Armor
    gpgme_set_armor(context, 1);

    // Create GPGME data objects for the clear- and cipher-text
    gpgme_data_t cleartext;
    gpgme_data_t ciphertext;

    gpgme_data_new_from_mem(&cleartext, ssh_key, (size_t)ssh_key_length, 0);
    gpgme_data_new(&ciphertext);

    // Set the protocol to OpenPGP (this doesn't really matter provided the
    // same protocol is used in check())
    gpgme_set_protocol(context, GPGME_PROTOCOL_OpenPGP);

    if((err = gpgme_op_keylist_start(context, key_filter, 1)))
        diegpg("gpgme_op_keylist_start", err);


    // Get the signer key
    gpgme_key_t gpg_key;
    if((err = gpgme_op_keylist_next(context, &gpg_key))) {
        if(gpgme_err_source(err) == GPG_ERR_SOURCE_GPGME &&
                gpgme_err_code(err) == GPG_ERR_EOF)
        {
            fprintf(stderr, "No key matching filter %s\n", key_filter);
            exit(1);
        }
        else diegpg("gpgme_op_keylist_next", err);
    }

    gpgme_op_keylist_end(context);
    gpgme_signers_clear(context);
    if((err = gpgme_signers_add(context, gpg_key)))
        diegpg("gpgme_signers_add", err);

    // Sign the cleartext into the ciphertext buffer
    if((err = gpgme_op_sign(context, cleartext, ciphertext, GPGME_SIG_MODE_DETACH)))
        diegpg("gpgme_op_sign", err);

    // Get the signed text
    char* pre_out = gpgme_data_release_and_get_mem(ciphertext, out_length);
    uint64_t ol = *out_length;
    *out = malloc((1 + ol) * sizeof(char));
    strncpy(*out, pre_out, ol);

    gpgme_free(pre_out);
    gpgme_release(context);

}

int check(char* ssh_key, uint32_t ssh_key_length, char* signature, uint32_t signature_length, const char* gpg_key, const uint32_t gpg_key_length) {

    int retval = -1;

    gpgme_error_t err;
    gpgme_ctx_t context;

    if((err = gpgme_new(&context)))
        diegpg("gpgme_new", err);

    // Create GPGME data objects for the clear- and cipher-text
    gpgme_data_t cleartext;
    gpgme_data_t ciphertext;

    gpgme_data_new_from_mem(&cleartext, ssh_key, (size_t)ssh_key_length, 0);
    gpgme_data_new_from_mem(&ciphertext, signature, (size_t)signature_length, 0);

    if((err = gpgme_op_verify(context, ciphertext, cleartext, NULL))) {
#ifdef DEBUG
        printf("gpgme_op_verify: %s -> %s\n", gpgme_strsource(err), gpgme_strerror(err));
#endif
    } else {
        gpgme_verify_result_t verifRes = gpgme_op_verify_result(context);
        gpgme_signature_t signature = verifRes->signatures;
        while(signature) {
            // Require fully valid signatures
            if(!(signature->summary & GPGME_SIGSUM_VALID)) {
                signature = signature->next;
                continue;
            }
            if(strncmp(signature->fpr, gpg_key, gpg_key_length) == 0)
                retval = 0;

            signature = signature->next;
        }
    }

    gpgme_release(context);

    return retval;
}

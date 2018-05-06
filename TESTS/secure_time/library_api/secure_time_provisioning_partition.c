#include "spm_server.h"
#include "spm_client.h"
#include "spm_panic.h"
#include "psa_secure_time_test_provisioning_partition.h"
#include "secure_time_client_spe.h"
#include <string.h>

void secure_time_provisioning_main(void *ptr)
{
    uint32_t signals = 0;
    psa_msg_t msg = {0};
    int32_t result = 0;


    while (1) {
        signals = psa_wait_any(PSA_WAIT_BLOCK);
        if (signals == 0 || (signals | TEST_SET_PUBLIC_KEY_MSK) != TEST_SET_PUBLIC_KEY_MSK) {
            SPM_PANIC("Unexpected signal(s) %d!\n", (int)signals);
        }

        psa_get(signals, &msg);
        switch (msg.type)
        {
            case PSA_IPC_MSG_TYPE_CALL:
                switch (signals) {
                    case TEST_SET_PUBLIC_KEY_MSK:
                        // ca_pubkey, ca_pubkey_size
                        if (msg.in_size[0] == 0) {
                            SPM_PANIC("Unknown parameters\n");
                        }

                        void *key = malloc(msg.in_size[0]);
                        psa_read(msg.handle, 0, key, msg.in_size[0]);
                        result = secure_time_set_stored_public_key(key, msg.in_size[0]);
                        memset(key, 0, msg.in_size[0]);
                        free(key);
                        break;
                    default:
                        SPM_PANIC("Unexpected signal %d (must be a programming error)!\n", signals);
                }
                psa_end(msg.handle, result);
                break;

            case PSA_IPC_MSG_TYPE_CONNECT:
            case PSA_IPC_MSG_TYPE_DISCONNECT:
                psa_end(msg.handle, PSA_SUCCESS);
                break;
            default:
                SPM_PANIC("Unexpected message type %d!\n", (int)msg.type);
        }
    }
}

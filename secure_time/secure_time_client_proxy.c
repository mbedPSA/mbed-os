#include "psa_defs.h"
#include "spm_client.h"
#include "psa_secure_time_ifs.h"
#include "secure_time_client_common.h"
#include "secure_time_client.h"

int32_t secure_time_set_trusted_init(uint64_t *nonce)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_outvec_t reply_data[2] = {
        {&reply_status, sizeof(reply_status)},
        {nonce, sizeof(*nonce)}
    };

    if (!psa_invoke_sf(
        TIME_SET_TRUSTED_INIT,
        TIME_SET_TRUSTED_INIT_MINOR,
        NULL,
        0,
        reply_data,
        2))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }

    return reply_status;
}

int32_t secure_time_set_trusted_commit(
    const void *blob,
    size_t blob_size
    )
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[1] = {
        {blob, blob_size}
    };
    psa_outvec_t reply_data[1] = {
        {&reply_status, sizeof(reply_status)}
    };

    if (!psa_invoke_sf(
        TIME_SET_TRUSTED_COMMIT,
        TIME_SET_TRUSTED_COMMIT_MINOR,
        request_data,
        1,
        reply_data,
        1))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }

    return reply_status;
}

int32_t secure_time_set(uint64_t new_time)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[1] = {
        {&new_time, sizeof(new_time)}
    };
    psa_outvec_t reply_data[1] = {
        {&reply_status, sizeof(reply_status)}
    };

    if (!psa_invoke_sf(
        TIME_SET,
        TIME_SET_MINOR,
        request_data,
        1,
        reply_data,
        1))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }

    return reply_status;
}

uint64_t secure_time_get(void)
{
    uint64_t current_time = 0;
    psa_outvec_t reply_data[1] = {
        {&current_time, sizeof(current_time)}
    };

    if (!psa_invoke_sf(
        TIME_GET,
        TIME_GET_MINOR,
        NULL,
        0,
        reply_data,
        1))
    {
        return 0;
    }

    return current_time;
}

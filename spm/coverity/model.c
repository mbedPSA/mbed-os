/*
 * Copyright (c) 2017, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#define osOK 0
typedef int osStatus_t;
typedef unsigned int uint32_t;
typedef void *osMemoryPoolId_t;

typedef unsigned int _U_UINT;
#define UNITY_LINE_TYPE _U_UINT

void mbed_die(void) {
    __coverity_panic__();
}

void error(const char* format, ...) {
    __coverity_panic__();
}

void UnityFail(const char* msg, const UNITY_LINE_TYPE line) {
    __coverity_panic__();
}

void *osMemoryPoolAlloc (osMemoryPoolId_t mp_id, uint32_t timeout) {
    return  __coverity_alloc_nosize__();
}

osStatus_t osMemoryPoolFree (osMemoryPoolId_t mp_id, void *block) {
    __coverity_free__(block);
    return osOK;
}

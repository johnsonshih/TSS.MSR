/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#pragma once

bool UnMarshal(TpmCpp::TPMT_PUBLIC& tpmtPublic, TPM2B_PUBLIC* tpm2bPublic);

#ifdef __cplusplus
extern "C" {
#endif

UINT32 TPMT_PUBLIC_GetExponent(void* tpmt_public);

#ifdef __cplusplus
}
#endif
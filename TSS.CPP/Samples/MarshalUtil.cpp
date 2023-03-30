/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"
#include "tpmtypes.h"
#include "tpm2-tss-engine.h"

#include "MarshalUtil.h"

bool UnMarshal(TpmCpp::TPMT_PUBLIC& tpmtPublic, TPM2B_PUBLIC* tpm2bPublic)
{
    return false;
}

UINT32 TPMT_PUBLIC_GetExponent(void* tpmt_public)
{
    auto tpmtPublic = static_cast<TpmCpp::TPMT_PUBLIC*>(tpmt_public);
    const auto exponent = dynamic_cast<TpmCpp::TPMS_RSA_PARMS*>(&*tpmtPublic->parameters)->exponent;
    return exponent;
}

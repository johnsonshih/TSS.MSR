/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"
#include "Samples.h"

using namespace std;

static const TPMT_SYM_DEF_OBJECT Aes128Cfb {TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB};

// Verify that the sample did not leave any dangling handles in the TPM.
#define _check AssertNoLoadedKeys()

void Samples::RunCreatePrimaryKey()
{
    _check;
    CreatePrimaryKey();
}

void Samples::CreatePrimaryKey()
{
    Announce("CreatePrimaryKey");

    // Set Password
    //std::string password = "abc123";
    std::string password = "";

    // key slot number
    const UINT32 keySlot = 0x1;

    // template for the primary key
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        null,           // No policy
        TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // Set the use-auth for the new key.
    ByteVec userAuth(password.size());
    std::transform(password.begin(), password.end(), userAuth.begin(),
        [](char c) { return c; });
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, null);

    // Create the key (no PCR-state captured)
    auto newPrimary = tpm._AllowErrors()
        .CreatePrimary(TPM_RH::OWNER, sensCreate, storagePrimaryTemplate, null, null);

    // Print out the public data for the new key. Note the parameter to
    // ToString() "pretty-prints" the byte-arrays.
    cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;

    cout << "Name of new key:" << endl;
    cout << " Returned by TPM " << newPrimary.name << endl;
    cout << " Calculated      " << newPrimary.outPublic.GetName() << endl;
    cout << " Set in handle   " << newPrimary.handle.GetName() << endl;
    _ASSERT(newPrimary.name == newPrimary.outPublic.GetName());

    // We can put the primary key into NV with EvictControl
    TPM_HANDLE persistentHandle = TPM_HANDLE::Persistent(keySlot);

    // First delete anything that might already be there
    tpm._AllowErrors().EvictControl(TPM_RH::OWNER, persistentHandle, persistentHandle);

    // Make our primary persistent
    tpm.EvictControl(TPM_RH::OWNER, newPrimary.handle, persistentHandle);

    // Flush the old one
    tpm.FlushContext(newPrimary.handle);

    // ReadPublic of the new persistent one
    auto persistentPub = tpm.ReadPublic(persistentHandle);
    cout << "Public part of persistent primary" << endl << persistentPub.ToString(false);

} // CreatePrimaryKey()


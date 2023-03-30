/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"
#include "Tpm2.h"
#include "tss2_tpm2_types.h"

#include "Samples.h"

extern "C" void tpm2tss_genkey_rsa(UINT32 inExponent, BYTE* rsaBuffer, UINT16 rsaBufferSize, BYTE* privateBuffer, UINT32 privateBufferSize,
                                   BYTE* publicBuffer, UINT32 publicBufferSize);

using namespace std;

static const TpmCpp::TPMT_SYM_DEF_OBJECT Aes128Cfb { TpmCpp::TPM_ALG_ID::AES, 128, TpmCpp::TPM_ALG_ID::CFB};

// Verify that the sample did not leave any dangling handles in the TPM.
#define _check AssertNoLoadedKeys()

void Samples::RunCreatePrimaryKey()
{
    _check;

    // Set Parent Password
    //std::string parentPassword = "pxyz123";
    std::string parentPassword = "";

    // key slot number
    const UINT32 keySlot = 0x1;

    const auto primaryHandle = CreatePrimaryKey(parentPassword, keySlot);

    // Set Child Password
    //std::string childPassword = "kabc";
    std::string childPassword = "";
    std::string filePath = "c:\\temp\\mykey";
    CreateChildKey(primaryHandle, childPassword, filePath);

    return;
}

TpmCpp::TPM_HANDLE Samples::CreatePrimaryKey(const std::string& password, UINT32 keySlot)
{
    using namespace TpmCpp;
    Announce("CreatePrimaryKey");

    // template for the primary key
    TpmCpp::TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},           // No policy
        TpmCpp::TPMS_RSA_PARMS(Aes128Cfb, TpmCpp::TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TpmCpp::TPM2B_PUBLIC_KEY_RSA());

    // Set the use-auth for the new key.
    ByteVec userAuth(password.size());
    std::transform(password.begin(), password.end(), userAuth.begin(),
        [](char c) { return c; });
    TpmCpp::TPMS_SENSITIVE_CREATE sensCreate(userAuth, {});

    // Create the key (no PCR-state captured)
    auto newPrimary = tpm._AllowErrors()
        .CreatePrimary(TPM_RH::OWNER, sensCreate, storagePrimaryTemplate, {}, {});

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
    tpm.EvictControl(TpmCpp::TPM_RH::OWNER, newPrimary.handle, persistentHandle);

    // Flush the old one
    tpm.FlushContext(newPrimary.handle);

    // ReadPublic of the new persistent one
    auto persistentPub = tpm.ReadPublic(persistentHandle);
    cout << "Public part of persistent primary" << endl << persistentPub.ToString(false);

    return persistentHandle;
} // CreatePrimaryKey()

void Samples::CreateChildKey(const TpmCpp::TPM_HANDLE& parentHandle, const std::string& keyPassword, const std::string& filePath)
{
    // Now we have a primary we can ask the TPM to make child keys. As always, we start with
    // a template. Here we specify a 1024-bit signing key to create a primary key the TPM
    // must be provided with a template.  This is for an RSA1024 signing key.
    TpmCpp::TPMT_PUBLIC templ(TpmCpp::TPM_ALG_ID::SHA256,
        TpmCpp::TPMA_OBJECT::sign | TpmCpp::TPMA_OBJECT::decrypt
        | TpmCpp::TPMA_OBJECT::fixedParent | TpmCpp::TPMA_OBJECT::fixedTPM
        | TpmCpp::TPMA_OBJECT::noDA
        | TpmCpp::TPMA_OBJECT::sensitiveDataOrigin | TpmCpp::TPMA_OBJECT::userWithAuth,
        {},                                   // No policy
        TpmCpp::TPMS_RSA_PARMS({}, TpmCpp::TPMS_NULL_SIG_SCHEME(), 2048, 65537),
        TpmCpp::TPM2B_PUBLIC_KEY_RSA());

    // Set the use-auth for the new key.
    TpmCpp::ByteVec userAuth(keyPassword.size());
    std::transform(keyPassword.begin(), keyPassword.end(), userAuth.begin(),
        [](char c) { return c; });
    TpmCpp::TPMS_SENSITIVE_CREATE sensCreate(userAuth, {});

    // Ask the TPM to create the key
    auto newSigKey = tpm.Create(parentHandle, sensCreate, templ, {}, {});

    cout << "Private part of child key" << endl << newSigKey.outPrivate.ToString(false) << endl;
    cout << "Public part of child key" << endl << newSigKey.outPublic.ToString(false) << endl;

    const auto exponent = dynamic_cast<TpmCpp::TPMS_RSA_PARMS*>(&*newSigKey.outPublic.parameters)->exponent;
    TpmCpp::TPM2B_PUBLIC_KEY_RSA* rsaPubKey = dynamic_cast<TpmCpp::TPM2B_PUBLIC_KEY_RSA*>(&*newSigKey.outPublic.unique);

    auto privateBuffer = newSigKey.outPrivate.toBytes();
    auto publicBuffer = newSigKey.outPublic.asTpm2B();

    tpm2tss_genkey_rsa(exponent, rsaPubKey->buffer.data(), (UINT16)rsaPubKey->buffer.size(),
        privateBuffer.data(), privateBuffer.size(), publicBuffer.data(), publicBuffer.size());
}
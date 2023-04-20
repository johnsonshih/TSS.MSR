/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#pragma once

extern bool UseSimulator;

// Beginning of the TPM NV indices range used by the samples
constexpr int NvRangeBegin = 2101;
constexpr int NvRangeEnd = 3000;

// Beginning of the TPM persistent objects range used by the samples
constexpr int PersRangeBegin = 2101;
constexpr int PersRangeEnd = 3000;

inline TpmCpp::TPM_HANDLE RandomNvHandle()
{
    return TpmCpp::TPM_HANDLE::NV(TpmCpp::Helpers::RandomInt(NvRangeBegin, NvRangeEnd));
}

inline TpmCpp::TPM_HANDLE RandomPersHandle()
{
    return TpmCpp::TPM_HANDLE::Persistent(TpmCpp::Helpers::RandomInt(PersRangeBegin, PersRangeEnd));
}


class Samples {
    public:
        Samples();
        ~Samples();

        void RunCreatePrimaryKey(const std::string& outfilePath, const std::string& parentPassword, const std::string& keyPassword);
        TpmCpp::TPM_HANDLE CreatePrimaryKey(const std::string& password, UINT32 keySlot);
        void CreateChildKey(const TpmCpp::TPM_HANDLE& parentHandle, const std::string& parentPassword, const std::string& keyPassword, const std::string& filePath);

        // The following methods demonstrate how TSS.C++ is used to perform TPM functions.
        void RunAllSamples();
        void RunDocSamples();
        void ArrayParameters();
        void PWAPAuth();
        void Errors();
        void Structures();
        void HMACSessions();
        void SigningPrimary();
        void SimplePolicy();
        void ThreeElementPolicy();
        void PolicyOrSample();

        void Rand();
        void PCR();
        void Locality();
        void Hash();
        void HMAC();
        void GetCapability();
        void NV();
        void NVX();
        void PrimaryKeys();
        void AuthSessions();
        void Async();
        void PolicySimplest();
        void PolicyLocalitySample();
        void PolicyPCRSample();
        void PolicyORSample();
        void ChildKeys();
        void CounterTimer();
        void Attestation();
        void Admin();
        void DictionaryAttack();
        void PolicyCpHashSample();
        void PolicyCounterTimerSample();
        void PolicyWithPasswords();
        void Unseal();
        void Serializer();
        void SessionEncryption();
        void ImportDuplicate();
        void MiscAdmin();
        void RsaEncryptDecrypt();
        void Audit();
        void Activate();
        void SoftwareKeys();
        void PolicySigned();
        void PolicyAuthorizeSample();
        void PolicySecretSample();
        void EncryptDecryptSample();
        void SeededSession();
        void PolicyNVSample();
        void PolicyNameHashSample();
        void ReWrapSample();
        void BoundSession();

        void StartCallbacks();
        void FinishCallbacks();

        void PresentationSnippets();

        /// <summary> Checks to see that there are no keys left in the TPM </summary>
        void AssertNoLoadedKeys();

        void TpmCallback(const TpmCpp::ByteVec& command, const TpmCpp::ByteVec& response);

        static void TpmCallbackStatic(const TpmCpp::ByteVec& command, const TpmCpp::ByteVec& response, void *context)
        {
            static_cast<Samples*>(context)->TpmCallback(command, response);
        }

    protected:
        void Announce(const char *testName);
        void RecoverTpm();
        void SetColor(UINT16 col);
        int GetSystemTime(bool reset = false);
        void Sleep(int numMillisecs);
        TpmCpp::TPM_HANDLE MakeHmacPrimaryWithPolicy(const TpmCpp::TPM_HASH& policy, const TpmCpp::ByteVec& keyAuth);
        TpmCpp::TPM_HANDLE MakeStoragePrimary(TpmCpp::AUTH_SESSION* sess = nullptr);
        TpmCpp::TPM_HANDLE MakeDuplicableStoragePrimary(const TpmCpp::ByteVec& policyDigest);
        TpmCpp::TPM_HANDLE MakeChildSigningKey(TpmCpp::TPM_HANDLE parent, bool restricted);
        TpmCpp::TPM_HANDLE MakeEndorsementKey();
        void TestAuthSession(TpmCpp::AUTH_SESSION& sess);

        _TPMCPP TpmCpp::Tpm2 tpm;
        _TPMCPP TpmCpp::TpmDevice *device;

        std::map<_TPMCPP TpmCpp::TPM_CC, int> commandsInvoked;
        std::map<_TPMCPP TpmCpp::TPM_RC, int> responses;
        std::vector<_TPMCPP TpmCpp::TPM_CC> commandsImplemented;
};
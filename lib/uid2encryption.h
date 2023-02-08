#pragma once

#include "keycontainer.h"

#include <uid2/timestamp.h>
#include <uid2/types.h>

#include <cstdint>
#include <vector>

namespace uid2
{
    enum class AdvertisingTokenType : std::uint8_t
    {
        //showing as "AHA..." in the Base64 Encoding (Base64 'H' is 000111 and 112 is 01110000)
        ADVERTISING_TOKEN_V3 = 112,
        //showing as "AIA..." in the Base64URL Encoding ('H' is followed by 'I' hence
        //this choice for the next token version) (Base64 'I' is 001000 and 128 is 10000000)
        ADVERTISING_TOKEN_V4 = 128,
    };

	DecryptionResult DecryptToken(
		const std::string& token,
		const KeyContainer& keys,
		Timestamp now,
        IdentityScope identityScope,
		bool checkValidity);

	EncryptionDataResult EncryptData(
		const EncryptionDataRequest& req,
		const KeyContainer* keys,
        IdentityScope identityScope);

	DecryptionDataResult DecryptData(
		const std::vector<std::uint8_t>& encryptedBytes,
		const KeyContainer& keys,
        IdentityScope identityScope);

    void RandomBytes(std::uint8_t* out, int count);

    int EncryptGCM(const std::uint8_t* data, int size, const std::uint8_t* secret, std::uint8_t* out_encrypted);
    int DecryptGCM(const std::uint8_t* encrypted, int size, const std::uint8_t* secret, std::uint8_t* out_decrypted);
}

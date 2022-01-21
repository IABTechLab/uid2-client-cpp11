// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <uid2/uid2client.h>

#include "base64.h"
#include "httplib.h"
#include "keycontainer.h"
#include "keyparser.h"
#include "uid2encryption.h"

#include <functional>
#include <mutex>

namespace uid2
{
	struct UID2Client::Impl
	{
		std::string endpoint;
		std::string authKey;
		httplib::Client httpClient;
		std::shared_ptr<KeyContainer> container;
		mutable std::recursive_mutex refreshMutex;
		mutable std::mutex containerMutex;

		Impl(std::string endpoint, std::string authKey)
			: endpoint(endpoint)
			, authKey(authKey)
			, httpClient(endpoint.c_str())
		{
			if (endpoint.rfind("https") != 0)
			{
				// TODO: non-https endpoint warning
			}

			httpClient.set_default_headers({
				{ "Authorization",  "Bearer " + authKey }
				});
		}

		~Impl();

		std::string GetLatestKeys(std::string& out_err);
		RefreshResult RefreshJson(const std::string& json);
		void SwapKeyContainer(const std::shared_ptr<KeyContainer>& newContainer);
		std::shared_ptr<KeyContainer> GetKeyContainer() const;
	};

	UID2Client::UID2Client(std::string endpoint, std::string authKey)
		: mImpl(new Impl(endpoint, authKey))
	{
	}

	UID2Client::~UID2Client()
	{
		mImpl.reset();
	}

	RefreshResult UID2Client::Refresh()
	{
		const std::lock_guard<std::recursive_mutex> lock(mImpl->refreshMutex);

		std::string err;
		std::string jsonResponse = mImpl->GetLatestKeys(err);
		if (!err.empty())
		{
			return RefreshResult::MakeError(std::move(err));
		}
		return mImpl->RefreshJson(jsonResponse);
	}

	DecryptionResult UID2Client::Decrypt(const std::string& token, Timestamp now)
	{
		// hold reference to container so it's not disposed by refresh
		const auto activeContainer = mImpl->GetKeyContainer();
		if (activeContainer == nullptr)
		{
			return DecryptionResult::MakeError(DecryptionStatus::NOT_INITIALIZED);
		}
		else if (!activeContainer->IsValid(now))
		{
			return DecryptionResult::MakeError(DecryptionStatus::KEYS_NOT_SYNCED);
		}

		return DecryptToken(token, *activeContainer, now, /*checkValidity*/true);
	}

	EncryptionDataResult UID2Client::EncryptData(const EncryptionDataRequest& req)
	{
		// hold reference to container so it's not disposed by refresh
		const auto activeContainer = mImpl->GetKeyContainer();
		return uid2::EncryptData(req, activeContainer.get());
	}

	DecryptionDataResult UID2Client::DecryptData(const std::string& encryptedData)
	{
		// hold reference to container so it's not disposed by refresh
		const auto activeContainer = mImpl->GetKeyContainer();
		if (activeContainer == nullptr)
		{
			return DecryptionDataResult::MakeError(DecryptionStatus::NOT_INITIALIZED);
		}
		else if (!activeContainer->IsValid(Timestamp::Now()))
		{
			return DecryptionDataResult::MakeError(DecryptionStatus::KEYS_NOT_SYNCED);
		}

		try
		{
			std::vector<std::uint8_t> encryptedBytes;
			macaron::Base64::Decode(encryptedData, encryptedBytes);
			return uid2::DecryptData(encryptedBytes, *activeContainer);
		}
		catch (...)
		{
			return DecryptionDataResult::MakeError(DecryptionStatus::INVALID_PAYLOAD);
		}


		return DecryptionDataResult::MakeError(DecryptionStatus::SUCCESS);
	}

	RefreshResult UID2Client::RefreshJson(const std::string& json)
	{
		const std::lock_guard<std::recursive_mutex> lock(mImpl->refreshMutex);

		return mImpl->RefreshJson(json);
	}

	UID2Client::Impl::~Impl()
	{
		httpClient.stop();
	}

	std::string UID2Client::Impl::GetLatestKeys(std::string& out_err)
	{
		if (auto res = httpClient.Get("/v1/key/latest"))
		{
			if (res->status >= 200 || res->status < 300)
			{
				return res->body;
			}
			else
			{
				out_err = "bad http response, status code: " + std::to_string(res->status);
			}
		}
		else
		{
			std::stringstream ss;
			ss << "error code: " << res.error();
			auto result = httpClient.get_openssl_verify_result();
			if (result)
			{
				ss << ", verify error: " << X509_verify_cert_error_string(result);
			}
			out_err = ss.str();
		}

		return "[]";
	}

	RefreshResult UID2Client::Impl::RefreshJson(const std::string& json)
	{
		std::string err;
		auto container = std::make_shared<KeyContainer>();
		if (KeyParser::TryParse(json, *container, err))
		{
			SwapKeyContainer(container);
			return RefreshResult::MakeSuccess();
		}
		else
		{
			return RefreshResult::MakeError(std::move(err));
		}
	}

	void UID2Client::Impl::SwapKeyContainer(const std::shared_ptr<KeyContainer>& newContainer)
	{
		const std::lock_guard<std::mutex> lock(containerMutex);
		this->container = std::shared_ptr<KeyContainer>{ newContainer };
	}

	std::shared_ptr<KeyContainer> UID2Client::Impl::GetKeyContainer() const
	{
		const std::lock_guard<std::mutex> lock(containerMutex);
		return this->container;
	}
}

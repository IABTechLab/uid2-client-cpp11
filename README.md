# UID2 SDK for C++

The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review [the governance rules](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md).

This SDK simplifies integration with UID2 for those using C++.

## Dependencies

This SDK supports C++ version 11.

```
CMake 3.12+

OpenSSL 1.1.1+
on Alpine: apk add libressl-dev
on Ubuntu: apt-get install libssl-dev

GTest
on Alpine: apk add gtest-dev
on Ubuntu: apt-get install libgtest-dev
```

## Install

To install, run the following:

```
cd <this directory>
mkdir build
cd build
cmake ..
make
make test
make install
```

For an installation example, see [Dockerfile](Dockerfile).

## Run

```
docker build . -t uid2_client_cpp
# docker run -it uid2_client_cpp <base-url> <api-key> <secret-key> <advertising-token>
# For example:
docker run -it uid2_client_cpp https://integ.uidapi.com test-id-reader-key your-secret-key \
	AgAAAANzUr8B6CCM+WBKichZGU8iyDBSI83LXiXa1SW2i4LaVQPzlBtOhjoeUUc3Nv+aOPLwiVol0rnxwdNkJNgm710I4lKAp8kpjqZO6evjN6mVZalwzQA5Y4usQVEtwBkYr3V3MbYR1eI3n0Bc7/KVeanfBXUF4odpHNBEWTAL+YgSCA==
```

## Example Usage

To create a UID2 client instance, use `UID2ClientFactory::Create`.

 - `client->Refresh()` to fetch the latest keys
 - `client->Decrypt()` to decrypt an advertising token
 - `client->EncryptData()` to encrypt arbitrary data
 - `client->DecryptData()` to decrypt data encrypted with `EncryptData()`

For an example, see [app/example.cpp](app/example.cpp).

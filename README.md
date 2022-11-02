# UID2 Client

UID2 Client for C++11

See `Dockerfile` for installation example

See `app/example.cpp` for example usage.

## Dependencies

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

```
cd <this directory>
mkdir build
cd build
cmake ..
make
make test
make install
```

## Running the example

```
docker build . -t uid2_client_cpp
# docker run -it uid2_client_cpp <base-url> <api-key> <secret-key> <advertising-token>
# For example:
docker run -it uid2_client_cpp https://integ.uidapi.com test-id-reader-key your-secret-key \
	AgAAAANzUr8B6CCM+WBKichZGU8iyDBSI83LXiXa1SW2i4LaVQPzlBtOhjoeUUc3Nv+aOPLwiVol0rnxwdNkJNgm710I4lKAp8kpjqZO6evjN6mVZalwzQA5Y4usQVEtwBkYr3V3MbYR1eI3n0Bc7/KVeanfBXUF4odpHNBEWTAL+YgSCA==
```

## Usage

Use `UID2ClientFactory::Create` to create a uid2 client instance.

 - `client->Refresh()` to fetch the latest keys
 - `client->Decrypt()` to decrypt an advertising token
 - `client->EncryptData()` to encrypt arbitrary data
 - `client->DecryptData()` to decrypt data encrypted with `EncryptData()`

Also see `app/example.cpp`.



cmake_minimum_required (VERSION 3.12)

project ("uid2-client")

set (CMAKE_CXX_STANDARD 11)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	if (NOT DEFINED OPENSSL_ROOT_DIR)
		set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
	endif()
endif()

add_subdirectory(lib)

add_subdirectory(app)

enable_testing()
add_subdirectory(test)

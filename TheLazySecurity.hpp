/*
    This file is part of TheLazySecurity.
    Copyright (C) 2020 ReimuNotMoe

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Apache License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#pragma once

#include <string>
#include <stdexcept>
#include <functional>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>

#include <unistd.h>
#include <fcntl.h>

#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>

#define __TLS_ERROR(func,ec)		TheLazySecurityException(func,ec)

namespace YukiWorkshop {
	class TheLazySecurityException : public std::exception {
	private:
		std::string errstr;
		int errnum;
	public:
		TheLazySecurityException(const std::string& __func_name, int __mbedtls_errnum);

		int code() const noexcept;

		virtual const char* what() const noexcept override;
	};
	class TheLazySecurity {
	private:
		mbedtls_ssl_cookie_ctx ctx_cookie;
		mbedtls_entropy_context ctx_entropy;
		mbedtls_ctr_drbg_context ctr_drbg;
		mbedtls_ssl_context ctx_ssl;
		mbedtls_ssl_config cfg_ssl;
		mbedtls_x509_crt cert_list;
		mbedtls_pk_context private_key;
		mbedtls_timing_delay_context ctx_timer;

		int transport = -1;

		static void __debug_print(void *ctx, int level, const char *file, int line, const char *str);

		static int __mcb_send(void *__userp, const uint8_t *__buf, size_t __len);

		static int __mcb_recv(void *__userp, uint8_t *__buf, size_t __len);

		static int __mcb_recv_timeout(void *__userp, uint8_t *__buf, size_t __len, uint32_t __timeout);

		void __init(int __role, int __transport, int __auth_mode);

	public:
		TheLazySecurity(int __role, int __transport, int __auth_mode) {
			transport = __transport;
			__init(__role, __transport, __auth_mode);
		}

		std::function<int(const uint8_t *, size_t)> callback_send;
		std::function<int(uint8_t *, size_t)> callback_recv;
		std::function<int(uint8_t *, size_t, uint32_t)> callback_recv_timeout;

		void set_mtu(uint16_t __mtu) {
			mbedtls_ssl_set_mtu(&ctx_ssl, __mtu);
		}

		void cert_parse(const uint8_t *__cert_data, size_t __cert_len) {
			int rc;
			if ((rc = mbedtls_x509_crt_parse(&cert_list, __cert_data, __cert_len)))
				throw __TLS_ERROR("mbedtls_ssl_config_defaults", rc);
		}

		void privkey_parse(const uint8_t *__pk_data, size_t __pk_len, const char *__pwd = nullptr, size_t __pwd_len = 0) {
			int rc;
			if ((rc = mbedtls_pk_parse_key(&private_key, __pk_data, __pk_len, (const uint8_t *)__pwd, __pwd_len)))
				throw __TLS_ERROR("mbedtls_pk_parse_key", rc);
		}

		void setup_certs() {
			int rc;
			mbedtls_ssl_conf_ca_chain(&cfg_ssl, &cert_list, nullptr); // TODO: crl
			if ((rc = mbedtls_ssl_conf_own_cert(&cfg_ssl, &cert_list, &private_key)))
				throw __TLS_ERROR("mbedtls_ssl_conf_own_cert", rc);
		}

		void setup_tls(const uint8_t *__transport_id, size_t __transport_id_len);

		int handshake() {
			return mbedtls_ssl_handshake(&ctx_ssl);
		}

		int read(uint8_t *__data, size_t __len) {
			return mbedtls_ssl_read(&ctx_ssl, __data, __len);
		}

		int write(const uint8_t *__data, size_t __len) {
			return mbedtls_ssl_write(&ctx_ssl, __data, __len);
		}

	};
}
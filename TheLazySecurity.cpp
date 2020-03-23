/*
    This file is part of TheLazySecurity.
    Copyright (C) 2020 ReimuNotMoe

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Apache License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#include "TheLazySecurity.hpp"

using namespace YukiWorkshop;

TheLazySecurityException::TheLazySecurityException(const std::string &__func_name, int __mbedtls_errnum) {
	errnum = __mbedtls_errnum;
	char buf[128];
	mbedtls_strerror(errnum, buf, 127);
	errstr = __func_name + ": " + buf;
}

int TheLazySecurityException::code() const noexcept {
	return errnum;
}

const char *TheLazySecurityException::what() const noexcept {
	return errstr.c_str();
}

void TheLazySecurity::__debug_print(void *ctx, int level, const char *file, int line, const char *str) {
	fprintf((FILE *)ctx, "[%d] %s:%04d: %s", level, file, line, str);
	fflush((FILE *)ctx);
}

int TheLazySecurity::__mcb_send(void *__userp, const uint8_t *__buf, size_t __len) {
	auto *ctx = (TheLazySecurity *)__userp;

	if (ctx->callback_send)
		return ctx->callback_send(__buf, __len);
	else
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;
}

int TheLazySecurity::__mcb_recv(void *__userp, uint8_t *__buf, size_t __len) {
	auto *ctx = (TheLazySecurity *)__userp;

	if (ctx->callback_recv)
		return ctx->callback_recv(__buf, __len);
	else
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;
}

int TheLazySecurity::__mcb_recv_timeout(void *__userp, uint8_t *__buf, size_t __len, uint32_t __timeout) {
	auto *ctx = (TheLazySecurity *)__userp;

	if (ctx->callback_recv_timeout)
		return ctx->callback_recv_timeout(__buf, __len, __timeout);
	else
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;
}

void TheLazySecurity::__init(int __role, int __transport, int __auth_mode) {
	mbedtls_ssl_init(&ctx_ssl);
	mbedtls_ssl_config_init(&cfg_ssl);
	mbedtls_x509_crt_init(&cert_list);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&ctx_entropy);


	int rc;

	if ((rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &ctx_entropy, nullptr, 0)))
		throw __TLS_ERROR("mbedtls_ctr_drbg_seed", rc);

	if ((rc = mbedtls_ssl_config_defaults(&cfg_ssl, __role, __transport, MBEDTLS_SSL_PRESET_DEFAULT)))
		throw __TLS_ERROR("mbedtls_ssl_config_defaults", rc);

	mbedtls_ssl_conf_authmode(&cfg_ssl, __auth_mode);
	mbedtls_ssl_conf_rng(&cfg_ssl, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_cookie_init(&ctx_cookie);

	if (__transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
		// TODO
	}

	if (__role == MBEDTLS_SSL_IS_SERVER) {
		mbedtls_pk_init(&private_key);
	}

	mbedtls_ssl_conf_dbg(&cfg_ssl, __debug_print, stderr);

}

void TheLazySecurity::setup_tls(const uint8_t *__transport_id, size_t __transport_id_len) {
	int rc;
	if (transport == MBEDTLS_SSL_TRANSPORT_STREAM) {
		if ((rc = mbedtls_ssl_cookie_setup(&ctx_cookie, mbedtls_ctr_drbg_random, &ctr_drbg)))
			throw __TLS_ERROR("mbedtls_ssl_cookie_setup", rc);
	} else if (transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
		mbedtls_ssl_conf_dtls_cookies(&cfg_ssl, mbedtls_ssl_cookie_write,
					      mbedtls_ssl_cookie_check, &ctx_cookie);
		mbedtls_ssl_set_timer_cb(&ctx_ssl, &ctx_timer, mbedtls_timing_set_delay,
					 mbedtls_timing_get_delay);
	}

	mbedtls_ssl_set_bio(&ctx_ssl, this, &TheLazySecurity::__mcb_send,
			    callback_recv ? &TheLazySecurity::__mcb_recv : nullptr,
			    callback_recv_timeout ? &TheLazySecurity::__mcb_recv_timeout : nullptr);

	if ((rc = mbedtls_ssl_setup(&ctx_ssl, &cfg_ssl)))
		throw __TLS_ERROR("mbedtls_ssl_setup", rc);


	if ((rc = mbedtls_ssl_set_client_transport_id(&ctx_ssl, __transport_id, __transport_id_len)))
		throw __TLS_ERROR("mbedtls_ssl_set_client_transport_id", rc);
}

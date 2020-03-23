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

int main() {
	int fd = open("/dev/ttyUSB0", O_RDWR);

	TheLazySecurity tls(MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_VERIFY_OPTIONAL);

	// TODO
	tls.callback_send = [&](const uint8_t *__data, size_t __size) {
		return 1;
	};

}
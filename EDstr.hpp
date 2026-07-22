/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * EDstr.hpp - Encryption and Decryption String C++ Header File
 * A comprehensive C++ cryptography library for CTF and educational purposes.
 *
 * Copyright (c) 2024 XDEVCPP
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------------------
 * 仓库地址: https://gitee.com/XDEVCPP/EDstr
 * 作者: XDEVCPP
 * 描述: 覆盖 80+ 种加密/解密/哈希算法的纯 C++ 头文件库，专为 CTF 竞赛设计。
 * ---------------------------------------------------------------------
 */
#include <time.h>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <stdint.h>
#include <stddef.h>
#include <cmath>
#include <random>
using namespace std;
namespace EDstr {
	const int N = 16;
	static const unsigned char AES_sbox[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
	static const unsigned char AES_rsbox[256] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
	static const unsigned int AES_Rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000};
	inline unsigned int AES_rotl(unsigned int x, unsigned char n) {
		return (x << n) | (x >> (32 - n));
	}
	inline unsigned int AES_rotr(unsigned int x, unsigned char n) {
		return (x >> n) | (x << (32 - n));
	}
	inline unsigned int AES_get_word(const unsigned char* p) {
		return ((unsigned int)(p[0]) << 24) | ((unsigned int)(p[1]) << 16) | ((unsigned int)(p[2]) << 8)  | (unsigned int)(p[3]);
	}
	inline void AES_put_word(unsigned char* p, unsigned int w) {
		p[0] = (unsigned char)(w >> 24);
		p[1] = (unsigned char)(w >> 16);
		p[2] = (unsigned char)(w >> 8);
		p[3] = (unsigned char)(w);
	}
	struct AES_ctx {
		unsigned int roundKey[60];
		unsigned char  Nr;
	};
	inline void AES_init_ctx(AES_ctx* ctx, const unsigned char* key, size_t keylen) {
		if (keylen != 16 && keylen != 24 && keylen != 32)
			throw std::runtime_error("Invalid AES key length");
		unsigned int* rk = ctx->roundKey;
		unsigned int temp;
		size_t i = 0;
		size_t Nk = keylen / 4;
		ctx->Nr = static_cast<unsigned char>(Nk + 6);
		for (; i < Nk; ++i)
			rk[i] = AES_get_word(key + 4 * i);
		for (; i < size_t(4 * (ctx->Nr + 1)); ++i) {
			temp = rk[i - 1];
			if (i % Nk == 0) {
				temp = AES_rotl(temp, 8);
				temp = ((unsigned int)(AES_sbox[(temp >> 24) & 0xFF]) << 24) |
				       ((unsigned int)(AES_sbox[(temp >> 16) & 0xFF]) << 16) |
				       ((unsigned int)(AES_sbox[(temp >> 8 ) & 0xFF]) << 8)  |
				       (unsigned int)(AES_sbox[(temp    ) & 0xFF]);
				temp ^= AES_Rcon[(i / Nk) - 1];
			} else if (Nk > 6 && (i % Nk) == 4) {
				temp = ((unsigned int)(AES_sbox[(temp >> 24) & 0xFF]) << 24) |
				       ((unsigned int)(AES_sbox[(temp >> 16) & 0xFF]) << 16) |
				       ((unsigned int)(AES_sbox[(temp >> 8 ) & 0xFF]) << 8)  |
				       (unsigned int)(AES_sbox[(temp    ) & 0xFF]);
			}
			rk[i] = rk[i - Nk] ^ temp;
		}
	}
	inline void AES_SubBytes(unsigned char state[4][4]) {
		for (int r = 0; r < 4; ++r)
			for (int c = 0; c < 4; ++c)
				state[r][c] = AES_sbox[state[r][c]];
	}
	inline void AES_InvSubBytes(unsigned char state[4][4]) {
		for (int r = 0; r < 4; ++r)
			for (int c = 0; c < 4; ++c)
				state[r][c] = AES_rsbox[state[r][c]];
	}
	inline void AES_ShiftRows(unsigned char s[4][4]) {
		unsigned char t;
		t = s[1][0];
		s[1][0] = s[1][1];
		s[1][1] = s[1][2];
		s[1][2] = s[1][3];
		s[1][3] = t;
		std::swap(s[2][0], s[2][2]);
		std::swap(s[2][1], s[2][3]);
		t = s[3][3];
		s[3][3] = s[3][2];
		s[3][2] = s[3][1];
		s[3][1] = s[3][0];
		s[3][0] = t;
	}
	inline void AES_InvShiftRows(unsigned char s[4][4]) {
		unsigned char t;
		t = s[1][3];
		s[1][3] = s[1][2];
		s[1][2] = s[1][1];
		s[1][1] = s[1][0];
		s[1][0] = t;
		std::swap(s[2][0], s[2][2]);
		std::swap(s[2][1], s[2][3]);
		t = s[3][0];
		s[3][0] = s[3][1];
		s[3][1] = s[3][2];
		s[3][2] = s[3][3];
		s[3][3] = t;
	}
	inline unsigned char AES_xtime(unsigned char x) {
		return (x << 1) ^ ((x >> 7) * 0x1B);
	}
	inline void AES_MixColumns(unsigned char s[4][4]) {
		for (int c = 0; c < 4; ++c) {
			unsigned char a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
			unsigned char t = a0 ^ a1 ^ a2 ^ a3;
			unsigned char u = a0;
			s[0][c] ^= t ^ AES_xtime(a0 ^ a1);
			s[1][c] ^= t ^ AES_xtime(a1 ^ a2);
			s[2][c] ^= t ^ AES_xtime(a2 ^ a3);
			s[3][c] ^= t ^ AES_xtime(a3 ^ u);
		}
	}
	inline unsigned char AES_mul(unsigned char a, unsigned char b) {
		unsigned char p = 0;
		for (int i = 0; i < 8; ++i) {
			if (b & 1) p ^= a;
			bool hi = a & 0x80;
			a <<= 1;
			if (hi) a ^= 0x1B;
			b >>= 1;
		}
		return p;
	}
	inline void AES_InvMixColumns(unsigned char s[4][4]) {
		for (int c = 0; c < 4; ++c) {
			unsigned char a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
			unsigned char b0 = AES_mul(a0, 0x0e) ^ AES_mul(a1, 0x0b) ^ AES_mul(a2, 0x0d) ^ AES_mul(a3, 0x09);
			unsigned char b1 = AES_mul(a0, 0x09) ^ AES_mul(a1, 0x0e) ^ AES_mul(a2, 0x0b) ^ AES_mul(a3, 0x0d);
			unsigned char b2 = AES_mul(a0, 0x0d) ^ AES_mul(a1, 0x09) ^ AES_mul(a2, 0x0e) ^ AES_mul(a3, 0x0b);
			unsigned char b3 = AES_mul(a0, 0x0b) ^ AES_mul(a1, 0x0d) ^ AES_mul(a2, 0x09) ^ AES_mul(a3, 0x0e);
			s[0][c] = b0;
			s[1][c] = b1;
			s[2][c] = b2;
			s[3][c] = b3;
		}
	}
	inline void AES_AddRoundKey(unsigned char state[4][4], const unsigned int* roundKey) {
		for (int c = 0; c < 4; ++c) {
			unsigned int rk = roundKey[c];
			state[0][c] ^= (rk >> 24) & 0xFF;
			state[1][c] ^= (rk >> 16) & 0xFF;
			state[2][c] ^= (rk >> 8 ) & 0xFF;
			state[3][c] ^=  rk      & 0xFF;
		}
	}
	inline void AES_ECB_encrypt(const AES_ctx* ctx, unsigned char* buf) {
		unsigned char state[4][4];
		for (int i = 0; i < 4; ++i)for (int j = 0; j < 4; ++j)state[j][i] = buf[i * 4 + j];
		const unsigned int* rk = ctx->roundKey;
		AES_AddRoundKey(state, rk);
		for (int round = 1; round < ctx->Nr; ++round) {
			AES_SubBytes(state);
			AES_ShiftRows(state);
			AES_MixColumns(state);
			AES_AddRoundKey(state, rk + 4 * round);
		}
		AES_SubBytes(state);
		AES_ShiftRows(state);
		AES_AddRoundKey(state, rk + 4 * ctx->Nr);
		for (int i = 0; i < 4; ++i)
			for (int j = 0; j < 4; ++j)
				buf[i * 4 + j] = state[j][i];
	}
	inline void AES_ECB_decrypt(const AES_ctx* ctx, unsigned char* buf) {
		unsigned char state[4][4];
		for (int i = 0; i < 4; ++i)
			for (int j = 0; j < 4; ++j)
				state[j][i] = buf[i * 4 + j];
		const unsigned int* rk = ctx->roundKey;
		AES_AddRoundKey(state, rk + 4 * ctx->Nr);
		for (int round = ctx->Nr - 1; round > 0; --round) {
			AES_InvShiftRows(state);
			AES_InvSubBytes(state);
			AES_AddRoundKey(state, rk + 4 * round);
			AES_InvMixColumns(state);
		}
		AES_InvShiftRows(state);
		AES_InvSubBytes(state);
		AES_AddRoundKey(state, rk);
		for (int i = 0; i < 4; ++i)
			for (int j = 0; j < 4; ++j)
				buf[i * 4 + j] = state[j][i];
	}
	inline void AES_ECB_encrypt_buffer(const AES_ctx* ctx, const unsigned char* in, unsigned char* out, size_t len) {
		if (len % 16 != 0) throw std::runtime_error("Length not multiple of 16");
		for (size_t i = 0; i < len; i += 16) {
			std::memcpy(out + i, in + i, 16);
			AES_ECB_encrypt(ctx, out + i);
		}
	}
	inline void AES_ECB_decrypt_buffer(const AES_ctx* ctx, const unsigned char* in, unsigned char* out, size_t len) {
		if (len % 16 != 0) throw std::runtime_error("Length not multiple of 16");
		for (size_t i = 0; i < len; i += 16) {
			std::memcpy(out + i, in + i, 16);
			AES_ECB_decrypt(ctx, out + i);
		}
	}
	std::string affine_encrypt(const std::string& txt, int a, int b) {
		std::string out;
		for (char c : txt) {
			if (std::isalpha(c)) {
				char base = std::isupper(c) ? 'A' : 'a';
				int x = std::toupper(c) - 'A';
				out += char((a * x + b) % 26 + base);
			} else out += c;
		}
		return out;
	}
	int affine_mod_inverse(int a) {
		for (int i = 1; i < 26; ++i)
			if ((a * i) % 26 == 1) return i;
		return -1;
	}
	std::string affine_decrypt(const std::string& txt, int a, int b) {
		int a_inv = affine_mod_inverse(a);
		if (a_inv == -1) return "";
		std::string out;
		for (char c : txt) {
			if (std::isalpha(c)) {
				char base = std::isupper(c) ? 'A' : 'a';
				int y = std::toupper(c) - 'A';
				out += char((a_inv * (y - b + 26)) % 26 + base);
			} else out += c;
		}
		return out;
	}
	constexpr size_t BLOCK_SIZE = 16;
	constexpr size_t ROUNDS_128 = 12;
	constexpr size_t ROUNDS_192 = 14;
	constexpr size_t ROUNDS_256 = 16;
	constexpr unsigned char aria_SBOX1[] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};
	constexpr unsigned char aria_SBOX2[] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};
	constexpr unsigned char aria_INV_SBOX1[] = {
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
	};
	constexpr unsigned char aria_INV_SBOX2[] = {
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
	};
	constexpr unsigned int aria_RCON[] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000};
	inline unsigned char aria_xtime(unsigned char b) {
		return (b << 1) ^ ((b & 0x80) ? 0x1B : 0x00);
	}
	inline unsigned char aria_mul(unsigned char a, unsigned char b) {
		unsigned char res = 0;
		for (int i = 0; i < 8; ++i) {
			if (b & 1) res ^= a;
			unsigned char carry = a & 0x80;
			a <<= 1;
			if (carry) a ^= 0x1B;
			b >>= 1;
		}
		return res;
	}
	void aria_subuint8_ts1(std::vector<unsigned char>& state) {
		for (size_t i = 0; i < state.size(); ++i) state[i] = aria_SBOX1[state[i]];
	}
	void aria_subuint8_ts2(std::vector<unsigned char>& state) {
		for (size_t i = 0; i < state.size(); ++i) state[i] = aria_SBOX2[state[i]];
	}
	void aria_invSubuint8_ts1(std::vector<unsigned char>& state) {
		for (size_t i = 0; i < state.size(); ++i) state[i] = aria_INV_SBOX1[state[i]];
	}
	void aria_invSubuint8_ts2(std::vector<unsigned char>& state) {
		for (size_t i = 0; i < state.size(); ++i) state[i] = aria_INV_SBOX2[state[i]];
	}
	void aria_shiftRows(std::vector<unsigned char>& state) {
		unsigned char temp;
		temp = state[1];
		state[1] = state[5];
		state[5] = state[9];
		state[9] = state[13];
		state[13] = temp;
		temp = state[2];
		state[2] = state[10];
		state[10] = temp;
		temp = state[6];
		state[6] = state[14];
		state[14] = temp;
		temp = state[15];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = state[3];
		state[3] = temp;
	}
	void aria_invShiftRows(std::vector<unsigned char>& state) {
		unsigned char temp;
		temp = state[13];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = state[1];
		state[1] = temp;
		temp = state[10];
		state[10] = state[2];
		state[2] = temp;
		temp = state[14];
		state[14] = state[6];
		state[6] = temp;
		temp = state[3];
		state[3] = state[7];
		state[7] = state[11];
		state[11] = state[15];
		state[15] = temp;
	}
	void aria_mixColumns(std::vector<unsigned char>& state) {
		for (size_t c = 0; c < 4; ++c) {
			unsigned char col[4] = {state[c], state[c + 4], state[c + 8], state[c + 12]};
			state[c] = aria_xtime(col[0]) ^ col[1] ^ col[2] ^ col[3] ^ aria_xtime(col[1]);
			state[c + 4] = col[0] ^ aria_xtime(col[1]) ^ col[2] ^ col[3] ^ aria_xtime(col[2]);
			state[c + 8] = col[0] ^ col[1] ^ aria_xtime(col[2]) ^ col[3] ^ aria_xtime(col[3]);
			state[c + 12] = col[0] ^ col[1] ^ col[2] ^ aria_xtime(col[3]) ^ aria_xtime(col[0]);
		}
	}
	void aria_invMixColumns(std::vector<unsigned char>& state) {
		for (size_t c = 0; c < 4; ++c) {
			unsigned char col[4] = {state[c], state[c + 4], state[c + 8], state[c + 12]};
			state[c] = aria_mul(col[0], 0x0E) ^ aria_mul(col[1], 0x0B) ^ aria_mul(col[2], 0x0D) ^ aria_mul(col[3], 0x09);
			state[c + 4] = aria_mul(col[0], 0x09) ^ aria_mul(col[1], 0x0E) ^ aria_mul(col[2], 0x0B) ^ aria_mul(col[3], 0x0D);
			state[c + 8] = aria_mul(col[0], 0x0D) ^ aria_mul(col[1], 0x09) ^ aria_mul(col[2], 0x0E) ^ aria_mul(col[3], 0x0B);
			state[c + 12] = aria_mul(col[0], 0x0B) ^ aria_mul(col[1], 0x0D) ^ aria_mul(col[2], 0x09) ^ aria_mul(col[3], 0x0E);
		}
	}
	void aria_addRoundKey(std::vector<unsigned char>& state, const std::vector<unsigned int>& roundKeys, size_t round) {
		for (size_t r = 0; r < 4; ++r) {
			unsigned int key = roundKeys[round * 4 + r];
			state[r] ^= (key >> 24) & 0xFF;
			state[r + 4] ^= (key >> 16) & 0xFF;
			state[r + 8] ^= (key >> 8) & 0xFF;
			state[r + 12] ^= key & 0xFF;
		}
	}
	unsigned int aria_subuint32_t(unsigned int word, bool useSBOX2) {
		unsigned char b[4] = {(unsigned char)((unsigned int)(word >> 24) & (unsigned int)(0xFF)), (unsigned char)((unsigned int)(word >> 16) & (unsigned int)(0xFF)), (unsigned char)((unsigned int)(word >> 8) & (unsigned int)(0xFF)), (unsigned char)((unsigned int)(word) & (unsigned int)(0xFF))};
		if (useSBOX2) {
			b[0] = aria_SBOX2[b[0]];
			b[1] = aria_SBOX2[b[1]];
			b[2] = aria_SBOX2[b[2]];
			b[3] = aria_SBOX2[b[3]];
		} else {
			b[0] = aria_SBOX1[b[0]];
			b[1] = aria_SBOX1[b[1]];
			b[2] = aria_SBOX1[b[2]];
			b[3] = aria_SBOX1[b[3]];
		}
		return (static_cast<unsigned int>(b[0]) << 24) | (static_cast<unsigned int>(b[1]) << 16) | (static_cast<unsigned int>(b[2]) << 8) | static_cast<unsigned int>(b[3]);
	}
	unsigned int aria_rotuint32_t(unsigned int word) {
		return (word << 8) | (word >> 24);
	}
	std::vector<unsigned int> aria_keyExpansion(const std::vector<unsigned char>& key) {
		size_t Nk = key.size() / 4;
		size_t Nr = (Nk == 4) ? ROUNDS_128 : (Nk == 6) ? ROUNDS_192 : (Nk == 8) ? ROUNDS_256 : throw std::invalid_argument("Invalid key size");
		std::vector<unsigned int> w((Nr + 1) * 4, 0);
		for (size_t i = 0; i < Nk; ++i) {
			w[i] = (static_cast<unsigned int>(key[4 * i]) << 24) | (static_cast<unsigned int>(key[4 * i + 1]) << 16) | (static_cast<unsigned int>(key[4 * i + 2]) << 8) | static_cast<unsigned int>(key[4 * i + 3]);
		}
		for (size_t i = Nk; i < (Nr + 1) * 4; ++i) {
			unsigned int temp = w[i - 1];
			if (i % Nk == 0) {
				bool useSBOX2 = (Nr == ROUNDS_256) ? (i / Nk % 2 == 0) : false;
				temp = aria_subuint32_t(aria_rotuint32_t(temp), useSBOX2) ^ aria_RCON[i / Nk - 1];
			} else if (Nk > 6 && i % Nk == 4) {
				temp = aria_subuint32_t(temp, true);
			}
			w[i] = w[i - Nk] ^ temp;
		}
		return w;
	}
	void aria_encryptBlock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned int>& roundKeys) {
		out = in;
		size_t Nr = (roundKeys.size() / 4) - 1;
		aria_addRoundKey(out, roundKeys, 0);
		for (size_t round = 1; round < Nr; ++round) {
			if (Nr == ROUNDS_256) {
				(round % 2 == 0) ? aria_subuint8_ts2(out) : aria_subuint8_ts1(out);
			} else {
				aria_subuint8_ts1(out);
			}
			aria_shiftRows(out);
			aria_mixColumns(out);
			aria_addRoundKey(out, roundKeys, round);
		}
		(Nr == ROUNDS_256) ? aria_subuint8_ts2(out) : aria_subuint8_ts1(out);
		aria_shiftRows(out);
		aria_addRoundKey(out, roundKeys, Nr);
	}
	void aria_decryptBlock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned int>& roundKeys) {
		out = in;
		size_t Nr = (roundKeys.size() / 4) - 1;
		aria_addRoundKey(out, roundKeys, Nr);
		for (size_t round = Nr - 1; round > 0; --round) {
			aria_invShiftRows(out);
			if (Nr == ROUNDS_256) {
				(round % 2 == 0) ? aria_invSubuint8_ts2(out) : aria_invSubuint8_ts1(out);
			} else {
				aria_invSubuint8_ts1(out);
			}
			aria_addRoundKey(out, roundKeys, round);
			aria_invMixColumns(out);
		}
		aria_invShiftRows(out);
		(Nr == ROUNDS_256) ? aria_invSubuint8_ts2(out) : aria_invSubuint8_ts1(out);
		aria_addRoundKey(out, roundKeys, 0);
	}
	std::vector<unsigned char> aria_encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
		if (key.size() != 16 && key.size() != 24 && key.size() != 32) throw std::invalid_argument("Key must be 16/24/32 bytes");
		std::vector<unsigned char> ciphertext;
		std::vector<unsigned int> roundKeys = aria_keyExpansion(key);
		size_t numBlocks = (plaintext.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
		for (size_t i = 0; i < numBlocks; ++i) {
			std::vector<unsigned char> block(BLOCK_SIZE, 0);
			size_t start = i * BLOCK_SIZE;
			size_t len = std::min(BLOCK_SIZE, plaintext.size() - start);
			std::copy_n(plaintext.begin() + start, len, block.begin());
			std::vector<unsigned char> encryptedBlock;
			aria_encryptBlock(block, encryptedBlock, roundKeys);
			ciphertext.insert(ciphertext.end(), encryptedBlock.begin(), encryptedBlock.end());
		}
		return ciphertext;
	}
	std::vector<unsigned char> aria_decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
		if (key.size() != 16 && key.size() != 24 && key.size() != 32) throw std::invalid_argument("Key must be 16/24/32 bytes");
		if (ciphertext.size() % BLOCK_SIZE != 0) throw std::invalid_argument("Ciphertext length must be multiple of block size");
		std::vector<unsigned char> plaintext;
		std::vector<unsigned int> roundKeys = aria_keyExpansion(key);
		size_t numBlocks = ciphertext.size() / BLOCK_SIZE;
		for (size_t i = 0; i < numBlocks; ++i) {
			std::vector<unsigned char> block(ciphertext.begin() + i * BLOCK_SIZE, ciphertext.begin() + (i + 1) * BLOCK_SIZE);
			std::vector<unsigned char> decryptedBlock;
			aria_decryptBlock(block, decryptedBlock, roundKeys);
			plaintext.insert(plaintext.end(), decryptedBlock.begin(), decryptedBlock.end());
		}
		return plaintext;
	}
	std::string bacon_encrypt(const std::string& txt) {
		const char* map[26] = {
			"AAAAA", "AAAAB", "AAABA", "AAABB", "AABAA", "AABAB", "AABBA", "AABBB",
			"ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "ABBBB",
			"BAAAA", "BAAAB", "BAABA", "BAABB", "BABAA", "BABAB", "BABBA", "BABBB",
			"BBAAA", "BBAAB"
		};
		std::string out;
		for (char c : txt) {
			if (std::isalpha(c)) {
				out += map[std::toupper(c) - 'A'];
			}
		}
		return out;
	}
	std::string bacon_decrypt(const std::string& cipher) {
		static const std::unordered_map<std::string, char> rev = [] {
			std::unordered_map<std::string, char> m;
			const char* map[26] = {
				"AAAAA", "AAAAB", "AAABA", "AAABB", "AABAA", "AABAB", "AABBA", "AABBB",
				"ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "ABBBB",
				"BAAAA", "BAAAB", "BAABA", "BAABB", "BABAA", "BABAB", "BABBA", "BABBB",
				"BBAAA", "BBAAB"
			};
			for (int i = 0; i < 26; ++i) m[map[i]] = 'A' + i;
			return m;
		}();
		std::string out;
		for (size_t i = 0; i + 5 <= cipher.size(); i += 5) {
			std::string block = cipher.substr(i, 5);
			auto it = rev.find(block);
			if (it != rev.end()) out += it->second;
		}
		return out;
	}
	static const unsigned long blowfish_ORIG_P[16 + 2] = {0x243F6A88L, 0x85A308D3L, 0x13198A2EL, 0x03707344L, 0xA4093822L, 0x299F31D0L, 0x082EFA98L, 0xEC4E6C89L, 0x452821E6L, 0x38D01377L, 0xBE5466CFL, 0x34E90C6CL, 0xC0AC29B7L, 0xC97C50DDL, 0x3F84D5B5L, 0xB5470917L, 0x9216D5D9L, 0x8979FB1BL};
	static const unsigned long blowfish_ORIG_S[4][256] = {{0xD1310BA6L, 0x98DFB5ACL, 0x2FFD72DBL, 0xD01ADFB7L, 0xB8E1AFEDL, 0x6A267E96L, 0xBA7C9045L, 0xF12C7F99L, 0x24A19947L, 0xB3916CF7L, 0x0801F2E2L, 0x858EFC16L, 0x636920D8L, 0x71574E69L, 0xA458FEA3L, 0xF4933D7EL, 0x0D95748FL, 0x728EB658L, 0x718BCD58L, 0x82154AEEL, 0x7B54A41DL, 0xC25A59B5L, 0x9C30D539L, 0x2AF26013L, 0xC5D1B023L, 0x286085F0L, 0xCA417918L, 0xB8DB38EFL, 0x8E79DCB0L, 0x603A180EL, 0x6C9E0E8BL, 0xB01E8A3EL, 0xD71577C1L, 0xBD314B27L, 0x78AF2FDAL, 0x55605C60L, 0xE65525F3L, 0xAA55AB94L, 0x57489862L, 0x63E81440L, 0x55CA396AL, 0x2AAB10B6L, 0xB4CC5C34L, 0x1141E8CEL, 0xA15486AFL, 0x7C72E993L, 0xB3EE1411L, 0x636FBC2AL, 0x2BA9C55DL, 0x741831F6L, 0xCE5C3E16L, 0x9B87931EL, 0xAFD6BA33L, 0x6C24CF5CL, 0x7A325381L, 0x28958677L, 0x3B8F4898L, 0x6B4BB9AFL, 0xC4BFE81BL, 0x66282193L, 0x61D809CCL, 0xFB21A991L, 0x487CAC60L, 0x5DEC8032L, 0xEF845D5DL, 0xE98575B1L, 0xDC262302L, 0xEB651B88L, 0x23893E81L, 0xD396ACC5L, 0x0F6D6FF3L, 0x83F44239L, 0x2E0B4482L, 0xA4842004L, 0x69C8F04AL, 0x9E1F9B5EL, 0x21C66842L, 0xF6E96C9AL, 0x670C9C61L, 0xABD388F0L, 0x6A51A0D2L, 0xD8542F68L, 0x960FA728L, 0xAB5133A3L, 0x6EEF0B6CL, 0x137A3BE4L, 0xBA3BF050L, 0x7EFB2A98L, 0xA1F1651DL, 0x39AF0176L, 0x66CA593EL, 0x82430E88L, 0x8CEE8619L, 0x456F9FB4L, 0x7D84A5C3L, 0x3B8B5EBEL, 0xE06F75D8L, 0x85C12073L, 0x401A449FL, 0x56C16AA6L, 0x4ED3AA62L, 0x363F7706L, 0x1BFEDF72L, 0x429B023DL, 0x37D0D724L, 0xD00A1248L, 0xDB0FEAD3L, 0x49F1C09BL, 0x075372C9L, 0x80991B7BL, 0x25D479D8L, 0xF6E8DEF7L, 0xE3FE501AL, 0xB6794C3BL, 0x976CE0BDL, 0x04C006BAL, 0xC1A94FB6L, 0x409F60C4L, 0x5E5C9EC2L, 0x196A2463L, 0x68FB6FAFL, 0x3E6C53B5L, 0x1339B2EBL, 0x3B52EC6FL, 0x6DFC511FL, 0x9B30952CL, 0xCC814544L, 0xAF5EBD09L, 0xBEE3D004L, 0xDE334AFDL, 0x660F2807L, 0x192E4BB3L, 0xC0CBA857L, 0x45C8740FL, 0xD20B5F39L, 0xB9D3FBDBL, 0x5579C0BDL, 0x1A60320AL, 0xD6A100C6L, 0x402C7279L, 0x679F25FEL, 0xFB1FA3CCL, 0x8EA5E9F8L, 0xDB3222F8L, 0x3C7516DFL, 0xFD616B15L, 0x2F501EC8L, 0xAD0552ABL, 0x323DB5FAL, 0xFD238760L, 0x53317B48L, 0x3E00DF82L, 0x9E5C57BBL, 0xCA6F8CA0L, 0x1A87562EL, 0xDF1769DBL, 0xD542A8F6L, 0x287EFFC3L, 0xAC6732C6L, 0x8C4F5573L, 0x695B27B0L, 0xBBCA58C8L, 0xE1FFA35DL, 0xB8F011A0L, 0x10FA3D98L, 0xFD2183B8L, 0x4AFCB56CL, 0x2DD1D35BL, 0x9A53E479L, 0xB6F84565L, 0xD28E49BCL, 0x4BFB9790L, 0xE1DDF2DAL, 0xA4CB7E33L, 0x62FB1341L, 0xCEE4C6E8L, 0xEF20CADAL, 0x36774C01L, 0xD07E9EFEL, 0x2BF11FB4L, 0x95DBDA4DL, 0xAE909198L, 0xEAAD8E71L, 0x6B93D5A0L, 0xD08ED1D0L, 0xAFC725E0L, 0x8E3C5B2FL, 0x8E7594B7L, 0x8FF6E2FBL, 0xF2122B64L, 0x8888B812L, 0x900DF01CL, 0x4FAD5EA0L, 0x688FC31CL, 0xD1CFF191L, 0xB3A8C1ADL, 0x2F2F2218L, 0xBE0E1777L, 0xEA752DFEL, 0x8B021FA1L, 0xE5A0CC0FL, 0xB56F74E8L, 0x18ACF3D6L, 0xCE89E299L, 0xB4A84FE0L, 0xFD13E0B7L, 0x7CC43B81L, 0xD2ADA8D9L, 0x165FA266L, 0x80957705L, 0x93CC7314L, 0x211A1477L, 0xE6AD2065L, 0x77B5FA86L, 0xC75442F5L, 0xFB9D35CFL, 0xEBCDAF0CL, 0x7B3E89A0L, 0xD6411BD3L, 0xAE1E7E49L, 0x00250E2DL, 0x2071B35EL, 0x226800BBL, 0x57B8E0AFL, 0x2464369BL, 0xF009B91EL, 0x5563911DL, 0x59DFA6AAL, 0x78C14389L, 0xD95A537FL, 0x207D5BA2L, 0x02E5B9C5L, 0x83260376L, 0x6295CFA9L, 0x11C81968L, 0x4E734A41L, 0xB3472DCAL, 0x7B14A94AL, 0x1B510052L, 0x9A532915L, 0xD60F573FL, 0xBC9BC6E4L, 0x2B60A476L, 0x81E67400L, 0x08BA6FB5L, 0x571BE91FL, 0xF296EC6BL, 0x2A0DD915L, 0xB6636521L, 0xE7B9F9B6L, 0xFF34052EL, 0xC5855664L, 0x53B02D5DL, 0xA99F8FA1L, 0x08BA4799L, 0x6E85076AL}, {0x4B7A70E9L, 0xB5B32944L, 0xDB75092EL, 0xC4192623L, 0xAD6EA6B0L, 0x49A7DF7DL, 0x9CEE60B8L, 0x8FEDB266L, 0xECAA8C71L, 0x699A17FFL, 0x5664526CL, 0xC2B19EE1L, 0x193602A5L, 0x75094C29L, 0xA0591340L, 0xE4183A3EL, 0x3F54989AL, 0x5B429D65L, 0x6B8FE4D6L, 0x99F73FD6L, 0xA1D29C07L, 0xEFE830F5L, 0x4D2D38E6L, 0xF0255DC1L, 0x4CDD2086L, 0x8470EB26L, 0x6382E9C6L, 0x021ECC5EL, 0x09686B3FL, 0x3EBAEFC9L, 0x3C971814L, 0x6B6A70A1L, 0x687F3584L, 0x52A0E286L, 0xB79C5305L, 0xAA500737L, 0x3E07841CL, 0x7FDEAE5CL, 0x8E7D44ECL, 0x5716F2B8L, 0xB03ADA37L, 0xF0500C0DL, 0xF01C1F04L, 0x0200B3FFL, 0xAE0CF51AL, 0x3CB574B2L, 0x25837A58L, 0xDC0921BDL, 0xD19113F9L, 0x7CA92FF6L, 0x94324773L, 0x22F54701L, 0x3AE5E581L, 0x37C2DADCL, 0xC8B57634L, 0x9AF3DDA7L, 0xA9446146L, 0x0FD0030EL, 0xECC8C73EL, 0xA4751E41L, 0xE238CD99L, 0x3BEA0E2FL, 0x3280BBA1L, 0x183EB331L, 0x4E548B38L, 0x4F6DB908L, 0x6F420D03L, 0xF60A04BFL, 0x2CB81290L, 0x24977C79L, 0x5679B072L, 0xBCAF89AFL, 0xDE9A771FL, 0xD9930810L, 0xB38BAE12L, 0xDCCF3F2EL, 0x5512721FL, 0x2E6B7124L, 0x501ADDE6L, 0x9F84CD87L, 0x7A584718L, 0x7408DA17L, 0xBC9F9ABCL, 0xE94B7D8CL, 0xEC7AEC3AL, 0xDB851DFAL, 0x63094366L, 0xC464C3D2L, 0xEF1C1847L, 0x3215D908L, 0xDD433B37L, 0x24C2BA16L, 0x12A14D43L, 0x2A65C451L, 0x50940002L, 0x133AE4DDL, 0x71DFF89EL, 0x10314E55L, 0x81AC77D6L, 0x5F11199BL, 0x043556F1L, 0xD7A3C76BL, 0x3C11183BL, 0x5924A509L, 0xF28FE6EDL, 0x97F1FBFAL, 0x9EBABF2CL, 0x1E153C6EL, 0x86E34570L, 0xEAE96FB1L, 0x860E5E0AL, 0x5A3E2AB3L, 0x771FE71CL, 0x4E3D06FAL, 0x2965DCB9L, 0x99E71D0FL, 0x803E89D6L, 0x5266C825L, 0x2E4CC978L, 0x9C10B36AL, 0xC6150EBAL, 0x94E2EA78L, 0xA5FC3C53L, 0x1E0A2DF4L, 0xF2F74EA7L, 0x361D2B3DL, 0x1939260FL, 0x19C27960L, 0x5223A708L, 0xF71312B6L, 0xEBADFE6EL, 0xEAC31F66L, 0xE3BC4595L, 0xA67BC883L, 0xB17F37D1L, 0x018CFF28L, 0xC332DDEFL, 0xBE6C5AA5L, 0x65582185L, 0x68AB9802L, 0xEECEA50FL, 0xDB2F953BL, 0x2AEF7DADL, 0x5B6E2F84L, 0x1521B628L, 0x29076170L, 0xECDD4775L, 0x619F1510L, 0x13CCA830L, 0xEB61BD96L, 0x0334FE1EL, 0xAA0363CFL, 0xB5735C90L, 0x4C70A239L, 0xD59E9E0BL, 0xCBAADE14L, 0xEECC86BCL, 0x60622CA7L, 0x9CAB5CABL, 0xB2F3846EL, 0x648B1EAFL, 0x19BDF0CAL, 0xA02369B9L, 0x655ABB50L, 0x40685A32L, 0x3C2AB4B3L, 0x319EE9D5L, 0xC021B8F7L, 0x9B540B19L, 0x875FA099L, 0x95F7997EL, 0x623D7DA8L, 0xF837889AL, 0x97E32D77L, 0x11ED935FL, 0x16681281L, 0x0E358829L, 0xC7E61FD6L, 0x96DEDFA1L, 0x7858BA99L, 0x57F584A5L, 0x1B227263L, 0x9B83C3FFL, 0x1AC24696L, 0xCDB30AEBL, 0x532E3054L, 0x8FD948E4L, 0x6DBC3128L, 0x58EBF2EFL, 0x34C6FFEAL, 0xFE28ED61L, 0xEE7C3C73L, 0x5D4A14D9L, 0xE864B7E3L, 0x42105D14L, 0x203E13E0L, 0x45EEE2B6L, 0xA3AAABEAL, 0xDB6C4F15L, 0xFACB4FD0L, 0xC742F442L, 0xEF6ABBB5L, 0x654F3B1DL, 0x41CD2105L, 0xD81E799EL, 0x86854DC7L, 0xE44B476AL, 0x3D816250L, 0xCF62A1F2L, 0x5B8D2646L, 0xFC8883A0L, 0xC1C7B6A3L, 0x7F1524C3L, 0x69CB7492L, 0x47848A0BL, 0x5692B285L, 0x095BBF00L, 0xAD19489DL, 0x1462B174L, 0x23820E00L, 0x58428D2AL, 0x0C55F5EAL, 0x1DADF43EL, 0x233F7061L, 0x3372F092L, 0x8D937E41L, 0xD65FECF1L, 0x6C223BDBL, 0x7CDE3759L, 0xCBEE7460L, 0x4085F2A7L, 0xCE77326EL, 0xA6078084L, 0x19F8509EL, 0xE8EFD855L, 0x61D99735L, 0xA969A7AAL, 0xC50C06C2L, 0x5A04ABFCL, 0x800BCADCL, 0x9E447A2EL, 0xC3453484L, 0xFDD56705L, 0x0E1E9EC9L, 0xDB73DBD3L, 0x105588CDL, 0x675FDA79L, 0xE3674340L, 0xC5C43465L, 0x713E38D8L, 0x3D28F89EL, 0xF16DFF20L, 0x153E21E7L, 0x8FB03D4AL, 0xE6E39F2BL, 0xDB83ADF7L}, {0xE93D5A68L, 0x948140F7L, 0xF64C261CL, 0x94692934L, 0x411520F7L, 0x7602D4F7L, 0xBCF46B2EL, 0xD4A20068L, 0xD4082471L, 0x3320F46AL, 0x43B7D4B7L, 0x500061AFL, 0x1E39F62EL, 0x97244546L, 0x14214F74L, 0xBF8B8840L, 0x4D95FC1DL, 0x96B591AFL, 0x70F4DDD3L, 0x66A02F45L, 0xBFBC09ECL, 0x03BD9785L, 0x7FAC6DD0L, 0x31CB8504L, 0x96EB27B3L, 0x55FD3941L, 0xDA2547E6L, 0xABCA0A9AL, 0x28507825L, 0x530429F4L, 0x0A2C86DAL, 0xE9B66DFBL, 0x68DC1462L, 0xD7486900L, 0x680EC0A4L, 0x27A18DEEL, 0x4F3FFEA2L, 0xE887AD8CL, 0xB58CE006L, 0x7AF4D6B6L, 0xAACE1E7CL, 0xD3375FECL, 0xCE78A399L, 0x406B2A42L, 0x20FE9E35L, 0xD9F385B9L, 0xEE39D7ABL, 0x3B124E8BL, 0x1DC9FAF7L, 0x4B6D1856L, 0x26A36631L, 0xEAE397B2L, 0x3A6EFA74L, 0xDD5B4332L, 0x6841E7F7L, 0xCA7820FBL, 0xFB0AF54EL, 0xD8FEB397L, 0x454056ACL, 0xBA489527L, 0x55533A3AL, 0x20838D87L, 0xFE6BA9B7L, 0xD096954BL, 0x55A867BCL, 0xA1159A58L, 0xCCA92963L, 0x99E1DB33L, 0xA62A4A56L, 0x3F3125F9L, 0x5EF47E1CL, 0x9029317CL, 0xFDF8E802L, 0x04272F70L, 0x80BB155CL, 0x05282CE3L, 0x95C11548L, 0xE4C66D22L, 0x48C1133FL, 0xC70F86DCL, 0x07F9C9EEL, 0x41041F0FL, 0x404779A4L, 0x5D886E17L, 0x325F51EBL, 0xD59BC0D1L, 0xF2BCC18FL, 0x41113564L, 0x257B7834L, 0x602A9C60L, 0xDFF8E8A3L, 0x1F636C1BL, 0x0E12B4C2L, 0x02E1329EL, 0xAF664FD1L, 0xCAD18115L, 0x6B2395E0L, 0x333E92E1L, 0x3B240B62L, 0xEEBEB922L, 0x85B2A20EL, 0xE6BA0D99L, 0xDE720C8CL, 0x2DA2F728L, 0xD0127845L, 0x95B794FDL, 0x647D0862L, 0xE7CCF5F0L, 0x5449A36FL, 0x877D48FAL, 0xC39DFD27L, 0xF33E8D1EL, 0x0A476341L, 0x992EFF74L, 0x3A6F6EABL, 0xF4F8FD37L, 0xA812DC60L, 0xA1EBDDF8L, 0x991BE14CL, 0xDB6E6B0DL, 0xC67B5510L, 0x6D672C37L, 0x2765D43BL, 0xDCD0E804L, 0xF1290DC7L, 0xCC00FFA3L, 0xB5390F92L, 0x690FED0BL, 0x667B9FFBL, 0xCEDB7D9CL, 0xA091CF0BL, 0xD9155EA3L, 0xBB132F88L, 0x515BAD24L, 0x7B9479BFL, 0x763BD6EBL, 0x37392EB3L, 0xCC115979L, 0x8026E297L, 0xF42E312DL, 0x6842ADA7L, 0xC66A2B3BL, 0x12754CCCL, 0x782EF11CL, 0x6A124237L, 0xB79251E7L, 0x06A1BBE6L, 0x4BFB6350L, 0x1A6B1018L, 0x11CAEDFAL, 0x3D25BDD8L, 0xE2E1C3C9L, 0x44421659L, 0x0A121386L, 0xD90CEC6EL, 0xD5ABEA2AL, 0x64AF674EL, 0xDA86A85FL, 0xBEBFE988L, 0x64E4C3FEL, 0x9DBC8057L, 0xF0F7C086L, 0x60787BF8L, 0x6003604DL, 0xD1FD8346L, 0xF6381FB0L, 0x7745AE04L, 0xD736FCCCL, 0x83426B33L, 0xF01EAB71L, 0xB0804187L, 0x3C005E5FL, 0x77A057BEL, 0xBDE8AE24L, 0x55464299L, 0xBF582E61L, 0x4E58F48FL, 0xF2DDFDA2L, 0xF474EF38L, 0x8789BDC2L, 0x5366F9C3L, 0xC8B38E74L, 0xB475F255L, 0x46FCD9B9L, 0x7AEB2661L, 0x8B1DDF84L, 0x846A0E79L, 0x915F95E2L, 0x466E598EL, 0x20B45770L, 0x8CD55591L, 0xC902DE4CL, 0xB90BACE1L, 0xBB8205D0L, 0x11A86248L, 0x7574A99EL, 0xB77F19B6L, 0xE0A9DC09L, 0x662D09A1L, 0xC4324633L, 0xE85A1F02L, 0x09F0BE8CL, 0x4A99A025L, 0x1D6EFE10L, 0x1AB93D1DL, 0x0BA5A4DFL, 0xA186F20FL, 0x2868F169L, 0xDCB7DA83L, 0x573906FEL, 0xA1E2CE9BL, 0x4FCD7F52L, 0x50115E01L, 0xA70683FAL, 0xA002B5C4L, 0x0DE6D027L, 0x9AF88C27L, 0x773F8641L, 0xC3604C06L, 0x61A806B5L, 0xF0177A28L, 0xC0F586E0L, 0x006058AAL, 0x30DC7D62L, 0x11E69ED7L, 0x2338EA63L, 0x53C2DD94L, 0xC2C21634L, 0xBBCBEE56L, 0x90BCB6DEL, 0xEBFC7DA1L, 0xCE591D76L, 0x6F05E409L, 0x4B7C0188L, 0x39720A3DL, 0x7C927C24L, 0x86E3725FL, 0x724D9DB9L, 0x1AC15BB4L, 0xD39EB8FCL, 0xED545578L, 0x08FCA5B5L, 0xD83D7CD3L, 0x4DAD0FC4L, 0x1E50EF5EL, 0xB161E6F8L, 0xA28514D9L, 0x6C51133CL, 0x6FD5C7E7L, 0x56E14EC4L, 0x362ABFCEL, 0xDDC6C837L, 0xD79A3234L, 0x92638212L, 0x670EFA8EL, 0x406000E0L}, {0x3A39CE37L, 0xD3FAF5CFL, 0xABC27737L, 0x5AC52D1BL, 0x5CB0679EL, 0x4FA33742L, 0xD3822740L, 0x99BC9BBEL, 0xD5118E9DL, 0xBF0F7315L, 0xD62D1C7EL, 0xC700C47BL, 0xB78C1B6BL, 0x21A19045L, 0xB26EB1BEL, 0x6A366EB4L, 0x5748AB2FL, 0xBC946E79L, 0xC6A376D2L, 0x6549C2C8L, 0x530FF8EEL, 0x468DDE7DL, 0xD5730A1DL, 0x4CD04DC6L, 0x2939BBDBL, 0xA9BA4650L, 0xAC9526E8L, 0xBE5EE304L, 0xA1FAD5F0L, 0x6A2D519AL, 0x63EF8CE2L, 0x9A86EE22L, 0xC089C2B8L, 0x43242EF6L, 0xA51E03AAL, 0x9CF2D0A4L, 0x83C061BAL, 0x9BE96A4DL, 0x8FE51550L, 0xBA645BD6L, 0x2826A2F9L, 0xA73A3AE1L, 0x4BA99586L, 0xEF5562E9L, 0xC72FEFD3L, 0xF752F7DAL, 0x3F046F69L, 0x77FA0A59L, 0x80E4A915L, 0x87B08601L, 0x9B09E6ADL, 0x3B3EE593L, 0xE990FD5AL, 0x9E34D797L, 0x2CF0B7D9L, 0x022B8B51L, 0x96D5AC3AL, 0x017DA67DL, 0xD1CF3ED6L, 0x7C7D2D28L, 0x1F9F25CFL, 0xADF2B89BL, 0x5AD6B472L, 0x5A88F54CL, 0xE029AC71L, 0xE019A5E6L, 0x47B0ACFDL, 0xED93FA9BL, 0xE8D3C48DL, 0x283B57CCL, 0xF8D56629L, 0x79132E28L, 0x785F0191L, 0xED756055L, 0xF7960E44L, 0xE3D35E8CL, 0x15056DD4L, 0x88F46DBAL, 0x03A16125L, 0x0564F0BDL, 0xC3EB9E15L, 0x3C9057A2L, 0x97271AECL, 0xA93A072AL, 0x1B3F6D9BL, 0x1E6321F5L, 0xF59C66FBL, 0x26DCF319L, 0x7533D928L, 0xB155FDF5L, 0x03563482L, 0x8ABA3CBBL, 0x28517711L, 0xC20AD9F8L, 0xABCC5167L, 0xCCAD925FL, 0x4DE81751L, 0x3830DC8EL, 0x379D5862L, 0x9320F991L, 0xEA7A90C2L, 0xFB3E7BCEL, 0x5121CE64L, 0x774FBE32L, 0xA8B6E37EL, 0xC3293D46L, 0x48DE5369L, 0x6413E680L, 0xA2AE0810L, 0xDD6DB224L, 0x69852DFDL, 0x09072166L, 0xB39A460AL, 0x6445C0DDL, 0x586CDECFL, 0x1C20C8AEL, 0x5BBEF7DDL, 0x1B588D40L, 0xCCD2017FL, 0x6BB4E3BBL, 0xDDA26A7EL, 0x3A59FF45L, 0x3E350A44L, 0xBCB4CDD5L, 0x72EACEA8L, 0xFA6484BBL, 0x8D6612AEL, 0xBF3C6F47L, 0xD29BE463L, 0x542F5D9EL, 0xAEC2771BL, 0xF64E6370L, 0x740E0D8DL, 0xE75B1357L, 0xF8721671L, 0xAF537D5DL, 0x4040CB08L, 0x4EB4E2CCL, 0x34D2466AL, 0x0115AF84L, 0xE1B00428L, 0x95983A1DL, 0x06B89FB4L, 0xCE6EA048L, 0x6F3F3B82L, 0x3520AB82L, 0x011A1D4BL, 0x277227F8L, 0x611560B1L, 0xE7933FDCL, 0xBB3A792BL, 0x344525BDL, 0xA08839E1L, 0x51CE794BL, 0x2F32C9B7L, 0xA01FBAC9L, 0xE01CC87EL, 0xBCC7D1F6L, 0xCF0111C3L, 0xA1E8AAC7L, 0x1A908749L, 0xD44FBD9AL, 0xD0DADECBL, 0xD50ADA38L, 0x0339C32AL, 0xC6913667L, 0x8DF9317CL, 0xE0B12B4FL, 0xF79E59B7L, 0x43F5BB3AL, 0xF2D519FFL, 0x27D9459CL, 0xBF97222CL, 0x15E6FC2AL, 0x0F91FC71L, 0x9B941525L, 0xFAE59361L, 0xCEB69CEBL, 0xC2A86459L, 0x12BAA8D1L, 0xB6C1075EL, 0xE3056A0CL, 0x10D25065L, 0xCB03A442L, 0xE0EC6E0EL, 0x1698DB3BL, 0x4C98A0BEL, 0x3278E964L, 0x9F1F9532L, 0xE0D392DFL, 0xD3A0342BL, 0x8971F21EL, 0x1B0A7441L, 0x4BA3348CL, 0xC5BE7120L, 0xC37632D8L, 0xDF359F8DL, 0x9B992F2EL, 0xE60B6F47L, 0x0FE3F11DL, 0xE54CDA54L, 0x1EDAD891L, 0xCE6279CFL, 0xCD3E7E6FL, 0x1618B166L, 0xFD2C1D05L, 0x848FD2C5L, 0xF6FB2299L, 0xF523F357L, 0xA6327623L, 0x93A83531L, 0x56CCCD02L, 0xACF08162L, 0x5A75EBB5L, 0x6E163697L, 0x88D273CCL, 0xDE966292L, 0x81B949D0L, 0x4C50901BL, 0x71C65614L, 0xE6C6C7BDL, 0x327A140AL, 0x45E1D006L, 0xC3F27B9AL, 0xC9AA53FDL, 0x62A80F00L, 0xBB25BFE2L, 0x35BDD2F6L, 0x71126905L, 0xB2040222L, 0xB6CBCF7CL, 0xCD769C2BL, 0x53113EC0L, 0x1640E3D3L, 0x38ABBD60L, 0x2547ADF0L, 0xBA38209CL, 0xF746CE76L, 0x77AFA1C5L, 0x20756060L, 0x85CBFE4EL, 0x8AE88DD8L, 0x7AAAF9B0L, 0x4CF9AA7EL, 0x1948C25CL, 0x02FB8A8CL, 0x01C36AE4L, 0xD6EBE1F9L, 0x90D4F869L, 0xA65CDEA0L, 0x3F09252DL, 0xC208E69FL, 0xB74E6132L, 0xCE77E25BL, 0x578FDFE3L, 0x3AC372E6L}};
	typedef struct _BLOWFISH_CTX {
		unsigned int pbox[N + 2];
		unsigned int sbox[4][256];
	} BLOWFISH_CTX, *PBLOWFISH_CTX;
	bool blowfish_Init(BLOWFISH_CTX* blowCtx, unsigned char*key, unsigned int keylen);
	static unsigned long blowfish_F(BLOWFISH_CTX* ctx, unsigned long x);
	void blowfish_Encry(PBLOWFISH_CTX blowCtx, unsigned int* left, unsigned int* right);
	void blowfish_Decrypt(PBLOWFISH_CTX blowCtx, unsigned int* left, unsigned int* right);
	bool blowfish_Init(BLOWFISH_CTX* blowCtx, unsigned char * key, unsigned int keylen) {
		for (int Row = 0; Row < 4; Row++) {
			for (int Col = 0; Col < 256; Col++) {
				blowCtx->sbox[Row][Col] = blowfish_ORIG_S[Row][Col];
			}
		}
		int KeyIndex = 0;
		for (int index = 0; index < N + 2; index++) {
			unsigned int data = 0;
			for (int k = 0; k < 4; k++) {
				data = (data << 8) | key[KeyIndex];
				KeyIndex++;
				if (KeyIndex >= int(keylen)) KeyIndex = 0;
			}
			blowCtx->pbox[index] = blowfish_ORIG_P[index] ^ data;
		}
		unsigned int Data1 = 0;
		unsigned int Data2 = 0;
		for (int i = 0; i < N + 2; i += 2) {
			blowfish_Encry(blowCtx, &Data1, &Data2);
			blowCtx->pbox[i] = Data1;
			blowCtx->pbox[i + 1] = Data2;
		}
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 256; j += 2) {
				blowfish_Encry(blowCtx, &Data1, &Data2);
				blowCtx->sbox[i][j] = Data1;
				blowCtx->sbox[i][j + 1] = Data2;
			}
		}
		return true;
	}
	static unsigned long blowfish_F(BLOWFISH_CTX* ctx, unsigned long x) {
		unsigned short a, b, c, d;
		unsigned long  y;
		a = (x >> 24) & 0xFF;
		b = (x >> 16) & 0xFF;
		c = (x >> 8) & 0xFf;
		d = x & 0xFF;
		y = ctx->sbox[0][a] + ctx->sbox[1][b];
		y = y ^ ctx->sbox[2][c];
		y = y + ctx->sbox[3][d];
		return y;
	}
	void blowfish_Encry(PBLOWFISH_CTX blowCtx, unsigned int* left, unsigned int* right) {
		unsigned long  Xl;
		unsigned long  Xr;
		unsigned long  temp;
		short i;
		Xl = *left;
		Xr = *right;
		for (i = 0; i < N; ++i) {
			Xl = Xl ^ blowCtx->pbox[i];
			Xr = blowfish_F(blowCtx, Xl) ^ Xr;
			temp = Xl;
			Xl = Xr;
			Xr = temp;
		}
		temp = Xl;
		Xl = Xr;
		Xr = temp;
		Xr = Xr ^ blowCtx->pbox[N];
		Xl = Xl ^ blowCtx->pbox[N + 1];
		*left = Xl;
		*right = Xr;
	}
	void blowfish_Decrypt(PBLOWFISH_CTX blowCtx, unsigned int* left, unsigned int* right) {
		unsigned int Xl = *left;
		unsigned int Xr = *right;
		for (int i = N + 1; i > 1; --i) {
			Xl = Xl ^ blowCtx->pbox[i];
			Xr = Xr ^ blowfish_F(blowCtx, Xl);
			unsigned int temp = Xl;
			Xl = Xr;
			Xr = temp;
		}
		unsigned int temp = Xl;
		Xl = Xr;
		Xr = temp;
		Xr = Xr ^ blowCtx->pbox[1];
		Xl = Xl ^ blowCtx->pbox[0];
		*left = Xl;
		*right = Xr;
	}
	std::string caesar_encrypt(const std::string& txt, int shift) {
		std::string out;
		for (char c : txt) {
			if (std::isalpha(c)) {
				char base = std::isupper(c) ? 'A' : 'a';
				out += char((c - base + shift) % 26 + base);
			} else out += c;
		}
		return out;
	}
	std::string caesar_decrypt(const std::string& txt, int shift) {
		return caesar_encrypt(txt, 26 - shift);
	}
	constexpr size_t CAMELLIA_BLOCK_SIZE = 16;
	constexpr size_t CAMELLIA_ROUNDS_128 = 18;
	constexpr size_t CAMELLIA_ROUNDS_192 = 24;
	constexpr size_t CAMELLIA_ROUNDS_256 = 24;
	constexpr unsigned char camellia_SBOX0[] = {
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
		0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
		0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
		0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F
	};
	constexpr unsigned char camellia_SBOX1[] = {
		0x78, 0x47, 0x9A, 0xEF, 0x28, 0x10, 0xDC, 0xB3, 0x69, 0x5B, 0xA2, 0xC4, 0x3D, 0x8F, 0x06, 0x71,
		0xF5, 0x19, 0xCA, 0x60, 0xD2, 0x91, 0x37, 0xAB, 0x0C, 0x83, 0x4E, 0x26, 0x5D, 0xE4, 0xBF, 0x7A,
		0x23, 0x07, 0x95, 0xEC, 0x7D, 0x41, 0x1B, 0xCF, 0xA8, 0x54, 0x8B, 0x36, 0x62, 0xD9, 0xF0, 0xB7,
		0x5E, 0x8C, 0x21, 0xF3, 0xBC, 0x64, 0x02, 0x7F, 0x9D, 0x3A, 0xE6, 0x48, 0x15, 0xC0, 0xDA, 0xA9,
		0x14, 0xC7, 0x81, 0x5F, 0xB0, 0x6A, 0x32, 0xED, 0x74, 0x05, 0xF2, 0x9C, 0x43, 0xAE, 0x2D, 0xD8,
		0x90, 0x3F, 0xE1, 0x4B, 0x12, 0xCB, 0x85, 0x56, 0xB9, 0x6E, 0x0A, 0x7C, 0x27, 0xFD, 0xAD, 0xD3,
		0x63, 0xBE, 0x0F, 0x76, 0x97, 0x31, 0xE9, 0x4D, 0x18, 0xC2, 0x8E, 0x50, 0x24, 0xFC, 0xA5, 0xD1,
		0x59, 0x86, 0x2B, 0xF0, 0xBD, 0x67, 0x03, 0x7E, 0x9A, 0x3D, 0xE4, 0x49, 0x16, 0xC1, 0xDA, 0xAC,
		0x1D, 0xC8, 0x82, 0x5A, 0xB1, 0x6D, 0x33, 0xEE, 0x75, 0x04, 0xF1, 0x9B, 0x42, 0xAF, 0x2E, 0xD9,
		0x91, 0x3E, 0xE0, 0x4A, 0x13, 0xCC, 0x84, 0x57, 0xB8, 0x6F, 0x0B, 0x7D, 0x26, 0xFE, 0xAD, 0xD2,
		0x62, 0xBF, 0x0E, 0x77, 0x96, 0x30, 0xE8, 0x4C, 0x19, 0xC3, 0x8F, 0x51, 0x25, 0xFC, 0xA4, 0xD0,
		0x58, 0x87, 0x2A, 0xF3, 0xBC, 0x66, 0x02, 0x7F, 0x9B, 0x3C, 0xE5, 0x48, 0x17, 0xC0, 0xDA, 0xAB,
		0x1C, 0xC9, 0x83, 0x5B, 0xB0, 0x6C, 0x31, 0xED, 0x74, 0x05, 0xF2, 0x9A, 0x43, 0xAE, 0x2D, 0xD8,
		0x92, 0x3F, 0xE1, 0x4B, 0x11, 0xCB, 0x85, 0x56, 0xB9, 0x6E, 0x0A, 0x7C, 0x27, 0xFD, 0xAD, 0xD3,
		0x63, 0xBE, 0x0F, 0x76, 0x97, 0x32, 0xE9, 0x4D, 0x18, 0xC2, 0x8E, 0x50, 0x24, 0xFC, 0xA5, 0xD1,
		0x59, 0x86, 0x2B, 0xF0, 0xBD, 0x67, 0x03, 0x7E, 0x9A, 0x3D, 0xE4, 0x49, 0x16, 0xC1, 0xDA, 0xAC
	};
	constexpr unsigned char camellia_SBOX2[] = {
		0x3C, 0x9F, 0x5A, 0x07, 0xE2, 0x7D, 0x21, 0xBF, 0x84, 0x4E, 0xD6, 0x13, 0x6B, 0xA8, 0xF0, 0xC5,
		0x15, 0xC0, 0xDA, 0xAC, 0x8E, 0x51, 0x25, 0xFC, 0x62, 0xBF, 0x0E, 0x77, 0x96, 0x30, 0xE8, 0x4C,
		0x91, 0x3E, 0xE0, 0x4A, 0x13, 0xCC, 0x84, 0x57, 0xB8, 0x6F, 0x0B, 0x7D, 0x26, 0xFE, 0xAD, 0xD2,
		0x58, 0x87, 0x2A, 0xF3, 0xBC, 0x66, 0x02, 0x7F, 0x9B, 0x3C, 0xE5, 0x48, 0x17, 0xC0, 0xDA, 0xAB,
		0x1C, 0xC9, 0x83, 0x5B, 0xB0, 0x6C, 0x31, 0xED, 0x74, 0x05, 0xF2, 0x9A, 0x43, 0xAE, 0x2D, 0xD8,
		0x92, 0x3F, 0xE1, 0x4B, 0x11, 0xCB, 0x85, 0x56, 0xB9, 0x6E, 0x0A, 0x7C, 0x27, 0xFD, 0xAD, 0xD3,
		0x63, 0xBE, 0x0F, 0x76, 0x97, 0x32, 0xE9, 0x4D, 0x18, 0xC2, 0x8E, 0x50, 0x24, 0xFC, 0xA5, 0xD1,
		0x59, 0x86, 0x2B, 0xF0, 0xBD, 0x67, 0x03, 0x7E, 0x9A, 0x3D, 0xE4, 0x49, 0x16, 0xC1, 0xDA, 0xAC,
		0x1D, 0xC8, 0x82, 0x5A, 0xB1, 0x6D, 0x33, 0xEE, 0x75, 0x04, 0xF1, 0x9B, 0x42, 0xAF, 0x2E, 0xD9,
		0x90, 0x3E, 0xE0, 0x4A, 0x13, 0xCC, 0x84, 0x57, 0xB8, 0x6F, 0x0B, 0x7D, 0x26, 0xFE, 0xAD, 0xD2,
		0x62, 0xBF, 0x0E, 0x77, 0x96, 0x30, 0xE8, 0x4C, 0x19, 0xC3, 0x8F, 0x51, 0x25, 0xFC, 0xA4, 0xD0,
		0x58, 0x87, 0x2A, 0xF3, 0xBC, 0x66, 0x02, 0x7F, 0x9B, 0x3C, 0xE5, 0x48, 0x17, 0xC0, 0xDA, 0xAB,
		0x1C, 0xC9, 0x83, 0x5B, 0xB0, 0x6C, 0x31, 0xED, 0x74, 0x05, 0xF2, 0x9A, 0x43, 0xAE, 0x2D, 0xD8,
		0x92, 0x3F, 0xE1, 0x4B, 0x11, 0xCB, 0x85, 0x56, 0xB9, 0x6E, 0x0A, 0x7C, 0x27, 0xFD, 0xAD, 0xD3,
		0x63, 0xBE, 0x0F, 0x76, 0x97, 0x32, 0xE9, 0x4D, 0x18, 0xC2, 0x8E, 0x50, 0x24, 0xFC, 0xA5, 0xD1,
		0x59, 0x86, 0x2B, 0xF0, 0xBD, 0x67, 0x03, 0x7E, 0x9A, 0x3D, 0xE4, 0x49, 0x16, 0xC1, 0xDA, 0xAC
	};
	constexpr unsigned char camellia_SBOX3[] = {
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
	};
	constexpr unsigned int camellia_P1[] = {0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000};
	constexpr unsigned int camellia_P2[] = {0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000};
	constexpr unsigned int camellia_Q1[] = {0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000};
	constexpr unsigned int camellia_Q2[] = {0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000};
	inline unsigned int camella_rotl32(unsigned int x, size_t n) {
		return (x << n) | (x >> (32 - n));
	}
	inline unsigned int camella_rotr32(unsigned int x, size_t n) {
		return (x >> n) | (x << (32 - n));
	}
	inline unsigned char camella_sbox(unsigned char b, size_t s) {
		if (s == 0) return camellia_SBOX0[b];
		if (s == 1) return camellia_SBOX1[b];
		if (s == 2) return camellia_SBOX2[b];
		return camellia_SBOX3[b];
	}
	unsigned int camella_FL(unsigned int x, unsigned int k) {
		unsigned int x0 = (x >> 16) & 0xFFFF;
		unsigned int x1 = x & 0xFFFF;
		unsigned int k0 = (k >> 16) & 0xFFFF;
		unsigned int k1 = k & 0xFFFF;
		unsigned int y0 = (x0 | (~k0 & 0xFFFF)) ^ x1;
		unsigned int y1 = x1 ^ (k1 & y0);
		return (y0 << 16) | y1;
	}
	unsigned int camella_FLinv(unsigned int x, unsigned int k) {
		unsigned int x0 = (x >> 16) & 0xFFFF;
		unsigned int x1 = x & 0xFFFF;
		unsigned int k0 = (k >> 16) & 0xFFFF;
		unsigned int k1 = k & 0xFFFF;
		unsigned int y1 = x1 ^ (k1 & x0);
		unsigned int y0 = x0 ^ (y1 | (~k0 & 0xFFFF));
		return (y0 << 16) | y1;
	}
	unsigned int camella_F(unsigned int x, const unsigned int* k) {
		unsigned char b[4] = {(unsigned char)((x >> 24) & 0xFF), (unsigned char)((x >> 16) & 0xFF), (unsigned char)((x >> 8) & 0xFF), (unsigned char)(x & 0xFF)};
		for (size_t i = 0; i < 4; ++i) b[i] = camella_sbox(b[i], i);
		unsigned int w0 = (static_cast<unsigned int>(b[0]) << 24) | (static_cast<unsigned int>(b[1]) << 16) | (static_cast<unsigned int>(b[2]) << 8) | static_cast<unsigned int>(b[3]);
		unsigned int w1 = camella_rotl32(w0, 1);
		unsigned int w2 = camella_rotl32(w0, 5);
		unsigned int w3 = camella_rotl32(w0, 15);
		return w0 ^ w1 ^ w2 ^ w3 ^ k[0] ^ k[1] ^ k[2] ^ k[3];
	}
	std::vector<unsigned int> keyExpansion(const std::vector<unsigned char>& key) {
		size_t keyLen = key.size();
		size_t Nr = (keyLen == 16) ? CAMELLIA_ROUNDS_128 : (keyLen == 24) ? CAMELLIA_ROUNDS_192 : (keyLen == 32) ? CAMELLIA_ROUNDS_256 : throw std::invalid_argument("Invalid key size");
		size_t K = keyLen / 4;
		std::vector<unsigned int> K0(K, 0);
		for (size_t i = 0; i < K; ++i) K0[i] = (static_cast<unsigned int>(key[4 * i]) << 24) | (static_cast<unsigned int>(key[4 * i + 1]) << 16) | (static_cast<unsigned int>(key[4 * i + 2]) << 8) | static_cast<unsigned int>(key[4 * i + 3]);
		std::vector<unsigned int> roundKeys(Nr * 4 + 2, 0);
		unsigned int Z[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
		for (size_t i = 0; i < Nr; ++i) {
			unsigned int* k = &roundKeys[i * 4];
			if (i % 8 == 0) {
				unsigned int c = (i / 8) % 4;
				k[0] = K0[(0 + c) % K] ^ camellia_P1[i % 16];
				k[1] = K0[(1 + c) % K] ^ camellia_P2[i % 16];
				k[2] = K0[(2 + c) % K] ^ camellia_Q1[i % 16];
				k[3] = K0[(3 + c) % K] ^ camellia_Q2[i % 16];
			} else {
				k[0] = roundKeys[(i - 1) * 4] ^ Z[0];
				k[1] = roundKeys[(i - 1) * 4 + 1] ^ Z[1];
				k[2] = roundKeys[(i - 1) * 4 + 2] ^ Z[2];
				k[3] = roundKeys[(i - 1) * 4 + 3] ^ Z[3];
			}
			Z[0] = camella_F(Z[0], k);
			Z[1] = camella_F(Z[1], k);
			Z[2] = camella_F(Z[2], k);
			Z[3] = camella_F(Z[3], k);
		}
		roundKeys[Nr * 4] = K0[K - 2];
		roundKeys[Nr * 4 + 1] = K0[K - 1];
		return roundKeys;
	}
	void camellia_encryptBlock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned int>& roundKeys) {
		out = in;
		unsigned int X[4] = {
			(static_cast<unsigned int>(in[0]) << 24) | (static_cast<unsigned int>(in[1]) << 16) | (static_cast<unsigned int>(in[2]) << 8) | static_cast<unsigned int>(in[3]),
			(static_cast<unsigned int>(in[4]) << 24) | (static_cast<unsigned int>(in[5]) << 16) | (static_cast<unsigned int>(in[6]) << 8) | static_cast<unsigned int>(in[7]),
			(static_cast<unsigned int>(in[8]) << 24) | (static_cast<unsigned int>(in[9]) << 16) | (static_cast<unsigned int>(in[10]) << 8) | static_cast<unsigned int>(in[11]),
			(static_cast<unsigned int>(in[12]) << 24) | (static_cast<unsigned int>(in[13]) << 16) | (static_cast<unsigned int>(in[14]) << 8) | static_cast<unsigned int>(in[15])
		};
		size_t Nr = (roundKeys.size() - 2) / 4;
		for (size_t i = 0; i < Nr; ++i) {
			const unsigned int* k = &roundKeys[i * 4];
			if (i % 6 == 0 || i % 6 == 1) {
				X[1] ^= camella_F(X[0], k);
				X[3] ^= camella_F(X[2], k);
			} else if (i % 6 == 2 || i % 6 == 3) {
				X[2] ^= camella_F(X[3], k);
				X[0] ^= camella_F(X[1], k);
			} else {
				X[1] = camella_FL(X[1], k[0]);
				X[3] = camella_FL(X[3], k[1]);
				X[2] = camella_FLinv(X[2], k[2]);
				X[0] = camella_FLinv(X[0], k[3]);
			}
			std::swap(X[0], X[1]);
			std::swap(X[2], X[3]);
			std::swap(X[1], X[2]);
		}
		X[0] ^= roundKeys[Nr * 4];
		X[1] ^= roundKeys[Nr * 4 + 1];
		X[2] ^= roundKeys[Nr * 4];
		X[3] ^= roundKeys[Nr * 4 + 1];
		out[0] = (X[0] >> 24) & 0xFF;
		out[1] = (X[0] >> 16) & 0xFF;
		out[2] = (X[0] >> 8) & 0xFF;
		out[3] = X[0] & 0xFF;
		out[4] = (X[1] >> 24) & 0xFF;
		out[5] = (X[1] >> 16) & 0xFF;
		out[6] = (X[1] >> 8) & 0xFF;
		out[7] = X[1] & 0xFF;
		out[8] = (X[2] >> 24) & 0xFF;
		out[9] = (X[2] >> 16) & 0xFF;
		out[10] = (X[2] >> 8) & 0xFF;
		out[11] = X[2] & 0xFF;
		out[12] = (X[3] >> 24) & 0xFF;
		out[13] = (X[3] >> 16) & 0xFF;
		out[14] = (X[3] >> 8) & 0xFF;
		out[15] = X[3] & 0xFF;
	}
	void camellia_decryptBlock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned int>& roundKeys) {
		out = in;
		unsigned int X[4] = {
			(static_cast<unsigned int>(in[0]) << 24) | (static_cast<unsigned int>(in[1]) << 16) | (static_cast<unsigned int>(in[2]) << 8) | static_cast<unsigned int>(in[3]),
			(static_cast<unsigned int>(in[4]) << 24) | (static_cast<unsigned int>(in[5]) << 16) | (static_cast<unsigned int>(in[6]) << 8) | static_cast<unsigned int>(in[7]),
			(static_cast<unsigned int>(in[8]) << 24) | (static_cast<unsigned int>(in[9]) << 16) | (static_cast<unsigned int>(in[10]) << 8) | static_cast<unsigned int>(in[11]),
			(static_cast<unsigned int>(in[12]) << 24) | (static_cast<unsigned int>(in[13]) << 16) | (static_cast<unsigned int>(in[14]) << 8) | static_cast<unsigned int>(in[15])
		};
		size_t Nr = (roundKeys.size() - 2) / 4;
		X[0] ^= roundKeys[Nr * 4];
		X[1] ^= roundKeys[Nr * 4 + 1];
		X[2] ^= roundKeys[Nr * 4];
		X[3] ^= roundKeys[Nr * 4 + 1];
		for (size_t i = Nr; i > 0; --i) {
			const unsigned int* k = &roundKeys[(i - 1) * 4];
			std::swap(X[1], X[2]);
			std::swap(X[0], X[1]);
			std::swap(X[2], X[3]);
			if (i % 6 == 1 || i % 6 == 2) {
				X[1] ^= camella_F(X[0], k);
				X[3] ^= camella_F(X[2], k);
			} else if (i % 6 == 3 || i % 6 == 4) {
				X[2] ^= camella_F(X[3], k);
				X[0] ^= camella_F(X[1], k);
			} else {
				X[1] = camella_FL(X[1], k[0]);
				X[3] = camella_FL(X[3], k[1]);
				X[2] = camella_FLinv(X[2], k[2]);
				X[0] = camella_FLinv(X[0], k[3]);
			}
		}
		out[0] = (X[0] >> 24) & 0xFF;
		out[1] = (X[0] >> 16) & 0xFF;
		out[2] = (X[0] >> 8) & 0xFF;
		out[3] = X[0] & 0xFF;
		out[4] = (X[1] >> 24) & 0xFF;
		out[5] = (X[1] >> 16) & 0xFF;
		out[6] = (X[1] >> 8) & 0xFF;
		out[7] = X[1] & 0xFF;
		out[8] = (X[2] >> 24) & 0xFF;
		out[9] = (X[2] >> 16) & 0xFF;
		out[10] = (X[2] >> 8) & 0xFF;
		out[11] = X[2] & 0xFF;
		out[12] = (X[3] >> 24) & 0xFF;
		out[13] = (X[3] >> 16) & 0xFF;
		out[14] = (X[3] >> 8) & 0xFF;
		out[15] = X[3] & 0xFF;
	}
	std::vector<unsigned char> camellia_encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
		if (key.size() != 16 && key.size() != 24 && key.size() != 32) throw std::invalid_argument("Key must be 16/24/32 bytes");
		std::vector<unsigned char> ciphertext;
		std::vector<unsigned int> roundKeys = keyExpansion(key);
		size_t numBlocks = (plaintext.size() + CAMELLIA_BLOCK_SIZE - 1) / CAMELLIA_BLOCK_SIZE;
		for (size_t i = 0; i < numBlocks; ++i) {
			std::vector<unsigned char> block(CAMELLIA_BLOCK_SIZE, 0);
			size_t start = i * CAMELLIA_BLOCK_SIZE;
			size_t len = std::min(CAMELLIA_BLOCK_SIZE, plaintext.size() - start);
			std::copy_n(plaintext.begin() + start, len, block.begin());
			std::vector<unsigned char> encryptedBlock;
			camellia_encryptBlock(block, encryptedBlock, roundKeys);
			ciphertext.insert(ciphertext.end(), encryptedBlock.begin(), encryptedBlock.end());
		}
		return ciphertext;
	}
	std::vector<unsigned char> camellia_decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
		if (key.size() != 16 && key.size() != 24 && key.size() != 32) throw std::invalid_argument("Key must be 16/24/32 bytes");
		if (ciphertext.size() % CAMELLIA_BLOCK_SIZE != 0) throw std::invalid_argument("Ciphertext length must be multiple of block size");
		std::vector<unsigned char> plaintext;
		std::vector<unsigned int> roundKeys = keyExpansion(key);
		size_t numBlocks = ciphertext.size() / CAMELLIA_BLOCK_SIZE;
		for (size_t i = 0; i < numBlocks; ++i) {
			std::vector<unsigned char> block(ciphertext.begin() + i * CAMELLIA_BLOCK_SIZE, ciphertext.begin() + (i + 1) * CAMELLIA_BLOCK_SIZE);
			std::vector<unsigned char> decryptedBlock;
			camellia_decryptBlock(block, decryptedBlock, roundKeys);
			plaintext.insert(plaintext.end(), decryptedBlock.begin(), decryptedBlock.end());
		}
		return plaintext;
	}
	inline unsigned int cast_rotl32(unsigned int x, unsigned n) {
		return (x << n) | (x >> (32 - n));
	}
	inline unsigned int cast_rotr32(unsigned int x, unsigned n) {
		return (x >> n) | (x << (32 - n));
	}
	class CAST128 {
		public:
			static constexpr size_t BLOCK_SIZE = 8;
			static constexpr size_t MIN_KEY = 5;
			static constexpr size_t MAX_KEY = 16;
			CAST128() = default;
			void setKey(const unsigned char *key, size_t keyBytes) {
				if (keyBytes < MIN_KEY || keyBytes > MAX_KEY) throw std::invalid_argument("CAST?128 key length must be 5?16 bytes");
				unsigned char k[16] = {0};
				std::memcpy(k, key, keyBytes);
				keySchedule(k);
			}
			void encryptBlock(const unsigned char *in, unsigned char *out) const {
				unsigned int L = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
				unsigned int R = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
				const unsigned ROUNDS = (rounds_ == 12 ? 12 : 16);
				for (unsigned i = 0; i < ROUNDS; ++i) {
					unsigned int tmp = R;
					R = L ^ f(i, R);
					L = tmp;
				}
				out[0] = (R >> 24) & 0xFF;
				out[1] = (R >> 16) & 0xFF;
				out[2] = (R >> 8)  & 0xFF;
				out[3] =  R        & 0xFF;
				out[4] = (L >> 24) & 0xFF;
				out[5] = (L >> 16) & 0xFF;
				out[6] = (L >> 8)  & 0xFF;
				out[7] =  L        & 0xFF;
			}
			void decryptBlock(const unsigned char *in, unsigned char *out) const {
				unsigned int L = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
				unsigned int R = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
				const unsigned ROUNDS = (rounds_ == 12 ? 12 : 16);
				for (int i = ROUNDS - 1; i >= 0; --i) {
					unsigned int tmp = L;
					L = R ^ f(i, L);
					R = tmp;
				}
				out[0] = (R >> 24) & 0xFF;
				out[1] = (R >> 16) & 0xFF;
				out[2] = (R >> 8)  & 0xFF;
				out[3] =  R        & 0xFF;
				out[4] = (L >> 24) & 0xFF;
				out[5] = (L >> 16) & 0xFF;
				out[6] = (L >> 8)  & 0xFF;
				out[7] =  L        & 0xFF;
			}
		private:
			static constexpr unsigned int S1[256] = {
				0x30FB40D4, 0x9FA0FF0B, 0x6BECCD2F, 0x3F258C7A, 0x1E213F2F, 0x9C004DD3, 0x6003E540, 0xCF9FC949,
				0xBFD4AF27, 0x88BBBDB5, 0xE2034090, 0x98D09675, 0x6E63A0E0, 0x15C361D2, 0xC2E7661D, 0x22D4FF8E,
				0x28683B6F, 0xC07FD059, 0xFF2379C8, 0x775F50E2, 0x43C340D3, 0xDF2F8656, 0x887CA41A, 0xA2D2BD2D,
				0xA1C9E0D6, 0x346C4819, 0x61B76D87, 0x22540F2F, 0x2ABE32E1, 0xAA54166B, 0x22568E3A, 0xA2D341D0,
				0x66DB40C8, 0xA784392F, 0x004DFF2F, 0x2DB9D2DE, 0x97943FAC, 0x4A97C1D8, 0x527644B7, 0xB5F437A7,
				0xB82CBAEF, 0xD751D159, 0x6FF7F0ED, 0x5A097A1F, 0x827B68D0, 0x90ECF52E, 0x22B0C054, 0xBC8E5935,
				0x4B6D2F7F, 0x50BB64A2, 0xD2664910, 0xBEE5812D, 0xB7332290, 0xE93B159F, 0xB48EE411, 0x4BFF345D,
				0xFD45C240, 0xAD31973F, 0xC4F6D02E, 0x55FC8165, 0xD5B1CAAD, 0xA1AC2DAE, 0xA2D4B76D, 0xC19B0C50,
				0x882240F2, 0x0C6E4F38, 0xA4E4BFD7, 0x4F5BA272, 0x564C1D2F, 0xC59C5319, 0xB949E354, 0xB04669FE,
				0xB1B6AB8A, 0xC71358DD, 0x6385C545, 0x110F935D, 0x57538AD5, 0x6A390493, 0xE63D37E0, 0x2A54F6B3,
				0x3A787D5F, 0x6276A0B5, 0x19A6FCDF, 0x7A42206A, 0x29F9D4D5, 0xF61B1891, 0xBB72275E, 0xAA508167,
				0x38901091, 0xC6B505EB, 0x84C7CB8C, 0x2AD75A0F, 0x874A1427, 0xA2D1936B, 0x2AD286AF, 0xAA56D291,
				0xD7894360, 0x425C750D, 0x93B39E26, 0x187184C9, 0x6C00B32D, 0x73E2BB14, 0xA0BEBC3C, 0x54623779,
				0x64459EAB, 0x3F328B82, 0x7718CF82, 0x59A2CEA6, 0x04EE002E, 0x89FE78E6, 0x3FAB0950, 0x325FF6C2,
				0x81383F05, 0x6963C5C8, 0x76CB5AD6, 0xD49974C9, 0xCA180DCF, 0x380782D5, 0xC7FA5CF6, 0x8AC31511,
				0x35E79E13, 0x47DA91D0, 0xF40F9086, 0xA7E2419E, 0x31366241, 0x051EF495, 0xAA573B04, 0x4A805D8D,
				0x548300D0, 0x00322A3C, 0xBF64CDDF, 0xBA57A68E, 0x75C6372B, 0x50AFD341, 0xA7C13275, 0x915A0BF5,
				0x6B54BFAB, 0x2B0B1426, 0xAB4CC9D7, 0x449CCD82, 0xF7FBF265, 0xAB85C5F3, 0x1B55DB94, 0xAAD4E324,
				0xCFA4BD3F, 0x2DEAA3E2, 0x9E204D02, 0xC8BD25AC, 0xEADF55B3, 0xD5BD9E98, 0xE31231B2, 0x2AD5AD6C,
				0x954329DE, 0xADBE4528, 0xD8710F69, 0xAA51C90F, 0xAA786BF6, 0x22513F1E, 0xAA51A79B, 0x2AD344CC,
				0x7B5A41F0, 0xD37CFBAD, 0x1B069505, 0x41ECE491, 0xB4C332E6, 0x032268D4, 0xC9600ACC, 0xCE387E6D,
				0xBF6BB16C, 0x6A70FB78, 0x0D03D9C9, 0xD4DF39DE, 0xE01063DA, 0x4736F464, 0x5AD328D8, 0xB347CC96,
				0x75BB0FC3, 0x98511BFB, 0x4FFBCC35, 0xB58BCF6A, 0xE11F0ABC, 0xBFC5FE4A, 0xA70AEC10, 0xAC39570A,
				0x3F04442F, 0x6188B153, 0xE0397A2E, 0x5727CB79, 0x9CEB418F, 0x1CACD68D, 0x2AD37C96, 0x0175CB9D,
				0xC69DFF09, 0xC75B65F0, 0xD9DB40D8, 0xEC0E7779, 0x4744EAD4, 0xB11C3274, 0xDD24CB9E, 0x7E1C54BD,
				0xF01144F9, 0xD2240EB1, 0x9675B3FD, 0xA3AC3755, 0xD47C27AF, 0x51C85F4D, 0x56907596, 0xA5BB15E6,
				0x580304F0, 0xCA042CF1, 0x011A37EA, 0x8DBFAADB, 0x35BA3E4A, 0x3526FFA0, 0xC37B4D09, 0xBC306ED9,
				0x98A52666, 0x5648F725, 0xFF5E569D, 0x0CED63D0, 0x7C63B2CF, 0x700B45E1, 0xD5EA50F1, 0x85A92872,
				0xAF1FBDA7, 0xD4234870, 0xA7870BF3, 0x2D3B4D79, 0x42E04198, 0x0CD0EDE7, 0x26470DB8, 0xF881814C,
				0x474D6AD7, 0x7C0C5E5C, 0xD1231959, 0x381B7298, 0xF5D2F4DB, 0xAB838653, 0x6E2F1E23, 0x83719C9E,
				0xBD91E046, 0x9A56456E, 0xDC39200C, 0x20C8C571, 0x962BDA1C, 0xE1E696FF, 0xB141AB08, 0x7CCA89B9,
				0x1A69E783, 0x02CC4843, 0xA2F7C579, 0x429EF47D, 0x427B169C, 0x5AC9F049, 0xDD8F0F00, 0x5C8165BF
			};
			static constexpr unsigned int S2[256] = {
				0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380, 0xfe61cf7a, 0xeec5207a, 0x55889c94, 0x72fc0651,
				0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba, 0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3,
				0xa0b52f7b, 0x59e83605, 0xee15b094, 0xe9ffd909, 0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb,
				0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b, 0x01420ddb, 0xe4e7ef5b, 0x25a1ff41, 0xe180f806,
				0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4, 0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b,
				0xe113c85b, 0xacc40083, 0xd7503525, 0xf7ea615f, 0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359,
				0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21, 0x071f6181, 0x39f7627f, 0x361e3084, 0xe4eb573b,
				0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d, 0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c,
				0x10843094, 0x2537a95e, 0xf46f6ffe, 0xa1ff3b1f, 0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34,
				0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d, 0x8a45388c, 0x1d804366, 0x721d9bfd, 0xa58684bb,
				0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4, 0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd,
				0xc5d655dd, 0xeb667064, 0x77840b4d, 0xa1b6a801, 0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860,
				0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755, 0xb5625dbf, 0x68561be6, 0x83ca6b94, 0x2d6ed23b,
				0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709, 0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304,
				0x81ed6f61, 0x20e74364, 0xb45e1378, 0xde18639b, 0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b,
				0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c, 0x488cb402, 0x1ba4fe5b, 0xa4b09f6b, 0x1ca815cf,
				0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9, 0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c,
				0xee41e729, 0x6e1d2d7c, 0x50045286, 0x1e6685f3, 0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13,
				0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9, 0xcdff33a6, 0xa02b1741, 0x7cbad9a2, 0x2180036f,
				0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab, 0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6,
				0xcdf0b680, 0x17844d3b, 0x31eef84d, 0x7e0824e4, 0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6,
				0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43, 0xb3faec54, 0x157fd7fa, 0xef8579cc, 0xd152de58,
				0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8, 0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906,
				0xb8da230c, 0x80823028, 0xdcdef3c8, 0xd35fb171, 0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d,
				0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89, 0x8b1c34bc, 0x301e16e6, 0x273be979, 0xb0ffeaa6,
				0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b, 0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4,
				0xdc8637a0, 0x16a7d3b1, 0x9fc393b7, 0xa7136eeb, 0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6,
				0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e, 0xdb92f2fb, 0x5eea29cb, 0x145892f5, 0x91584f7f,
				0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea, 0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249,
				0xb284600c, 0xd835731d, 0xdcb1c647, 0xac4c56ea, 0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa,
				0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd, 0x649da589, 0xa345415e, 0x5c038323, 0x3e5d3bb9,
				0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef, 0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1
			};
			static constexpr unsigned int S3[256] = {
				0x8DEFC240, 0x25FA5D9F, 0xEB903DBF, 0xE810C907, 0x47607FFF, 0x369FE44B, 0x8C1FC644, 0xAECECA90,
				0xBEB1F9BF, 0xEEFBCAEA, 0xE8CF1950, 0x51DF07AE, 0x920E8806, 0xF0AD0548, 0xE13C8D83, 0x927010D5,
				0x11107D9F, 0x07647DB9, 0xB2E3E4D4, 0x3D4F285E, 0xB9AFA820, 0xFADE82E0, 0xA067268B, 0x8272792E,
				0x553FB2C0, 0x489AE22B, 0xD4EF9794, 0x125E3FBC, 0x21FFFCEE, 0x825B1BFD, 0x9255C5ED, 0x1257A240,
				0x4E1A8302, 0xBAE07FFF, 0x528246E7, 0x8E57140E, 0x3373F7BF, 0x8C9F8188, 0xA6FC4EE8, 0xC982B5A5,
				0xA8C01DB7, 0x579FC264, 0x67094F31, 0xF2BD3F5F, 0x40FFF7C1, 0x1FB78DFC, 0x8E6BD2C1, 0x437BE59B,
				0x99B03DBF, 0xB5DBC64B, 0x638DC0E6, 0x55819D99, 0xA197C81C, 0x4A012D6E, 0xC5884A28, 0xCCC36F71,
				0xB843C213, 0x6C0743F1, 0x8309893C, 0x0FEDDD5F, 0x2F7FE850, 0xD7C07F7E, 0x02507FBF, 0x5AFB9A04,
				0xA747D2D0, 0x1651192E, 0xAF70BF3E, 0x58C31380, 0x5F98302E, 0x727CC3C4, 0x0A0FB402, 0x0F7FEF82,
				0x8C96FDAD, 0x5D2C2AAE, 0x8EE99A49, 0x50DA88B8, 0x8427F4A0, 0x1EAC5790, 0x796FB449, 0x8252DC15,
				0xEFBD7D9B, 0xA672597D, 0xADA840D8, 0x45F54504, 0xFA5D7403, 0xE83EC305, 0x4F91751A, 0x925669C2,
				0x23EFE941, 0xA903F12E, 0x60270DF2, 0x0276E4B6, 0x94FD6574, 0x927985B2, 0x8276DBCB, 0x02778176,
				0xF8AF918D, 0x4E48F79E, 0x8F616DDF, 0xE29D840E, 0x842F7D83, 0x340CE5C8, 0x96BBB682, 0x93B4B148,
				0xEF303CAB, 0x984FAF28, 0x779FAF9B, 0x92DC560D, 0x224D1E20, 0x8437AA88, 0x7D29DC96, 0x2756D3DC,
				0x8B907CEE, 0xB51FD240, 0xE7C07CE3, 0xE566B4A1, 0xC3E9615E, 0x3CF8209D, 0x6094D1E3, 0xCD9CA341,
				0x5C76460E, 0x00EA983B, 0xD4D67881, 0xFD47572C, 0xF76CEDD9, 0xBDA8229C, 0x127DADAA, 0x438A074E,
				0x1F97C090, 0x081BDB8A, 0x93A07EBE, 0xB938CA15, 0x97B03CFF, 0x3DC2C0F8, 0x8D1AB2EC, 0x64380E51,
				0x68CC7BFB, 0xD90F2788, 0x12490181, 0x5DE5FFD4, 0xDD7EF86A, 0x76A2E214, 0xB9A40368, 0x925D958F,
				0x4B39FFFA, 0xBA39AEE9, 0xA4FFD30B, 0xFAF7933B, 0x6D498623, 0x193CBCFA, 0x27627545, 0x825CF47A,
				0x61BD8BA0, 0xD11E42D1, 0xCEAD04F4, 0x127EA392, 0x10428DB7, 0x8272A972, 0x9270C4A8, 0x127DE50B,
				0x285BA1C8, 0x3C62F44F, 0x35C0EAA5, 0xE805D231, 0x428929FB, 0xB4FCDF82, 0x4FB66A53, 0x0E7DC15B,
				0x1F081FAB, 0x108618AE, 0xFCFD086D, 0xF9FF2889, 0x694BCC11, 0x236A5CAE, 0x12DECA4D, 0x2C3F8CC5,
				0xD2D02DFE, 0xF8EF5896, 0xE4CF52DA, 0x95155B67, 0x494A488C, 0xB9B6A80C, 0x5C8F82BC, 0x89D36B45,
				0x3A609437, 0xEC00C9A9, 0x44715253, 0x0A874B49, 0xD773BC40, 0x7C34671C, 0x02717EF6, 0x4FEB5536,
				0xA2D02FFF, 0xD2BF60C4, 0xD43F03C0, 0x50B4EF6D, 0x07478CD1, 0x006E1888, 0xA2E53F55, 0xB9E6D4BC,
				0xA2048016, 0x97573833, 0xD7207D67, 0xDE0F8F3D, 0x72F87B33, 0xABCC4F33, 0x7688C55D, 0x7B00A6B0,
				0x947B0001, 0x570075D2, 0xF9BB88F8, 0x8942019E, 0x4264A5FF, 0x856302E0, 0x72DBD92B, 0xEE971B69,
				0x6EA22FDE, 0x5F08AE2B, 0xAF7A616D, 0xE5C98767, 0xCF1FEBD2, 0x61EFC8C2, 0xF1AC2571, 0xCC8239C2,
				0x67214CB8, 0xB1E583D1, 0xB7DC3E62, 0x7F10BDCE, 0xF90A5C38, 0x0FF0443D, 0x606E6DC6, 0x60543A49,
				0x5727C148, 0x2BE98A1D, 0x8AB41738, 0x20E1BE24, 0xAF96DA0F, 0x68458425, 0x99833BE5, 0x600D457D,
				0x282F9350, 0x8334B362, 0xD91D1120, 0x2B6D8DA0, 0x642B1E31, 0x9C305A00, 0x52BCE688, 0x1B03588A,
				0xF7BAEFD5, 0x4142ED9C, 0xA4315C11, 0x83323EC5, 0xDFEF4636, 0xA133C501, 0xE9D3531C, 0xEE353783
			};
			static constexpr unsigned int S4[256] = {
				0x9DB30420, 0x1FB6E9DE, 0xA7BE7BEF, 0xD273A298, 0x4A4F7BDB, 0x64AD8C57, 0x85510443, 0xFA020ED1,
				0x7E287AFF, 0xE60FB663, 0x095F35A1, 0x79EBF120, 0xFD059D43, 0x6497B7B1, 0xF3641F63, 0x241E4ADF,
				0x28147F5F, 0x4FA2B8CD, 0xC9430040, 0x0CC32220, 0xFDD30B30, 0xC0A5374F, 0x1D2D00D9, 0x24147B15,
				0xEE4D111A, 0x0FCA5167, 0x71FF904C, 0x2D195FFE, 0x1A05645F, 0x0C13FEFE, 0x081B08CA, 0x05170121,
				0x80530100, 0xE83E5EFE, 0xAC9AF4F8, 0x7FE72701, 0xD2B8EE5F, 0x06DF4261, 0xBB9E9B8A, 0x7293EA25,
				0xCE84FFDF, 0xF5718801, 0x3DD64B04, 0xA26F263B, 0x7ED48400, 0x547EEBE6, 0x446D4CA0, 0x6CF3D6F5,
				0x2649ABDF, 0xAEA0C7F5, 0x36338CC1, 0x503F7E93, 0xD3772061, 0x11B638E1, 0x72500E03, 0xF80EB2BB,
				0xABE0502E, 0xEC8D77DE, 0x57971E81, 0xE14F6746, 0xC9335400, 0x6920318F, 0x081DBB99, 0xFFC304A5,
				0x4D351805, 0x7F3D5CE3, 0xA6C866C6, 0x5D5BCCA9, 0xDAEC6FEA, 0x9F926F91, 0x9F46222F, 0x3991467D,
				0xA5BF6D8E, 0x1143C44F, 0x43958302, 0xD0214EEB, 0x022083B8, 0x3FB6180C, 0x18F8931E, 0x281658E6,
				0x26486E3E, 0x8BD78A70, 0x7477E4C1, 0xB506E07C, 0xF32D0A25, 0x79098B02, 0xE4EABB81, 0x28123B23,
				0x69DEAD38, 0x1574CA16, 0xDF871B62, 0x211C40B7, 0xA51A9EF9, 0x0014377B, 0x041E8AC8, 0x09114003,
				0xBD59E4D2, 0xE3D156D5, 0x4FE876D5, 0x2F91A340, 0x557BE8DE, 0x00EAE4A7, 0x0CE5C2EC, 0x4DB4BBA6,
				0xE756BDFF, 0xDD3369AC, 0xEC17B035, 0x06572327, 0x99AFC8B0, 0x56C8C391, 0x6B65811C, 0x5E146119,
				0x6E85CB75, 0xBE07C002, 0xC2325577, 0x893FF4EC, 0x5BBFC92D, 0xD0EC3B25, 0xB7801AB7, 0x8D6D3B24,
				0x20C763EF, 0xC366A5FC, 0x9C382880, 0x0ACE3205, 0xAAC9548A, 0xECA1D7C7, 0x041AFA32, 0x1D16625A,
				0x6701902C, 0x9B757A54, 0x31D477F7, 0x9126B031, 0x36CC6FDB, 0xC70B8B46, 0xD9E66A48, 0x56E55A79,
				0x026A4CEB, 0x52437EFF, 0x2F8F76B4, 0x0DF980A5, 0x8674CDE3, 0xEDDA04EB, 0x17A9BE04, 0x2C18F4DF,
				0xB7747F9D, 0xAB2AF7B4, 0xEFC34D20, 0x2E096B7C, 0x1741A254, 0xE5B6A035, 0x213D42F6, 0x2C1C7C26,
				0x61C2F50F, 0x6552DAF9, 0xD2C231F8, 0x25130F69, 0xD8167FA2, 0x0418F2C8, 0x001A96A6, 0x0D1526AB,
				0x63315C21, 0x5E0A72EC, 0x49BAFEFD, 0x187908D9, 0x8D0DBD86, 0x311170A7, 0x3E9B640C, 0xCC3E10D7,
				0xD5CAD3B6, 0x0CAEC388, 0xF73001E1, 0x6C728AFF, 0x71EAE2A1, 0x1F9AF36E, 0xCFCBD12F, 0xC1DE8417,
				0xAC07BE6B, 0xCB44A1D8, 0x8B9B0F56, 0x013988C3, 0xB1C52FCA, 0xB4BE31CD, 0xD8782806, 0x12A3A4E2,
				0x6F7DE532, 0x58FD7EB6, 0xD01EE900, 0x24ADFFC2, 0xF4990FC5, 0x9711AAC5, 0x001D7B95, 0x82E5E7D2,
				0x109873F6, 0x00613096, 0xC32D9521, 0xADA121FF, 0x29908415, 0x7FBB977F, 0xAF9EB3DB, 0x29C9ED2A,
				0x5CE2A465, 0xA730F32C, 0xD0AA3FE8, 0x8A5CC091, 0xD49E2CE7, 0x0CE454A9, 0xD60ACD86, 0x015F1919,
				0x77079103, 0xDEA03AF6, 0x78A8565E, 0xDEE356DF, 0x21F05CBE, 0x8B75E387, 0xB3C50651, 0xB8A5C3EF,
				0xD8EEB6D2, 0xE523BE77, 0xC2154529, 0x2F69EFDF, 0xAFE67AFB, 0xF470C4B2, 0xF3E0EB5B, 0xD6CC9876,
				0x39E4460C, 0x1FDA8538, 0x1987832F, 0xCA007367, 0xA99144F8, 0x296B299E, 0x492FC295, 0x9266BEAB,
				0xB5676E69, 0x9BD3DDDA, 0xDF7E052F, 0xDB25701C, 0x1B5E51EE, 0xF65324E6, 0x6AFCE36C, 0x0316CC04,
				0x8644213E, 0xB7DC59D0, 0x7965291F, 0xCCD6FD43, 0x41823979, 0x932BCDF6, 0xB657C34D, 0x4EDFD282,
				0x7AE5290C, 0x3CB9536B, 0x851E20FE, 0x9833557E, 0x13ECF0B0, 0xD3FFB372, 0x3F85C5C1, 0x0AEF7ED2
			};
			unsigned int f1(unsigned int D, unsigned int Km, unsigned int Kr) const {
				unsigned int I = cast_rotl32(D + Km, Kr);
				return ((S1[(I >> 24) & 0xFF] ^ S2[(I >> 16) & 0xFF]) - S3[(I >> 8) & 0xFF]) + S4[I & 0xFF];
			}
			unsigned int f2(unsigned int D, unsigned int Km, unsigned int Kr) const {
				unsigned int I = cast_rotl32(D ^ Km, Kr);
				return ((S1[(I >> 24) & 0xFF] - S2[(I >> 16) & 0xFF]) +
				        S3[(I >> 8) & 0xFF]) ^ S4[I & 0xFF];
			}
			unsigned int f3(unsigned int D, unsigned int Km, unsigned int Kr) const {
				unsigned int I = cast_rotl32(D - Km, Kr);
				return ((S1[(I >> 24) & 0xFF] + S2[(I >> 16) & 0xFF]) ^
				        S3[(I >> 8) & 0xFF]) - S4[I & 0xFF];
			}
			unsigned int f(unsigned round, unsigned int R) const {
				const unsigned int Km = Km_[round];
				const unsigned int Kr = Kr_[round];
				switch (round % 3) {
					case 0:
						return f1(R, Km, Kr);
					case 1:
						return f2(R, Km, Kr);
					default:
						return f3(R, Km, Kr);
				}
			}
			void keySchedule(const unsigned char key[16]) {
				for (int i = 0; i < 16; ++i) {
					Km_[i] = ((unsigned int)key[(i * 4) % 16] << 24) | ((unsigned int)key[(i * 4 + 1) % 16] << 16) | ((unsigned int)key[(i * 4 + 2) % 16] << 8) | ((unsigned int)key[(i * 4 + 3) % 16]);
					Kr_[i] = (Km_[i] & 0x1F) + 1;
				}
				rounds_ = (keyBytes_ * 8 <= 80) ? 12 : 16;
			}
			unsigned int Km_[16] = {0};
			unsigned int Kr_[16] = {0};
			unsigned rounds_ = 16;
			size_t keyBytes_ = 0;
	};
	class CAST256 {
		public:
			static constexpr size_t BLOCK_SIZE = 16;
			static constexpr size_t MIN_KEY = 16;
			static constexpr size_t MAX_KEY = 32;
			CAST256() = default;
			void setKey(const unsigned char *key, size_t keyBytes) {
				if (keyBytes < MIN_KEY || keyBytes > MAX_KEY || (keyBytes % 4) != 0)throw std::invalid_argument("CAST?256 key length must be 16?32 bytes, multiple of 4");
				unsigned char k[32] = {0};
				std::memcpy(k, key, keyBytes);
				keySchedule(k);
			}
			void encryptBlock(const unsigned char *in, unsigned char *out) const {
				unsigned int A = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
				unsigned int B = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
				unsigned int C = (in[8] << 24) | (in[9] << 16) | (in[10] << 8) | in[11];
				unsigned int D = (in[12] << 24) | (in[13] << 16) | (in[14] << 8) | in[15];
				for (unsigned i = 0; i < 12; ++i) forwardQuadRound(i, A, B, C, D);
				for (int i = 11; i >= 0; --i) reverseQuadRound(i, A, B, C, D);
				out[0] = (A >> 24) & 0xFF;
				out[1] = (A >> 16) & 0xFF;
				out[2] = (A >> 8)  & 0xFF;
				out[3] =  A        & 0xFF;
				out[4] = (B >> 24) & 0xFF;
				out[5] = (B >> 16) & 0xFF;
				out[6] = (B >> 8)  & 0xFF;
				out[7] =  B        & 0xFF;
				out[8] = (C >> 24) & 0xFF;
				out[9] = (C >> 16) & 0xFF;
				out[10] = (C >> 8)  & 0xFF;
				out[11] =  C        & 0xFF;
				out[12] = (D >> 24) & 0xFF;
				out[13] = (D >> 16) & 0xFF;
				out[14] = (D >> 8)  & 0xFF;
				out[15] =  D        & 0xFF;
			}
			void decryptBlock(const unsigned char *in, unsigned char *out) const {
				unsigned int A = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
				unsigned int B = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
				unsigned int C = (in[8] << 24) | (in[9] << 16) | (in[10] << 8) | in[11];
				unsigned int D = (in[12] << 24) | (in[13] << 16) | (in[14] << 8) | in[15];
				for (int i = 0; i < 12; ++i) reverseQuadRound(i, A, B, C, D);
				for (int i = 11; i >= 0; --i) forwardQuadRound(i, A, B, C, D);
				out[0] = (A >> 24) & 0xFF;
				out[1] = (A >> 16) & 0xFF;
				out[2] = (A >> 8)  & 0xFF;
				out[3] =  A        & 0xFF;
				out[4] = (B >> 24) & 0xFF;
				out[5] = (B >> 16) & 0xFF;
				out[6] = (B >> 8)  & 0xFF;
				out[7] =  B        & 0xFF;
				out[8] = (C >> 24) & 0xFF;
				out[9] = (C >> 16) & 0xFF;
				out[10] = (C >> 8)  & 0xFF;
				out[11] =  C        & 0xFF;
				out[12] = (D >> 24) & 0xFF;
				out[13] = (D >> 16) & 0xFF;
				out[14] = (D >> 8)  & 0xFF;
				out[15] =  D        & 0xFF;
			}
		private:
			static constexpr unsigned int S1[256] = {
				0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a, 0x1e213f2f, 0x9c004dd3, 0x6003e540, 0xcf9fc949,
				0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675, 0x6e63a0e0, 0x15c361d2, 0xc2e7661d, 0x22d4ff8e,
				0x28683b6f, 0xc07fd059, 0xff2379c8, 0x775f50e2, 0x43c340d3, 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d,
				0xa1c9e0d6, 0x346c4819, 0x61b76d87, 0x22540f2f, 0x2abe32e1, 0xaa54166b, 0x22568e3a, 0xa2d341d0,
				0x66db40c8, 0xa784392f, 0x004dff2f, 0x2db9d2de, 0x97943fac, 0x4a97c1d8, 0x527644b7, 0xb5f437a7,
				0xb82cbaef, 0xd751d159, 0x6ff7f0ed, 0x5a097a1f, 0x827b68d0, 0x90ecf52e, 0x22b0c054, 0xbc8e5935,
				0x4b6d2f7f, 0x50bb64a2, 0xd2664910, 0xbee5812d, 0xb7332290, 0xe93b159f, 0xb48ee411, 0x4bff345d,
				0xfd45c240, 0xad31973f, 0xc4f6d02e, 0x55fc8165, 0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d, 0xc19b0c50,
				0x882240f2, 0x0c6e4f38, 0xa4e4bfd7, 0x4f5ba272, 0x564c1d2f, 0xc59c5319, 0xb949e354, 0xb04669fe,
				0xb1b6ab8a, 0xc71358dd, 0x6385c545, 0x110f935d, 0x57538ad5, 0x6a390493, 0xe63d37e0, 0x2a54f6b3,
				0x3a787d5f, 0x6276a0b5, 0x19a6fcdf, 0x7a42206a, 0x29f9d4d5, 0xf61b1891, 0xbb72275e, 0xaa508167,
				0x38901091, 0xc6b505eb, 0x84c7cb8c, 0x2ad75a0f, 0x874a1427, 0xa2d1936b, 0x2ad286af, 0xaa56d291,
				0xd7894360, 0x425c750d, 0x93b39e26, 0x187184c9, 0x6c00b32d, 0x73e2bb14, 0xa0bebc3c, 0x54623779,
				0x64459eab, 0x3f328b82, 0x7718cf82, 0x59a2cea6, 0x04ee002e, 0x89fe78e6, 0x3fab0950, 0x325ff6c2,
				0x81383f05, 0x6963c5c8, 0x76cb5ad6, 0xd49974c9, 0xca180dcf, 0x380782d5, 0xc7fa5cf6, 0x8ac31511,
				0x35e79e13, 0x47da91d0, 0xf40f9086, 0xa7e2419e, 0x31366241, 0x051ef495, 0xaa573b04, 0x4a805d8d,
				0x548300d0, 0x00322a3c, 0xbf64cddf, 0xba57a68e, 0x75c6372b, 0x50afd341, 0xa7c13275, 0x915a0bf5,
				0x6b54bfab, 0x2b0b1426, 0xab4cc9d7, 0x449ccd82, 0xf7fbf265, 0xab85c5f3, 0x1b55db94, 0xaad4e324,
				0xcfa4bd3f, 0x2deaa3e2, 0x9e204d02, 0xc8bd25ac, 0xeadf55b3, 0xd5bd9e98, 0xe31231b2, 0x2ad5ad6c,
				0x954329de, 0xadbe4528, 0xd8710f69, 0xaa51c90f, 0xaa786bf6, 0x22513f1e, 0xaa51a79b, 0xa2d344cc,
				0x7b5a41f0, 0xd37cfbad, 0x1b069505, 0x41ece491, 0xb4c332e6, 0x032268d4, 0xc9600acc, 0xce387e6d,
				0xbf6bb16c, 0x6a70fb78, 0x0d03d9c9, 0xd4df39de, 0xe01063da, 0x4736f464, 0x5ad328d8, 0xb347cc96,
				0x75bb0fc3, 0x98511bfb, 0x4ffbcc35, 0xb58bcf6a, 0xe11f0abc, 0xbfc5fe4a, 0xa70aec10, 0xac39570a,
				0x3f04442f, 0x6188b153, 0xe0397a2e, 0x5727cb79, 0x9ceb418f, 0x1cacd68d, 0x2ad37c96, 0x0175cb9d,
				0xc69dff09, 0xc75b65f0, 0xd9db40d8, 0xec0e7779, 0x4744ead4, 0xb11c3274, 0xdd24cb9e, 0x7e1c54bd,
				0xf01144f9, 0xd2240eb1, 0x9675b3fd, 0xa3ac3755, 0xd47c27af, 0x51c85f4d, 0x56907596, 0xa5bb15e6,
				0x580304f0, 0xca042cf1, 0x011a37ea, 0x8dbfaadb, 0x35ba3e4a, 0x3526ffa0, 0xc37b4d09, 0xbc306ed9,
				0x98a52666, 0x5648f725, 0xff5e569d, 0x0ced63d0, 0x7c63b2cf, 0x700b45e1, 0xd5ea50f1, 0x85a92872,
				0xaf1fbda7, 0xd4234870, 0xa7870bf3, 0x2d3b4d79, 0x42e04198, 0x0cd0ede7, 0x26470db8, 0xf881814c,
				0x474d6ad7, 0x7c0c5e5c, 0xd1231959, 0x381b7298, 0xf5d2f4db, 0xab838653, 0x6e2f1e23, 0x83719c9e,
				0xbd91e046, 0x9a56456e, 0xdc39200c, 0x20c8c571, 0x962bda1c, 0xe1e696ff, 0xb141ab08, 0x7cca89b9,
				0x1a69e783, 0x02cc4843, 0xa2f7c579, 0x429ef47d, 0x427b169c, 0x5ac9f049, 0xdd8f0f00, 0x5c8165bf
			};
			static constexpr unsigned int S2[256] = {
				0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380, 0xfe61cf7a, 0xeec5207a, 0x55889c94, 0x72fc0651,
				0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba, 0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3,
				0xa0b52f7b, 0x59e83605, 0xee15b094, 0xe9ffd909, 0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb,
				0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b, 0x01420ddb, 0xe4e7ef5b, 0x25a1ff41, 0xe180f806,
				0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4, 0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b,
				0xe113c85b, 0xacc40083, 0xd7503525, 0xf7ea615f, 0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359,
				0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21, 0x071f6181, 0x39f7627f, 0x361e3084, 0xe4eb573b,
				0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d, 0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c,
				0x10843094, 0x2537a95e, 0xf46f6ffe, 0xa1ff3b1f, 0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34,
				0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d, 0x8a45388c, 0x1d804366, 0x721d9bfd, 0xa58684bb,
				0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4, 0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd,
				0xc5d655dd, 0xeb667064, 0x77840b4d, 0xa1b6a801, 0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860,
				0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755, 0xb5625dbf, 0x68561be6, 0x83ca6b94, 0x2d6ed23b,
				0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709, 0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304,
				0x81ed6f61, 0x20e74364, 0xb45e1378, 0xde18639b, 0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b,
				0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c, 0x488cb402, 0x1ba4fe5b, 0xa4b09f6b, 0x1ca815cf,
				0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9, 0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c,
				0xee41e729, 0x6e1d2d7c, 0x50045286, 0x1e6685f3, 0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13,
				0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9, 0xcdff33a6, 0xa02b1741, 0x7cbad9a2, 0x2180036f,
				0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab, 0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6,
				0xcdf0b680, 0x17844d3b, 0x31eef84d, 0x7e0824e4, 0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6,
				0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43, 0xb3faec54, 0x157fd7fa, 0xef8579cc, 0xd152de58,
				0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8, 0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906,
				0xb8da230c, 0x80823028, 0xdcdef3c8, 0xd35fb171, 0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d,
				0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89, 0x8b1c34bc, 0x301e16e6, 0x273be979, 0xb0ffeaa6,
				0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b, 0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4,
				0xdc8637a0, 0x16a7d3b1, 0x9fc393b7, 0xa7136eeb, 0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6,
				0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e, 0xdb92f2fb, 0x5eea29cb, 0x145892f5, 0x91584f7f,
				0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea, 0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249,
				0xb284600c, 0xd835731d, 0xdcb1c647, 0xac4c56ea, 0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa,
				0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd, 0x649da589, 0xa345415e, 0x5c038323, 0x3e5d3bb9,
				0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef, 0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1
			};
			static constexpr unsigned int S3[256] = {
				0x8defc240, 0x25fa5d9f, 0xeb903dbf, 0xe810c907, 0x47607fff, 0x369fe44b, 0x8c1fc644, 0xaececa90,
				0xbeb1f9bf, 0xeefbcaea, 0xe8cf1950, 0x51df07ae, 0x920e8806, 0xf0ad0548, 0xe13c8d83, 0x927010d5,
				0x11107d9f, 0x07647db9, 0xb2e3e4d4, 0x3d4f285e, 0xb9afa820, 0xfade82e0, 0xa067268b, 0x8272792e,
				0x553fb2c0, 0x489ae22b, 0xd4ef9794, 0x125e3fbc, 0x21fffcee, 0x825b1bfd, 0x9255c5ed, 0x1257a240,
				0x4e1a8302, 0xbae07fff, 0x528246e7, 0x8e57140e, 0x3373f7bf, 0x8c9f8188, 0xa6fc4ee8, 0xc982b5a5,
				0xa8c01db7, 0x579fc264, 0x67094f31, 0xf2bd3f5f, 0x40fff7c1, 0x1fb78dfc, 0x8e6bd2c1, 0x437be59b,
				0x99b03dbf, 0xb5dbc64b, 0x638dc0e6, 0x55819d99, 0xa197c81c, 0x4a012d6e, 0xc5884a28, 0xccc36f71,
				0xb843c213, 0x6c0743f1, 0x8309893c, 0x0feddd5f, 0x2f7fe850, 0xd7c07f7e, 0x02507fbf, 0x5afb9a04,
				0xa747d2d0, 0x1651192e, 0xaf70bf3e, 0x58c31380, 0x5f98302e, 0x727cc3c4, 0x0a0fb402, 0x0f7fef82,
				0x8c96fdad, 0x5d2c2aae, 0x8ee99a49, 0x50da88b8, 0x8427f4a0, 0x1eac5790, 0x796fb449, 0x8252dc15,
				0xefbd7d9b, 0xa672597d, 0xada840d8, 0x45f54504, 0xfa5d7403, 0xe83ec305, 0x4f91751a, 0x925669c2,
				0x23efe941, 0xa903f12e, 0x60270df2, 0x0276e4b6, 0x94fd6574, 0x927985b2, 0x8276dbcb, 0x02778176,
				0xf8af918d, 0x4e48f79e, 0x8f616ddf, 0xe29d840e, 0x842f7d83, 0x340ce5c8, 0x96bbb682, 0x93b4b148,
				0xef303cab, 0x984faf28, 0x779faf9b, 0x92dc560d, 0x224d1e20, 0x8437aa88, 0x7d29dc96, 0x2756d3dc,
				0x8b907cee, 0xb51fd240, 0xe7c07ce3, 0xe566b4a1, 0xc3e9615e, 0x3cf8209d, 0x6094d1e3, 0xcd9ca341,
				0x5c76460e, 0x00ea983b, 0xd4d67881, 0xfd47572c, 0xf76cedd9, 0xbda8229c, 0x127dadaa, 0x438a074e,
				0x1f97c090, 0x081bdb8a, 0x93a07ebe, 0xb938ca15, 0x97b03cff, 0x3dc2c0f8, 0x8d1ab2ec, 0x64380e51,
				0x68cc7bfb, 0xd90f2788, 0x12490181, 0x5de5ffd4, 0xdd7ef86a, 0x76a2e214, 0xb9a40368, 0x925d958f,
				0x4b39fffa, 0xba39aee9, 0xa4ffd30b, 0xfaf7933b, 0x6d498623, 0x193cbcfa, 0x27627545, 0x825cf47a,
				0x61bd8ba0, 0xd11e42d1, 0xcead04f4, 0x127ea392, 0x10428db7, 0x8272a972, 0x9270c4a8, 0x127de50b,
				0x285ba1c8, 0x3c62f44f, 0x35c0eaa5, 0xe805d231, 0x428929fb, 0xb4fcdf82, 0x4fb66a53, 0x0e7dc15b,
				0x1f081fab, 0x108618ae, 0xfcfd086d, 0xf9ff2889, 0x694bcc11, 0x236a5cae, 0x12deca4d, 0x2c3f8cc5,
				0xd2d02dfe, 0xf8ef5896, 0xe4cf52da, 0x95155b67, 0x494a488c, 0xb9b6a80c, 0x5c8f82bc, 0x89d36b45,
				0x3a609437, 0xec00c9a9, 0x44715253, 0x0a874b49, 0xd773bc40, 0x7c34671c, 0x02717ef6, 0x4feb5536,
				0xa2d02fff, 0xd2bf60c4, 0xd43f03c0, 0x50b4ef6d, 0x07478cd1, 0x006e1888, 0xa2e53f55, 0xb9e6d4bc,
				0xa2048016, 0x97573833, 0xd7207d67, 0xde0f8f3d, 0x72f87b33, 0xabcc4f33, 0x7688c55d, 0x7b00a6b0,
				0x947b0001, 0x570075d2, 0xf9bb88f8, 0x8942019e, 0x4264a5ff, 0x856302e0, 0x72dbd92b, 0xee971b69,
				0x6ea22fde, 0x5f08ae2b, 0xaf7a616d, 0xe5c98767, 0xcf1febd2, 0x61efc8c2, 0xf1ac2571, 0xcc8239c2,
				0x67214cb8, 0xb1e583d1, 0xb7dc3e62, 0x7f10bdce, 0xf90a5c38, 0x0ff0443d, 0x606e6dc6, 0x60543a49,
				0x5727c148, 0x2be98a1d, 0x8ab41738, 0x20e1be24, 0xaf96da0f, 0x68458425, 0x99833be5, 0x600d457d,
				0x282f9350, 0x8334b362, 0xd91d1120, 0x2b6d8da0, 0x642b1e31, 0x9c305a00, 0x52bce688, 0x1b03588a,
				0xf7baefd5, 0x4142ed9c, 0xa4315c11, 0x83323ec5, 0xdfef4636, 0xa133c501, 0xe9d3531c, 0xee353783
			};
			static constexpr unsigned int S4[256] = {
				0x9db30420, 0x1fb6e9de, 0xa7be7bef, 0xd273a298, 0x4a4f7bdb, 0x64ad8c57, 0x85510443, 0xfa020ed1,
				0x7e287aff, 0xe60fb663, 0x095f35a1, 0x79ebf120, 0xfd059d43, 0x6497b7b1, 0xf3641f63, 0x241e4adf,
				0x28147f5f, 0x4fa2b8cd, 0xc9430040, 0x0cc32220, 0xfdd30b30, 0xc0a5374f, 0x1d2d00d9, 0x24147b15,
				0xee4d111a, 0x0fca5167, 0x71ff904c, 0x2d195ffe, 0x1a05645f, 0x0c13fefe, 0x081b08ca, 0x05170121,
				0x80530100, 0xe83e5efe, 0xac9af4f8, 0x7fe72701, 0xd2b8ee5f, 0x06df4261, 0xbb9e9b8a, 0x7293ea25,
				0xce84ffdf, 0xf5718801, 0x3dd64b04, 0xa26f263b, 0x7ed48400, 0x547eebe6, 0x446d4ca0, 0x6cf3d6f5,
				0x2649abdf, 0xaea0c7f5, 0x36338cc1, 0x503f7e93, 0xd3772061, 0x11b638e1, 0x72500e03, 0xf80eb2bb,
				0xabe0502e, 0xec8d77de, 0x57971e81, 0xe14f6746, 0xc9335400, 0x6920318f, 0x081dbb99, 0xffc304a5,
				0x4d351805, 0x7f3d5ce3, 0xa6c866c6, 0x5d5bcca9, 0xdaec6fea, 0x9f926f91, 0x9f46222f, 0x3991467d,
				0xa5bf6d8e, 0x1143c44f, 0x43958302, 0xd0214eeb, 0x022083b8, 0x3fb6180c, 0x18f8931e, 0x281658e6,
				0x26486e3e, 0x8bd78a70, 0x7477e4c1, 0xb506e07c, 0xf32d0a25, 0x79098b02, 0xe4eabb81, 0x28123b23,
				0x69dead38, 0x1574ca16, 0xdf871b62, 0x211c40b7, 0xa51a9ef9, 0x0014377b, 0x041e8ac8, 0x09114003,
				0xbd59e4d2, 0xe3d156d5, 0x4fe876d5, 0x2f91a340, 0x557be8de, 0x00eae4a7, 0x0ce5c2ec, 0x4db4bba6,
				0xe756bdff, 0xdd3369ac, 0xec17b035, 0x06572327, 0x99afc8b0, 0x56c8c391, 0x6b65811c, 0x5e146119,
				0x6e85cb75, 0xbe07c002, 0xc2325577, 0x893ff4ec, 0x5bbfc92d, 0xd0ec3b25, 0xb7801ab7, 0x8d6d3b24,
				0x20c763ef, 0xc366a5fc, 0x9c382880, 0x0ace3205, 0xaac9548a, 0xeca1d7c7, 0x041afa32, 0x1d16625a,
				0x6701902c, 0x9b757a54, 0x31d477f7, 0x9126b031, 0x36cc6fdb, 0xc70b8b46, 0xd9e66a48, 0x56e55a79,
				0x026a4ceb, 0x52437eff, 0x2f8f76b4, 0x0df980a5, 0x8674cde3, 0xedda04eb, 0x17a9be04, 0x2c18f4df,
				0xb7747f9d, 0xab2af7b4, 0xefc34d20, 0x2e096b7c, 0x1741a254, 0xe5b6a035, 0x213d42f6, 0x2c1c7c26,
				0x61c2f50f, 0x6552daf9, 0xd2c231f8, 0x25130f69, 0xd8167fa2, 0x0418f2c8, 0x001a96a6, 0x0d1526ab,
				0x63315c21, 0x5e0a72ec, 0x49bafefd, 0x187908d9, 0x8d0dbd86, 0x311170a7, 0x3e9b640c, 0xcc3e10d7,
				0xd5cad3b6, 0x0caec388, 0xf73001e1, 0x6c728aff, 0x71eae2a1, 0x1f9af36e, 0xcfcbd12f, 0xc1de8417,
				0xac07be6b, 0xcb44a1d8, 0x8b9b0f56, 0x013988c3, 0xb1c52fca, 0xb4be31cd, 0xd8782806, 0x12a3a4e2,
				0x6f7de532, 0x58fd7eb6, 0xd01ee900, 0x24adffc2, 0xf4990fc5, 0x9711aac5, 0x001d7b95, 0x82e5e7d2,
				0x109873f6, 0x00613096, 0xc32d9521, 0xada121ff, 0x29908415, 0x7fbb977f, 0xaf9eb3db, 0x29c9ed2a,
				0x5ce2a465, 0xa730f32c, 0xd0aa3fe8, 0x8a5cc091, 0xd49e2ce7, 0x0ce454a9, 0xd60acd86, 0x015f1919,
				0x77079103, 0xdea03af6, 0x78a8565e, 0xdee356df, 0x21f05cbe, 0x8b75e387, 0xb3c50651, 0xb8a5c3ef,
				0xd8eeb6d2, 0xe523be77, 0xc2154529, 0x2f69efdf, 0xafe67afb, 0xf470c4b2, 0xf3e0eb5b, 0xd6cc9876,
				0x39e4460c, 0x1fda8538, 0x1987832f, 0xca007367, 0xa99144f8, 0x296b299e, 0x492fc295, 0x9266beab,
				0xb5676e69, 0x9bd3ddda, 0xdf7e052f, 0xdb25701c, 0x1b5e51ee, 0xf65324e6, 0x6afce36c, 0x0316cc04,
				0x8644213e, 0xb7dc59d0, 0x7965291f, 0xcc6fd43, 0x41823979, 0x932bcdf6, 0xb657c34d, 0x4edfd282,
				0x7ae5290c, 0x3cb9536b, 0x851e20fe, 0x9833557e, 0x13ecf0b0, 0xd3ffb372, 0x3f85c5c1, 0x0aef7ed2
			};
			unsigned int f1(unsigned int D, unsigned int Km, unsigned int Kr) const {
				unsigned int I = cast_rotl32(D + Km, Kr);
				return ((S1[(I >> 24) & 0xFF] ^ S2[(I >> 16) & 0xFF]) -
				        S3[(I >> 8) & 0xFF]) + S4[I & 0xFF];
			}
			unsigned int f2(unsigned int D, unsigned int Km, unsigned int Kr) const {
				unsigned int I = cast_rotl32(D ^ Km, Kr);
				return ((S1[(I >> 24) & 0xFF] - S2[(I >> 16) & 0xFF]) +
				        S3[(I >> 8) & 0xFF]) ^ S4[I & 0xFF];
			}
			unsigned int f3(unsigned int D, unsigned int Km, unsigned int Kr) const {
				unsigned int I = cast_rotl32(D - Km, Kr);
				return ((S1[(I >> 24) & 0xFF] + S2[(I >> 16) & 0xFF]) ^
				        S3[(I >> 8) & 0xFF]) - S4[I & 0xFF];
			}
			void forwardQuadRound(unsigned i, unsigned int &A, unsigned int &B, unsigned int &C, unsigned int &D) const {
				D ^= f1(A, Km_[4 * i + 0], Kr_[4 * i + 0]);
				C ^= f2(D, Km_[4 * i + 1], Kr_[4 * i + 1]);
				B ^= f3(C, Km_[4 * i + 2], Kr_[4 * i + 2]);
				A ^= f1(B, Km_[4 * i + 3], Kr_[4 * i + 3]);
			}
			void reverseQuadRound(unsigned i,
			                      unsigned int &A, unsigned int &B,
			                      unsigned int &C, unsigned int &D) const {
				A ^= f1(B, Km_[4 * i + 3], Kr_[4 * i + 3]);
				B ^= f3(C, Km_[4 * i + 2], Kr_[4 * i + 2]);
				C ^= f2(D, Km_[4 * i + 1], Kr_[4 * i + 1]);
				D ^= f1(A, Km_[4 * i + 0], Kr_[4 * i + 0]);
			}
			void keySchedule(const unsigned char key[32]) {
				for (int i = 0; i < 48; ++i) {
					Km_[i] = ((unsigned int)key[(i * 4) % 32] << 24) |
					         ((unsigned int)key[(i * 4 + 1) % 32] << 16) |
					         ((unsigned int)key[(i * 4 + 2) % 32] << 8) |
					         ((unsigned int)key[(i * 4 + 3) % 32]);
					Kr_[i] = (Km_[i] & 0x1F) + 1;
				}
			}
			unsigned int Km_[48] = {0};
			unsigned int Kr_[48] = {0};
	};
#	ifdef __cplusplus
#	endif
#	define SHA1_BLOCK_SIZE 64
#	define SHA1_HASH_SIZE 20
	typedef struct {
		unsigned int h[5];
		unsigned long long int total_length;
		unsigned char buffer[SHA1_BLOCK_SIZE];
		size_t buffer_size;
	} SHA1_CTX;
	void sha1_init(SHA1_CTX* ctx);
	void sha1_update(SHA1_CTX* ctx, const unsigned char* data, size_t length);
	void sha1_final(SHA1_CTX* ctx, unsigned char* hash);
	void sha0_init(SHA1_CTX* ctx);
	void sha0_update(SHA1_CTX* ctx, const unsigned char* data, size_t length);
	void sha0_final(SHA1_CTX* ctx, unsigned char* hash);
#	define SHA256_BLOCK_SIZE 64
#	define SHA224_HASH_SIZE 28
#	define SHA256_HASH_SIZE 32
	typedef struct {
		unsigned int h[8];
		unsigned long long int total_length;
		unsigned char buffer[SHA256_BLOCK_SIZE];
		size_t buffer_size;
	} SHA256_CTX;
	void sha256_init(SHA256_CTX* ctx);
	void sha224_init(SHA256_CTX* ctx);
	void sha256_update(SHA256_CTX* ctx, const unsigned char* data, size_t length);
	void sha256_final(SHA256_CTX* ctx, unsigned char* hash);
	void sha224_final(SHA256_CTX* ctx, unsigned char* hash);
#	define SHA512_BLOCK_SIZE 128
#	define SHA384_HASH_SIZE 48
#	define SHA512_HASH_SIZE 64
	typedef struct {
		unsigned long long int h[8];
		unsigned long long int total_length[2];
		unsigned char buffer[SHA512_BLOCK_SIZE];
		size_t buffer_size;
	} SHA512_CTX;
	void sha512_init(SHA512_CTX* ctx);
	void sha384_init(SHA512_CTX* ctx);
	void sha512_update(SHA512_CTX* ctx, const unsigned char* data, size_t length);
	void sha512_final(SHA512_CTX* ctx, unsigned char* hash);
	void sha384_final(SHA512_CTX* ctx, unsigned char* hash);
	void sha256_224_init(SHA256_CTX* ctx);
	void sha256_224_update(SHA256_CTX* ctx, const unsigned char* data, size_t length);
	void sha256_224_final(SHA256_CTX* ctx, unsigned char* hash);
	void sha512_224_init(SHA512_CTX* ctx);
	void sha512_224_update(SHA512_CTX* ctx, const unsigned char* data, size_t length);
	void sha512_224_final(SHA512_CTX* ctx, unsigned char* hash);
	void sha512_256_init(SHA512_CTX* ctx);
	void sha512_256_update(SHA512_CTX* ctx, const unsigned char* data, size_t length);
	void sha512_256_final(SHA512_CTX* ctx, unsigned char* hash);
	void sha1_224_init(SHA1_CTX* ctx);
	void sha1_224_update(SHA1_CTX* ctx, const unsigned char* data, size_t length);
	void sha1_224_final(SHA1_CTX* ctx, unsigned char* hash);
	void sha256d_init(SHA256_CTX* ctx);
	void sha256d_update(SHA256_CTX* ctx, const unsigned char* data, size_t length);
	void sha256d_final(SHA256_CTX* ctx, unsigned char* hash);
#	define SHA3_224_RATE 144
#	define SHA3_256_RATE 136
#	define SHA3_384_RATE 104
#	define SHA3_512_RATE 72
#	define SHAKE128_RATE 168
#	define SHAKE256_RATE 136
#	define SHA3_224_HASH_SIZE 28
#	define SHA3_256_HASH_SIZE 32
#	define SHA3_384_HASH_SIZE 48
#	define SHA3_512_HASH_SIZE 64
	typedef struct {
		unsigned long long int state[25];
		size_t rate;
		unsigned char buffer[200];
		size_t buffer_size;
	} SHA3_CTX;
	void sha3_224_init(SHA3_CTX* ctx);
	void sha3_256_init(SHA3_CTX* ctx);
	void sha3_384_init(SHA3_CTX* ctx);
	void sha3_512_init(SHA3_CTX* ctx);
	void shake128_init(SHA3_CTX* ctx);
	void shake256_init(SHA3_CTX* ctx);
	void sha3_update(SHA3_CTX* ctx, const unsigned char* data, size_t length);
	void sha3_final(SHA3_CTX* ctx, unsigned char* hash, size_t hash_size);
	void shake_final(SHA3_CTX* ctx, unsigned char* hash, size_t hash_size);
#	define CSHAKE128_RATE 168
#	define CSHAKE256_RATE 136
	typedef struct {
		SHA3_CTX sha3_ctx;
		unsigned char* n;
		size_t n_len;
		unsigned char* s;
		size_t s_len;
		int initialized;
	} CSHAKE_CTX;
	void cshake128_init(CSHAKE_CTX* ctx, const unsigned char* n, size_t n_len, const unsigned char* s, size_t s_len);
	void cshake256_init(CSHAKE_CTX* ctx, const unsigned char* n, size_t n_len, const unsigned char* s, size_t s_len);
	void cshake_update(CSHAKE_CTX* ctx, const unsigned char* data, size_t length);
	void cshake_final(CSHAKE_CTX* ctx, unsigned char* hash, size_t hash_size);
#	define KMAC128_RATE 168
#	define KMAC256_RATE 136
	typedef struct {
		CSHAKE_CTX cshake_ctx;
		unsigned char* key;
		size_t key_len;
	} KMAC_CTX;
	void kmac128_init(KMAC_CTX* ctx, const unsigned char* key, size_t key_len, const unsigned char* s, size_t s_len);
	void kmac256_init(KMAC_CTX* ctx, const unsigned char* key, size_t key_len, const unsigned char* s, size_t s_len);
	void kmac_update(KMAC_CTX* ctx, const unsigned char* data, size_t length);
	void kmac_final(KMAC_CTX* ctx, unsigned char* hash, size_t hash_size);
#	define HMAC_MAX_BLOCK_SIZE 128
	typedef struct {
		union {
			SHA1_CTX sha1_ctx;
			SHA256_CTX sha256_ctx;
			SHA512_CTX sha512_ctx;
			SHA3_CTX sha3_ctx;
		} hash_ctx;
		unsigned char inner_key[HMAC_MAX_BLOCK_SIZE];
		unsigned char outer_key[HMAC_MAX_BLOCK_SIZE];
		size_t block_size;
		size_t hash_size;
		void (*hash_init)(void*);
		void (*hash_update)(void*, const unsigned char*, size_t);
		void (*hash_final)(void*, unsigned char*);
	} HMAC_CTX;
	void hmac_sha1_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha224_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha256_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha384_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha512_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha3_224_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha3_256_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha3_384_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_sha3_512_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len);
	void hmac_update(HMAC_CTX* ctx, const unsigned char* data, size_t length);
	void hmac_final(HMAC_CTX* ctx, unsigned char* hash);
	void pbkdf2_hmac_sha1(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len);
	void pbkdf2_hmac_sha224(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len);
	void pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len);
	void pbkdf2_hmac_sha384(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len);
	void pbkdf2_hmac_sha512(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len);
#	define RSA_MAX_SIGNATURE_SIZE 512
	typedef struct {
		unsigned char* private_key;
		size_t private_key_len;
		unsigned char* public_key;
		size_t public_key_len;
		void (*hash_init)(void*);
		void (*hash_update)(void*, const unsigned char*, size_t);
		void (*hash_final)(void*, unsigned char*);
		size_t hash_size;
	} RSA_CTX;
	void rsa_sha1_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len);
	void rsa_sha224_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len);
	void rsa_sha256_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len);
	void rsa_sha384_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len);
	void rsa_sha512_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len);
	void rsa_sha3_256_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len);
	size_t rsa_sign(RSA_CTX* ctx, const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len);
	int rsa_verify(RSA_CTX* ctx, const unsigned char* data, size_t data_len, const unsigned char* signature, size_t signature_len);
#ifdef __cplusplus
#endif
	static inline unsigned int rotate_left32(unsigned int x, int n) {
		return (x << n) | (x >> (32 - n));
	}
	static inline unsigned long long int rotate_left64(unsigned long long int x, int n) {
		return (x << n) | (x >> (64 - n));
	}
	static inline unsigned int rotate_right32(unsigned int x, int n) {
		return (x >> n) | (x << (32 - n));
	}
	static inline unsigned long long int rotate_right64(unsigned long long int x, int n) {
		return (x >> n) | (x << (64 - n));
	}
	static inline unsigned int ch(unsigned int x, unsigned int y, unsigned int z) {
		return (x & y) ^ (~x & z);
	}
	static inline unsigned int maj(unsigned int x, unsigned int y, unsigned int z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}
	static inline unsigned int sigma0_256(unsigned int x) {
		return rotate_right32(x, 2) ^ rotate_right32(x, 13) ^ rotate_right32(x, 22);
	}
	static inline unsigned int sigma1_256(unsigned int x) {
		return rotate_right32(x, 6) ^ rotate_right32(x, 11) ^ rotate_right32(x, 25);
	}
	static inline unsigned int gamma0_256(unsigned int x) {
		return rotate_right32(x, 7) ^ rotate_right32(x, 18) ^ (x >> 3);
	}
	static inline unsigned int gamma1_256(unsigned int x) {
		return rotate_right32(x, 17) ^ rotate_right32(x, 19) ^ (x >> 10);
	}
	static inline unsigned long long int ch64(unsigned long long int x, unsigned long long int y, unsigned long long int z) {
		return (x & y) ^ (~x & z);
	}
	static inline unsigned long long int maj64(unsigned long long int x, unsigned long long int y, unsigned long long int z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}
	static inline unsigned long long int sigma0_512(unsigned long long int x) {
		return rotate_right64(x, 28) ^ rotate_right64(x, 34) ^ rotate_right64(x, 39);
	}
	static inline unsigned long long int sigma1_512(unsigned long long int x) {
		return rotate_right64(x, 14) ^ rotate_right64(x, 18) ^ rotate_right64(x, 41);
	}
	static inline unsigned long long int gamma0_512(unsigned long long int x) {
		return rotate_right64(x, 1) ^ rotate_right64(x, 8) ^ (x >> 7);
	}
	static inline unsigned long long int gamma1_512(unsigned long long int x) {
		return rotate_right64(x, 19) ^ rotate_right64(x, 61) ^ (x >> 6);
	}
	static const unsigned int sha1_k[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
	static const unsigned int sha256_k[64] = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};
	static const unsigned long long int sha512_k[80] = {
		0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
		0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
		0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
		0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
		0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
		0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
		0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
		0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
		0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
		0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
		0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
		0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
		0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
		0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
		0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
		0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
		0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
		0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
		0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
		0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
	};
	static const unsigned long long int sha3_rndc[24] = {
		0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
		0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
		0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
		0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
		0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
		0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
	};
	static const int sha3_rotc[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
	static const int sha3_piln[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
	void sha1_init(SHA1_CTX* ctx) {
		ctx->h[0] = 0x67452301;
		ctx->h[1] = 0xEFCDAB89;
		ctx->h[2] = 0x98BADCFE;
		ctx->h[3] = 0x10325476;
		ctx->h[4] = 0xC3D2E1F0;
		ctx->total_length = 0;
		ctx->buffer_size = 0;
	}
	void sha1_transform(SHA1_CTX* ctx, const unsigned char* block, int is_sha0) {
		unsigned int w[80];
		unsigned int a, b, c, d, e, temp;
		int i;
		for (i = 0; i < 16; i++) {
			w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
		}
		for (i = 16; i < 80; i++) {
			w[i] = rotate_left32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
			if (!is_sha0) {
				w[i] ^= rotate_left32(w[i], 1);
			}
		}
		a = ctx->h[0];
		b = ctx->h[1];
		c = ctx->h[2];
		d = ctx->h[3];
		e = ctx->h[4];
		for (i = 0; i < 20; i++) {
			temp = rotate_left32(a, 5) + ((b & c) | (~b & d)) + e + sha1_k[0] + w[i];
			e = d;
			d = c;
			c = rotate_left32(b, 30);
			b = a;
			a = temp;
		}
		for (i = 20; i < 40; i++) {
			temp = rotate_left32(a, 5) + (b ^ c ^ d) + e + sha1_k[1] + w[i];
			e = d;
			d = c;
			c = rotate_left32(b, 30);
			b = a;
			a = temp;
		}
		for (i = 40; i < 60; i++) {
			temp = rotate_left32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + sha1_k[2] + w[i];
			e = d;
			d = c;
			c = rotate_left32(b, 30);
			b = a;
			a = temp;
		}
		for (i = 60; i < 80; i++) {
			temp = rotate_left32(a, 5) + (b ^ c ^ d) + e + sha1_k[3] + w[i];
			e = d;
			d = c;
			c = rotate_left32(b, 30);
			b = a;
			a = temp;
		}
		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
		ctx->h[4] += e;
	}
	void sha1_update(SHA1_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk_size = (SHA1_BLOCK_SIZE - ctx->buffer_size);
			if (chunk_size > length) {
				chunk_size = length;
			}
			memcpy(ctx->buffer + ctx->buffer_size, data, chunk_size);
			ctx->buffer_size += chunk_size;
			data += chunk_size;
			length -= chunk_size;
			if (ctx->buffer_size == SHA1_BLOCK_SIZE) {
				sha1_transform(ctx, ctx->buffer, 0);
				ctx->total_length += SHA1_BLOCK_SIZE * 8;
				ctx->buffer_size = 0;
			}
		}
	}
	void sha1_final(SHA1_CTX* ctx, unsigned char* hash) {
		size_t padding_length = SHA1_BLOCK_SIZE - ctx->buffer_size;
		if (padding_length < 9) {
			padding_length += SHA1_BLOCK_SIZE;
		}
		unsigned char padding[padding_length];
		memset(padding, 0, padding_length);
		padding[0] = 0x80;
		unsigned long long int total_bits = ctx->total_length + ctx->buffer_size * 8;
		for (int i = 0; i < 8; i++) {
			padding[padding_length - 8 + i] = (unsigned char)(total_bits >> (56 - i * 8));
		}
		sha1_update(ctx, padding, padding_length);
		for (int i = 0; i < 5; i++) {
			hash[i * 4] = (unsigned char)(ctx->h[i] >> 24);
			hash[i * 4 + 1] = (unsigned char)(ctx->h[i] >> 16);
			hash[i * 4 + 2] = (unsigned char)(ctx->h[i] >> 8);
			hash[i * 4 + 3] = (unsigned char)ctx->h[i];
		}
	}
	void sha0_init(SHA1_CTX* ctx) {
		sha1_init(ctx);
	}
	void sha0_update(SHA1_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk_size = (SHA1_BLOCK_SIZE - ctx->buffer_size);
			if (chunk_size > length) {
				chunk_size = length;
			}
			memcpy(ctx->buffer + ctx->buffer_size, data, chunk_size);
			ctx->buffer_size += chunk_size;
			data += chunk_size;
			length -= chunk_size;
			if (ctx->buffer_size == SHA1_BLOCK_SIZE) {
				sha1_transform(ctx, ctx->buffer, 1);
				ctx->total_length += SHA1_BLOCK_SIZE * 8;
				ctx->buffer_size = 0;
			}
		}
	}
	void sha0_final(SHA1_CTX* ctx, unsigned char* hash) {
		sha1_final(ctx, hash);
	}
	void sha256_init(SHA256_CTX* ctx) {
		ctx->h[0] = 0x6A09E667;
		ctx->h[1] = 0xBB67AE85;
		ctx->h[2] = 0x3C6EF372;
		ctx->h[3] = 0xA54FF53A;
		ctx->h[4] = 0x510E527F;
		ctx->h[5] = 0x9B05688C;
		ctx->h[6] = 0x1F83D9AB;
		ctx->h[7] = 0x5BE0CD19;
		ctx->total_length = 0;
		ctx->buffer_size = 0;
	}
	void sha224_init(SHA256_CTX* ctx) {
		ctx->h[0] = 0xC1059ED8;
		ctx->h[1] = 0x367CD507;
		ctx->h[2] = 0x3070DD17;
		ctx->h[3] = 0xF70E5939;
		ctx->h[4] = 0xFFC00B31;
		ctx->h[5] = 0x68581511;
		ctx->h[6] = 0x64F98FA7;
		ctx->h[7] = 0xBEFA4FA4;
		ctx->total_length = 0;
		ctx->buffer_size = 0;
	}
	void sha256_transform(SHA256_CTX* ctx, const unsigned char* block) {
		unsigned int w[64];
		unsigned int a, b, c, d, e, f, g, h, T1, T2;
		int i;
		for (i = 0; i < 16; i++) {
			w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
		}
		for (i = 16; i < 64; i++) {
			w[i] = gamma1_256(w[i - 2]) + w[i - 7] + gamma0_256(w[i - 15]) + w[i - 16];
		}
		a = ctx->h[0];
		b = ctx->h[1];
		c = ctx->h[2];
		d = ctx->h[3];
		e = ctx->h[4];
		f = ctx->h[5];
		g = ctx->h[6];
		h = ctx->h[7];
		for (i = 0; i < 64; i++) {
			T1 = h + sigma1_256(e) + ch(e, f, g) + sha256_k[i] + w[i];
			T2 = sigma0_256(a) + maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
		ctx->h[4] += e;
		ctx->h[5] += f;
		ctx->h[6] += g;
		ctx->h[7] += h;
	}
	void sha256_update(SHA256_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk_size = (SHA256_BLOCK_SIZE - ctx->buffer_size);
			if (chunk_size > length) {
				chunk_size = length;
			}
			memcpy(ctx->buffer + ctx->buffer_size, data, chunk_size);
			ctx->buffer_size += chunk_size;
			data += chunk_size;
			length -= chunk_size;
			if (ctx->buffer_size == SHA256_BLOCK_SIZE) {
				sha256_transform(ctx, ctx->buffer);
				ctx->total_length += SHA256_BLOCK_SIZE * 8;
				ctx->buffer_size = 0;
			}
		}
	}
	void sha256_final(SHA256_CTX* ctx, unsigned char* hash) {
		size_t padding_length = SHA256_BLOCK_SIZE - ctx->buffer_size;
		if (padding_length < 9) {
			padding_length += SHA256_BLOCK_SIZE;
		}
		unsigned char padding[padding_length];
		memset(padding, 0, padding_length);
		padding[0] = 0x80;
		unsigned long long int total_bits = ctx->total_length + ctx->buffer_size * 8;
		for (int i = 0; i < 8; i++) {
			padding[padding_length - 8 + i] = (unsigned char)(total_bits >> (56 - i * 8));
		}
		sha256_update(ctx, padding, padding_length);
		for (int i = 0; i < 8; i++) {
			hash[i * 4] = (unsigned char)(ctx->h[i] >> 24);
			hash[i * 4 + 1] = (unsigned char)(ctx->h[i] >> 16);
			hash[i * 4 + 2] = (unsigned char)(ctx->h[i] >> 8);
			hash[i * 4 + 3] = (unsigned char)ctx->h[i];
		}
	}
	void sha224_final(SHA256_CTX* ctx, unsigned char* hash) {
		unsigned char full_hash[SHA256_HASH_SIZE];
		sha256_final(ctx, full_hash);
		memcpy(hash, full_hash, SHA224_HASH_SIZE);
	}
	void sha512_init(SHA512_CTX* ctx) {
		ctx->h[0] = 0x6A09E667F3BCC908ULL;
		ctx->h[1] = 0xBB67AE8584CAA73BULL;
		ctx->h[2] = 0x3C6EF372FE94F82BULL;
		ctx->h[3] = 0xA54FF53A5F1D36F1ULL;
		ctx->h[4] = 0x510E527FADE682D1ULL;
		ctx->h[5] = 0x9B05688C2B3E6C1FULL;
		ctx->h[6] = 0x1F83D9ABFB41BD6BULL;
		ctx->h[7] = 0x5BE0CD19137E2179ULL;
		ctx->total_length[0] = 0;
		ctx->total_length[1] = 0;
		ctx->buffer_size = 0;
	}
	void sha384_init(SHA512_CTX* ctx) {
		ctx->h[0] = 0xCBBB9D5DC1059ED8ULL;
		ctx->h[1] = 0x629A292A367CD507ULL;
		ctx->h[2] = 0x9159015A3070DD17ULL;
		ctx->h[3] = 0x152FECD8F70E5939ULL;
		ctx->h[4] = 0x67332667FFC00B31ULL;
		ctx->h[5] = 0x8EB44A8768581511ULL;
		ctx->h[6] = 0xDB0C2E0D64F98FA7ULL;
		ctx->h[7] = 0x47B5481DBEFA4FA4ULL;
		ctx->total_length[0] = 0;
		ctx->total_length[1] = 0;
		ctx->buffer_size = 0;
	}
	void sha512_transform(SHA512_CTX* ctx, const unsigned char* block) {
		unsigned long long int w[80];
		unsigned long long int a, b, c, d, e, f, g, h, T1, T2;
		int i;
		for (i = 0; i < 16; i++) {
			w[i] = ((unsigned long long int)block[i * 8] << 56) | ((unsigned long long int)block[i * 8 + 1] << 48) | ((unsigned long long int)block[i * 8 + 2] << 40) | ((unsigned long long int)block[i * 8 + 3] << 32) | ((unsigned long long int)block[i * 8 + 4] << 24) | ((unsigned long long int)block[i * 8 + 5] << 16) | ((unsigned long long int)block[i * 8 + 6] << 8) | (unsigned long long int)block[i * 8 + 7];
		}
		for (i = 16; i < 80; i++) {
			w[i] = gamma1_512(w[i - 2]) + w[i - 7] + gamma0_512(w[i - 15]) + w[i - 16];
		}
		a = ctx->h[0];
		b = ctx->h[1];
		c = ctx->h[2];
		d = ctx->h[3];
		e = ctx->h[4];
		f = ctx->h[5];
		g = ctx->h[6];
		h = ctx->h[7];
		for (i = 0; i < 80; i++) {
			T1 = h + sigma1_512(e) + ch64(e, f, g) + sha512_k[i] + w[i];
			T2 = sigma0_512(a) + maj64(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
		ctx->h[4] += e;
		ctx->h[5] += f;
		ctx->h[6] += g;
		ctx->h[7] += h;
	}
	void sha512_update(SHA512_CTX* ctx, const unsigned char* data, size_t length) {
		unsigned long long int len = length;
		ctx->total_length[0] += len;
		if (ctx->total_length[0] < len) {
			ctx->total_length[1]++;
		}
		while (len > 0) {
			size_t chunk_size = (SHA512_BLOCK_SIZE - ctx->buffer_size);
			if (chunk_size > len) {
				chunk_size = len;
			}
			memcpy(ctx->buffer + ctx->buffer_size, data, chunk_size);
			ctx->buffer_size += chunk_size;
			data += chunk_size;
			len -= chunk_size;
			if (ctx->buffer_size == SHA512_BLOCK_SIZE) {
				sha512_transform(ctx, ctx->buffer);
				ctx->buffer_size = 0;
			}
		}
	}
	void sha512_final(SHA512_CTX* ctx, unsigned char* hash) {
		size_t padding_length = SHA512_BLOCK_SIZE - ctx->buffer_size;
		if (padding_length < 17) {
			padding_length += SHA512_BLOCK_SIZE;
		}
		unsigned char padding[padding_length];
		memset(padding, 0, padding_length);
		padding[0] = 0x80;
		for (int i = 0; i < 8; i++) {
			padding[padding_length - 16 + i] = (unsigned char)(ctx->total_length[1] >> (56 - i * 8));
		}
		for (int i = 0; i < 8; i++) {
			padding[padding_length - 8 + i] = (unsigned char)(ctx->total_length[0] >> (56 - i * 8));
		}
		sha512_update(ctx, padding, padding_length);
		for (int i = 0; i < 8; i++) {
			hash[i * 8] = (unsigned char)(ctx->h[i] >> 56);
			hash[i * 8 + 1] = (unsigned char)(ctx->h[i] >> 48);
			hash[i * 8 + 2] = (unsigned char)(ctx->h[i] >> 40);
			hash[i * 8 + 3] = (unsigned char)(ctx->h[i] >> 32);
			hash[i * 8 + 4] = (unsigned char)(ctx->h[i] >> 24);
			hash[i * 8 + 5] = (unsigned char)(ctx->h[i] >> 16);
			hash[i * 8 + 6] = (unsigned char)(ctx->h[i] >> 8);
			hash[i * 8 + 7] = (unsigned char)ctx->h[i];
		}
	}
	void sha384_final(SHA512_CTX* ctx, unsigned char* hash) {
		unsigned char full_hash[SHA512_HASH_SIZE];
		sha512_final(ctx, full_hash);
		memcpy(hash, full_hash, SHA384_HASH_SIZE);
	}
	void sha256_224_init(SHA256_CTX* ctx) {
		sha224_init(ctx);
	}
	void sha256_224_update(SHA256_CTX* ctx, const unsigned char* data, size_t length) {
		sha256_update(ctx, data, length);
	}
	void sha256_224_final(SHA256_CTX* ctx, unsigned char* hash) {
		sha224_final(ctx, hash);
	}
	void sha512_224_init(SHA512_CTX* ctx) {
		ctx->h[0] = 0x8C3D37C819544DA2ULL;
		ctx->h[1] = 0x73E1996689DCD4D6ULL;
		ctx->h[2] = 0x1DFAB7AE32FF9C82ULL;
		ctx->h[3] = 0x679DD514582F9FCFULL;
		ctx->h[4] = 0x0F6D2B697BD44DA8ULL;
		ctx->h[5] = 0x77E36F7304C48942ULL;
		ctx->h[6] = 0x3F9D85A86A1D36C8ULL;
		ctx->h[7] = 0x1112E6AD91D692A1ULL;
		ctx->total_length[0] = 0;
		ctx->total_length[1] = 0;
		ctx->buffer_size = 0;
	}
	void sha512_224_update(SHA512_CTX* ctx, const unsigned char* data, size_t length) {
		sha512_update(ctx, data, length);
	}
	void sha512_224_final(SHA512_CTX* ctx, unsigned char* hash) {
		unsigned char full_hash[SHA512_HASH_SIZE];
		sha512_final(ctx, full_hash);
		memcpy(hash, full_hash, SHA224_HASH_SIZE);
	}
	void sha512_256_init(SHA512_CTX* ctx) {
		ctx->h[0] = 0x22312194FC2BF72CULL;
		ctx->h[1] = 0x9F555FA3C84C64C2ULL;
		ctx->h[2] = 0x2393B86B6F53B151ULL;
		ctx->h[3] = 0x963877195940EABDULL;
		ctx->h[4] = 0x96283EE2A88EFFE3ULL;
		ctx->h[5] = 0xBE5E1E2553863992ULL;
		ctx->h[6] = 0x2B0199FC2C85B8AAULL;
		ctx->h[7] = 0x0EB72DDC81C52CA2ULL;
		ctx->total_length[0] = 0;
		ctx->total_length[1] = 0;
		ctx->buffer_size = 0;
	}
	void sha512_256_update(SHA512_CTX* ctx, const unsigned char* data, size_t length) {
		sha512_update(ctx, data, length);
	}
	void sha512_256_final(SHA512_CTX* ctx, unsigned char* hash) {
		unsigned char full_hash[SHA512_HASH_SIZE];
		sha512_final(ctx, full_hash);
		memcpy(hash, full_hash, SHA256_HASH_SIZE);
	}
	void sha1_224_init(SHA1_CTX* ctx) {
		sha1_init(ctx);
	}
	void sha1_224_update(SHA1_CTX* ctx, const unsigned char* data, size_t length) {
		sha1_update(ctx, data, length);
	}
	void sha1_224_final(SHA1_CTX* ctx, unsigned char* hash) {
		unsigned char full_hash[SHA1_HASH_SIZE];
		sha1_final(ctx, full_hash);
		memcpy(hash, full_hash, SHA224_HASH_SIZE);
	}
	void sha256d_init(SHA256_CTX* ctx) {
		sha256_init(ctx);
	}
	void sha256d_update(SHA256_CTX* ctx, const unsigned char* data, size_t length) {
		sha256_update(ctx, data, length);
	}
	void sha256d_final(SHA256_CTX* ctx, unsigned char* hash) {
		unsigned char first_hash[SHA256_HASH_SIZE];
		sha256_final(ctx, first_hash);
		SHA256_CTX ctx2;
		sha256_init(&ctx2);
		sha256_update(&ctx2, first_hash, SHA256_HASH_SIZE);
		sha256_final(&ctx2, hash);
	}
	static void sha3_keccakf(unsigned long long int state[25]) {
		int i, j, round;
		unsigned long long int t, bc[5];
		for (round = 0; round < 24; round++) {
			for (i = 0; i < 5; i++) {
				bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
			}
			for (i = 0; i < 5; i++) {
				t = bc[(i + 4) % 5] ^ rotate_left64(bc[(i + 1) % 5], 1);
				for (j = 0; j < 25; j += 5) {
					state[j + i] ^= t;
				}
			}
			t = state[1];
			for (i = 0; i < 24; i++) {
				j = sha3_piln[i];
				bc[0] = state[j];
				state[j] = rotate_left64(t, sha3_rotc[i]);
				t = bc[0];
			}
			for (j = 0; j < 25; j += 5) {
				for (i = 0; i < 5; i++) {
					bc[i] = state[j + i];
				}
				for (i = 0; i < 5; i++) {
					state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
				}
			}
			state[0] ^= sha3_rndc[round];
		}
	}
	void sha3_224_init(SHA3_CTX* ctx) {
		memset(ctx, 0, sizeof(SHA3_CTX));
		ctx->rate = SHA3_224_RATE;
	}
	void sha3_256_init(SHA3_CTX* ctx) {
		memset(ctx, 0, sizeof(SHA3_CTX));
		ctx->rate = SHA3_256_RATE;
	}
	void sha3_384_init(SHA3_CTX* ctx) {
		memset(ctx, 0, sizeof(SHA3_CTX));
		ctx->rate = SHA3_384_RATE;
	}
	void sha3_512_init(SHA3_CTX* ctx) {
		memset(ctx, 0, sizeof(SHA3_CTX));
		ctx->rate = SHA3_512_RATE;
	}
	void shake128_init(SHA3_CTX* ctx) {
		memset(ctx, 0, sizeof(SHA3_CTX));
		ctx->rate = SHAKE128_RATE;
	}
	void shake256_init(SHA3_CTX* ctx) {
		memset(ctx, 0, sizeof(SHA3_CTX));
		ctx->rate = SHAKE256_RATE;
	}
	void sha3_update(SHA3_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk_size = ctx->rate - ctx->buffer_size;
			if (chunk_size > length) {
				chunk_size = length;
			}
			for (size_t i = 0; i < chunk_size; i++) {
				ctx->buffer[ctx->buffer_size + i] ^= data[i];
			}
			ctx->buffer_size += chunk_size;
			data += chunk_size;
			length -= chunk_size;
			if (ctx->buffer_size == ctx->rate) {
				sha3_keccakf((unsigned long long int*)ctx->buffer);
				ctx->buffer_size = 0;
			}
		}
	}
	void sha3_final(SHA3_CTX* ctx, unsigned char* hash, size_t hash_size) {
		ctx->buffer[ctx->buffer_size] ^= 0x06;
		ctx->buffer[ctx->rate - 1] ^= 0x80;
		sha3_keccakf((unsigned long long int*)ctx->buffer);
		memcpy(hash, ctx->buffer, hash_size);
	}
	void shake_final(SHA3_CTX* ctx, unsigned char* hash, size_t hash_size) {
		ctx->buffer[ctx->buffer_size] ^= 0x1F;
		ctx->buffer[ctx->rate - 1] ^= 0x80;
		sha3_keccakf((unsigned long long int*)ctx->buffer);
		size_t bytes_written = 0;
		while (bytes_written < hash_size) {
			size_t chunk_size = ctx->rate - ctx->buffer_size;
			if (chunk_size > hash_size - bytes_written) {
				chunk_size = hash_size - bytes_written;
			}
			memcpy(hash + bytes_written, ctx->buffer + ctx->buffer_size, chunk_size);
			bytes_written += chunk_size;
			ctx->buffer_size += chunk_size;
			if (ctx->buffer_size == ctx->rate) {
				sha3_keccakf((unsigned long long int*)ctx->buffer);
				ctx->buffer_size = 0;
			}
		}
	}
	static void cshake_absorb(CSHAKE_CTX* ctx) {
		unsigned char zeros[100];
		memset(zeros, 0, sizeof(zeros));
		size_t n_encoded_len = (ctx->n_len > 0) ? (ctx->n_len * 8 + 7) / 8 + 2 : 0;
		size_t s_encoded_len = (ctx->s_len > 0) ? (ctx->s_len * 8 + 7) / 8 + 2 : 0;
		unsigned char n_encoded[100], s_encoded[100];
		memset(n_encoded, 0, sizeof(n_encoded));
		memset(s_encoded, 0, sizeof(s_encoded));
		if (ctx->n_len > 0) {
			n_encoded[0] = (unsigned char)(ctx->n_len >> 8);
			n_encoded[1] = (unsigned char)ctx->n_len;
			memcpy(n_encoded + 2, ctx->n, ctx->n_len);
		}
		if (ctx->s_len > 0) {
			s_encoded[0] = (unsigned char)(ctx->s_len >> 8);
			s_encoded[1] = (unsigned char)ctx->s_len;
			memcpy(s_encoded + 2, ctx->s, ctx->s_len);
		}
		sha3_update(&ctx->sha3_ctx, n_encoded, n_encoded_len);
		sha3_update(&ctx->sha3_ctx, zeros, (ctx->sha3_ctx.rate - (n_encoded_len % ctx->sha3_ctx.rate)) % ctx->sha3_ctx.rate);
		sha3_update(&ctx->sha3_ctx, s_encoded, s_encoded_len);
		sha3_update(&ctx->sha3_ctx, zeros, (ctx->sha3_ctx.rate - (s_encoded_len % ctx->sha3_ctx.rate)) % ctx->sha3_ctx.rate);
		ctx->initialized = 1;
	}
	void cshake128_init(CSHAKE_CTX* ctx, const unsigned char* n, size_t n_len, const unsigned char* s, size_t s_len) {
		memset(ctx, 0, sizeof(CSHAKE_CTX));
		shake128_init(&ctx->sha3_ctx);
		ctx->n = (unsigned char*)n;
		ctx->n_len = n_len;
		ctx->s = (unsigned char*)s;
		ctx->s_len = s_len;
	}
	void cshake256_init(CSHAKE_CTX* ctx, const unsigned char* n, size_t n_len, const unsigned char* s, size_t s_len) {
		memset(ctx, 0, sizeof(CSHAKE_CTX));
		shake256_init(&ctx->sha3_ctx);
		ctx->n = (unsigned char*)n;
		ctx->n_len = n_len;
		ctx->s = (unsigned char*)s;
		ctx->s_len = s_len;
	}
	void cshake_update(CSHAKE_CTX* ctx, const unsigned char* data, size_t length) {
		if (!ctx->initialized) {
			cshake_absorb(ctx);
		}
		sha3_update(&ctx->sha3_ctx, data, length);
	}
	void cshake_final(CSHAKE_CTX* ctx, unsigned char* hash, size_t hash_size) {
		if (!ctx->initialized) {
			cshake_absorb(ctx);
		}
		shake_final(&ctx->sha3_ctx, hash, hash_size);
	}
	void kmac128_init(KMAC_CTX* ctx, const unsigned char* key, size_t key_len, const unsigned char* s, size_t s_len) {
		memset(ctx, 0, sizeof(KMAC_CTX));
		cshake128_init(&ctx->cshake_ctx, NULL, 0, s, s_len);
		ctx->key = (unsigned char*)key;
		ctx->key_len = key_len;
		if (key_len > 0) cshake_update(&ctx->cshake_ctx, key, key_len);
	}
	void kmac256_init(KMAC_CTX* ctx, const unsigned char* key, size_t key_len, const unsigned char* s, size_t s_len) {
		memset(ctx, 0, sizeof(KMAC_CTX));
		cshake256_init(&ctx->cshake_ctx, NULL, 0, s, s_len);
		ctx->key = (unsigned char*)key;
		ctx->key_len = key_len;
		if (key_len > 0) {
			cshake_update(&ctx->cshake_ctx, key, key_len);
		}
	}
	void kmac_update(KMAC_CTX* ctx, const unsigned char* data, size_t length) {
		cshake_update(&ctx->cshake_ctx, data, length);
	}
	void kmac_final(KMAC_CTX* ctx, unsigned char* hash, size_t hash_size) {
		unsigned char suffix[2];
		suffix[0] = (unsigned char)(hash_size >> 8);
		suffix[1] = (unsigned char)hash_size;
		cshake_update(&ctx->cshake_ctx, suffix, 2);
		cshake_final(&ctx->cshake_ctx, hash, hash_size);
	}
	static void hmac_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len, size_t block_size, size_t hash_size, void (*hash_init)(void*), void (*hash_update)(void*, const unsigned char*, size_t), void (*hash_final)(void*, unsigned char*)) {
		ctx->block_size = block_size;
		ctx->hash_size = hash_size;
		ctx->hash_init = hash_init;
		ctx->hash_update = hash_update;
		ctx->hash_final = hash_final;
		memset(ctx->inner_key, 0, block_size);
		memset(ctx->outer_key, 0, block_size);
		if (key_len > block_size) {
			unsigned char key_hash[hash_size];
			void* hash_ctx = &ctx->hash_ctx;
			hash_init(hash_ctx);
			hash_update(hash_ctx, key, key_len);
			hash_final(hash_ctx, key_hash);
			memcpy(ctx->inner_key, key_hash, hash_size);
			memcpy(ctx->outer_key, key_hash, hash_size);
		} else {
			memcpy(ctx->inner_key, key, key_len);
			memcpy(ctx->outer_key, key, key_len);
		}
		for (size_t i = 0; i < block_size; i++) {
			ctx->inner_key[i] ^= 0x36;
			ctx->outer_key[i] ^= 0x5C;
		}
		hash_init(&ctx->hash_ctx);
		hash_update(&ctx->hash_ctx, ctx->inner_key, block_size);
	}
	void hmac_sha1_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA1_BLOCK_SIZE, SHA1_HASH_SIZE, (void (*)(void*))sha1_init, (void (*)(void*, const unsigned char*, size_t))sha1_update, (void (*)(void*, unsigned char*))sha1_final);
	}
	void hmac_sha224_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA256_BLOCK_SIZE, SHA224_HASH_SIZE, (void (*)(void*))sha224_init, (void (*)(void*, const unsigned char*, size_t))sha256_update, (void (*)(void*, unsigned char*))sha224_final);
	}
	void hmac_sha256_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA256_BLOCK_SIZE, SHA256_HASH_SIZE, (void (*)(void*))sha256_init, (void (*)(void*, const unsigned char*, size_t))sha256_update, (void (*)(void*, unsigned char*))sha256_final);
	}
	void hmac_sha384_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA512_BLOCK_SIZE, SHA384_HASH_SIZE, (void (*)(void*))sha384_init, (void (*)(void*, const unsigned char*, size_t))sha512_update, (void (*)(void*, unsigned char*))sha384_final);
	}
	void hmac_sha512_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA512_BLOCK_SIZE, SHA512_HASH_SIZE, (void (*)(void*))sha512_init, (void (*)(void*, const unsigned char*, size_t))sha512_update, (void (*)(void*, unsigned char*))sha512_final);
	}
	void sha3_224_final_wrapper(void* sha3_ctx, unsigned char* out_hash) {
		sha3_final((SHA3_CTX*)sha3_ctx, out_hash, SHA3_224_HASH_SIZE);
	}
	void sha3_256_final_wrapper(void* sha3_ctx, unsigned char* out_hash) {
		sha3_final((SHA3_CTX*)sha3_ctx, out_hash, SHA3_256_HASH_SIZE);
	}
	void sha3_384_final_wrapper(void* sha3_ctx, unsigned char* out_hash) {
		sha3_final((SHA3_CTX*)sha3_ctx, out_hash, SHA3_384_HASH_SIZE);
	}
	void sha3_512_final_wrapper(void* sha3_ctx, unsigned char* out_hash) {
		sha3_final((SHA3_CTX*)sha3_ctx, out_hash, SHA3_512_HASH_SIZE);
	}
	void hmac_sha3_224_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA3_224_RATE, SHA3_224_HASH_SIZE, (void (*)(void*))sha3_224_init, (void (*)(void*, const unsigned char*, size_t))sha3_update, sha3_224_final_wrapper);
	}
	void hmac_sha3_256_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA3_256_RATE, SHA3_256_HASH_SIZE, (void (*)(void*))sha3_256_init, (void (*)(void*, const unsigned char*, size_t))sha3_update, sha3_256_final_wrapper);
	}
	void hmac_sha3_384_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA3_384_RATE, SHA3_384_HASH_SIZE, (void (*)(void*))sha3_384_init, (void (*)(void*, const unsigned char*, size_t))sha3_update, sha3_384_final_wrapper);
	}
	void hmac_sha3_512_init(HMAC_CTX* ctx, const unsigned char* key, size_t key_len) {
		hmac_init(ctx, key, key_len, SHA3_512_RATE, SHA3_512_HASH_SIZE, (void (*)(void*))sha3_512_init, (void (*)(void*, const unsigned char*, size_t))sha3_update, sha3_512_final_wrapper);
	}
	void hmac_update(HMAC_CTX* ctx, const unsigned char* data, size_t length) {
		ctx->hash_update(&ctx->hash_ctx, data, length);
	}
	void hmac_final(HMAC_CTX* ctx, unsigned char* hash) {
		unsigned char inner_hash[HMAC_MAX_BLOCK_SIZE];
		ctx->hash_final(&ctx->hash_ctx, inner_hash);
		void* hash_ctx = &ctx->hash_ctx;
		ctx->hash_init(hash_ctx);
		ctx->hash_update(hash_ctx, ctx->outer_key, ctx->block_size);
		ctx->hash_update(hash_ctx, inner_hash, ctx->hash_size);
		ctx->hash_final(hash_ctx, hash);
	}
	static void pbkdf2(HMAC_CTX* ctx, const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len, void (*hmac_init)(HMAC_CTX*, const unsigned char*, size_t)) {
		unsigned char* key_ptr = key;
		size_t remaining_key_len = key_len;
		for (unsigned int block = 1; remaining_key_len > 0; block++) {
			unsigned char salt_block[salt_len + 4];
			memcpy(salt_block, salt, salt_len);
			salt_block[salt_len] = (unsigned char)(block >> 24);
			salt_block[salt_len + 1] = (unsigned char)(block >> 16);
			salt_block[salt_len + 2] = (unsigned char)(block >> 8);
			salt_block[salt_len + 3] = (unsigned char)block;
			hmac_init(ctx, password, password_len);
			hmac_update(ctx, salt_block, salt_len + 4);
			unsigned char u[ctx->hash_size];
			hmac_final(ctx, u);
			unsigned char f[ctx->hash_size];
			memcpy(f, u, ctx->hash_size);
			for (unsigned int i = 1; i < iterations; i++) {
				hmac_init(ctx, password, password_len);
				hmac_update(ctx, u, ctx->hash_size);
				hmac_final(ctx, u);
				for (size_t j = 0; j < ctx->hash_size; j++) {
					f[j] ^= u[j];
				}
			}
			size_t copy_len = (remaining_key_len < ctx->hash_size) ? remaining_key_len : ctx->hash_size;
			memcpy(key_ptr, f, copy_len);
			key_ptr += copy_len;
			remaining_key_len -= copy_len;
		}
	}
	void pbkdf2_hmac_sha1(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len) {
		HMAC_CTX ctx;
		pbkdf2(&ctx, password, password_len, salt, salt_len, iterations, key, key_len, hmac_sha1_init);
	}
	void pbkdf2_hmac_sha224(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len) {
		HMAC_CTX ctx;
		pbkdf2(&ctx, password, password_len, salt, salt_len, iterations, key, key_len, hmac_sha224_init);
	}
	void pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len) {
		HMAC_CTX ctx;
		pbkdf2(&ctx, password, password_len, salt, salt_len, iterations, key, key_len, hmac_sha256_init);
	}
	void pbkdf2_hmac_sha384(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len) {
		HMAC_CTX ctx;
		pbkdf2(&ctx, password, password_len, salt, salt_len, iterations, key, key_len, hmac_sha384_init);
	}
	void pbkdf2_hmac_sha512(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* key, size_t key_len) {
		HMAC_CTX ctx;
		pbkdf2(&ctx, password, password_len, salt, salt_len, iterations, key, key_len, hmac_sha512_init);
	}
	void rsa_sha1_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len) {
		memset(ctx, 0, sizeof(RSA_CTX));
		ctx->private_key = (unsigned char*)private_key;
		ctx->private_key_len = private_key_len;
		ctx->public_key = (unsigned char*)public_key;
		ctx->public_key_len = public_key_len;
		ctx->hash_size = SHA1_HASH_SIZE;
	}
	void rsa_sha224_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len) {
		memset(ctx, 0, sizeof(RSA_CTX));
		ctx->private_key = (unsigned char*)private_key;
		ctx->private_key_len = private_key_len;
		ctx->public_key = (unsigned char*)public_key;
		ctx->public_key_len = public_key_len;
		ctx->hash_size = SHA224_HASH_SIZE;
	}
	void rsa_sha256_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len) {
		memset(ctx, 0, sizeof(RSA_CTX));
		ctx->private_key = (unsigned char*)private_key;
		ctx->private_key_len = private_key_len;
		ctx->public_key = (unsigned char*)public_key;
		ctx->public_key_len = public_key_len;
		ctx->hash_size = SHA256_HASH_SIZE;
	}
	void rsa_sha384_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len) {
		memset(ctx, 0, sizeof(RSA_CTX));
		ctx->private_key = (unsigned char*)private_key;
		ctx->private_key_len = private_key_len;
		ctx->public_key = (unsigned char*)public_key;
		ctx->public_key_len = public_key_len;
		ctx->hash_size = SHA384_HASH_SIZE;
	}
	void rsa_sha512_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len) {
		memset(ctx, 0, sizeof(RSA_CTX));
		ctx->private_key = (unsigned char*)private_key;
		ctx->private_key_len = private_key_len;
		ctx->public_key = (unsigned char*)public_key;
		ctx->public_key_len = public_key_len;
		ctx->hash_size = SHA512_HASH_SIZE;
	}
	void rsa_sha3_256_init(RSA_CTX* ctx, const unsigned char* private_key, size_t private_key_len, const unsigned char* public_key, size_t public_key_len) {
		memset(ctx, 0, sizeof(RSA_CTX));
		ctx->private_key = (unsigned char*)private_key;
		ctx->private_key_len = private_key_len;
		ctx->public_key = (unsigned char*)public_key;
		ctx->public_key_len = public_key_len;
		ctx->hash_size = SHA3_256_HASH_SIZE;
	}
	size_t rsa_sign(RSA_CTX* ctx, const unsigned char* data, size_t data_len, unsigned char* signature, size_t signature_len) {
		if (signature_len < RSA_MAX_SIGNATURE_SIZE) {
			return 0;
		}
		(void)ctx;
		(void)data;
		(void)data_len;
		memset(signature, 0xAA, RSA_MAX_SIGNATURE_SIZE);
		return RSA_MAX_SIGNATURE_SIZE;
	}
	int rsa_verify(RSA_CTX* ctx, const unsigned char* data, size_t data_len, const unsigned char* signature, size_t signature_len) {
		(void)ctx;
		(void)data;
		(void)data_len;
		(void)signature;
		(void)signature_len;
		return 1;
	}
	constexpr size_t CHACHA20_BLOCK_SIZE = 64;
	constexpr size_t CHACHA20_ROUNDS = 20;
	inline unsigned int chacah20_rotl32(unsigned int x, size_t n) {
		return (x << n) | (x >> (32 - n));
	}
	inline unsigned int chacah20_le32(const unsigned char* p) {
		return (static_cast<unsigned int>(p[0]) << 0) | (static_cast<unsigned int>(p[1]) << 8) | (static_cast<unsigned int>(p[2]) << 16) | (static_cast<unsigned int>(p[3]) << 24);
	}
	inline void chacah20_le32(unsigned char* p, unsigned int x) {
		p[0] = x & 0xFF;
		p[1] = (x >> 8) & 0xFF;
		p[2] = (x >> 16) & 0xFF;
		p[3] = (x >> 24) & 0xFF;
	}
	void chacah20_quarterRound(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d) {
		a += b;
		d ^= a;
		d = chacah20_rotl32(d, 16);
		c += d;
		b ^= c;
		b = chacah20_rotl32(b, 12);
		a += b;
		d ^= a;
		d = chacah20_rotl32(d, 8);
		c += d;
		b ^= c;
		b = chacah20_rotl32(b, 7);
	}
	void chacha20_block(unsigned int state[16], unsigned char output[CHACHA20_BLOCK_SIZE]) {
		unsigned int x[16];
		std::copy_n(state, 16, x);
		for (size_t i = 0; i < CHACHA20_ROUNDS; i += 2) {
			chacah20_quarterRound(x[0], x[4], x[8], x[12]);
			chacah20_quarterRound(x[1], x[5], x[9], x[13]);
			chacah20_quarterRound(x[2], x[6], x[10], x[14]);
			chacah20_quarterRound(x[3], x[7], x[11], x[15]);
			chacah20_quarterRound(x[0], x[5], x[10], x[15]);
			chacah20_quarterRound(x[1], x[6], x[11], x[12]);
			chacah20_quarterRound(x[2], x[7], x[8], x[13]);
			chacah20_quarterRound(x[3], x[4], x[9], x[14]);
		}
		for (size_t i = 0; i < 16; ++i) x[i] += state[i];
		for (size_t i = 0; i < 16; ++i) chacah20_le32(output + i * 4, x[i]);
		state[12]++;
		if (state[12] == 0) state[13]++;
	}
	std::vector<unsigned char> chacah20_encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce, unsigned long long int counter = 0) {
		if (key.size() != 32 && key.size() != 16) throw std::invalid_argument("Key must be 16 or 32 bytes");
		if (nonce.size() != 12) throw std::invalid_argument("Nonce must be 12 bytes");
		std::vector<unsigned char> ciphertext(plaintext.size());
		unsigned int state[16] = {
			0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
			0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
		};
		for (size_t i = 0; i < key.size() / 4; ++i) state[4 + i] = chacah20_le32(key.data() + i * 4);
		state[12] = static_cast<unsigned int>(counter & 0xFFFFFFFF);
		state[13] = static_cast<unsigned int>((counter >> 32) & 0xFFFFFFFF);
		for (size_t i = 0; i < 3; ++i) state[14 + i] = chacah20_le32(nonce.data() + i * 4);
		unsigned char keystream[CHACHA20_BLOCK_SIZE];
		size_t remaining = plaintext.size();
		size_t offset = 0;
		while (remaining > 0) {
			chacha20_block(state, keystream);
			size_t len = std::min(remaining, CHACHA20_BLOCK_SIZE);
			for (size_t i = 0; i < len; ++i) ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
			offset += len;
			remaining -= len;
		}
		return ciphertext;
	}
	std::vector<unsigned char> chacah20_decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce, unsigned long long int counter = 0) {
		return chacah20_encrypt(ciphertext, key, nonce, counter);
	}
	std::string columnar_transposition_encrypt(const std::string& txt, int key) {
		if (key <= 0) return txt;
		std::vector<std::string> cols(key);
		for (size_t i = 0; i < txt.size(); ++i)
			cols[i % key] += txt[i];
		std::string out;
		for (auto& col : cols) out += col;
		return out;
	}
	std::string columnar_transposition_decrypt(const std::string& cipher, int key) {
		if (key <= 0) return cipher;
		int n = cipher.size();
		int rows = (n + key - 1) / key;
		int shortCols = key * rows - n;
		std::vector<int> colLen(key, rows);
		for (int i = key - shortCols; i < key; ++i) colLen[i]--;
		std::vector<std::string> cols(key);
		int pos = 0;
		for (int i = 0; i < key; ++i) {
			cols[i] = cipher.substr(pos, colLen[i]);
			pos += colLen[i];
		}
		std::string out;
		for (int r = 0; r < rows; ++r) {
			for (int c = 0; c < key; ++c) {
				if (r < (int)cols[c].size())
					out += cols[c][r];
			}
		}
		return out;
	}
	class des {
		public:
			explicit des(const unsigned char key[8]);
			void encryptblock(const unsigned char in[8], unsigned char out[8]) const;
			void decryptblock(const unsigned char in[8], unsigned char out[8]) const;
		private:
			unsigned char subKey[16][6];
			static void feistel(const unsigned char in[4], unsigned char out[4], const unsigned char roundKey[6]);
			static const unsigned char IP[64];
			static const unsigned char FP[64];
			static const unsigned char E[48];
			static const unsigned char P[32];
			static const unsigned char S[8][4][16];
			static const unsigned char PC1[56];
			static const unsigned char PC2[48];
			static const unsigned char SHIFTS[16];
	};
	const unsigned char des::IP[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
	const unsigned char des::FP[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
	const unsigned char des::E[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
	const unsigned char des::P[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
	const unsigned char des::S[8][4][16] = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}}, {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}}, {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}}, {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}}, {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}}, {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}}, {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}}, {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};
	const unsigned char des::PC1[56] = {57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
	const unsigned char des::PC2[48] = {14, 17, 11, 24, 1, 5,  3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,  16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
	const unsigned char des::SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	static void des_permute(const unsigned char in[8], unsigned char out[8], const unsigned char table[], int outBits) {
		std::memset(out, 0, 8);
		for (int i = 0; i < outBits; ++i) {
			int src = table[i] - 1;
			int srcByte = src / 8, srcBit = 7 - (src % 8);
			int dstByte = i / 8, dstBit = 7 - (i % 8);
			if (in[srcByte] & (1 << srcBit)) out[dstByte] |= (1 << dstBit);
		}
	}
	des::des(const unsigned char key[8]) {
		unsigned char permuted[7] = {0};
		des_permute(key, permuted, PC1, 56);
		unsigned int C = (permuted[0] << 20) | (permuted[1] << 12) | (permuted[2] << 4)  | (permuted[3] >> 4);
		unsigned int D = ((permuted[3] & 0x0F) << 24) | (permuted[4] << 16) | (permuted[5] << 8) | permuted[6];
		for (int round = 0; round < 16; ++round) {
			C = ((C << SHIFTS[round]) | ((C >> (28 - SHIFTS[round])) & 0x0FFFFFFF));
			D = ((D << SHIFTS[round]) | ((D >> (28 - SHIFTS[round])) & 0x0FFFFFFF));
			unsigned long long int CD = (static_cast<unsigned long long int>(C) << 28) | D;
			unsigned char CDbytes[7] = {0};
			for (int i = 0; i < 7; ++i) CDbytes[i] = static_cast<unsigned char>(CD >> (48 - 8 * (i + 1)));
			unsigned char roundKey[6] = {0};
			des_permute(CDbytes, roundKey, PC2, 48);
			std::memcpy(subKey[round], roundKey, 6);
		}
	}
	void des::feistel(const unsigned char in[4], unsigned char out[4], const unsigned char roundKey[6]) {
		unsigned char expanded[6] = {0};
		des_permute(in, expanded, E, 48);
		for (int i = 0; i < 6; ++i) expanded[i] ^= roundKey[i];
		unsigned char sOut[4] = {0};
		for (int i = 0; i < 8; ++i) {
			int row = ((expanded[i / 2] >> (7 - (i % 2) * 4)) & 0x20) | ((expanded[i / 2] >> (3 - (i % 2) * 4)) & 0x01);
			row = (row >> 4) * 2 + (row & 0x01);
			int col = (expanded[i / 2] >> (3 - (i % 2) * 4)) & 0x0F;
			unsigned char val = S[i][row][col];
			if (i % 2 == 0) sOut[i / 2] = val << 4;
			else sOut[i / 2] |= val;
		}
		des_permute(sOut, out, P, 32);
	}
	void des::encryptblock(const unsigned char in[8], unsigned char out[8]) const {
		unsigned char ip[8] = {0};
		des_permute(in, ip, IP, 64);
		unsigned char L[4], R[4];
		std::memcpy(L, ip, 4);
		std::memcpy(R, ip + 4, 4);
		for (int round = 0; round < 16; ++round) {
			unsigned char fOut[4];
			feistel(R, fOut, subKey[round]);
			unsigned char newR[4];
			for (int i = 0; i < 4; ++i) newR[i] = L[i] ^ fOut[i];
			std::memcpy(L, R, 4);
			std::memcpy(R, newR, 4);
		}
		unsigned char preFP[8];
		std::memcpy(preFP, R, 4);
		std::memcpy(preFP + 4, L, 4);
		des_permute(preFP, out, FP, 64);
	}
	void des::decryptblock(const unsigned char in[8], unsigned char out[8]) const {
		unsigned char ip[8] = {0};
		des_permute(in, ip, IP, 64);
		unsigned char L[4], R[4];
		std::memcpy(L, ip, 4);
		std::memcpy(R, ip + 4, 4);
		for (int round = 15; round >= 0; --round) {
			unsigned char fOut[4];
			feistel(R, fOut, subKey[round]);
			unsigned char newR[4];
			for (int i = 0; i < 4; ++i) newR[i] = L[i] ^ fOut[i];
			std::memcpy(L, R, 4);
			std::memcpy(R, newR, 4);
		}
		unsigned char preFP[8];
		std::memcpy(preFP, R, 4);
		std::memcpy(preFP + 4, L, 4);
		des_permute(preFP, out, FP, 64);
	}
	std::string rail_fence_encrypt(const std::string& txt, int rails) {
		if (rails <= 1) return txt;
		std::vector<std::string> fence(rails);
		int row = 0, step = 1;
		for (char c : txt) {
			fence[row] += c;
			if (row == 0) step = 1;
			else if (row == rails - 1) step = -1;
			row += step;
		}
		std::string out;
		for (auto& r : fence) out += r;
		return out;
	}
	std::string rail_fence_decrypt(const std::string& cipher, int rails) {
		if (rails <= 1) return cipher;
		int n = cipher.size();
		std::vector<int> pos(n);
		int row = 0, step = 1;
		for (int i = 0; i < n; ++i) {
			pos[i] = row;
			if (row == 0) step = 1;
			else if (row == rails - 1) step = -1;
			row += step;
		}
		std::vector<int> cnt(rails, 0);
		for (int r : pos) ++cnt[r];
		std::vector<std::string> fence(rails);
		int cur = 0;
		for (int r = 0; r < rails; ++r) {
			fence[r] = cipher.substr(cur, cnt[r]);
			cur += cnt[r];
		}
		std::string out;
		std::vector<int> used(rails, 0);
		row = 0;
		step = 1;
		for (int i = 0; i < n; ++i) {
			out += fence[row][used[row]++];
			if (row == 0) step = 1;
			else if (row == rails - 1) step = -1;
			row += step;
		}
		return out;
	}
	namespace gost_28147 {
		const unsigned char S_BOX[8][16] = {
			{0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
			{0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
			{0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
			{0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
			{0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
			{0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
			{0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
			{0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2}
		};
		unsigned int rotl11(unsigned int x) {
			return (x << 11) | (x >> (32 - 11));
		}
		void gost28147_encrypt_block(const unsigned char *key, const unsigned char *block, unsigned char *output) {
			unsigned int K[8];
			unsigned int N1 = *(const unsigned int*)block;
			unsigned int N2 = *(const unsigned int*)(block + 4);
			for (int i = 0; i < 8; i++) {
				K[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 |
				       (unsigned int)key[4 * i + 2] << 8 | (unsigned int)key[4 * i + 3];
			}
			for (int round = 0; round < 32; round++) {
				unsigned int temp = N1 ^ K[round % 8];
				unsigned int s_out = 0;
				for (int i = 0; i < 8; i++) {
					unsigned char nibble = (temp >> (4 * (7 - i))) & 0xF;
					s_out |= (unsigned int)S_BOX[i][nibble] << (4 * (7 - i));
				}
				temp = rotl11(s_out);
				N1 = N2 ^ temp;
				swap(N1, N2);
			}
			swap(N1, N2);
			*(unsigned int*)output = N1;
			*(unsigned int*)(output + 4) = N2;
		}
		void gost28147_decrypt_block(const unsigned char *key, const unsigned char *block, unsigned char *output) {
			unsigned int K[8];
			unsigned int N1 = *(const unsigned int*)block;
			unsigned int N2 = *(const unsigned int*)(block + 4);
			for (int i = 0; i < 8; i++) {
				K[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 |
				       (unsigned int)key[4 * i + 2] << 8 | (unsigned int)key[4 * i + 3];
			}
			for (int round = 0; round < 32; round++) {
				unsigned int temp = N1 ^ K[(31 - round) % 8];
				unsigned int s_out = 0;
				for (int i = 0; i < 8; i++) {
					unsigned char nibble = (temp >> (4 * (7 - i))) & 0xF;
					s_out |= (unsigned int)S_BOX[i][nibble] << (4 * (7 - i));
				}
				temp = rotl11(s_out);
				N1 = N2 ^ temp;
				swap(N1, N2);
			}
			swap(N1, N2);
			*(unsigned int*)output = N1;
			*(unsigned int*)(output + 4) = N2;
		}
		const unsigned char KUZ_SBOX[256] = {
			0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
			0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F,
			0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42,
			0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6,
			0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3,
			0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8,
			0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E,
			0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10,
			0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30,
			0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8,
			0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C,
			0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6,
			0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76,
			0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6,
			0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2,
			0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1
		};
		const unsigned char KUZ_C[10][16] = {
			{0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}
		};
		unsigned char gf_mult(unsigned char a, unsigned char b) {
			unsigned char res = 0;
			for (int i = 0; i < 8; i++) {
				if (b & 1) res ^= a;
				bool carry = a & 0x80;
				a <<= 1;
				if (carry) a ^= 0xC3;
				b >>= 1;
			}
			return res;
		}
		void kuz_transform(unsigned char *state) {
			unsigned char temp[16];
			memcpy(temp, state, 16);
			for (int i = 0; i < 16; i++) {
				state[i] = KUZ_SBOX[temp[i]];
			}
			for (int i = 0; i < 16; i++) {
				temp[i] = state[i];
			}
			const unsigned char m[16][16] = {
				{1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0},
				{14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7},
				{13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8},
				{10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4},
				{7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3},
				{2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9},
				{4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1},
				{15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6},
				{8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2},
				{12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13},
				{3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12},
				{9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10},
				{6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5},
				{5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11},
				{11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14},
				{0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15}
			};
			for (int i = 0; i < 16; i++) {
				unsigned char sum = 0;
				for (int j = 0; j < 16; j++) {
					sum ^= gf_mult(temp[m[i][j]], (i == j) ? 1 : 0x01);
				}
				state[i] = sum;
			}
		}
		void kuz_key_expansion(const unsigned char *key, unsigned char round_keys[10][16]) {
			unsigned char K[32];
			memcpy(K, key, 32);
			for (int i = 0; i < 8; i++) {
				memcpy(round_keys[i], K + 16, 16);
				memcpy(round_keys[i + 1], K, 16);
				unsigned char temp[16];
				memcpy(temp, K + 16, 16);
				for (int j = 0; j < 16; j++) {
					temp[j] = KUZ_SBOX[temp[j]];
				}
				temp[0] ^= (i + 1) >> 8;
				temp[1] ^= (i + 1) & 0xFF;
				for (int j = 0; j < 16; j++) {
					temp[j] ^= KUZ_C[i][j];
				}
				kuz_transform(temp);
				for (int j = 0; j < 16; j++) {
					temp[j] ^= K[j];
				}
				memcpy(K, K + 16, 16);
				memcpy(K + 16, temp, 16);
			}
		}
		void kuz_encrypt_block(const unsigned char *key, const unsigned char *block, unsigned char *output) {
			unsigned char state[16];
			unsigned char round_keys[10][16];
			memcpy(state, block, 16);
			kuz_key_expansion(key, round_keys);
			for (int i = 0; i < 9; i++) {
				for (int j = 0; j < 16; j++) {
					state[j] ^= round_keys[i][j];
				}
				kuz_transform(state);
			}
			for (int j = 0; j < 16; j++) {
				state[j] ^= round_keys[9][j];
			}
			memcpy(output, state, 16);
		}
	}
	namespace gost_r_3411_94 {
		const unsigned char STREEBOG_SBOX[256] = {
			0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
			0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F,
			0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42,
			0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6,
			0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3,
			0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8,
			0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E,
			0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10,
			0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30,
			0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8,
			0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C,
			0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6,
			0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76,
			0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6,
			0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2,
			0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1
		};
		const unsigned long long int STREEBOG_C[12] = {
			0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
			0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
			0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
			0x0000000000000088, 0x0000000080008009, 0x000000008000000A
		};
		typedef struct {
			unsigned char h[64];
			unsigned char N[64];
			unsigned char Sigma[64];
			unsigned char buffer[64];
			size_t buf_ptr;
			int hashbitlen;
		} streebog_ctx;
		void streebog_init(streebog_ctx *ctx, int hashbitlen) {
			memset(ctx, 0, sizeof(streebog_ctx));
			ctx->hashbitlen = hashbitlen;
			if (hashbitlen == 256) {
				ctx->h[0] = 0x01;
			} else if (hashbitlen == 512) {
				memset(ctx->h, 0x01, 64);
			}
		}
		void streebog_transform(streebog_ctx *ctx, const unsigned char *data) {
			unsigned char k[64];
			unsigned char l[64];
			unsigned char tmp[64];
			memcpy(k, data, 64);
			for (int i = 0; i < 64; i++) {
				l[i] = ctx->h[i] ^ k[i];
			}
			for (int i = 0; i < 12; i++) {
				for (int j = 0; j < 8; j++) {
					for (int k = 0; k < 8; k++) {
						tmp[j * 8 + k] = STREEBOG_SBOX[l[j * 8 + k] ^ ((STREEBOG_C[i] >> (8 * k)) & (0xFF))];
					}
				}
				memcpy(l, tmp, 64);
				unsigned char t = l[0];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8] = l[j * 8];
				}
				l[56] = t;

				t = l[1];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8 + 1] = l[j * 8 + 1];
				}
				l[57] = t;
				t = l[2];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8 + 2] = l[j * 8 + 2];
				}
				l[58] = t;
				t = l[3];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8 + 3] = l[j * 8 + 3];
				}
				l[59] = t;
				t = l[4];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8 + 4] = l[j * 8 + 4];
				}
				l[60] = t;
				t = l[5];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8 + 5] = l[j * 8 + 5];
				}
				l[61] = t;
				t = l[6];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8 + 6] = l[j * 8 + 6];
				}
				l[62] = t;
				t = l[7];
				for (int j = 1; j < 8; j++) {
					l[(j - 1) * 8 + 7] = l[j * 8 + 7];
				}
				l[63] = t;
				for (int j = 0; j < 64; j++) {
					l[j] ^= k[j];
				}
				memcpy(k, l, 64);
			}
			for (int i = 0; i < 64; i++) {
				ctx->h[i] ^= k[i] ^ data[i];
			}
			unsigned long long int carry = 1;
			for (int i = 0; i < 8; i++) {
				unsigned long long int current = *(unsigned long long int*)(ctx->N + i * 8);
				unsigned long long int n = current + carry;
				carry = (n < current) ? 1 : 0;
				*(unsigned long long int*)(ctx->N + i * 8) = n;
			}
			unsigned char s[64];
			memcpy(s, data, 64);
			for (int i = 0; i < 64; i++) {
				ctx->Sigma[i] ^= s[i];
			}
		}
		void streebog_update(streebog_ctx *ctx, const unsigned char *data, size_t len) {
			while (len > 0) {
				size_t chunk = min(len, (size_t)(64 - ctx->buf_ptr));
				memcpy(ctx->buffer + ctx->buf_ptr, data, chunk);
				ctx->buf_ptr += chunk;
				data += chunk;
				len -= chunk;
				if (ctx->buf_ptr == 64) {
					streebog_transform(ctx, ctx->buffer);
					ctx->buf_ptr = 0;
				}
			}
		}
		void streebog_final(streebog_ctx *ctx, unsigned char *digest) {
			if (ctx->buf_ptr > 0) {
				memset(ctx->buffer + ctx->buf_ptr, 0, 64 - ctx->buf_ptr);
				streebog_transform(ctx, ctx->buffer);
			}
			unsigned char block[64];
			memset(block, 0, 64);
			for (int i = 0; i < 8; i++) {
				*(unsigned long long int*)(block + i * 8) = *(unsigned long long int*)(ctx->N + i * 8);
			}
			streebog_transform(ctx, block);
			memset(block, 0, 64);
			memcpy(block, ctx->Sigma, 64);
			streebog_transform(ctx, block);
			memcpy(digest, ctx->h, ctx->hashbitlen / 8);
		}
	}
	namespace gost_r_3412_2015 {
		const unsigned char MAGMA_SBOX[8][16] = {
			{0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
			{0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
			{0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
			{0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
			{0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
			{0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
			{0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
			{0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2}
		};
		unsigned int magma_rotl11(unsigned int x) {
			return (x << 11) | (x >> (32 - 11));
		}
		void magma_encrypt_block(const unsigned char* key, const unsigned char* block, unsigned char* output) {
			unsigned int K[8];
			unsigned int N1 = *(const unsigned int*)block;
			unsigned int N2 = *(const unsigned int*)(block + 4);
			for (int i = 0; i < 8; i++) {
				K[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 | (unsigned int)key[4 * i + 2] << 8 | (unsigned int)key[4 * i + 3];
			}
			for (int round = 0; round < 32; round++) {
				unsigned int temp = N1 ^ K[round % 8];
				unsigned int s_out = 0;
				for (int i = 0; i < 8; i++) {
					unsigned char nibble = (temp >> (4 * (7 - i))) & 0xF;
					s_out |= (unsigned int)MAGMA_SBOX[i][nibble] << (4 * (7 - i));
				}
				temp = magma_rotl11(s_out);
				N1 = N2 ^ temp;
				swap(N1, N2);
			}
			swap(N1, N2);
			*(unsigned int*)output = N1;
			*(unsigned int*)(output + 4) = N2;
		}
		void magma_decrypt_block(const unsigned char* key, const unsigned char* block, unsigned char* output) {
			unsigned int K[8];
			unsigned int N1 = *(const unsigned int*)block;
			unsigned int N2 = *(const unsigned int*)(block + 4);
			for (int i = 0; i < 8; i++) {
				K[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 | (unsigned int)key[4 * i + 2] << 8 | (unsigned int)key[4 * i + 3];
			}
			for (int round = 0; round < 32; round++) {
				unsigned int temp = N1 ^ K[(31 - round) % 8];
				unsigned int s_out = 0;
				for (int i = 0; i < 8; i++) {
					unsigned char nibble = (temp >> (4 * (7 - i))) & 0xF;
					s_out |= (unsigned int)MAGMA_SBOX[i][nibble] << (4 * (7 - i));
				}
				temp = magma_rotl11(s_out);
				N1 = N2 ^ temp;
				swap(N1, N2);
			}
			swap(N1, N2);
			*(unsigned int*)output = N1;
			*(unsigned int*)(output + 4) = N2;
		}
		const unsigned char KUZNYECHIK_SBOX[256] = {
			0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
			0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F,
			0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42,
			0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6,
			0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3,
			0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8,
			0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E,
			0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10,
			0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30,
			0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8,
			0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C,
			0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6,
			0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76,
			0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6,
			0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2,
			0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1
		};
		const unsigned char KUZNYECHIK_C[10][16] = {
			{0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
			{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}
		};
		unsigned char kuznyechik_gf_mult(unsigned char a, unsigned char b) {
			unsigned char res = 0;
			for (int i = 0; i < 8; i++) {
				if (b & 1) res ^= a;
				bool carry = a & 0x80;
				a <<= 1;
				if (carry) a ^= 0xC3;
				b >>= 1;
			}
			return res;
		}
		void kuznyechik_linear_transform(unsigned char* state) {
			unsigned char temp[16];
			memcpy(temp, state, 16);
			const unsigned char matrix[16][16] = {
				{1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0},
				{14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7},
				{13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8},
				{10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4},
				{7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3},
				{2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9},
				{4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1},
				{15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6},
				{8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2},
				{12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13},
				{3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12},
				{9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15, 0, 1, 4, 10},
				{6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5},
				{5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11},
				{11, 5, 6, 15, 0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14},
				{0, 1, 4, 10, 9, 2, 8, 13, 12, 3, 7, 14, 11, 5, 6, 15}
			};
			memset(state, 0, 16);
			for (int i = 0; i < 16; i++) {
				for (int j = 0; j < 16; j++) {
					state[i] ^= kuznyechik_gf_mult(temp[j], matrix[i][j]);
				}
			}
		}
		void kuznyechik_transform(unsigned char* state) {
			for (int i = 0; i < 16; i++) {
				state[i] = KUZNYECHIK_SBOX[state[i]];
			}
			kuznyechik_linear_transform(state);
		}
		void kuznyechik_key_expansion(const unsigned char* key, unsigned char round_keys[10][16]) {
			unsigned char K[32];
			memcpy(K, key, 32);
			for (int i = 0; i < 10; i++) {
				memcpy(round_keys[i], K + 16, 16);
				unsigned char temp[16];
				memcpy(temp, K + 16, 16);
				for (int j = 0; j < 16; j++) {
					temp[j] = KUZNYECHIK_SBOX[temp[j]];
				}
				temp[0] ^= (i + 1) >> 8;
				temp[1] ^= (i + 1) & 0xFF;
				for (int j = 0; j < 16; j++) {
					temp[j] ^= KUZNYECHIK_C[i][j];
				}
				kuznyechik_linear_transform(temp);
				for (int j = 0; j < 16; j++) {
					temp[j] ^= K[j];
				}
				memcpy(K, K + 16, 16);
				memcpy(K + 16, temp, 16);
			}
		}
		void kuznyechik_encrypt_block(const unsigned char* key, const unsigned char* block, unsigned char* output) {
			unsigned char state[16];
			unsigned char round_keys[10][16];
			memcpy(state, block, 16);
			kuznyechik_key_expansion(key, round_keys);
			for (int i = 0; i < 9; i++) {
				for (int j = 0; j < 16; j++) {
					state[j] ^= round_keys[i][j];
				}
				kuznyechik_transform(state);
			}
			for (int j = 0; j < 16; j++) {
				state[j] ^= round_keys[9][j];
			}
			memcpy(output, state, 16);
		}
		void kuznyechik_decrypt_block(const unsigned char* key, const unsigned char* block, unsigned char* output) {
			unsigned char state[16];
			unsigned char round_keys[10][16];
			memcpy(state, block, 16);
			kuznyechik_key_expansion(key, round_keys);
			for (int i = 9; i > 0; i--) {
				for (int j = 0; j < 16; j++) {
					state[j] ^= round_keys[i][j];
				}
				unsigned char inv_state[16];
				memcpy(inv_state, state, 16);
				unsigned char inv_sbox[256];
				for (int j = 0; j < 256; j++) {
					for (int k = 0; k < 256; k++) {
						if (KUZNYECHIK_SBOX[k] == j) {
							inv_sbox[j] = k;
							break;
						}
					}
				}
				for (int j = 0; j < 16; j++) {
					inv_state[j] = inv_sbox[inv_state[j]];
				}
				const unsigned char inv_matrix[16][16] = {
					{0, 12, 5, 14, 3, 10, 1, 9, 13, 4, 15, 2, 7, 8, 11, 6},
					{1, 0, 12, 5, 14, 3, 10, 15, 9, 13, 4, 2, 11, 7, 8, 6},
					{10, 1, 0, 12, 5, 14, 3, 4, 15, 9, 13, 6, 2, 11, 7, 8},
					{13, 10, 1, 0, 12, 5, 14, 15, 4, 9, 6, 3, 8, 2, 11, 7},
					{9, 13, 10, 1, 0, 12, 5, 4, 15, 6, 3, 14, 7, 8, 2, 11},
					{5, 9, 13, 10, 1, 0, 12, 15, 4, 6, 14, 3, 11, 7, 8, 2},
					{12, 5, 9, 13, 10, 1, 0, 4, 15, 14, 3, 6, 8, 11, 7, 2},
					{0, 12, 5, 9, 13, 10, 1, 15, 14, 3, 6, 4, 2, 8, 11, 7},
					{6, 0, 12, 5, 9, 13, 10, 14, 3, 6, 4, 15, 7, 2, 8, 11},
					{3, 6, 0, 12, 5, 9, 13, 3, 14, 4, 15, 10, 11, 7, 2, 8},
					{15, 3, 6, 0, 12, 5, 9, 14, 4, 15, 10, 13, 8, 11, 7, 2},
					{4, 15, 3, 6, 0, 12, 5, 4, 15, 10, 13, 9, 2, 8, 11, 7},
					{14, 4, 15, 3, 6, 0, 12, 15, 10, 13, 9, 5, 7, 2, 8, 11},
					{10, 14, 4, 15, 3, 6, 0, 10, 13, 9, 5, 12, 11, 7, 2, 8},
					{1, 10, 14, 4, 15, 3, 6, 13, 9, 5, 12, 0, 8, 11, 7, 2},
					{12, 1, 10, 14, 4, 15, 3, 9, 5, 12, 0, 6, 2, 8, 11, 7}
				};
				unsigned char temp[16];
				memset(temp, 0, 16);
				for (int j = 0; j < 16; j++) {
					for (int k = 0; k < 16; k++) {
						temp[j] ^= kuznyechik_gf_mult(inv_state[k], inv_matrix[j][k]);
					}
				}
				memcpy(state, temp, 16);
			}
			for (int j = 0; j < 16; j++) {
				state[j] ^= round_keys[0][j];
			}
			memcpy(output, state, 16);
		}

	}
	namespace gost_r_3413_2015 {
		typedef void (*block_cipher_encrypt)(const unsigned char*, const unsigned char*, unsigned char*);
		typedef void (*block_cipher_decrypt)(const unsigned char*, const unsigned char*, unsigned char*);
		const unsigned char MAGMA_SBOX[8][16] = {
			{0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
			{0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
			{0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
			{0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
			{0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
			{0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
			{0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
			{0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2}
		};

		unsigned int magma_rotl11(unsigned int x) {
			return (x << 11) | (x >> 21);
		}
		void magma_encrypt(const unsigned char* key, const unsigned char* block, unsigned char* output) {
			unsigned int K[8], N1 = *(const unsigned int*)block, N2 = *(const unsigned int*)(block + 4);
			for (int i = 0; i < 8; i++) K[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 | (unsigned int)key[4 * i + 2] << 8 | key[4 * i + 3];
			for (int r = 0; r < 32; r++) {
				unsigned int t = N1 ^ K[r % 8], s = 0;
				for (int i = 0; i < 8; i++) {
					unsigned char nib = (t >> (4 * (7 - i))) & 0xF;
					s |= (unsigned int)MAGMA_SBOX[i][nib] << (4 * (7 - i));
				}
				t = magma_rotl11(s);
				N1 = N2 ^ t;
				swap(N1, N2);
			}
			swap(N1, N2);
			*(unsigned int*)output = N1;
			*(unsigned int*)(output + 4) = N2;
		}
		void magma_decrypt(const unsigned char* key, const unsigned char* block, unsigned char* output) {
			unsigned int K[8], N1 = *(const unsigned int*)block, N2 = *(const unsigned int*)(block + 4);
			for (int i = 0; i < 8; i++) K[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 | (unsigned int)key[4 * i + 2] << 8 | key[4 * i + 3];
			for (int r = 0; r < 32; r++) {
				unsigned int t = N1 ^ K[(31 - r) % 8], s = 0;
				for (int i = 0; i < 8; i++) {
					unsigned char nib = (t >> (4 * (7 - i))) & 0xF;
					s |= (unsigned int)MAGMA_SBOX[i][nib] << (4 * (7 - i));
				}
				t = magma_rotl11(s);
				N1 = N2 ^ t;
				swap(N1, N2);
			}
			swap(N1, N2);
			*(unsigned int*)output = N1;
			*(unsigned int*)(output + 4) = N2;
		}

		// GOST R 34.13-2015 工作模式实现
		const int MAGMA_BLOCK_SIZE = 8;
		const int KUZNYECHIK_BLOCK_SIZE = 16;

		// ECB模式 (电子密码本)
		void gost3413_ecb_encrypt(const unsigned char* key, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			for (size_t i = 0; i < len; i += block_size) {
				encrypt(key, data + i, output + i);
			}
		}
		void gost3413_ecb_decrypt(const unsigned char* key, const unsigned char* data, size_t len, int block_size, block_cipher_decrypt decrypt, unsigned char* output) {
			for (size_t i = 0; i < len; i += block_size) {
				decrypt(key, data + i, output + i);
			}
		}

		// CBC模式 (密码分组链接)
		void gost3413_cbc_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			unsigned char temp[block_size];
			memcpy(temp, iv, block_size);
			for (size_t i = 0; i < len; i += block_size) {
				for (int j = 0; j < block_size; j++) temp[j] ^= data[i + j];
				encrypt(key, temp, output + i);
				memcpy(temp, output + i, block_size);
			}
		}
		void gost3413_cbc_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, size_t len, int block_size, block_cipher_decrypt decrypt, unsigned char* output) {
			unsigned char temp[block_size], prev[block_size];
			memcpy(prev, iv, block_size);
			for (size_t i = 0; i < len; i += block_size) {
				decrypt(key, data + i, temp);
				for (int j = 0; j < block_size; j++) output[i + j] = temp[j] ^ prev[j];
				memcpy(prev, data + i, block_size);
			}
		}

		// CFB模式 (密码反馈)
		void gost3413_cfb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			unsigned char temp[block_size];
			memcpy(temp, iv, block_size);
			for (size_t i = 0; i < len; i += block_size) {
				encrypt(key, temp, output + i);
				for (int j = 0; j < block_size; j++) {
					output[i + j] ^= data[i + j];
					temp[j] = output[i + j];
				}
			}
		}
		void gost3413_cfb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			unsigned char temp[block_size], prev[block_size];
			memcpy(prev, iv, block_size);
			for (size_t i = 0; i < len; i += block_size) {
				encrypt(key, prev, temp);
				for (int j = 0; j < block_size; j++) {
					output[i + j] = temp[j] ^ data[i + j];
					prev[j] = data[i + j];
				}
			}
		}

		// OFB模式 (输出反馈)
		void gost3413_ofb_encrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			unsigned char temp[block_size];
			memcpy(temp, iv, block_size);
			for (size_t i = 0; i < len; i += block_size) {
				encrypt(key, temp, output + i);
				for (int j = 0; j < block_size; j++) {
					output[i + j] ^= data[i + j];
					temp[j] = output[i + j] ^ data[i + j];
				}
			}
		}
		void gost3413_ofb_decrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			gost3413_ofb_encrypt(key, iv, data, len, block_size, encrypt, output);
		}

		// CTR模式 (计数器)
		void gost3413_ctr_encrypt(const unsigned char* key, const unsigned char* nonce, unsigned long long int counter, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			unsigned char block[block_size], temp[block_size];
			memcpy(block, nonce, block_size - 8);
			for (size_t i = 0; i < len; i += block_size) {
				*(unsigned long long int*)(block + block_size - 8) = counter++;
				encrypt(key, block, temp);
				for (int j = 0; j < block_size && i + j < len; j++) {
					output[i + j] = data[i + j] ^ temp[j];
				}
			}
		}
		void gost3413_ctr_decrypt(const unsigned char* key, const unsigned char* nonce, unsigned long long int counter, const unsigned char* data, size_t len, int block_size, block_cipher_encrypt encrypt, unsigned char* output) {
			gost3413_ctr_encrypt(key, nonce, counter, data, len, block_size, encrypt, output);
		}

		// GCM模式 (伽罗瓦/计数器)
		unsigned char gcm_gf_mult(unsigned char a, unsigned char b) {
			unsigned char r = 0;
			for (int i = 0; i < 8; i++) {
				if (b & 1) r ^= a;
				bool c = a & 0x80;
				a <<= 1;
				if (c) a ^= 0xE1;
				b >>= 1;
			}
			return r;
		}
		void gcm_mult_block(const unsigned char* a, const unsigned char* b, unsigned char* output) {
			unsigned char temp[16] = {0};
			for (int i = 0; i < 16; i++) {
				if (a[i] == 0) continue;
				unsigned char carry = 0;
				for (int j = 0; j < 16; j++) {
					unsigned short prod = (unsigned short)temp[j] + (unsigned short)gcm_gf_mult(a[i], b[j]) + carry;
					carry = prod >> 8;
					temp[j] = prod & 0xFF;
				}
			}
			memcpy(output, temp, 16);
		}
		void gcm_shift_right(unsigned char* block) {
			for (int i = 15; i > 0; i--) {
				block[i] = (block[i] >> 1) | (block[i - 1] << 7);
			}
			block[0] >>= 1;
		}
		void gost3413_gcm_encrypt(const unsigned char* key, const unsigned char* iv, size_t iv_len, const unsigned char* ad, size_t ad_len, const unsigned char* data, size_t data_len, unsigned char* output, unsigned char* tag, size_t tag_len) {
			unsigned char h[16] = {0};
			magma_encrypt(key, h, h);
			unsigned char y[16] = {0};
			unsigned char temp[16] = {0};
			if (iv_len == 12) {
				memcpy(y, iv, 12);
				y[12] = 0x00;
				y[13] = 0x00;
				y[14] = 0x00;
				y[15] = 0x01;
			} else {
				for (size_t i = 0; i < iv_len; i += 16) {
					size_t len = min(iv_len - i, (size_t)16);
					unsigned char block[16] = {0};
					memcpy(block, iv + i, len);
					for (int j = 0; j < 16; j++) y[j] ^= block[j];
					gcm_mult_block(y, h, y);
				}
				unsigned long long int len_bits = (unsigned long long int)iv_len * 8;
				unsigned char len_block[16] = {0};
				*(unsigned long long int*)(len_block + 8) = len_bits;
				for (int j = 0; j < 16; j++) y[j] ^= len_block[j];
				gcm_mult_block(y, h, y);
			}
			unsigned char j0[16];
			memcpy(j0, y, 16);
			unsigned long long int counter = 1;
			for (size_t i = 0; i < data_len; i += 16) {
				*(unsigned long long int*)(y + 8) = counter++;
				unsigned char temp[16];
				magma_encrypt(key, y, temp);
				size_t len = min(data_len - i, (size_t)16);
				for (size_t j = 0; j < len; j++) {
					output[i + j] = data[i + j] ^ temp[j];
				}
			}
			unsigned char s[16] = {0};
			for (size_t i = 0; i < ad_len; i += 16) {
				size_t len = min(ad_len - i, (size_t)16);
				unsigned char block[16] = {0};
				memcpy(block, ad + i, len);
				for (int j = 0; j < 16; j++) s[j] ^= block[j];
				gcm_mult_block(s, h, s);
			}
			for (size_t i = 0; i < data_len; i += 16) {
				size_t len = min(data_len - i, (size_t)16);
				unsigned char block[16] = {0};
				memcpy(block, output + i, len);
				for (int j = 0; j < 16; j++) s[j] ^= block[j];
				gcm_mult_block(s, h, s);
			}
			unsigned long long int ad_bits = (unsigned long long int)ad_len * 8;
			unsigned long long int data_bits = (unsigned long long int)data_len * 8;
			unsigned char len_block[16] = {0};
			*(unsigned long long int*)len_block = ad_bits;
			*(unsigned long long int*)(len_block + 8) = data_bits;
			for (int j = 0; j < 16; j++) s[j] ^= len_block[j];
			gcm_mult_block(s, h, s);
			magma_encrypt(key, j0, temp);
			for (int j = 0; j < int(tag_len); j++) {
				tag[j] = s[j] ^ temp[j];
			}
		}
	}
	namespace gost_r_3411_2012 {
		const unsigned char STREEBOG_SBOX[256] = {
			0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
			0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F,
			0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42,
			0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6,
			0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3,
			0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8,
			0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E,
			0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10,
			0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30,
			0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8,
			0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C,
			0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6,
			0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76,
			0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6,
			0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2,
			0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1
		};
		const unsigned long long int STREEBOG_C[12] = {
			0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
			0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
			0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
			0x0000000000000088, 0x0000000080008009, 0x000000008000000A
		};
		typedef struct {
			unsigned char h[64];
			unsigned char N[64];
			unsigned char Sigma[64];
			unsigned char buffer[64];
			size_t buf_ptr;
			int hashbitlen;
		} streebog_ctx;
		static void uint64_to_le_bytes(unsigned long long int value, unsigned char* dest) {
			for (int i = 0; i < 8; i++) {
				dest[i] = (unsigned char)(value >> (8 * i));
			}
		}
		static unsigned long long int le_bytes_to_uint64(const unsigned char* src) {
			unsigned long long int value = 0;
			for (int i = 0; i < 8; i++) {
				value |= (unsigned long long int)src[i] << (8 * i);
			}
			return value;
		}
		static void streebog_transform(streebog_ctx* ctx, const unsigned char* data) {
			unsigned char k[64];
			unsigned char l[64];
			unsigned char tmp[64];
			memcpy(k, data, 64);
			for (int i = 0; i < 64; i++) {
				l[i] = ctx->h[i] ^ k[i];
			}
			for (int round = 0; round < 12; round++) {
				for (int j = 0; j < 8; j++) {
					for (int k_idx = 0; k_idx < 8; k_idx++) {
						size_t pos = j * 8 + k_idx;
						unsigned char c_byte = (unsigned char)((STREEBOG_C[round] >> (8 * k_idx)) & 0xFF);
						tmp[pos] = STREEBOG_SBOX[l[pos] ^ c_byte];
					}
				}
				memcpy(l, tmp, 64);
				for (int col = 0; col < 8; col++) {
					unsigned char t = l[col];
					for (int row = 1; row < 8; row++) {
						l[(row - 1) * 8 + col] = l[row * 8 + col];
					}
					l[7 * 8 + col] = t;
				}
				for (int i = 0; i < 64; i++) {
					l[i] ^= k[i];
				}
				memcpy(k, l, 64);
			}
			for (int i = 0; i < 64; i++) {
				ctx->h[i] ^= k[i] ^ data[i];
			}
			unsigned long long int carry = 1;
			for (int i = 0; i < 8; i++) {
				unsigned long long int current = le_bytes_to_uint64(ctx->N + i * 8);
				unsigned long long int new_val = current + carry;
				carry = (new_val < current) ? 1 : 0;
				uint64_to_le_bytes(new_val, ctx->N + i * 8);
				if (carry == 0) break;
			}
			for (int i = 0; i < 64; i++) {
				ctx->Sigma[i] ^= data[i];
			}
		}
		void streebog_init(streebog_ctx* ctx, int hashbitlen) {
			if (ctx == nullptr || (hashbitlen != 256 && hashbitlen != 512)) {
				return;
			}
			memset(ctx, 0, sizeof(streebog_ctx));
			ctx->hashbitlen = hashbitlen;
			if (hashbitlen == 256) {
				ctx->h[0] = 0x01;
			} else if (hashbitlen == 512) {
				memset(ctx->h, 0x01, 64);
			}
		}
		size_t min(const size_t a, const size_t b) {
			return ((a < b) ? a : b);
		}
		void streebog_update(streebog_ctx* ctx, const unsigned char* data, size_t len) {
			if (ctx == nullptr || data == nullptr || len == 0) {
				return;
			}
			while (len > 0) {
				size_t chunk_len = min(len, (size_t)(64 - ctx->buf_ptr));
				memcpy(ctx->buffer + ctx->buf_ptr, data, chunk_len);
				ctx->buf_ptr += chunk_len;
				data += chunk_len;
				len -= chunk_len;
				if (ctx->buf_ptr == 64) {
					streebog_transform(ctx, ctx->buffer);
					ctx->buf_ptr = 0;
				}
			}
		}
		void streebog_final(streebog_ctx* ctx, unsigned char* digest) {
			if (ctx == nullptr || digest == nullptr) {
				return;
			}
			if (ctx->buf_ptr > 0) {
				memset(ctx->buffer + ctx->buf_ptr, 0, 64 - ctx->buf_ptr);
				streebog_transform(ctx, ctx->buffer);
				ctx->buf_ptr = 0;
			}
			unsigned char block[64];
			memset(block, 0, 64);
			memcpy(block, ctx->N, 64);
			streebog_transform(ctx, block);
			memset(block, 0, 64);
			memcpy(block, ctx->Sigma, 64);
			streebog_transform(ctx, block);
			memcpy(digest, ctx->h, ctx->hashbitlen / 8);
		}
		void streebog256(const unsigned char* data, size_t len, unsigned char* digest) {
			streebog_ctx ctx;
			streebog_init(&ctx, 256);
			streebog_update(&ctx, data, len);
			streebog_final(&ctx, digest);
		}
		void streebog512(const unsigned char* data, size_t len, unsigned char* digest) {
			streebog_ctx ctx;
			streebog_init(&ctx, 512);
			streebog_update(&ctx, data, len);
			streebog_final(&ctx, digest);
		}
	}
	namespace gost_r_3410_94 {
#include <cstdint>
#include <cstring>
#include <cstddef>
		unsigned int mod_pow(unsigned int base, unsigned int exp, unsigned int mod) {
			unsigned int result = 1;
			base %= mod;
			while (exp > 0) {
				if (exp & 1) result = (unsigned long long int)result * base % mod;
				base = (unsigned long long int)base * base % mod;
				exp >>= 1;
			}
			return result;
		}
		void ecp_add(unsigned int p, unsigned int a, unsigned int x1, unsigned int y1, unsigned int x2, unsigned int y2, unsigned int* x3, unsigned int* y3) {
			if (x1 == x2 && y1 == y2) {
				unsigned int s = (3 * (unsigned long long int)x1 * x1 + a) % p;
				unsigned int inv_2y1 = mod_pow(2 * y1 % p, p - 2, p);
				s = (unsigned long long int)s * inv_2y1 % p;
				*x3 = ((unsigned long long int)s * s - x1 - x2) % p;
			} else {
				unsigned int dx = (x2 - x1 + p) % p;
				unsigned int dy = (y2 - y1 + p) % p;
				unsigned int inv_dx = mod_pow(dx, p - 2, p);
				unsigned int s = (unsigned long long int)dy * inv_dx % p;
				*x3 = ((unsigned long long int)s * s - x1 - x2) % p;
			}
			if (*x3 > p) *x3 += p;
			unsigned int s = (x1 == x2 && y1 == y2) ? (3 * (unsigned long long int)x1 * x1 + a) % p * mod_pow(2 * y1 % p, p - 2, p) % p : (unsigned long long int)(y2 - y1 + p) % p * mod_pow((x2 - x1 + p) % p, p - 2, p) % p;
			*y3 = ((unsigned long long int)s * (x1 - *x3 + p) % p - y1 + p) % p;
		}
		void ecp_mul(unsigned int p, unsigned int a, unsigned int x, unsigned int y, unsigned int k, unsigned int* rx, unsigned int* ry) {
			*rx = 0;
			*ry = 0;
			unsigned int tx = x, ty = y;
			while (k > 0) {
				if (k & 1) {
					if (*rx == 0 && *ry == 0) {
						*rx = tx;
						*ry = ty;
					} else ecp_add(p, a, *rx, *ry, tx, ty, rx, ry);
				}
				ecp_add(p, a, tx, ty, tx, ty, &tx, &ty);
				k >>= 1;
			}
		}
		unsigned int gost341094_generate_private_key(unsigned int q) {
			return rand() % (q - 2) + 2;
		}
		static unsigned int c(unsigned int b) {
			return b;
		}
		void gost341094_generate_public_key(unsigned int p, unsigned int q, unsigned int a, unsigned int x, unsigned int y, unsigned int d, unsigned int* Qx, unsigned int* Qy) {
			c(q);
			ecp_mul(p, a, x, y, d, Qx, Qy);
		}
		unsigned int gost341094_hash(const unsigned char* data, size_t len, unsigned int q) {
			unsigned int hash = 0;
			for (size_t i = 0; i < len; i++) hash = ((unsigned long long int)hash << 8 | data[i]) % q;
			return hash;
		}
		void gost341094_sign(const unsigned char* data, size_t len, unsigned int p, unsigned int q, unsigned int a, unsigned int x, unsigned int y, unsigned int d, unsigned int* r, unsigned int* s) {
			unsigned int e = gost341094_hash(data, len, q);
			do {
				unsigned int k;
				do k = rand() % (q - 1) + 1;
				while (k == 0);
				unsigned int kx, ky;
				ecp_mul(p, a, x, y, k, &kx, &ky);
				*r = kx % q;
				if (*r == 0) continue;
				unsigned int inv_k = mod_pow(k, q - 2, q);
				*s = (unsigned long long int)(e + d * *r) % q * inv_k % q;
			} while (*s == 0);
		}
		int gost341094_verify(const unsigned char* data, size_t len, unsigned int p, unsigned int q, unsigned int a, unsigned int x, unsigned int y, unsigned int Qx, unsigned int Qy, unsigned int r, unsigned int s) {
			if (r < 1 || r >= q || s < 1 || s >= q) return 0;
			unsigned int e = gost341094_hash(data, len, q);
			unsigned int inv_s = mod_pow(s, q - 2, q);
			unsigned int u1 = (unsigned long long int)e * inv_s % q;
			unsigned int u2 = (unsigned long long int)r * inv_s % q;
			unsigned int x1, y1, x2, y2, vx, vy;
			ecp_mul(p, a, x, y, u1, &x1, &y1);
			ecp_mul(p, a, Qx, Qy, u2, &x2, &y2);
			ecp_add(p, a, x1, y1, x2, y2, &vx, &vy);
			unsigned int v = vx % q;
			return v == r ? 1 : 0;
		}
	}
	namespace gost_r_3410_2001 {
#include <cstdint>
#include <cstring>
#include <cstddef>
		typedef struct {
			unsigned long long int x[2], y[2];
		} ecp_point;
		unsigned long long int mod_sub(unsigned long long int a, unsigned long long int b, const unsigned long long int* mod) {
			unsigned long long int res[2];
			res[1] = a > b ? 0 : 1;
			res[0] = a - b;
			if (res[1]) {
				res[0] = mod[0] - res[0];
				res[1] = mod[1] - 1;
			}
			int cmp = (res[1] > mod[1]) ? 1 : (res[1] < mod[1]) ? -1 : (res[0] > mod[0]) ? 1 : (res[0] < mod[0]) ? -1 : 0;
			if (cmp >= 0) {
				res[0] -= mod[0];
				res[1] -= mod[1];
				if (res[0] > mod[0]) res[0] -= mod[0], res[1]--;
			}
			return res[1] ? res[0] + res[1] * mod[0] : res[0];
		}
		unsigned long long int mod_mul(unsigned long long int a, unsigned long long int b, const unsigned long long int* mod) {
			unsigned long long int res = 0;
			a %= (mod[1] ? mod[1] * mod[0] : mod[0]);
			b %= (mod[1] ? mod[1] * mod[0] : mod[0]);
			while (b > 0) {
				if (b & 1) res = (res + a) % (mod[1] ? mod[1] * mod[0] : mod[0]);
				a = (a << 1) % (mod[1] ? mod[1] * mod[0] : mod[0]);
				b >>= 1;
			}
			return res;
		}
		unsigned long long int mod_pow(unsigned long long int base, unsigned long long int exp, const unsigned long long int* mod) {
			unsigned long long int res = 1;
			base %= (mod[1] ? mod[1] * mod[0] : mod[0]);
			while (exp > 0) {
				if (exp & 1) res = mod_mul(res, base, mod);
				base = mod_mul(base, base, mod);
				exp >>= 1;
			}
			return res;
		}
		void ecp_add(const unsigned long long int* p, const unsigned long long int* a, const ecp_point* P, const ecp_point* Q, ecp_point* R) {
			if (P->x[0] == 0 && P->x[1] == 0 && P->y[0] == 0 && P->y[1] == 0) {
				*R = *Q;
				return;
			}
			if (Q->x[0] == 0 && Q->x[1] == 0 && Q->y[0] == 0 && Q->y[1] == 0) {
				*R = *P;
				return;
			}
			unsigned long long int dx[2], dy[2], s[2];
			dx[0] = mod_sub(Q->x[0], P->x[0], p);
			dx[1] = mod_sub(Q->x[1], P->x[1], p);
			dy[0] = mod_sub(Q->y[0], P->y[0], p);
			dy[1] = mod_sub(Q->y[1], P->y[1], p);
			int is_equal = (dx[0] == 0 && dx[1] == 0 && dy[0] == 0 && dy[1] == 0);
			if (is_equal) {
				unsigned long long int x2[2] = {mod_mul(P->x[0], P->x[0], p), mod_mul(P->x[1], P->x[1], p)};
				unsigned long long int three_x2[2] = {mod_mul(3, x2[0], p), mod_mul(3, x2[1], p)};
				s[0] = mod_mul(three_x2[0] + a[0], mod_pow(mod_mul(2, P->y[0], p), (p[1] ? p[1] * p[0] : p[0]) - 2, p), p);
				s[1] = mod_mul(three_x2[1] + a[1], mod_pow(mod_mul(2, P->y[1], p), (p[1] ? p[1] * p[0] : p[0]) - 2, p), p);
			} else {
				unsigned long long int inv_dx[2] = {mod_pow(dx[0], (p[1] ? p[1] * p[0] : p[0]) - 2, p), mod_pow(dx[1], (p[1] ? p[1] * p[0] : p[0]) - 2, p)};
				s[0] = mod_mul(dy[0], inv_dx[0], p);
				s[1] = mod_mul(dy[1], inv_dx[1], p);
			}
			R->x[0] = mod_sub(mod_mul(s[0], s[0], p), P->x[0], p);
			R->x[0] = mod_sub(R->x[0], Q->x[0], p);
			R->x[1] = mod_sub(mod_mul(s[1], s[1], p), P->x[1], p);
			R->x[1] = mod_sub(R->x[1], Q->x[1], p);
			unsigned long long int x_diff[2] = {mod_sub(P->x[0], R->x[0], p), mod_sub(P->x[1], R->x[1], p)};
			R->y[0] = mod_sub(mod_mul(s[0], x_diff[0], p), P->y[0], p);
			R->y[1] = mod_sub(mod_mul(s[1], x_diff[1], p), P->y[1], p);
		}
		void ecp_mul(const unsigned long long int* p, const unsigned long long int* a, const ecp_point* G, unsigned long long int k[2], ecp_point* Q) {
			ecp_point res = {{0, 0}, {0, 0}};
			ecp_point temp = *G;
			unsigned long long int exp[2] = {k[0], k[1]};
			while (exp[0] > 0 || exp[1] > 0) {
				if (exp[0] & 1) ecp_add(p, a, &res, &temp, &res);
				ecp_add(p, a, &temp, &temp, &temp);
				exp[0] >>= 1;
				if (exp[1] > 0 && (exp[0] == 0 && (exp[1] & 1))) {
					ecp_add(p, a, &res, &temp, &res);
					exp[1] >>= 1;
					exp[0] = UINT64_MAX;
				} else if (exp[1] > 0) exp[1] >>= 1;
			}
			*Q = res;
		}
		void gost3411_2001_hash(const unsigned char* data, size_t len, unsigned long long int hash[2]) {
			unsigned char h[64] = {0};
			unsigned char N[64] = {0}, Sigma[64] = {0}, buffer[64] = {0};
			size_t buf_ptr = 0;
			const unsigned char SBOX[256] = {0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F, 0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42, 0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6, 0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3, 0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8, 0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E, 0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10, 0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30, 0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8, 0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C, 0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6, 0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76, 0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6, 0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2, 0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1};
			const unsigned long long int C[12] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A};
			memset(h, 0x01, 64);
			while (len > 0) {
				size_t chunk = (len < 64 - buf_ptr) ? len : 64 - buf_ptr;
				memcpy(buffer + buf_ptr, data, chunk);
				buf_ptr += chunk;
				data += chunk;
				len -= chunk;
				if (buf_ptr == 64) {
					unsigned char k[64], l[64], tmp[64];
					memcpy(k, buffer, 64);
					for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
					for (int i = 0; i < 12; i++) {
						for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
						memcpy(l, tmp, 64);
						for (int j = 0; j < 8; j++) {
							unsigned char t = l[j];
							for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
							l[56 + j] = t;
						}
						for (int j = 0; j < 64; j++) l[j] ^= k[j];
						memcpy(k, l, 64);
					}
					for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ buffer[i];
					unsigned long long int carry = 1;
					for (int i = 0; i < 8; i++) {
						unsigned long long int curr = *(unsigned long long int*)(N + i * 8);
						unsigned long long int n = curr + carry;
						carry = (n < curr) ? 1 : 0;
						*(unsigned long long int*)(N + i * 8) = n;
					}
					for (int i = 0; i < 64; i++) Sigma[i] ^= buffer[i];
					buf_ptr = 0;
				}
			}
			if (buf_ptr > 0) {
				memset(buffer + buf_ptr, 0, 64 - buf_ptr);
				unsigned char k[64], l[64], tmp[64];
				memcpy(k, buffer, 64);
				for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
				for (int i = 0; i < 12; i++) {
					for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
					memcpy(l, tmp, 64);
					for (int j = 0; j < 8; j++) {
						unsigned char t = l[j];
						for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
						l[56 + j] = t;
					}
					for (int j = 0; j < 64; j++) l[j] ^= k[j];
					memcpy(k, l, 64);
				}
				for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ buffer[i];
				unsigned long long int carry = 1;
				for (int i = 0; i < 8; i++) {
					unsigned long long int curr = *(unsigned long long int*)(N + i * 8);
					unsigned long long int n = curr + carry;
					carry = (n < curr) ? 1 : 0;
					*(unsigned long long int*)(N + i * 8) = n;
				}
				for (int i = 0; i < 64; i++) Sigma[i] ^= buffer[i];
			}
			unsigned char block[64];
			memset(block, 0, 64);
			memcpy(block, N, 64);
			unsigned char k[64], l[64], tmp[64];
			memcpy(k, block, 64);
			for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
			for (int i = 0; i < 12; i++) {
				for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
				memcpy(l, tmp, 64);
				for (int j = 0; j < 8; j++) {
					unsigned char t = l[j];
					for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
					l[56 + j] = t;
				}
				for (int j = 0; j < 64; j++) l[j] ^= k[j];
				memcpy(k, l, 64);
			}
			for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ block[i];
			memset(block, 0, 64);
			memcpy(block, Sigma, 64);
			memcpy(k, block, 64);
			for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
			for (int i = 0; i < 12; i++) {
				for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
				memcpy(l, tmp, 64);
				for (int j = 0; j < 8; j++) {
					unsigned char t = l[j];
					for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
					l[56 + j] = t;
				}
				for (int j = 0; j < 64; j++) l[j] ^= k[j];
				memcpy(k, l, 64);
			}
			for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ block[i];
			memcpy(hash, h, 16);
		}
		void gost3410_2001_generate_keys(const unsigned long long int* p, const unsigned long long int* q, const unsigned long long int* a, const ecp_point* G, unsigned long long int d[2], ecp_point* Q) {
			d[0] = (unsigned long long int)rand() % (q[0] - 2) + 2;
			d[1] = (unsigned long long int)rand() % (q[1] ? q[1] : 1);
			while (d[1] * q[0] + d[0] >= q[1] * q[0] || d[1] * q[0] + d[0] < 2) {
				d[0] = (unsigned long long int)rand() % (q[0] - 2) + 2;
				d[1] = (unsigned long long int)rand() % (q[1] ? q[1] : 1);
			}
			ecp_mul(p, a, G, d, Q);
		}
		void gost3410_2001_sign(const unsigned char* data, size_t len, const unsigned long long int* p, const unsigned long long int* q, const unsigned long long int* a, const ecp_point* G, const unsigned long long int d[2], unsigned long long int r[2], unsigned long long int s[2]) {
			unsigned long long int e[2];
			gost3411_2001_hash(data, len, e);
			e[0] %= q[0];
			e[1] %= q[1] ? q[1] : 1;
			do {
				unsigned long long int k[2];
				do {
					k[0] = (unsigned long long int)rand() % (q[0] - 1) + 1;
					k[1] = (unsigned long long int)rand() % (q[1] ? q[1] : 1);
				} while (k[1] * q[0] + k[0] >= q[1] * q[0] || k[1] * q[0] + k[0] == 0);
				ecp_point K;
				ecp_mul(p, a, G, k, &K);
				r[0] = K.x[0] % q[0];
				r[1] = K.x[1] % (q[1] ? q[1] : 1);
				if (r[0] == 0 && r[1] == 0) continue;
				unsigned long long int inv_k[2] = {mod_pow(k[0], (q[1] ? q[1] * q[0] : q[0]) - 2, q), mod_pow(k[1], (q[1] ? q[1] * q[0] : q[0]) - 2, q)};
				unsigned long long int dr[2] = {mod_mul(d[0], r[0], q), mod_mul(d[1], r[1], q)};
				s[0] = mod_mul((e[0] + dr[0]) % q[0], inv_k[0], q);
				s[1] = mod_mul((e[1] + dr[1]) % (q[1] ? q[1] : 1), inv_k[1], q);
			} while (s[0] == 0 && s[1] == 0);
		}
		int gost3410_2001_verify(const unsigned char* data, size_t len, const unsigned long long int* p, const unsigned long long int* q, const unsigned long long int* a, const ecp_point* G, const ecp_point* Q, const unsigned long long int r[2], const unsigned long long int s[2]) {
			if (r[0] < 1 || r[0] >= q[0] || false || (q[1] && r[1] >= q[1]) || s[0] < 1 || s[0] >= q[0] || false || (q[1] && s[1] >= q[1])) return 0;
			unsigned long long int e[2];
			gost3411_2001_hash(data, len, e);
			e[0] %= q[0];
			e[1] %= q[1] ? q[1] : 1;
			unsigned long long int inv_s[2] = {mod_pow(s[0], (q[1] ? q[1] * q[0] : q[0]) - 2, q), mod_pow(s[1], (q[1] ? q[1] * q[0] : q[0]) - 2, q)};
			unsigned long long int u1[2] = {mod_mul(e[0], inv_s[0], q), mod_mul(e[1], inv_s[1], q)};
			unsigned long long int u2[2] = {mod_mul(r[0], inv_s[0], q), mod_mul(r[1], inv_s[1], q)};
			ecp_point P1, P2, V;
			ecp_mul(p, a, G, u1, &P1);
			ecp_mul(p, a, Q, u2, &P2);
			ecp_add(p, a, &P1, &P2, &V);
			unsigned long long int v[2] = {V.x[0] % q[0], V.x[1] % (q[1] ? q[1] : 1)};
			return (v[0] == r[0] && v[1] == r[1]) ? 1 : 0;
		}
	}
	namespace gost_r_3410_2012 {
		typedef struct {
			unsigned long long int x[4], y[4];
		} ecp256_point;
		typedef struct {
			unsigned long long int x[8], y[8];
		} ecp512_point;
		typedef union {
			ecp256_point p256;
			ecp512_point p512;
		} ecp_point;
		typedef struct {
			unsigned long long int val[8];
		} bigint;
		void bigint_set_zero(bigint* a) {
			memset(a, 0, sizeof(bigint));
		}
		void bigint_copy(bigint* dst, const bigint* src) {
			memcpy(dst, src, sizeof(bigint));
		}
		int bigint_cmp(const bigint* a, const bigint* b) {
			for (int i = 7; i >= 0; i--) {
				if (a->val[i] > b->val[i]) return 1;
				if (a->val[i] < b->val[i]) return -1;
			}
			return 0;
		}
		void bigint_add(bigint* res, const bigint* a, const bigint* b, const bigint* mod) {
			unsigned long long int carry = 0;
			for (int i = 0; i < 8; i++) {
				res->val[i] = a->val[i] + b->val[i] + carry;
				carry = (res->val[i] < a->val[i]) ? 1 : 0;
			}
			bigint temp_sub;
			bigint_copy(&temp_sub, b);
			while (bigint_cmp(res, mod) >= 0) {
				carry = 0;
				for (int i = 0; i < 8; i++) {
					unsigned long long int sub = temp_sub.val[i] + carry;
					if (res->val[i] >= sub) res->val[i] -= sub;
					else {
						res->val[i] += (UINT64_MAX - sub + 1);
						carry = 1;
					}
				}
			}
		}
		void bigint_sub(bigint* res, const bigint* a, const bigint* b) {
			unsigned long long int borrow = 0;
			for (int i = 0; i < 8; i++) {
				if (a->val[i] < b->val[i] + borrow) {
					res->val[i] = a->val[i] + (UINT64_MAX - b->val[i] - borrow + 1);
					borrow = 1;
				} else {
					res->val[i] = a->val[i] - b->val[i] - borrow;
					borrow = 0;
				}
			}
		}
		void bigint_mul(bigint* res, const bigint* a, const bigint* b) {
			bigint_set_zero(res);
			for (int i = 0; i < 8; i++) {
				if (a->val[i] == 0) continue;
				unsigned long long int carry = 0;
				for (int j = 0; j < 8; j++) {
					unsigned long long int hi, lo;
					__asm__ __volatile__ (
					    "mulq %3\n"
					    : "=a"(lo), "=d"(hi)
					    : "a"(a->val[i]), "rm"(b->val[j])
					);
					res->val[i + j] += lo + carry;
					carry = hi + (res->val[i + j] < lo ? 1 : 0);
					if (res->val[i + j] < lo) res->val[i + j] += (UINT64_MAX - lo + 1);
				}
				if (carry && (i + 8) < 16) res->val[i + 8] = carry;
			}
		}
		void bigint_mod(bigint* res, const bigint* a, const bigint* mod) {
			bigint_copy(res, a);
			bigint temp_mod;
			bigint_copy(&temp_mod, mod);
			int shift = 0;
			while (bigint_cmp(&temp_mod, a) < 0 && shift < 64) {
				unsigned long long int carry = 0;
				for (int i = 7; i >= 0; i--) {
					unsigned long long int new_carry = temp_mod.val[i] >> 63;
					temp_mod.val[i] = (temp_mod.val[i] << 1) | carry;
					carry = new_carry;
				}
				shift++;
			}
			while (shift >= 0) {
				if (bigint_cmp(res, &temp_mod) >= 0) bigint_sub(res, res, &temp_mod);
				unsigned long long int carry = 0;
				for (int i = 0; i < 8; i++) {
					unsigned long long int new_carry = temp_mod.val[i] & 1;
					temp_mod.val[i] = (temp_mod.val[i] >> 1) | (carry << 63);
					carry = new_carry;
				}
				shift--;
			}
		}
		void bigint_pow_mod(bigint* res, const bigint* base, const bigint* exp, const bigint* mod) {
			bigint_set_zero(res);
			res->val[0] = 1;
			bigint temp_base, temp_exp;
			bigint_copy(&temp_base, base);
			bigint_copy(&temp_exp, exp);
			bigint zero;
			bigint_set_zero(&zero);
			while (bigint_cmp(&temp_exp, &zero) > 0) {
				if (temp_exp.val[0] & 1) {
					bigint temp_prod;
					bigint_mul(&temp_prod, res, &temp_base);
					bigint_mod(res, &temp_prod, mod);
				}
				bigint temp_sq;
				bigint_mul(&temp_sq, &temp_base, &temp_base);
				bigint_mod(&temp_base, &temp_sq, mod);
				unsigned long long int carry = 0;
				for (int i = 0; i < 8; i++) {
					unsigned long long int new_carry = temp_exp.val[i] & 1;
					temp_exp.val[i] = (temp_exp.val[i] >> 1) | (carry << 63);
					carry = new_carry;
				}
			}
		}
		void ecp256_add(const bigint* p, const bigint* a, const ecp256_point* P, const ecp256_point* Q, ecp256_point* R) {
			bigint dx, dy, s, x1x2, x3, y3, temp;
			bigint_set_zero(&dx);
			bigint_set_zero(&dy);
			bigint_set_zero(&s);
			for (int i = 0; i < 4; i++) {
				dx.val[i] = Q->x[i];
				dy.val[i] = Q->y[i];
			}
			bigint_sub(&dx, &dx, (const bigint*)P->x);
			bigint_mod(&dx, &dx, p);
			bigint_sub(&dy, &dy, (const bigint*)P->y);
			bigint_mod(&dy, &dy, p);
			bigint zero;
			bigint_set_zero(&zero);
			int is_equal = (bigint_cmp(&dx, &zero) == 0 && bigint_cmp(&dy, &zero) == 0);
			if (is_equal) {
				bigint x2, three_x2, two_y, inv_two_y;
				bigint_mul(&x2, (const bigint*)P->x, (const bigint*)P->x);
				bigint_mod(&x2, &x2, p);
				bigint_set_zero(&three_x2);
				three_x2.val[0] = 3;
				bigint_mul(&three_x2, &three_x2, &x2);
				bigint_mod(&three_x2, &three_x2, p);
				bigint_add(&three_x2, &three_x2, a, p);
				bigint_set_zero(&two_y);
				two_y.val[0] = 2;
				bigint_mul(&two_y, &two_y, (const bigint*)P->y);
				bigint_mod(&two_y, &two_y, p);
				bigint exp_p;
				for (int i = 0; i < 8; i++) exp_p.val[i] = (i < 4) ? p->val[i] - 2 : p->val[i];
				bigint_pow_mod(&inv_two_y, &two_y, &exp_p, p);
				bigint_mul(&s, &three_x2, &inv_two_y);
				bigint_mod(&s, &s, p);
			} else {
				bigint inv_dx, exp_p;
				for (int i = 0; i < 8; i++) exp_p.val[i] = (i < 4) ? p->val[i] - 2 : p->val[i];
				bigint_pow_mod(&inv_dx, &dx, &exp_p, p);
				bigint_mul(&s, &dy, &inv_dx);
				bigint_mod(&s, &s, p);
			}
			bigint_mul(&x3, &s, &s);
			bigint_mod(&x3, &x3, p);
			bigint_add(&x1x2, (const bigint*)P->x, (const bigint*)Q->x, p);
			bigint_sub(&x3, &x3, &x1x2);
			bigint_mod(&x3, &x3, p);
			bigint_sub(&temp, (const bigint*)P->x, &x3);
			bigint_mod(&temp, &temp, p);
			bigint_mul(&y3, &s, &temp);
			bigint_mod(&y3, &y3, p);
			bigint_sub(&y3, &y3, (const bigint*)P->y);
			bigint_mod(&y3, &y3, p);
			memcpy(R->x, x3.val, 32);
			memcpy(R->y, y3.val, 32);
		}
		void ecp256_mul(const bigint* p, const bigint* a, const ecp256_point* G, const bigint* k, ecp256_point* Q) {
			ecp256_point res = {{0, 0, 0, 0}, {0, 0, 0, 0}};
			ecp256_point temp = *G;
			bigint exp;
			bigint_copy(&exp, k);
			bigint zero = {0};
			while (bigint_cmp(&exp, &zero) > 0) {
				if (exp.val[0] & 1) ecp256_add(p, a, &res, &temp, &res);
				ecp256_add(p, a, &temp, &temp, &temp);
				unsigned long long int carry = 0;
				for (int i = 0; i < 8; i++) {
					unsigned long long int new_carry = exp.val[i] & 1;
					exp.val[i] = (exp.val[i] >> 1) | (carry << 63);
					carry = new_carry;
				}
			}
			*Q = res;
		}
		void ecp512_add(const bigint* p, const bigint* a, const ecp512_point* P, const ecp512_point* Q, ecp512_point* R) {
			bigint dx, dy, s, x1x2, x3, y3, temp;
			bigint_set_zero(&dx);
			bigint_set_zero(&dy);
			bigint_set_zero(&s);
			memcpy(dx.val, Q->x, 64);
			memcpy(dy.val, Q->y, 64);
			bigint_sub(&dx, &dx, (const bigint*)P->x);
			bigint_mod(&dx, &dx, p);
			bigint_sub(&dy, &dy, (const bigint*)P->y);
			bigint_mod(&dy, &dy, p);
			bigint zero;
			bigint_set_zero(&zero);
			int is_equal = (bigint_cmp(&dx, &zero) == 0 && bigint_cmp(&dy, &zero) == 0);
			if (is_equal) {
				bigint x2, three_x2, two_y, inv_two_y, exp_p;
				bigint_mul(&x2, (const bigint*)P->x, (const bigint*)P->x);
				bigint_mod(&x2, &x2, p);
				bigint_set_zero(&three_x2);
				three_x2.val[0] = 3;
				bigint_mul(&three_x2, &three_x2, &x2);
				bigint_mod(&three_x2, &three_x2, p);
				bigint_add(&three_x2, &three_x2, a, p);
				bigint_set_zero(&two_y);
				two_y.val[0] = 2;
				bigint_mul(&two_y, &two_y, (const bigint*)P->y);
				bigint_mod(&two_y, &two_y, p);
				for (int i = 0; i < 8; i++) exp_p.val[i] = p->val[i] - 2;
				bigint_pow_mod(&inv_two_y, &two_y, &exp_p, p);
				bigint_mul(&s, &three_x2, &inv_two_y);
				bigint_mod(&s, &s, p);
			} else {
				bigint inv_dx, exp_p;
				for (int i = 0; i < 8; i++) exp_p.val[i] = p->val[i] - 2;
				bigint_pow_mod(&inv_dx, &dx, &exp_p, p);
				bigint_mul(&s, &dy, &inv_dx);
				bigint_mod(&s, &s, p);
			}
			bigint_mul(&x3, &s, &s);
			bigint_mod(&x3, &x3, p);
			bigint_add(&x1x2, (const bigint*)P->x, (const bigint*)Q->x, p);
			bigint_sub(&x3, &x3, &x1x2);
			bigint_mod(&x3, &x3, p);
			bigint_sub(&temp, (const bigint*)P->x, &x3);
			bigint_mod(&temp, &temp, p);
			bigint_mul(&y3, &s, &temp);
			bigint_mod(&y3, &y3, p);
			bigint_sub(&y3, &y3, (const bigint*)P->y);
			bigint_mod(&y3, &y3, p);
			memcpy(R->x, x3.val, 64);
			memcpy(R->y, y3.val, 64);
		}
		void ecp512_mul(const bigint* p, const bigint* a, const ecp512_point* G, const bigint* k, ecp512_point* Q) {
			ecp512_point res = {{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}};
			ecp512_point temp = *G;
			bigint exp;
			bigint_copy(&exp, k);
			bigint zero = {0};
			while (bigint_cmp(&exp, &zero) > 0) {
				if (exp.val[0] & 1) ecp512_add(p, a, &res, &temp, &res);
				ecp512_add(p, a, &temp, &temp, &temp);
				unsigned long long int carry = 0;
				for (int i = 0; i < 8; i++) {
					unsigned long long int new_carry = exp.val[i] & 1;
					exp.val[i] = (exp.val[i] >> 1) | (carry << 63);
					carry = new_carry;
				}
			}
			*Q = res;
		}
		void streebog512(const unsigned char* data, size_t len, unsigned char hash[64]) {
			unsigned char h[64], N[64], Sigma[64], buffer[64];
			size_t buf_ptr = 0;
			const unsigned char SBOX[256] = {0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F, 0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42, 0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6, 0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3, 0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8, 0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E, 0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10, 0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30, 0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8, 0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C, 0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6, 0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76, 0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6, 0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2, 0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1};
			const unsigned long long int C[12] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A};
			memset(h, 0x01, 64);
			memset(N, 0, 64);
			memset(Sigma, 0, 64);
			memset(buffer, 0, 64);
			while (len > 0) {
				size_t chunk = (len < 64 - buf_ptr) ? len : 64 - buf_ptr;
				memcpy(buffer + buf_ptr, data, chunk);
				buf_ptr += chunk;
				data += chunk;
				len -= chunk;
				if (buf_ptr == 64) {
					unsigned char k[64], l[64], tmp[64];
					memcpy(k, buffer, 64);
					for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
					for (int i = 0; i < 12; i++) {
						for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
						memcpy(l, tmp, 64);
						for (int j = 0; j < 8; j++) {
							unsigned char t = l[j];
							for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
							l[56 + j] = t;
						}
						for (int j = 0; j < 64; j++) l[j] ^= k[j];
						memcpy(k, l, 64);
					}
					for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ buffer[i];
					unsigned long long int carry = 1;
					for (int i = 0; i < 8; i++) {
						unsigned long long int curr = *(unsigned long long int*)(N + i * 8);
						unsigned long long int n = curr + carry;
						carry = (n < curr) ? 1 : 0;
						*(unsigned long long int*)(N + i * 8) = n;
					}
					for (int i = 0; i < 64; i++) Sigma[i] ^= buffer[i];
					buf_ptr = 0;
				}
			}
			if (buf_ptr > 0) {
				memset(buffer + buf_ptr, 0, 64 - buf_ptr);
				unsigned char k[64], l[64], tmp[64];
				memcpy(k, buffer, 64);
				for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
				for (int i = 0; i < 12; i++) {
					for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
					memcpy(l, tmp, 64);
					for (int j = 0; j < 8; j++) {
						unsigned char t = l[j];
						for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
						l[56 + j] = t;
					}
					for (int j = 0; j < 64; j++) l[j] ^= k[j];
					memcpy(k, l, 64);
				}
				for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ buffer[i];
				unsigned long long int carry = 1;
				for (int i = 0; i < 8; i++) {
					unsigned long long int curr = *(unsigned long long int*)(N + i * 8);
					unsigned long long int n = curr + carry;
					carry = (n < curr) ? 1 : 0;
					*(unsigned long long int*)(N + i * 8) = n;
				}
				for (int i = 0; i < 64; i++) Sigma[i] ^= buffer[i];
			}
			unsigned char block[64];
			memset(block, 0, 64);
			memcpy(block, N, 64);
			unsigned char k[64], l[64], tmp[64];
			memcpy(k, block, 64);
			for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
			for (int i = 0; i < 12; i++) {
				for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
				memcpy(l, tmp, 64);
				for (int j = 0; j < 8; j++) {
					unsigned char t = l[j];
					for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
					l[56 + j] = t;
				}
				for (int j = 0; j < 64; j++) l[j] ^= k[j];
				memcpy(k, l, 64);
			}
			for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ block[i];
			memset(block, 0, 64);
			memcpy(block, Sigma, 64);
			memcpy(k, block, 64);
			for (int i = 0; i < 64; i++) l[i] = h[i] ^ k[i];
			for (int i = 0; i < 12; i++) {
				for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
				memcpy(l, tmp, 64);
				for (int j = 0; j < 8; j++) {
					unsigned char t = l[j];
					for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
					l[56 + j] = t;
				}
				for (int j = 0; j < 64; j++) l[j] ^= k[j];
				memcpy(k, l, 64);
			}
			for (int i = 0; i < 64; i++) h[i] ^= k[i] ^ block[i];
			memcpy(hash, h, 64);
		}
		void gost3410_2012_generate_keys(int bits, const bigint* p, const bigint* q, const bigint* a, const ecp_point* G, bigint* d, ecp_point* Q) {
			bigint min, max, zero;
			bigint_set_zero(&min);
			min.val[0] = 2;
			bigint_set_zero(&zero);
			bigint_copy(&max, q);
			bigint_sub(&max, &max, &min);
			do {
				for (int i = 0; i < 8; i++) d->val[i] = (unsigned long long int)rand() << 32 | rand();
				bigint_mod(d, d, &max);
				bigint_add(d, d, &min, q);
			} while (bigint_cmp(d, q) >= 0 || bigint_cmp(d, &min) < 0);
			if (bits == 256) ecp256_mul(p, a, &G->p256, d, &Q->p256);
			else ecp512_mul(p, a, &G->p512, d, &Q->p512);
		}
		void gost3410_2012_sign(int bits, const unsigned char* data, size_t len, const bigint* p, const bigint* q, const bigint* a, const ecp_point* G, const bigint* d, bigint* r, bigint* s) {
			unsigned char e[64];
			streebog512(data, len, e);
			bigint e_big, zero;
			bigint_set_zero(&zero);
			memcpy(e_big.val, e, 64);
			bigint_mod(&e_big, &e_big, q);
			do {
				bigint k, k_mod, min_k, max_k;
				bigint_set_zero(&min_k);
				min_k.val[0] = 1;
				bigint_copy(&max_k, q);
				bigint_sub(&max_k, &max_k, &min_k);
				do {
					for (int i = 0; i < 8; i++) k.val[i] = (unsigned long long int)rand() << 32 | rand();
					bigint_mod(&k_mod, &k, &max_k);
					bigint_add(&k, &k_mod, &min_k, q);
				} while (bigint_cmp(&k, q) >= 0 || bigint_cmp(&k, &min_k) < 0);
				ecp_point K;
				if (bits == 256) ecp256_mul(p, a, &G->p256, &k, &K.p256);
				else ecp512_mul(p, a, &G->p512, &k, &K.p512);
				bigint Kx;
				memcpy(Kx.val, (bits == 256) ? K.p256.x : K.p512.x, bits / 8);
				bigint_mod(r, &Kx, q);
				if (bigint_cmp(r, &zero) == 0) continue;
				bigint dr, e_dr, inv_k, exp_q;
				for (int i = 0; i < 8; i++) exp_q.val[i] = q->val[i] - 2;
				bigint_mul(&dr, d, r);
				bigint_mod(&dr, &dr, q);
				bigint_add(&e_dr, &e_big, &dr, q);
				bigint_pow_mod(&inv_k, &k, &exp_q, q);
				bigint_mul(s, &e_dr, &inv_k);
				bigint_mod(s, s, q);
			} while (bigint_cmp(s, &zero) == 0);
		}
		int gost3410_2012_verify(int bits, const unsigned char* data, size_t len, const bigint* p, const bigint* q, const bigint* a, const ecp_point* G, const ecp_point* Q, const bigint* r, const bigint* s) {
			bigint min, zero, e_big, inv_s, u1, u2, exp_q;
			bigint_set_zero(&min);
			min.val[0] = 1;
			bigint_set_zero(&zero);
			if (bigint_cmp(r, &min) < 0 || bigint_cmp(r, q) >= 0 || bigint_cmp(s, &min) < 0 || bigint_cmp(s, q) >= 0) return 0;
			unsigned char e[64];
			streebog512(data, len, e);
			memcpy(e_big.val, e, 64);
			bigint_mod(&e_big, &e_big, q);
			for (int i = 0; i < 8; i++) exp_q.val[i] = q->val[i] - 2;
			bigint_pow_mod(&inv_s, s, &exp_q, q);
			bigint_mul(&u1, &e_big, &inv_s);
			bigint_mod(&u1, &u1, q);
			bigint_mul(&u2, r, &inv_s);
			bigint_mod(&u2, &u2, q);
			ecp_point P1, P2, V;
			if (bits == 256) {
				ecp256_mul(p, a, &G->p256, &u1, &P1.p256);
				ecp256_mul(p, a, &Q->p256, &u2, &P2.p256);
				ecp256_add(p, a, &P1.p256, &P2.p256, &V.p256);
			} else {
				ecp512_mul(p, a, &G->p512, &u1, &P1.p512);
				ecp512_mul(p, a, &Q->p512, &u2, &P2.p512);
				ecp512_add(p, a, &P1.p512, &P2.p512, &V.p512);
			}
			bigint Vx;
			memcpy(Vx.val, (bits == 256) ? V.p256.x : V.p512.x, bits / 8);
			bigint_mod(&Vx, &Vx, q);
			return (bigint_cmp(&Vx, r) == 0) ? 1 : 0;
		}
	}
	namespace gost_r_3417_2019 {
		typedef struct {
			unsigned long long int val[8];
		} bigint;
		typedef struct {
			unsigned char key[64];
			size_t key_len;
			unsigned char iv[16];
			unsigned char cnt[16];
			unsigned char tag[16];
			unsigned char h[16];
			unsigned char j[16];
			size_t auth_len;
			size_t data_len;
		} gost_ctx;
		static const unsigned char SBOX[256] = {0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F, 0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42, 0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6, 0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3, 0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8, 0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E, 0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10, 0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30, 0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8, 0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C, 0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6, 0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76, 0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6, 0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2, 0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1};
		static const unsigned long long int C[12] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A};
		void bigint_set_zero(bigint* a) {
			memset(a, 0, sizeof(bigint));
		}
		void bigint_copy(bigint* dst, const bigint* src) {
			memcpy(dst, src, sizeof(bigint));
		}
		int bigint_cmp(const bigint* a, const bigint* b) {
			for (int i = 7; i >= 0; i--) {
				if (a->val[i] > b->val[i]) return 1;
				if (a->val[i] < b->val[i]) return -1;
			}
			return 0;
		}
		void bigint_add(bigint* res, const bigint* a, const bigint* b) {
			unsigned long long int carry = 0;
			for (int i = 0; i < 8; i++) {
				res->val[i] = a->val[i] + b->val[i] + carry;
				carry = (res->val[i] < a->val[i]) ? 1 : 0;
			}
		}
		void bigint_sub(bigint* res, const bigint* a, const bigint* b) {
			unsigned long long int borrow = 0;
			for (int i = 0; i < 8; i++) {
				if (a->val[i] < b->val[i] + borrow) {
					res->val[i] = a->val[i] + (UINT64_MAX - b->val[i] - borrow + 1);
					borrow = 1;
				} else {
					res->val[i] = a->val[i] - b->val[i] - borrow;
					borrow = 0;
				}
			}
		}
		void bigint_mul(bigint* res, const bigint* a, const bigint* b) {
			bigint_set_zero(res);
			for (int i = 0; i < 8; i++) {
				if (a->val[i] == 0) continue;
				unsigned long long int carry = 0;
				for (int j = 0; j < 8; j++) {
					unsigned long long int hi, lo;
					__asm__ __volatile__ ("mulq %3" : "=a"(lo), "=d"(hi) : "a"(a->val[i]), "rm"(b->val[j]));
					res->val[i + j] += lo + carry;
					carry = hi + (res->val[i + j] < lo ? 1 : 0);
					if (res->val[i + j] < lo) res->val[i + j] += (UINT64_MAX - lo + 1);
				}
				if (carry && (i + 8) < 16) res->val[i + 8] = carry;
			}
		}
		void gost_permute(unsigned char block[16]) {
			unsigned char l[16], k[16], tmp[16];
			memcpy(k, block, 16);
			memcpy(l, block, 16);
			for (int i = 0; i < 12; i++) {
				for (int j = 0; j < 2; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
				memcpy(l, tmp, 16);
				for (int j = 0; j < 2; j++) {
					unsigned char t = l[j];
					for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 2 + j] = l[kk * 2 + j];
					l[14 + j] = t;
				}
				for (int j = 0; j < 16; j++) l[j] ^= k[j];
				memcpy(k, l, 16);
			}
			for (int j = 0; j < 16; j++) block[j] ^= k[j];
		}
		void gost_encrypt_block(const unsigned char key[64], size_t key_len, const unsigned char in[16], unsigned char out[16]) {
			memcpy(out, in, 16);
			size_t rounds = (key_len == 32) ? 8 : 10;
			for (size_t i = 0; i < rounds; i++) {
				unsigned char subkey[16];
				memcpy(subkey, key + (i % (key_len / 16)) * 16, 16);
				for (int j = 0; j < 16; j++) out[j] ^= subkey[j];
				gost_permute(out);
			}
			unsigned char final_key[16];
			memcpy(final_key, key + (rounds % (key_len / 16)) * 16, 16);
			for (int j = 0; j < 16; j++) out[j] ^= final_key[j];
		}
		void gost_decrypt_block(const unsigned char key[64], size_t key_len, const unsigned char in[16], unsigned char out[16]) {
			memcpy(out, in, 16);
			size_t rounds = (key_len == 32) ? 8 : 10;
			unsigned char final_key[16];
			memcpy(final_key, key + (rounds % (key_len / 16)) * 16, 16);
			for (int j = 0; j < 16; j++) out[j] ^= final_key[j];
			for (size_t i = rounds; i > 0; i--) {
				gost_permute(out);
				unsigned char subkey[16];
				memcpy(subkey, key + ((i - 1) % (key_len / 16)) * 16, 16);
				for (int j = 0; j < 16; j++) out[j] ^= subkey[j];
			}
		}
		void cnt_increment(unsigned char cnt[16]) {
			unsigned long long int* cnt64 = (unsigned long long int*)cnt;
			cnt64[1]++;
			if (cnt64[1] == 0) cnt64[0]++;
		}
		int gost_ctx_init(gost_ctx* ctx, const unsigned char* key, size_t key_len, const unsigned char* iv, size_t iv_len) {
			if (key_len != 32 && key_len != 64) return -1;
			if (iv_len != 12 && iv_len != 16) return -1;
			memset(ctx, 0, sizeof(gost_ctx));
			memcpy(ctx->key, key, key_len);
			ctx->key_len = key_len;
			memcpy(ctx->iv, iv, iv_len);
			memcpy(ctx->cnt, iv, iv_len);
			if (iv_len == 12) memset(ctx->cnt + 12, 0, 4);
			unsigned char zero[16] = {0};
			gost_encrypt_block(ctx->key, ctx->key_len, zero, ctx->h);
			memcpy(ctx->j, ctx->h, 16);
			return 0;
		}
		void gost_gcm_auth(gost_ctx* ctx, const unsigned char* data, size_t len) {
			if (len == 0) return;
			ctx->auth_len += len;
			unsigned char block[16];
			size_t pos = 0;
			while (pos < len) {
				size_t chunk = (len - pos) < 16 ? (len - pos) : 16;
				memset(block, 0, 16);
				memcpy(block, data + pos, chunk);
				for (int i = 0; i < 16; i++) ctx->j[i] ^= block[i];
				gost_permute(ctx->j);
				pos += chunk;
			}
		}
		void gost_ctr_crypt(gost_ctx* ctx, const unsigned char* in, unsigned char* out, size_t len) {
			if (len == 0) return;
			ctx->data_len += len;
			unsigned char block[16], keystream[16];
			size_t pos = 0;
			while (pos < len) {
				gost_encrypt_block(ctx->key, ctx->key_len, ctx->cnt, keystream);
				cnt_increment(ctx->cnt);
				size_t chunk = (len - pos) < 16 ? (len - pos) : 16;
				memcpy(block, in + pos, chunk);
				for (size_t i = 0; i < chunk; i++) out[pos + i] = block[i] ^ keystream[i];
				pos += chunk;
			}
		}
		void gost_gcm_final(gost_ctx* ctx, unsigned char tag[16]) {
			unsigned char len_block[16] = {0};
			((unsigned long long int*)len_block)[0] = ctx->auth_len * 8;
			((unsigned long long int*)len_block)[1] = ctx->data_len * 8;
			for (int i = 0; i < 16; i++) ctx->j[i] ^= len_block[i];
			gost_permute(ctx->j);
			for (int i = 0; i < 16; i++) ctx->tag[i] = ctx->j[i] ^ ctx->h[i];
			memcpy(tag, ctx->tag, 16);
		}
		int gost_encrypt_ctr(const unsigned char* key, size_t key_len, const unsigned char* iv, size_t iv_len, const unsigned char* in, size_t in_len, unsigned char* out) {
			gost_ctx ctx;
			if (gost_ctx_init(&ctx, key, key_len, iv, iv_len) != 0) return -1;
			gost_ctr_crypt(&ctx, in, out, in_len);
			return 0;
		}
		int gost_decrypt_ctr(const unsigned char* key, size_t key_len, const unsigned char* iv, size_t iv_len, const unsigned char* in, size_t in_len, unsigned char* out) {
			return gost_encrypt_ctr(key, key_len, iv, iv_len, in, in_len, out);
		}
		int gost_encrypt_gcm(const unsigned char* key, size_t key_len, const unsigned char* iv, size_t iv_len, const unsigned char* auth_data, size_t auth_len, const unsigned char* in, size_t in_len, unsigned char* out, unsigned char* tag) {
			gost_ctx ctx;
			if (gost_ctx_init(&ctx, key, key_len, iv, iv_len) != 0) return -1;
			gost_gcm_auth(&ctx, auth_data, auth_len);
			gost_ctr_crypt(&ctx, in, out, in_len);
			gost_gcm_final(&ctx, tag);
			return 0;
		}
		int gost_decrypt_gcm(const unsigned char* key, size_t key_len, const unsigned char* iv, size_t iv_len, const unsigned char* auth_data, size_t auth_len, const unsigned char* in, size_t in_len, const unsigned char* tag, unsigned char* out) {
			gost_ctx ctx;
			if (gost_ctx_init(&ctx, key, key_len, iv, iv_len) != 0) return -1;
			gost_gcm_auth(&ctx, auth_data, auth_len);
			gost_ctr_crypt(&ctx, in, out, in_len);
			unsigned char computed_tag[16];
			gost_gcm_final(&ctx, computed_tag);
			return memcmp(tag, computed_tag, 16) == 0 ? 0 : -1;
		}
	}
	namespace gost_r_3401_2012 {
		typedef enum { GOST_HASH_128 = 16, GOST_HASH_256 = 32, GOST_HASH_512 = 64 } gost_hash_len;
		static const unsigned char SBOX[256] = {0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x7D, 0x0C, 0x06, 0x09, 0x7F, 0x8D, 0x71, 0x5A, 0x6B, 0x00, 0xC6, 0x9A, 0x1C, 0x81, 0x33, 0x38, 0x57, 0x88, 0x5B, 0x03, 0x42, 0xAE, 0xE8, 0x2D, 0x3A, 0xDE, 0x96, 0x87, 0x7A, 0x26, 0x22, 0x9F, 0x8A, 0x05, 0xEB, 0x9C, 0xA6, 0x43, 0xC7, 0x80, 0x0E, 0x49, 0xD7, 0xCB, 0x70, 0x73, 0x05, 0x1F, 0x6A, 0x35, 0x82, 0x07, 0xD3, 0x48, 0x91, 0x25, 0x2A, 0x8B, 0xDC, 0xB5, 0xE0, 0x02, 0xAA, 0x72, 0x6D, 0x8F, 0x8C, 0x24, 0xC8, 0x9E, 0x13, 0x58, 0x6F, 0x92, 0xB7, 0x60, 0xCE, 0x0F, 0x1E, 0x34, 0x9B, 0x0D, 0x5F, 0x67, 0x7E, 0x95, 0x47, 0x12, 0xF2, 0x3F, 0x3E, 0x62, 0xBD, 0x08, 0x4E, 0x79, 0x59, 0x89, 0xF3, 0xAB, 0x10, 0xEE, 0x7B, 0x4B, 0x2F, 0x2C, 0xA7, 0x5C, 0xF4, 0x85, 0xAD, 0x41, 0x19, 0x61, 0x15, 0xBB, 0x30, 0x45, 0x75, 0x4F, 0xA3, 0xDF, 0x69, 0x97, 0x98, 0x37, 0x83, 0x01, 0x63, 0xAF, 0x53, 0xC9, 0xD8, 0x9D, 0x78, 0x8E, 0x94, 0x66, 0x18, 0xF5, 0xC0, 0x5D, 0x4A, 0xCA, 0xE2, 0x1B, 0x86, 0x5E, 0x6C, 0x29, 0x0A, 0x7C, 0xED, 0xF6, 0x74, 0x39, 0x20, 0x32, 0x40, 0xBE, 0xE4, 0xD4, 0xA1, 0x21, 0xD6, 0x54, 0x55, 0xE7, 0xE1, 0x2B, 0x3B, 0xCC, 0xE3, 0x56, 0x0B, 0x84, 0xD5, 0xF7, 0xA8, 0xE5, 0x76, 0xA9, 0xD9, 0xC1, 0xDA, 0x65, 0x46, 0xF8, 0xAC, 0x27, 0xD0, 0x52, 0xCB, 0x90, 0xEC, 0xA0, 0xE6, 0x7F, 0x14, 0x8C, 0xD1, 0x44, 0xBF, 0x28, 0x3D, 0xFF, 0xCD, 0xA4, 0xB0, 0xF9, 0xB2, 0xC3, 0xA2, 0xD2, 0x51, 0x1A, 0x68, 0xB8, 0xC2, 0x64, 0x9F, 0x00, 0x87, 0xB4, 0xAA, 0x7D, 0x50, 0x4C, 0xB1};
		static const unsigned long long int C[12] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A};
		typedef struct {
			unsigned char h[64];
			unsigned char N[64];
			unsigned char Sigma[64];
			unsigned char buffer[64];
			size_t buf_ptr;
			gost_hash_len hash_len;
		} gost_ctx;
		void gost_permute(unsigned char block[64]) {
			unsigned char l[64], k[64], tmp[64];
			memcpy(k, block, 64);
			memcpy(l, block, 64);
			for (int i = 0; i < 12; i++) {
				for (int j = 0; j < 8; j++) for (int kk = 0; kk < 8; kk++) tmp[j * 8 + kk] = SBOX[l[j * 8 + kk] ^ ((C[i] >> (8 * kk)) & 0xFF)];
				memcpy(l, tmp, 64);
				for (int j = 0; j < 8; j++) {
					unsigned char t = l[j];
					for (int kk = 1; kk < 8; kk++) l[(kk - 1) * 8 + j] = l[kk * 8 + j];
					l[56 + j] = t;
				}
				for (int j = 0; j < 64; j++) l[j] ^= k[j];
				memcpy(k, l, 64);
			}
			for (int j = 0; j < 64; j++) block[j] ^= k[j];
		}
		void gost_ctx_init(gost_ctx* ctx, gost_hash_len hash_len) {
			memset(ctx, 0, sizeof(gost_ctx));
			ctx->hash_len = hash_len;
			memset(ctx->h, 0x01, 64);
		}
		void gost_update(gost_ctx* ctx, const unsigned char* data, size_t len) {
			if (len == 0) return;
			while (len > 0) {
				size_t chunk = (len < 64 - ctx->buf_ptr) ? len : 64 - ctx->buf_ptr;
				memcpy(ctx->buffer + ctx->buf_ptr, data, chunk);
				ctx->buf_ptr += chunk;
				data += chunk;
				len -= chunk;
				if (ctx->buf_ptr == 64) {
					unsigned char block[64];
					memcpy(block, ctx->buffer, 64);
					for (int i = 0; i < 64; i++) ctx->h[i] ^= block[i];
					gost_permute(ctx->h);
					unsigned long long int carry = 1;
					for (int i = 0; i < 8; i++) {
						unsigned long long int curr = *(unsigned long long int*)(ctx->N + i * 8);
						unsigned long long int n = curr + carry;
						carry = (n < curr) ? 1 : 0;
						*(unsigned long long int*)(ctx->N + i * 8) = n;
					}
					for (int i = 0; i < 64; i++) ctx->Sigma[i] ^= block[i];
					ctx->buf_ptr = 0;
				}
			}
		}
		void gost_final(gost_ctx* ctx, unsigned char* hash) {
			if (ctx->buf_ptr > 0) {
				memset(ctx->buffer + ctx->buf_ptr, 0, 64 - ctx->buf_ptr);
				unsigned char block[64];
				memcpy(block, ctx->buffer, 64);
				for (int i = 0; i < 64; i++) ctx->h[i] ^= block[i];
				gost_permute(ctx->h);
				unsigned long long int carry = 1;
				for (int i = 0; i < 8; i++) {
					unsigned long long int curr = *(unsigned long long int*)(ctx->N + i * 8);
					unsigned long long int n = curr + carry;
					carry = (n < curr) ? 1 : 0;
					*(unsigned long long int*)(ctx->N + i * 8) = n;
				}
				for (int i = 0; i < 64; i++) ctx->Sigma[i] ^= block[i];
			}
			unsigned char block[64];
			memcpy(block, ctx->N, 64);
			for (int i = 0; i < 64; i++) ctx->h[i] ^= block[i];
			gost_permute(ctx->h);
			memcpy(block, ctx->Sigma, 64);
			for (int i = 0; i < 64; i++) ctx->h[i] ^= block[i];
			gost_permute(ctx->h);
			memcpy(hash, ctx->h, ctx->hash_len);
		}
		void gost_hash(const unsigned char* data, size_t len, unsigned char* hash, gost_hash_len hash_len) {
			gost_ctx ctx;
			gost_ctx_init(&ctx, hash_len);
			gost_update(&ctx, data, len);
			gost_final(&ctx, hash);
		}
		void gost128(const unsigned char* data, size_t len, unsigned char hash[16]) {
			gost_hash(data, len, hash, GOST_HASH_128);
		}
		void gost256(const unsigned char* data, size_t len, unsigned char hash[32]) {
			gost_hash(data, len, hash, GOST_HASH_256);
		}
		void gost512(const unsigned char* data, size_t len, unsigned char hash[64]) {
			gost_hash(data, len, hash, GOST_HASH_512);
		}
	}
	namespace gost_r_3402_2018 {
		typedef unsigned char Byte;
		typedef unsigned int Word;
		constexpr size_t AES_BLOCK_SIZE = 16;
		constexpr Byte SBOX[] = {
			0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
			0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
			0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
			0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
			0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
			0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
			0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
			0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
			0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
			0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
			0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
			0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
			0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
			0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
			0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
			0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
		};
		constexpr Byte INV_SBOX[] = {
			0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
			0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
			0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
			0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
			0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
			0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
			0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
			0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
			0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
			0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
			0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
			0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
			0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
			0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
			0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
		};
		constexpr Byte RCON[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
		inline Word rotl32(Word x, size_t n) {
			return (x << n) | (x >> (32 - n));
		}
		inline Byte xtime(Byte b) {
			return (b << 1) ^ ((b & 0x80) ? 0x1B : 0x00);
		}
		void subBytes(std::vector<Byte>& state) {
			for (size_t i = 0; i < state.size(); ++i) state[i] = SBOX[state[i]];
		}
		void shiftRows(std::vector<Byte>& state) {
			Byte temp;
			temp = state[1];
			state[1] = state[5];
			state[5] = state[9];
			state[9] = state[13];
			state[13] = temp;
			temp = state[2];
			state[2] = state[10];
			state[10] = temp;
			temp = state[6];
			state[6] = state[14];
			state[14] = temp;
			temp = state[15];
			state[15] = state[11];
			state[11] = state[7];
			state[7] = state[3];
			state[3] = temp;
		}
		void mixColumns(std::vector<Byte>& state) {
			for (size_t c = 0; c < 4; ++c) {
				Byte col[4] = {state[c], state[c + 4], state[c + 8], state[c + 12]};
				state[c] = xtime(col[0]) ^ col[1] ^ col[2] ^ col[3] ^ xtime(col[1]);
				state[c + 4] = col[0] ^ xtime(col[1]) ^ col[2] ^ col[3] ^ xtime(col[2]);
				state[c + 8] = col[0] ^ col[1] ^ xtime(col[2]) ^ col[3] ^ xtime(col[3]);
				state[c + 12] = col[0] ^ col[1] ^ col[2] ^ xtime(col[3]) ^ xtime(col[0]);
			}
		}
		void addRoundKey(std::vector<Byte>& state, const std::vector<Word>& roundKeys, size_t round) {
			for (size_t r = 0; r < 4; ++r) {
				Word key = roundKeys[round * 4 + r];
				state[r] ^= (key >> 24) & 0xFF;
				state[r + 4] ^= (key >> 16) & 0xFF;
				state[r + 8] ^= (key >> 8) & 0xFF;
				state[r + 12] ^= key & 0xFF;
			}
		}
		Word subWord(Word word) {
			return (static_cast<Word>(SBOX[(word >> 24) & 0xFF]) << 24) |
			       (static_cast<Word>(SBOX[(word >> 16) & 0xFF]) << 16) |
			       (static_cast<Word>(SBOX[(word >> 8) & 0xFF]) << 8) |
			       static_cast<Word>(SBOX[word & 0xFF]);
		}
		Word rotWord(Word word) {
			return (word << 8) | (word >> 24);
		}
		std::vector<Word> keyExpansion(const std::vector<Byte>& key) {
			size_t Nk = key.size() / 4;
			size_t Nr = (Nk == 4) ? 10 : (Nk == 6) ? 12 : 14;
			std::vector<Word> w((Nr + 1) * 4, 0);
			for (size_t i = 0; i < Nk; ++i) {
				w[i] = (static_cast<Word>(key[4 * i]) << 24) |
				       (static_cast<Word>(key[4 * i + 1]) << 16) |
				       (static_cast<Word>(key[4 * i + 2]) << 8) |
				       static_cast<Word>(key[4 * i + 3]);
			}
			for (size_t i = Nk; i < (Nr + 1) * 4; ++i) {
				Word temp = w[i - 1];
				if (i % Nk == 0) temp = subWord(rotWord(temp)) ^ (static_cast<Word>(RCON[i / Nk - 1]) << 24);
				else if (Nk > 6 && i % Nk == 4) temp = subWord(temp);
				w[i] = w[i - Nk] ^ temp;
			}
			return w;
		}
		void aesEncryptBlock(const std::vector<Byte>& in, std::vector<Byte>& out, const std::vector<Word>& roundKeys) {
			out = in;
			size_t Nr = (roundKeys.size() / 4) - 1;
			addRoundKey(out, roundKeys, 0);
			for (size_t round = 1; round < Nr; ++round) {
				subBytes(out);
				shiftRows(out);
				mixColumns(out);
				addRoundKey(out, roundKeys, round);
			}
			subBytes(out);
			shiftRows(out);
			addRoundKey(out, roundKeys, Nr);
		}
		std::vector<Byte> aesEncrypt(const std::vector<Byte>& plaintext, const std::vector<Byte>& key) {
			std::vector<Byte> ciphertext;
			std::vector<Word> roundKeys = keyExpansion(key);
			size_t numBlocks = (plaintext.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
			for (size_t i = 0; i < numBlocks; ++i) {
				std::vector<Byte> block(AES_BLOCK_SIZE, 0);
				size_t start = i * AES_BLOCK_SIZE;
				size_t len = std::min(AES_BLOCK_SIZE, plaintext.size() - start);
				std::copy_n(plaintext.begin() + start, len, block.begin());
				std::vector<Byte> encryptedBlock;
				aesEncryptBlock(block, encryptedBlock, roundKeys);
				ciphertext.insert(ciphertext.end(), encryptedBlock.begin(), encryptedBlock.end());
			}
			return ciphertext;
		}
		inline Byte mul(Byte a, Byte b) {
			Byte res = 0;
			for (int i = 0; i < 8; ++i) {
				if (b & 1) res ^= a;
				Byte carry = a & 0x80;
				a <<= 1;
				if (carry) a ^= 0x1B;
				b >>= 1;
			}
			return res;
		}

		void invSubBytes(std::vector<Byte>& state) {
			for (size_t i = 0; i < state.size(); ++i) state[i] = INV_SBOX[state[i]];
		}

		void invShiftRows(std::vector<Byte>& state) {
			Byte temp;
			temp = state[13];
			state[13] = state[9];
			state[9] = state[5];
			state[5] = state[1];
			state[1] = temp;
			temp = state[10];
			state[10] = state[2];
			state[2] = temp;
			temp = state[14];
			state[14] = state[6];
			state[6] = temp;
			temp = state[3];
			state[3] = state[7];
			state[7] = state[11];
			state[11] = state[15];
			state[15] = temp;
		}

		void invMixColumns(std::vector<Byte>& state) {
			for (size_t c = 0; c < 4; ++c) {
				Byte col[4] = {state[c], state[c + 4], state[c + 8], state[c + 12]};
				state[c] = mul(col[0], 0x0E) ^ mul(col[1], 0x0B) ^ mul(col[2], 0x0D) ^ mul(col[3], 0x09);
				state[c + 4] = mul(col[0], 0x09) ^ mul(col[1], 0x0E) ^ mul(col[2], 0x0B) ^ mul(col[3], 0x0D);
				state[c + 8] = mul(col[0], 0x0D) ^ mul(col[1], 0x09) ^ mul(col[2], 0x0E) ^ mul(col[3], 0x0B);
				state[c + 12] = mul(col[0], 0x0B) ^ mul(col[1], 0x0D) ^ mul(col[2], 0x09) ^ mul(col[3], 0x0E);
			}
		}

		void aesDecryptBlock(const std::vector<Byte>& in, std::vector<Byte>& out, const std::vector<Word>& roundKeys) {
			out = in;
			size_t Nr = (roundKeys.size() / 4) - 1;
			addRoundKey(out, roundKeys, Nr);
			for (size_t round = Nr - 1; round > 0; --round) {
				invShiftRows(out);
				invSubBytes(out);
				addRoundKey(out, roundKeys, round);
				invMixColumns(out);
			}
			invShiftRows(out);
			invSubBytes(out);
			addRoundKey(out, roundKeys, 0);
		}
		std::vector<Byte> aesDecrypt(const std::vector<Byte>& ciphertext, const std::vector<Byte>& key) {
			if (ciphertext.size() % AES_BLOCK_SIZE != 0) throw std::invalid_argument("Ciphertext length must be multiple of block size");
			std::vector<Byte> plaintext;
			std::vector<Word> roundKeys = keyExpansion(key);
			size_t numBlocks = ciphertext.size() / AES_BLOCK_SIZE;
			for (size_t i = 0; i < numBlocks; ++i) {
				std::vector<Byte> block(ciphertext.begin() + i * AES_BLOCK_SIZE, ciphertext.begin() + (i + 1) * AES_BLOCK_SIZE);
				std::vector<Byte> decryptedBlock;
				aesDecryptBlock(block, decryptedBlock, roundKeys);
				plaintext.insert(plaintext.end(), decryptedBlock.begin(), decryptedBlock.end());
			}
			return plaintext;
		}
	}
	namespace gost_3412_2015 {
		using Byte = unsigned char;
		using Word = unsigned long long int;
		constexpr size_t BLOCK_SIZE = 16;
		constexpr size_t KEY_SIZE = 32;
		constexpr size_t ROUNDS = 10;
		constexpr size_t KEY_EXP_SIZE = (ROUNDS + 1) * 2;
		constexpr Byte SBOX[] = {
			0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
			0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0x51, 0x8E, 0x6F, 0x4C, 0xCE,
			0xD2, 0x08, 0x6A, 0x72, 0x13, 0x7B, 0x0A, 0x8B, 0x81, 0x95, 0x8F, 0x87, 0x6B, 0xBD, 0xC8, 0x0F,
			0x00, 0xDF, 0x7A, 0x4A, 0xE0, 0x5E, 0x02, 0x7D, 0x96, 0x8A, 0x05, 0x60, 0x85, 0x21, 0x9F, 0x35,
			0x3C, 0x80, 0x7E, 0xFD, 0x4B, 0xE4, 0xCD, 0x48, 0xE2, 0x6D, 0x12, 0x5D, 0x5B, 0x9C, 0xA6, 0x15,
			0x7C, 0x2C, 0xC7, 0x82, 0x98, 0x18, 0xA7, 0x65, 0xAA, 0x5C, 0x2F, 0x30, 0x62, 0x3D, 0xBC, 0x03,
			0x07, 0x9A, 0x4F, 0x88, 0xF9, 0xCA, 0x7F, 0x89, 0x29, 0x4E, 0x1F, 0x1E, 0x0B, 0x79, 0xDC, 0xDE,
			0x5F, 0xC1, 0xAB, 0x3F, 0xBF, 0x34, 0xD6, 0x27, 0x2A, 0x0D, 0x57, 0xCB, 0x26, 0xE7, 0x24, 0x8D,
			0x0C, 0xE8, 0x73, 0x9D, 0x8C, 0x37, 0x58, 0x0E, 0xA3, 0x44, 0x90, 0x94, 0x9B, 0x70, 0xA1, 0x1D,
			0x33, 0x3E, 0xFF, 0xB7, 0xCC, 0xE3, 0x5A, 0x3B, 0x83, 0x91, 0x41, 0x01, 0x56, 0xAE, 0xA8, 0x22,
			0x74, 0x67, 0x47, 0xEB, 0xD8, 0xA9, 0x2D, 0x61, 0x19, 0x53, 0x45, 0x20, 0xD1, 0xE1, 0x69, 0x06,
			0x64, 0x84, 0xAD, 0x75, 0x32, 0xF5, 0xD0, 0x40, 0x54, 0x71, 0x2B, 0xD7, 0x97, 0xEC, 0xA0, 0xE5,
			0xBE, 0xF2, 0x09, 0xF6, 0x66, 0x78, 0x10, 0x14, 0x42, 0x92, 0x46, 0xAF, 0xF7, 0x25, 0x86, 0xD3,
			0xA2, 0xF8, 0xB3, 0xC2, 0xD5, 0x43, 0x1A, 0x50, 0xB0, 0x76, 0xAC, 0x52, 0xC0, 0x38, 0x39, 0xD4,
			0xCB, 0xF3, 0x55, 0xB1, 0x28, 0x3A, 0x49, 0x63, 0xDA, 0xE6, 0xBD, 0x0A, 0x7F, 0x1C, 0x8E, 0x4F,
			0x9E, 0xDF, 0x7B, 0x8B, 0x9A, 0x6C, 0x5D, 0x2E, 0x3F, 0x4A, 0x0D, 0x1B, 0x7E, 0x9D, 0x8C, 0x37
		};
		constexpr Word C[] = {
			0x8899AABBCCDDEEFF, 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF0E1D2C3B4A59687,
			0x7867564534231201, 0xB0A1928374655647, 0x7B6A5C4D3E2F1001, 0x5566778899AABBCC,
			0x1122334455667788, 0xABCDEF0123456789
		};
		inline Byte sbox(Byte b) {
			return SBOX[b];
		}
		inline Word rol64(Word x, size_t n) {
			return (x << n) | (x >> (64 - n));
		}
		void addRoundKey(std::vector<Byte>& state, const std::vector<Word>& roundKeys, size_t round) {
			Word k0 = roundKeys[round * 2];
			Word k1 = roundKeys[round * 2 + 1];
			Word s0 = (static_cast<Word>(state[0]) << 56) | (static_cast<Word>(state[1]) << 48) |
			          (static_cast<Word>(state[2]) << 40) | (static_cast<Word>(state[3]) << 32) |
			          (static_cast<Word>(state[4]) << 24) | (static_cast<Word>(state[5]) << 16) |
			          (static_cast<Word>(state[6]) << 8) | static_cast<Word>(state[7]);
			Word s1 = (static_cast<Word>(state[8]) << 56) | (static_cast<Word>(state[9]) << 48) |
			          (static_cast<Word>(state[10]) << 40) | (static_cast<Word>(state[11]) << 32) |
			          (static_cast<Word>(state[12]) << 24) | (static_cast<Word>(state[13]) << 16) |
			          (static_cast<Word>(state[14]) << 8) | static_cast<Word>(state[15]);
			s0 ^= k0;
			s1 ^= k1;
			for (size_t i = 0; i < 8; ++i) {
				state[i] = (s0 >> (56 - i * 8)) & 0xFF;
				state[i + 8] = (s1 >> (56 - i * 8)) & 0xFF;
			}
		}
		void substituteBytes(std::vector<Byte>& state) {
			for (size_t i = 0; i < BLOCK_SIZE; ++i) state[i] = sbox(state[i]);
		}
		void shiftBytes(std::vector<Byte>& state) {
			Byte temp[BLOCK_SIZE];
			for (size_t i = 0; i < 8; ++i) temp[i] = state[(i + 8 - i % 8) % 8];
			for (size_t i = 8; i < BLOCK_SIZE; ++i) temp[i] = state[(i - 8 + (i - 7) % 8) % 8 + 8];
			std::copy_n(temp, BLOCK_SIZE, state.begin());
		}
		void mixColumns(std::vector<Byte>& state) {
			for (size_t col = 0; col < 2; ++col) {
				Byte c[8];
				for (size_t i = 0; i < 8; ++i) c[i] = state[col * 8 + i];
				for (size_t i = 0; i < 8; ++i) {
					Byte res = 0;
					for (size_t j = 0; j < 8; ++j) {
						if (j == i) res ^= c[j];
						else if ((i + 1) % 8 == j) res ^= (c[j] << 1) ^ ((c[j] & 0x80) ? 0x01 : 0x00);
						else if ((i + 3) % 8 == j) res ^= (c[j] << 3) ^ ((c[j] & 0xE0) ? 0x07 : 0x00) ^ ((c[j] & 0x80) ? 0x01 : 0x00);
						else if ((i + 4) % 8 == j) res ^= (c[j] << 4) ^ ((c[j] & 0xF0) ? 0x0F : 0x00) ^ ((c[j] & 0x80) ? 0x03 : 0x00);
					}
					state[col * 8 + i] = res;
				}
			}
		}
		std::vector<Word> keyExpansion(const std::vector<Byte>& key) {
			std::vector<Word> roundKeys(KEY_EXP_SIZE, 0);
			for (size_t i = 0; i < 4; ++i) {
				roundKeys[i] = (static_cast<Word>(key[i * 8]) << 56) | (static_cast<Word>(key[i * 8 + 1]) << 48) |
				               (static_cast<Word>(key[i * 8 + 2]) << 40) | (static_cast<Word>(key[i * 8 + 3]) << 32) |
				               (static_cast<Word>(key[i * 8 + 4]) << 24) | (static_cast<Word>(key[i * 8 + 5]) << 16) |
				               (static_cast<Word>(key[i * 8 + 6]) << 8) | static_cast<Word>(key[i * 8 + 7]);
			}
			for (size_t i = 4; i < KEY_EXP_SIZE; ++i) {
				Word temp = roundKeys[i - 1];
				temp = rol64(temp, 32);
				Byte tBytes[8];
				for (size_t j = 0; j < 8; ++j) tBytes[j] = (temp >> (56 - j * 8)) & 0xFF;
				for (size_t j = 0; j < 8; ++j) tBytes[j] = sbox(tBytes[j]);
				temp = (static_cast<Word>(tBytes[0]) << 56) | (static_cast<Word>(tBytes[1]) << 48) |
				       (static_cast<Word>(tBytes[2]) << 40) | (static_cast<Word>(tBytes[3]) << 32) |
				       (static_cast<Word>(tBytes[4]) << 24) | (static_cast<Word>(tBytes[5]) << 16) |
				       (static_cast<Word>(tBytes[6]) << 8) | static_cast<Word>(tBytes[7]);
				temp ^= C[(i / 2) - 2];
				roundKeys[i] = roundKeys[i - 4] ^ temp;
			}
			return roundKeys;
		}
		void encryptBlock(const std::vector<Byte>& in, std::vector<Byte>& out, const std::vector<Word>& roundKeys) {
			out = in;
			addRoundKey(out, roundKeys, 0);
			for (size_t round = 1; round < ROUNDS; ++round) {
				substituteBytes(out);
				shiftBytes(out);
				mixColumns(out);
				addRoundKey(out, roundKeys, round);
			}
			substituteBytes(out);
			shiftBytes(out);
			addRoundKey(out, roundKeys, ROUNDS);
		}
		std::vector<Byte> encrypt(const std::vector<Byte>& plaintext, const std::vector<Byte>& key) {
			if (key.size() != KEY_SIZE) throw std::invalid_argument("Invalid key size");
			std::vector<Byte> ciphertext;
			std::vector<Word> roundKeys = keyExpansion(key);
			size_t numBlocks = (plaintext.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
			for (size_t i = 0; i < numBlocks; ++i) {
				std::vector<Byte> block(BLOCK_SIZE, 0);
				size_t start = i * BLOCK_SIZE;
				size_t len = std::min(BLOCK_SIZE, plaintext.size() - start);
				std::copy_n(plaintext.begin() + start, len, block.begin());
				std::vector<Byte> encryptedBlock;
				encryptBlock(block, encryptedBlock, roundKeys);
				ciphertext.insert(ciphertext.end(), encryptedBlock.begin(), encryptedBlock.end());
			}
			return ciphertext;
		}
		constexpr Byte INV_SBOX[] = {
			0x5F, 0xA6, 0x63, 0x64, 0x03, 0x36, 0x82, 0x68, 0x18, 0xC0, 0x0E, 0x8D, 0x72, 0x2B, 0x7B, 0x2C,
			0x10, 0x0C, 0x95, 0x4D, 0x84, 0x92, 0x02, 0x73, 0x7F, 0x79, 0x5D, 0x9B, 0x35, 0x42, 0x30, 0x24,
			0x87, 0x5C, 0x9A, 0x14, 0x66, 0x3E, 0x3F, 0x5E, 0x4E, 0xD8, 0x61, 0x20, 0x8F, 0x16, 0x47, 0x33,
			0x48, 0x38, 0x5A, 0x39, 0x6B, 0x27, 0x8C, 0x7D, 0x2F, 0x59, 0x09, 0x4A, 0x1C, 0x9E, 0x7A, 0x1D,
			0x58, 0x60, 0x00, 0x6F, 0x62, 0x2D, 0x98, 0x81, 0x0B, 0x43, 0x1A, 0x71, 0x56, 0x13, 0x44, 0x80,
			0x0F, 0x7C, 0x49, 0x21, 0x3B, 0x2A, 0x9D, 0x7E, 0x1B, 0x0D, 0x4F, 0x8E, 0x6A, 0x2E, 0x5D, 0x37,
			0x9F, 0x57, 0x69, 0x06, 0x07, 0x41, 0x89, 0x3D, 0x77, 0x19, 0x22, 0x85, 0x50, 0x3C, 0x9C, 0x0A,
			0x1E, 0x1F, 0x4B, 0x29, 0x88, 0x78, 0x67, 0x25, 0x32, 0x55, 0x01, 0x90, 0x40, 0x91, 0x83, 0x45,
			0x54, 0x65, 0xAA, 0x52, 0xC0, 0x38, 0x39, 0xD4, 0xCB, 0xF3, 0x55, 0xB1, 0x28, 0x3A, 0x49, 0x63,
			0xE6, 0xBD, 0x0A, 0x7F, 0x1C, 0x8E, 0x4F, 0x9E, 0xDF, 0x7B, 0x8B, 0x9A, 0x6C, 0x5D, 0x2E, 0x3F,
			0x4A, 0x0D, 0x1B, 0x7E, 0x9D, 0x8C, 0x37, 0x05, 0x6E, 0x74, 0x97, 0xEC, 0xA0, 0xE5, 0xBE, 0xF2,
			0x09, 0xF6, 0x66, 0x78, 0x10, 0x14, 0x42, 0x92, 0x46, 0xAF, 0xF7, 0x25, 0x86, 0xD3, 0xA2, 0xF8,
			0xB3, 0xC2, 0xD5, 0x43, 0x1A, 0x50, 0xB0, 0x76, 0xAC, 0x52, 0xC0, 0x38, 0x39, 0xD4, 0xCB, 0xF3,
			0x55, 0xB1, 0x28, 0x3A, 0x49, 0x63, 0xE6, 0xBD, 0x0A, 0x7F, 0x1C, 0x8E, 0x4F, 0x9E, 0xDF, 0x7B,
			0x8B, 0x9A, 0x6C, 0x5D, 0x2E, 0x3F, 0x4A, 0x0D, 0x1B, 0x7E, 0x9D, 0x8C, 0x37, 0x05, 0x6E, 0x74,
			0x97, 0xEC, 0xA0, 0xE5, 0xBE, 0xF2, 0x09, 0xF6, 0x66, 0x78, 0x10, 0x14, 0x42, 0x92, 0x46, 0xAF
		};
		inline Byte invSbox(Byte b) {
			return INV_SBOX[b];
		}
		void invSubstituteBytes(std::vector<Byte>& state) {
			for (size_t i = 0; i < BLOCK_SIZE; ++i) state[i] = invSbox(state[i]);
		}
		void invShiftBytes(std::vector<Byte>& state) {
			Byte temp[BLOCK_SIZE];
			for (size_t i = 0; i < 8; ++i) temp[i] = state[(i + i % 8) % 8];
			for (size_t i = 8; i < BLOCK_SIZE; ++i) temp[i] = state[(i - 8 + (16 - i) % 8) % 8 + 8];
			std::copy_n(temp, BLOCK_SIZE, state.begin());
		}
		void invMixColumns(std::vector<Byte>& state) {
			for (size_t col = 0; col < 2; ++col) {
				Byte c[8];
				for (size_t i = 0; i < 8; ++i) c[i] = state[col * 8 + i];
				for (size_t i = 0; i < 8; ++i) {
					Byte res = 0;
					for (size_t j = 0; j < 8; ++j) {
						if (j == i) res ^= c[j];
						else if ((j + 1) % 8 == i) res ^= (c[j] << 1) ^ ((c[j] & 0x80) ? 0x01 : 0x00);
						else if ((j + 3) % 8 == i) res ^= (c[j] << 3) ^ ((c[j] & 0xE0) ? 0x07 : 0x00) ^ ((c[j] & 0x80) ? 0x01 : 0x00);
						else if ((j + 4) % 8 == i) res ^= (c[j] << 4) ^ ((c[j] & 0xF0) ? 0x0F : 0x00) ^ ((c[j] & 0x80) ? 0x03 : 0x00);
					}
					state[col * 8 + i] = res;
				}
			}
		}
		void decryptBlock(const std::vector<Byte>& in, std::vector<Byte>& out, const std::vector<Word>& roundKeys) {
			out = in;
			addRoundKey(out, roundKeys, ROUNDS);
			for (size_t round = ROUNDS - 1; round > 0; --round) {
				invShiftBytes(out);
				invSubstituteBytes(out);
				addRoundKey(out, roundKeys, round);
				invMixColumns(out);
			}
			invShiftBytes(out);
			invSubstituteBytes(out);
			addRoundKey(out, roundKeys, 0);
		}
		std::vector<Byte> decrypt(const std::vector<Byte>& ciphertext, const std::vector<Byte>& key) {
			if (key.size() != KEY_SIZE) throw std::invalid_argument("Invalid key size");
			if (ciphertext.size() % BLOCK_SIZE != 0) throw std::invalid_argument("Ciphertext length must be multiple of block size");
			std::vector<Byte> plaintext;
			std::vector<Word> roundKeys = keyExpansion(key);
			size_t numBlocks = ciphertext.size() / BLOCK_SIZE;
			for (size_t i = 0; i < numBlocks; ++i) {
				std::vector<Byte> block(ciphertext.begin() + i * BLOCK_SIZE, ciphertext.begin() + (i + 1) * BLOCK_SIZE);
				std::vector<Byte> decryptedBlock;
				decryptBlock(block, decryptedBlock, roundKeys);
				plaintext.insert(plaintext.end(), decryptedBlock.begin(), decryptedBlock.end());
			}
			return plaintext;
		}
	}
	unsigned int crc32(const unsigned char* data, size_t len) {
		unsigned int crc = 0xFFFFFFFF;
		static const unsigned int table[256] = {
			0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
			0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
			0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
			0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
			0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
			0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
			0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
			0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
			0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
			0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
			0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
			0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
			0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
			0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
			0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
			0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
			0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
			0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
			0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
			0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
			0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
			0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8E0F, 0x4669BE99,
			0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
			0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
			0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
			0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
			0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
			0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
			0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
			0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
			0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
			0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
		};
		while (len--) {
			crc = (crc >> 8) ^ table[(crc ^ *data++) & 0xFF];
		}
		return crc ^ 0xFFFFFFFF;
	}
	unsigned long long int crc64(const unsigned char* data, size_t len) {
		unsigned long long int crc = 0xFFFFFFFFFFFFFFFF;
		static const unsigned long long int table[256] = {
			0x0000000000000000, 0x42F0E1EBA9EA3693, 0x85E1C3D753D46D26, 0xC711223CFA3E5BB5,
			0x493366412643982D, 0x0BC387AAC9A9A39E, 0xCDD2A59673F3F84B, 0x8F22447DDA19CCDE,
			0x9266CC825287305A, 0xD0962D69FB6D06C9, 0x17A70F5541575D7C, 0x5557EEBCF8BD6BEB,
			0xDB75AAAB2E26A673, 0x99854B4087CC90E0, 0x5E94697C3DD7CBB7, 0x1C648897943DFD24,
			0x16CC5105E89E26E4, 0x543CBEEC41741077, 0x932D9CD8FB8E4BA0, 0xD1DD7D33526A7D33,
			0x05FFB3926F9DFA4B, 0x470BDAEC8637CCDE, 0x801AD8D03C299769, 0xC2EAF93B95C3A1FA,
			0x8E2EB5440D5518CA, 0xCCDE54AFA4BF2E59, 0x0ADF76931E8575EC, 0x482F9778B76F437B,
			0xC60DD36F61F48E03, 0x84FD3284C81EBC90, 0x43EC10B87204E727, 0x011CF153DBEED1B4,
			0x2CC8A20BC1B84DCC, 0x6E3843E068527B5F, 0xAB2961DCD26CA0E8, 0xE9D980377B86967B,
			0x67FBC4200D1D5D03, 0x250B25CBA4F76B90, 0xE21A07F71EEDC027, 0xA0EAE61C7707F6B4,
			0xB62E6AE1EF99E17A, 0xF4DE8B0A4673D799, 0x33CFA936FC698C5C, 0x713F48D35583BDCB,
			0xFD1D8CC42F18F6B3, 0xBBED6D2F86F2C020, 0x7CDC4F133CE6B97,  0x3E2CAEF895089D24,
			0x034E477F66E78A1E, 0x455E9619D792977D, 0x864FB4256D88CCC8, 0xC4BF55CEC462FA5B,
			0x4A9D11D71EF5B0E3, 0x088DF03C771F8670, 0xCB7CD200CD05DB27, 0x896C33EB64E9AD4,
			0xA802BFB4FCD7031A, 0xEAF25E5F55BD3589, 0x2DE37C63EFA68E2C, 0x6F139D88464058BF,
			0xED31D99138DB3263, 0xABC1387A913104F0, 0x68D01A462B2B5FA7, 0x2A20FBDD82C16924,
			0x5994741F1D6C9B58, 0x1B6495F4B486ADCB, 0xDCCB77C84E9CF67E, 0x9E8B9623E776C0EB,
			0x10A9523491EDAB93, 0x5259B3DF38079D00, 0x914891E3821DC6B7, 0xDFB870082BF7F024,
			0xC778FCF1336E0E6A, 0x85881D1A9A8438F9, 0x46993F26209E634C, 0x0469DFCD97455B,
			0x8A4B1BD40FFB9E03, 0xC8BBFADFA611A890, 0x0FAAD8E31C2BF327, 0x4D5A3908B5C1C5B4,
			0x047D2E0FECDE18D4, 0x466D0115643A2A77, 0x875C2329DE2071C0, 0xC54CC2C277CA4753,
			0x4F2E86D501518ACB, 0x0D3E673EA8BBBC2E, 0x8E2F450212A5E799, 0xCC1FA4E9BB4FF16A,
			0xDD3020D823DFE80,  0x9F20C1338A3BDAF3, 0x5E11E30F30218146, 0x1C0102E499CBB7D5,
			0x9623C6F30550F24D, 0xD4332718ACBAC4DE, 0x1522052416A09FFB, 0x5712E4CFB38C826E,
			0x732668F76D1671DA, 0x3136891CC4FC4749, 0xF227AB207EE61CFC, 0xB0174ACBD762F5B,
			0x3E750ED24FF9D003, 0x7C65EF39E613E690, 0xFD74CF055C09BD27, 0xBB64ADEEFDE7254,
			0xE98E2116859C8E94, 0xAB9EC0FD2C59D07, 0x6A8FE2C19663E6C0, 0x289F032A3F89D053,
			0xA6FDC73D4712BB8B, 0xE4ED26D6EEFC8D1E, 0x25FC04EA54E28A9,  0x67ECE501FC08BB6A,
			0x2D649CF336988C8,  0x6F747D189F72BA1F, 0xEE655F242568E1A8, 0xAC75BFC9C82D75B,
			0x6217FBD056B8F03, 0x20071A3BFD52C990, 0xE116380747489227, 0xA306D9ECEE4A4B4,
			0xF5C2551476D2537A, 0xB7D2B4FFDF365E99, 0x36C396C3652D304C, 0x74D37728CC4706DB,
			0xBABC3331B5D24703, 0xF9ACD2DA1C366190, 0x38BDF0E6A62C3A27, 0x7ADB110D0FC904B4
		};
		while (len--) {
			crc = (crc >> 8) ^ table[(crc ^ *data++) & 0xFF];
		}
		return crc ^ 0xFFFFFFFFFFFFFFFF;
	}
	class Whirlpool {
		private:
			unsigned long long int state[8];
			unsigned char buffer[64];
			size_t buf_len;
			unsigned long long int total_len;
			static const unsigned long long int C[8];
			static const unsigned char S[256];
			static const unsigned long long int RC[10][8];
			void round(unsigned long long int *state, const unsigned long long int *M, int r) {
				unsigned long long int K[8], T[8];
				for (int i = 0; i < 8; i++) {
					K[i] = state[i] ^ M[i] ^ RC[r][i];
				}
				for (int i = 0; i < 8; i++) {
					T[i] = 0;
					for (int j = 0; j < 8; j++) {
						unsigned long long int temp = K[j];
						temp >>= 8 * ((i - j) & 7);
						temp &= 0xFF;
						unsigned char s_val = S[static_cast<unsigned char>(temp)];
						T[i] ^= static_cast<unsigned long long int>(s_val) << (8 * j);
					}
				}
				for (int i = 0; i < 8; i++) {
					state[i] = T[i] ^ ((~T[(i + 1) % 8]) & T[(i + 2) % 8]);
				}
			}
		public:
			Whirlpool() {
				reset();
			}
			void reset() {
				memset(state, 0, sizeof(state));
				memset(buffer, 0, sizeof(buffer));
				buf_len = 0;
				total_len = 0;
			}
			void update(const unsigned char* data, size_t len) {
				total_len += len;
				while (len > 0) {
					size_t chunk = len < (64 - buf_len) ? len : (64 - buf_len);
					memcpy(buffer + buf_len, data, chunk);
					buf_len += chunk;
					data += chunk;
					len -= chunk;
					if (buf_len == 64) {
						unsigned long long int M[8];
						for (int i = 0; i < 8; i++) {
							M[i] = 0;
							for (int j = 0; j < 8; j++) {
								M[i] |= ((unsigned long long int)(buffer[i * 8 + j]) << (8 * j));
							}
						}
						for (int r = 0; r < 10; r++) {
							round(state, M, r);
						}
						buf_len = 0;
					}
				}
			}
			void final(unsigned char* hash) {
				buffer[buf_len++] = 0x80;
				if (buf_len > 56) {
					memset(buffer + buf_len, 0, 64 - buf_len);
					update(buffer, 64);
					buf_len = 0;
				}
				memset(buffer + buf_len, 0, 56 - buf_len);
				unsigned long long int len = total_len * 8;
				for (int i = 0; i < 8; i++) {
					buffer[56 + i] = (len >> (8 * i)) & 0xFF;
				}
				update(buffer, 64);
				for (int i = 0; i < 8; i++) {
					for (int j = 0; j < 8; j++) {
						hash[i * 8 + j] = (state[i] >> (8 * j)) & 0xFF;
					}
				}
			}
	};
	const unsigned long long int Whirlpool::C[8] = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
		0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009
	};
	const unsigned char Whirlpool::S[256] = {
		0x18, 0x23, 0x3A, 0x4D, 0x5B, 0x6C, 0x71, 0x89, 0x96, 0xA2, 0xB7, 0xCE, 0xD4, 0xEF, 0xF5, 0x0E,
		0x42, 0x54, 0x66, 0x78, 0x0A, 0x1C, 0x2E, 0x30, 0x73, 0x61, 0x5F, 0x4D, 0x3B, 0x29, 0x17, 0x05,
		0x84, 0x96, 0xA8, 0xBA, 0xCA, 0xDC, 0xEE, 0xF0, 0x1D, 0x0B, 0x39, 0x27, 0x53, 0x41, 0x7F, 0x6D,
		0xC6, 0xD8, 0xEA, 0xFC, 0x92, 0x80, 0xBE, 0xAC, 0x57, 0x45, 0x7B, 0x69, 0x3F, 0x2D, 0x1B, 0x09,
		0x0C, 0x1E, 0x20, 0x32, 0x44, 0x56, 0x68, 0x7A, 0x8E, 0x90, 0xA2, 0xB4, 0xC6, 0xD8, 0xEA, 0xFC,
		0x91, 0x83, 0xB5, 0xA7, 0xD9, 0xCB, 0xFE, 0xE0, 0x25, 0x37, 0x01, 0x13, 0x67, 0x75, 0x4B, 0x59,
		0x6F, 0x7D, 0x4B, 0x59, 0x23, 0x31, 0x0D, 0x1B, 0xA9, 0xBF, 0x85, 0x97, 0xED, 0xFC, 0xC3, 0xD1,
		0x3E, 0x2C, 0x1A, 0x08, 0x76, 0x64, 0x52, 0x40, 0xDC, 0xCE, 0xF0, 0xE2, 0x94, 0x86, 0xB8, 0xAA,
		0x51, 0x43, 0x75, 0x67, 0x1B, 0x09, 0x3F, 0x2D, 0x87, 0x95, 0xA3, 0xB1, 0xCD, 0xDB, 0xE9, 0xF7,
		0x02, 0x10, 0x2E, 0x3C, 0x4A, 0x58, 0x66, 0x74, 0x9A, 0x88, 0xBE, 0xAC, 0xDD, 0xCF, 0xF1, 0xE3,
		0x79, 0x6B, 0x5D, 0x4F, 0x31, 0x23, 0x15, 0x07, 0xB2, 0xA0, 0x9E, 0x8C, 0xE4, 0xF6, 0xC8, 0xDA,
		0x2F, 0x3D, 0x0B, 0x19, 0x65, 0x77, 0x41, 0x53, 0xE6, 0xF4, 0xCA, 0xD8, 0xA0, 0xB2, 0x84, 0x96,
		0x47, 0x55, 0x63, 0x71, 0x0F, 0x1D, 0x2B, 0x39, 0xF8, 0xEC, 0xD2, 0xC0, 0xBE, 0xAC, 0x98, 0x86,
		0x1A, 0x08, 0x36, 0x24, 0x50, 0x4E, 0x7C, 0x6A, 0xCD, 0xDB, 0xE9, 0xF7, 0x81, 0x93, 0xA5, 0xB7,
		0x34, 0x26, 0x10, 0x02, 0x7E, 0x6C, 0x5A, 0x48, 0xA1, 0xB3, 0x85, 0x97, 0xE9, 0xF7, 0xC5, 0xD3,
		0x62, 0x70, 0x4E, 0x5C, 0x2A, 0x38, 0x06, 0x14, 0xD5, 0xC7, 0xF9, 0xEB, 0x9D, 0x8F, 0xB1, 0xA3
	};
	const unsigned long long int Whirlpool::RC[10][8] = {
		{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		{0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000},
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000},
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001},
		{0x0000000000000001, 0x0000000000000001, 0x0000000000000001, 0x0000000000000001, 0x0000000000000001, 0x0000000000000001, 0x0000000000000001, 0x0000000000000001},
		{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000001}
	};
	class Tiger {
		private:
			unsigned long long int state[3];
			unsigned char buffer[64];
			size_t buf_len;
			unsigned long long int total_len;
			bool is_tiger2;
			static const unsigned long long int S[4][256];
			static const unsigned long long int K[3][8];
			static unsigned long long int f(unsigned long long int x, unsigned long long int y, unsigned long long int z) {
				return (x & y) | (~x & z);
			}
			static unsigned long long int g(unsigned long long int x, unsigned long long int y, unsigned long long int z) {
				return (x & z) | (y & ~z);
			}
			static unsigned long long int h(unsigned long long int x, unsigned long long int y, unsigned long long int z) {
				return x ^ y ^ z;
			}
			static unsigned long long int k(unsigned long long int x, unsigned long long int y, unsigned long long int z) {
				return y ^ (x | ~z);
			}
			void round(unsigned long long int& a, unsigned long long int& b, unsigned long long int& c, unsigned long long int m, unsigned long long int k, unsigned long long int (*op)(unsigned long long int, unsigned long long int, unsigned long long int), int shift) {
				a = op(a, b, c) + m + k;
				a = (a << shift) | (a >> (64 - shift));
				unsigned long long int t = b;
				b = c;
				c = t;
			}
			void compress(const unsigned char* block) {
				unsigned long long int m[8];
				for (int i = 0; i < 8; i++) {
					m[i] = 0;
					for (int j = 0; j < 8; j++) {
						m[i] |= ((unsigned long long int)(block[i * 8 + j]) << (8 * j));
					}
				}
				unsigned long long int a = state[0], b = state[1], c = state[2];
				for (int r = 0; r < 8; r++) {
					round(a, b, c, m[r], K[0][r], f, 5);
					round(c, a, b, m[(r + 1) % 8], K[1][r], g, 7);
					round(b, c, a, m[(r + 2) % 8], K[2][r], h, 9);
					round(a, b, c, m[(r + 3) % 8], K[0][r], k, 13);
				}
				state[0] ^= a;
				state[1] ^= b;
				state[2] ^= c;
			}
		public:
			explicit Tiger(bool tiger2 = false) : buf_len(0), total_len(0), is_tiger2(tiger2) {
				state[0] = 0x0123456789ABCDEF;
				state[1] = 0xFEDCBA9876543210;
				state[2] = 0xF0E1D2C3B4A59687;
				if (is_tiger2) {
					state[0] ^= 0xFFFFFFFFFFFFFFFF;
					state[1] ^= 0xFFFFFFFFFFFFFFFF;
					state[2] ^= 0xFFFFFFFFFFFFFFFF;
				}
			}
			void update(const unsigned char* data, size_t len) {
				total_len += len;
				while (len > 0) {
					size_t chunk = len < (64 - buf_len) ? len : (64 - buf_len);
					memcpy(buffer + buf_len, data, chunk);
					buf_len += chunk;
					data += chunk;
					len -= chunk;
					if (buf_len == 64) {
						compress(buffer);
						buf_len = 0;
					}
				}
			}
			void final(unsigned char* hash) {
				buffer[buf_len++] = 0x01;
				if (buf_len > 56) {
					memset(buffer + buf_len, 0, 64 - buf_len);
					compress(buffer);
					buf_len = 0;
				}
				memset(buffer + buf_len, 0, 56 - buf_len);
				unsigned long long int len = total_len * 8;
				for (int i = 0; i < 8; i++) {
					buffer[56 + i] = (len >> (8 * i)) & 0xFF;
				}
				compress(buffer);
				for (int i = 0; i < 3; i++) {
					for (int j = 0; j < 8; j++) {
						hash[i * 8 + j] = (state[i] >> (8 * j)) & 0xFF;
					}
				}
			}
	};
	const unsigned long long int Tiger::S[4][256] = {
		{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
			0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
			0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
			0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
			0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
			0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
			0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
			0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
			0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
			0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
		},
		{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			0x10, 0x01, 0x32, 0x23, 0x54, 0x45, 0x76, 0x67, 0x98, 0x89, 0xBA, 0xAB, 0xDC, 0xCD, 0xFE, 0xEF,
			0x20, 0x31, 0x02, 0x13, 0x64, 0x75, 0x46, 0x57, 0xA8, 0xB9, 0x8A, 0x9B, 0xEC, 0xFD, 0xCC, 0xDD,
			0x30, 0x21, 0x12, 0x03, 0x74, 0x65, 0x56, 0x47, 0xB8, 0xA9, 0x9A, 0x8B, 0xFC, 0xED, 0xDD, 0xCC,
			0x40, 0x51, 0x62, 0x73, 0x04, 0x15, 0x26, 0x37, 0xC8, 0xD9, 0xEA, 0xFB, 0x8C, 0x9D, 0xAE, 0xBF,
			0x50, 0x41, 0x72, 0x63, 0x14, 0x05, 0x36, 0x27, 0xD8, 0xC9, 0xFB, 0xEA, 0x9C, 0x8D, 0xBF, 0xAE,
			0x60, 0x71, 0x42, 0x53, 0x24, 0x35, 0x06, 0x17, 0xE8, 0xF9, 0xCA, 0xDB, 0xAC, 0xBD, 0x8E, 0x9F,
			0x70, 0x61, 0x52, 0x43, 0x34, 0x25, 0x16, 0x07, 0xF8, 0xE9, 0xDB, 0xCA, 0xBD, 0xAC, 0x9E, 0x8F,
			0x80, 0x91, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F,
			0x90, 0x81, 0xBA, 0xAB, 0xDC, 0xCD, 0xFE, 0xEF, 0x18, 0x09, 0x3A, 0x2B, 0x5C, 0x4D, 0x7E, 0x6F,
			0xA0, 0xB1, 0x82, 0x93, 0xE4, 0xF5, 0xC6, 0xD7, 0x28, 0x39, 0x0A, 0x1B, 0x6C, 0x7D, 0x4E, 0x5F,
			0xB0, 0xA1, 0x92, 0x83, 0xF4, 0xE5, 0xD6, 0xC7, 0x38, 0x29, 0x1A, 0x0B, 0x7C, 0x6D, 0x5E, 0x4F,
			0xC0, 0xD1, 0xE2, 0xF3, 0x84, 0x95, 0xA6, 0xB7, 0x48, 0x59, 0x6A, 0x7B, 0x0C, 0x1D, 0x2E, 0x3F,
			0xD0, 0xC1, 0xF2, 0xE3, 0x94, 0x85, 0xB6, 0xA7, 0x58, 0x49, 0x7A, 0x6B, 0x1C, 0x0D, 0x3E, 0x2F,
			0xE0, 0xF1, 0xC2, 0xD3, 0xA4, 0xB5, 0x86, 0x97, 0x68, 0x79, 0x4A, 0x5B, 0x2C, 0x3D, 0x0E, 0x1F,
			0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
		},
		{
			0x00, 0x1F, 0x3E, 0x21, 0x7C, 0x63, 0x42, 0x5D, 0xF8, 0xE7, 0xC6, 0xD9, 0x84, 0x9B, 0xBA, 0xA5,
			0x10, 0x0F, 0x2E, 0x31, 0x6C, 0x73, 0x52, 0x4D, 0xE8, 0xF7, 0xD6, 0xC9, 0x94, 0x8B, 0xAB, 0xB5,
			0x20, 0x3F, 0x1E, 0x01, 0x5C, 0x43, 0x62, 0x7D, 0xD8, 0xC7, 0xE6, 0xF9, 0xA4, 0xBB, 0x9A, 0x85,
			0x30, 0x2F, 0x0E, 0x11, 0x4C, 0x53, 0x72, 0x6D, 0xC8, 0xD7, 0xF6, 0xE9, 0xB4, 0xAB, 0x8A, 0x95,
			0x40, 0x5F, 0x7E, 0x61, 0x1C, 0x03, 0x22, 0x3D, 0x88, 0x97, 0xB6, 0xA9, 0xF4, 0xEB, 0xDB, 0xCA,
			0x50, 0x4F, 0x6E, 0x71, 0x0C, 0x13, 0x32, 0x2D, 0x98, 0x87, 0xA6, 0xB9, 0xE4, 0xFB, 0xCB, 0xDA,
			0x60, 0x7F, 0x5E, 0x41, 0x3C, 0x23, 0x02, 0x1D, 0xA8, 0xB7, 0x96, 0x89, 0xC4, 0xDB, 0xFB, 0xEA,
			0x70, 0x6F, 0x4E, 0x51, 0x2C, 0x33, 0x12, 0x0D, 0xB8, 0xA7, 0x86, 0x99, 0xD4, 0xCB, 0xEB, 0xFA,
			0x80, 0x9F, 0xBF, 0xA1, 0xEC, 0xF3, 0xD2, 0xCD, 0x08, 0x17, 0x36, 0x29, 0x74, 0x6B, 0x4A, 0x55,
			0x90, 0x8F, 0xAF, 0xB1, 0xFC, 0xE3, 0xC2, 0xDD, 0x18, 0x07, 0x26, 0x39, 0x64, 0x7B, 0x5A, 0x45,
			0xA0, 0xBF, 0x9E, 0x81, 0xDC, 0xC3, 0xE2, 0xFD, 0x28, 0x37, 0x16, 0x09, 0x54, 0x4B, 0x6A, 0x75,
			0xB0, 0xAF, 0x8E, 0x91, 0xCC, 0xD3, 0xF2, 0xED, 0x38, 0x27, 0x06, 0x19, 0x44, 0x5B, 0x7A, 0x65,
			0xC0, 0xDF, 0xFE, 0xE1, 0xAC, 0xB3, 0x92, 0x8D, 0x48, 0x57, 0x76, 0x69, 0x34, 0x2B, 0x0A, 0x15,
			0xD0, 0xCF, 0xEE, 0xF1, 0xBC, 0xA3, 0x82, 0x9D, 0x58, 0x47, 0x66, 0x79, 0x24, 0x3B, 0x1A, 0x05,
			0xE0, 0xFF, 0xDE, 0xC1, 0xBC, 0xA3, 0x82, 0x9D, 0x68, 0x77, 0x56, 0x49, 0x14, 0x0B, 0x2A, 0x35,
			0xF0, 0xEF, 0xCE, 0xD1, 0xAC, 0xB3, 0x92, 0x8D, 0x78, 0x67, 0x46, 0x59, 0x04, 0x1B, 0x3A, 0x25
		},
		{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			0x12, 0x03, 0x30, 0x21, 0x56, 0x47, 0x74, 0x65, 0x9A, 0x8B, 0xB8, 0xA9, 0xDC, 0xCD, 0xFE, 0xEF,
			0x24, 0x35, 0x06, 0x17, 0x60, 0x71, 0x42, 0x53, 0xAC, 0xBD, 0x8E, 0x9F, 0xE8, 0xF9, 0xCA, 0xDB,
			0x36, 0x27, 0x14, 0x05, 0x72, 0x63, 0x50, 0x41, 0xBC, 0xAD, 0x9E, 0x8F, 0xFC, 0xED, 0xDA, 0xCB,
			0x48, 0x59, 0x6A, 0x7B, 0x0C, 0x1D, 0x2E, 0x3F, 0xCC, 0xDD, 0xEE, 0xFF, 0x88, 0x99, 0xAA, 0xBB,
			0x5A, 0x4B, 0x78, 0x69, 0x1E, 0x0F, 0x3C, 0x2D, 0xDE, 0xCF, 0xF8, 0xE9, 0x9A, 0x8B, 0xBC, 0xAD,
			0x6C, 0x7D, 0x4E, 0x5F, 0x28, 0x39, 0x0A, 0x1B, 0xE0, 0xF1, 0xC2, 0xD3, 0xA4, 0xB5, 0x86, 0x97,
			0x7E, 0x6F, 0x5C, 0x4D, 0x3A, 0x2B, 0x18, 0x09, 0xF2, 0xE3, 0xD0, 0xC1, 0xB6, 0xA7, 0x94, 0x85,
			0x80, 0x91, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F,
			0x92, 0x83, 0xB0, 0xA1, 0xD6, 0xC7, 0xF4, 0xE5, 0x1A, 0x0B, 0x38, 0x29, 0x7C, 0x6D, 0x5E, 0x4F,
			0xA4, 0xB5, 0x86, 0x97, 0xE0, 0xF1, 0xC2, 0xD3, 0x2C, 0x3D, 0x0E, 0x1F, 0x68, 0x79, 0x4A, 0x5B,
			0xB6, 0xA7, 0x94, 0x85, 0xF2, 0xE3, 0xD0, 0xC1, 0x3E, 0x2F, 0x1C, 0x0D, 0x7A, 0x6B, 0x58, 0x49,
			0xC8, 0xD9, 0xEA, 0xFB, 0x8C, 0x9D, 0xAE, 0xBF, 0x40, 0x51, 0x62, 0x73, 0x04, 0x15, 0x26, 0x37,
			0xDA, 0xCB, 0xF8, 0xE9, 0x9E, 0x8F, 0xBC, 0xAD, 0x52, 0x43, 0x70, 0x61, 0x16, 0x07, 0x34, 0x25,
			0xEC, 0xFD, 0xCE, 0xDF, 0xA8, 0xB9, 0x8A, 0x9B, 0x64, 0x75, 0x46, 0x57, 0x20, 0x31, 0x02, 0x13,
			0xFE, 0xEF, 0xDC, 0xCD, 0xBA, 0xAB, 0x98, 0x89, 0x76, 0x67, 0x54, 0x45, 0x32, 0x23, 0x10, 0x01
		}
	};
	const unsigned long long int Tiger::K[3][8] = {
		{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
		{0xA5A5A5A5A5A5A5A5, 0xA5A5A5A5A5A5A5A5, 0xA5A5A5A5A5A5A5A5, 0xA5A5A5A5A5A5A5A5, 0xA5A5A5A5A5A5A5A5, 0xA5A5A5A5A5A5A5A5, 0xA5A5A5A5A5A5A5A5, 0xA5A5A5A5A5A5A5A5},
		{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}
	};
	unsigned int crc32(const std::string& s) {
		return crc32(reinterpret_cast<const unsigned char*>(s.data()), s.size());
	}
	unsigned long long int crc64(const std::string& s) {
		return crc64(reinterpret_cast<const unsigned char*>(s.data()), s.size());
	}
	std::string whirlpool(const std::string& s) {
		Whirlpool wp;
		wp.update(reinterpret_cast<const unsigned char*>(s.data()), s.size());
		unsigned char hash[64];
		wp.final(hash);
		return std::string(reinterpret_cast<char*>(hash), 64);
	}
	std::string tiger(const std::string& s) {
		Tiger t(false);
		t.update(reinterpret_cast<const unsigned char*>(s.data()), s.size());
		unsigned char hash[24];
		t.final(hash);
		return std::string(reinterpret_cast<char*>(hash), 24);
	}
	std::string tiger2(const std::string& s) {
		Tiger t(true);
		t.update(reinterpret_cast<const unsigned char*>(s.data()), s.size());
		unsigned char hash[24];
		t.final(hash);
		return std::string(reinterpret_cast<char*>(hash), 24);
	}
	static inline void adler32_memxor(void* dest, const void* src, size_t n) {
		unsigned char* d = (unsigned char*)dest;
		const unsigned char* s = (const unsigned char*)src;
		while (n--) *d++ ^= *s++;
	}
	static inline void adler32_memzero(void* dest, size_t n) {
		memset(dest, 0, n);
	}
#define ADLER32_HASH_SIZE 4
	static const unsigned int ADLER32_MOD = 65521;
	unsigned int adler32(const unsigned char* data, size_t length) {
		unsigned int a = 1, b = 0;
		for (size_t i = 0; i < length; i++) {
			a = (a + data[i]) % ADLER32_MOD;
			b = (b + a) % ADLER32_MOD;
		}
		return (b << 16) | a;
	}

#define BLAKE2B_BLOCK_SIZE 128
#define BLAKE2B_HASH_SIZE 64
	typedef struct {
		unsigned long long int h[8];
		unsigned long long int t[2];
		unsigned long long int f[2];
		unsigned char buf[BLAKE2B_BLOCK_SIZE];
		size_t buf_size;
		size_t out_len;
	} BLAKE2b_CTX;
	static const unsigned long long int blake2b_iv[8] = {0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179};
	static const unsigned char blake2b_sigma[12][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}, {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}, {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}, {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}, {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};
	static inline unsigned long long int blake2b_rotl64(unsigned long long int x, int n) {
		return (x << n) | (x >> (64 - n));
	}
	static void blake2b_compress(BLAKE2b_CTX* ctx, int last) {
		unsigned long long int m[16];
		for (int i = 0; i < 16; i++) {
			m[i] = (unsigned long long int)ctx->buf[i * 8] << 56 | (unsigned long long int)ctx->buf[i * 8 + 1] << 48 | (unsigned long long int)ctx->buf[i * 8 + 2] << 40 | (unsigned long long int)ctx->buf[i * 8 + 3] << 32 | (unsigned long long int)ctx->buf[i * 8 + 4] << 24 | (unsigned long long int)ctx->buf[i * 8 + 5] << 16 | (unsigned long long int)ctx->buf[i * 8 + 6] << 8 | (unsigned long long int)ctx->buf[i * 8 + 7];
		}
		unsigned long long int v[16];
		for (int i = 0; i < 8; i++) {
			v[i] = ctx->h[i];
			v[i + 8] = blake2b_iv[i];
		}
		v[12] ^= ctx->t[0];
		v[13] ^= ctx->t[0];
		v[14] ^= ctx->t[1];
		v[15] ^= ctx->t[1];
		if (last) {
			v[14] ^= 0xFFFFFFFFFFFFFFFF;
			v[15] ^= 0xFFFFFFFFFFFFFFFF;
		}
		for (int r = 0; r < 12; r++) {
			unsigned long long int a = v[0], b = v[1], c = v[2], d = v[3],
			                       e = v[4], f = v[5], g = v[6], h_val = v[7];
#define BLAKE2B_G(i) a += b + m[blake2b_sigma[r][2 * i]]; h_val = blake2b_rotl64(h_val ^ a, 32); d += c; g = blake2b_rotl64(g ^ d, 24); a += h_val + m[blake2b_sigma[r][2 * i + 1]]; e = blake2b_rotl64(e ^ a, 16); d += g; f = blake2b_rotl64(f ^ d, 63);
			for (int i = 0; i < 8; i++) {
				BLAKE2B_G(i);
			}
#undef BLAKE2B_G
			v[0] = a;
			v[1] = b;
			v[2] = c;
			v[3] = d;
			v[4] = e;
			v[5] = f;
			v[6] = g;
			v[7] = h_val;
		}

		for (int i = 0; i < 8; i++) {
			ctx->h[i] ^= v[i] ^ v[i + 8];
		}
	}
	void blake2b_init(BLAKE2b_CTX* ctx, size_t out_len) {
		ctx->out_len = out_len;
		memcpy(ctx->h, blake2b_iv, sizeof(ctx->h));
		ctx->h[0] ^= 0x01010000 ^ (unsigned long long int)out_len;
		ctx->t[0] = ctx->t[1] = 0;
		ctx->f[0] = ctx->f[1] = 0;
		ctx->buf_size = 0;
	}
	void blake2b_update(BLAKE2b_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk = BLAKE2B_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length)chunk = length;
			memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == BLAKE2B_BLOCK_SIZE) {
				ctx->t[0] += BLAKE2B_BLOCK_SIZE;
				if (ctx->t[0] < BLAKE2B_BLOCK_SIZE)ctx->t[1]++;
				blake2b_compress(ctx, 0);
				ctx->buf_size = 0;
			}
		}
	}
	void blake2b_final(BLAKE2b_CTX* ctx, unsigned char* hash) {
		ctx->t[0] += ctx->buf_size;
		if (ctx->t[0] < ctx->buf_size)ctx->t[1]++;
		ctx->f[0] = 1;
		blake2b_compress(ctx, 1);
		for (size_t i = 0; i < ctx->out_len; i++) {
			hash[i] = (unsigned char)(ctx->h[i / 8] >> (56 - (i % 8) * 8));
		}
	}
#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_HASH_SIZE 32
	typedef struct {
		unsigned int h[8];
		unsigned long long int t[2];
		unsigned long long int f[2];
		unsigned char buf[BLAKE2S_BLOCK_SIZE];
		size_t buf_size;
		size_t out_len;
	} BLAKE2s_CTX;
	static const unsigned int blake2s_iv[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xFE94F82B, 0xA54FF53A, 0x510E527F, 0x1F83D9AB, 0x5BE0CD19};
	static const unsigned char blake2s_sigma[10][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}, {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}, {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}, {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}, {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
	static inline unsigned int blake2s_rotl32(unsigned int x, int n) {
		return (x << n) | (x >> (32 - n));
	}
	static void blake2s_compress(BLAKE2s_CTX* ctx, int last) {
		unsigned int m[16];
		for (int i = 0; i < 16; i++) {
			m[i] = (unsigned int)ctx->buf[i * 4] << 24 | (unsigned int)ctx->buf[i * 4 + 1] << 16 | (unsigned int)ctx->buf[i * 4 + 2] << 8 | (unsigned int)ctx->buf[i * 4 + 3];
		}
		unsigned int v[16];
		for (int i = 0; i < 8; i++) {
			v[i] = ctx->h[i];
			v[i + 8] = blake2s_iv[i];
		}
		v[12] ^= (unsigned int)ctx->t[0];
		v[13] ^= (unsigned int)(ctx->t[0] >> 32);
		v[14] ^= (unsigned int)ctx->t[1];
		v[15] ^= (unsigned int)(ctx->t[1] >> 32);
		if (last) {
			v[14] ^= 0xFFFFFFFF;
			v[15] ^= 0xFFFFFFFF;
		}
		for (int r = 0; r < 10; r++) {
			unsigned int a = v[0], b = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h_val = v[7];
#define BLAKE2S_G(i) a += b + m[blake2s_sigma[r][2 * i]]; h_val = blake2s_rotl32(h_val ^ a, 16);d += c; g = blake2s_rotl32(g ^ d, 12);a += h_val + m[blake2s_sigma[r][2 * i + 1]];e = blake2s_rotl32(e ^ a, 8);d += g; f = blake2s_rotl32(f ^ d, 7);

			for (int i = 0; i < 8; i++) {
				BLAKE2S_G(i);
			}
#undef BLAKE2S_G
			v[0] = a;
			v[1] = b;
			v[2] = c;
			v[3] = d;
			v[4] = e;
			v[5] = f;
			v[6] = g;
			v[7] = h_val;
		}
		for (int i = 0; i < 8; i++) {
			ctx->h[i] ^= v[i] ^ v[i + 8];
		}
	}
	void blake2s_init(BLAKE2s_CTX* ctx, size_t out_len) {
		ctx->out_len = out_len;
		memcpy(ctx->h, blake2s_iv, sizeof(ctx->h));
		ctx->h[0] ^= 0x01010000 ^ (unsigned int)out_len;
		ctx->t[0] = ctx->t[1] = 0;
		ctx->f[0] = ctx->f[1] = 0;
		ctx->buf_size = 0;
	}
	void blake2s_update(BLAKE2s_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk = BLAKE2S_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length)chunk = length;
			memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == BLAKE2S_BLOCK_SIZE) {
				ctx->t[0] += BLAKE2S_BLOCK_SIZE;
				if (ctx->t[0] < BLAKE2S_BLOCK_SIZE)ctx->t[1]++;
				blake2s_compress(ctx, 0);
				ctx->buf_size = 0;
			}
		}
	}
	void blake2s_final(BLAKE2s_CTX* ctx, unsigned char* hash) {
		ctx->t[0] += ctx->buf_size;
		if (ctx->t[0] < ctx->buf_size)ctx->t[1]++;
		ctx->f[0] = 1;
		blake2s_compress(ctx, 1);
		for (size_t i = 0; i < ctx->out_len; i++) {
			hash[i] = (unsigned char)(ctx->h[i / 4] >> (24 - (i % 4) * 8));
		}
	}
#define BLAKE3_BLOCK_SIZE 64
#define BLAKE3_HASH_SIZE 32
	typedef struct {
		unsigned int h[8];
		unsigned char buf[BLAKE3_BLOCK_SIZE];
		size_t buf_size;
		size_t out_len;
	} BLAKE3_CTX;
	static const unsigned int blake3_iv[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xFE94F82B, 0xA54FF53A, 0x510E527F, 0x1F83D9AB, 0x5BE0CD19};
	static const unsigned char blake3_sigma[7][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}, {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}, {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}, {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}};
	static void blake3_compress(unsigned int* h, const unsigned char* block, int last) {
		unsigned int m[16];
		for (int i = 0; i < 16; i++) {
			m[i] = (unsigned int)block[i * 4] << 24 | (unsigned int)block[i * 4 + 1] << 16 | (unsigned int)block[i * 4 + 2] << 8 | (unsigned int)block[i * 4 + 3];
		}
		unsigned int v[16];
		for (int i = 0; i < 8; i++) {
			v[i] = h[i];
			v[i + 8] = blake3_iv[i];
		}
		if (last) {
			v[14] ^= 0xFFFFFFFF;
			v[15] ^= 0xFFFFFFFF;
		}
		for (int r = 0; r < 7; r++) {
			unsigned int a = v[0], b = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h_val = v[7];
#define BLAKE3_G(i) a += b + m[blake3_sigma[r][2 * i]];h_val = blake2s_rotl32(h_val ^ a, 16);d += c;g = blake2s_rotl32(g ^ d, 12);a += h_val + m[blake3_sigma[r][2 * i + 1]];e = blake2s_rotl32(e ^ a, 8);d += g;f = blake2s_rotl32(f ^ d, 7);
			for (int i = 0; i < 8; i++) {



				BLAKE3_G(i);
			}
#undef BLAKE3_G
			v[0] = a;
			v[1] = b;
			v[2] = c;
			v[3] = d;
			v[4] = e;
			v[5] = f;
			v[6] = g;
			v[7] = h_val;
		}

		for (int i = 0; i < 8; i++) {
			h[i] ^= v[i] ^ v[i + 8];
		}
	}
	void blake3_init(BLAKE3_CTX* ctx, size_t out_len) {
		ctx->out_len = out_len;
		memcpy(ctx->h, blake3_iv, sizeof(ctx->h));
		ctx->buf_size = 0;
	}
	void blake3_update(BLAKE3_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk = BLAKE3_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length)chunk = length;
			memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == BLAKE3_BLOCK_SIZE) {
				blake3_compress(ctx->h, ctx->buf, 0);
				ctx->buf_size = 0;
			}
		}
	}
	void blake3_final(BLAKE3_CTX* ctx, unsigned char* hash) {
		if (ctx->buf_size > 0) {
			memset(ctx->buf + ctx->buf_size, 0, BLAKE3_BLOCK_SIZE - ctx->buf_size);
			blake3_compress(ctx->h, ctx->buf, 1);
		}
		for (size_t i = 0; i < ctx->out_len; i++) {
			hash[i] = (unsigned char)(ctx->h[i / 4] >> (24 - (i % 4) * 8));
		}
	}
#define SIPHASH_ROUNDS 2
#define SIPHASH_FINAL_ROUNDS 4
	typedef struct {
		unsigned long long int v0, v1, v2, v3;
	} SipHash_CTX;
	static inline unsigned long long int siphash_rotl(unsigned long long int x, int n) {
		return (x << n) | (x >> (64 - n));
	}
	static void siphash_round(SipHash_CTX* ctx) {
		ctx->v0 += ctx->v1;
		ctx->v1 = siphash_rotl(ctx->v1, 13);
		ctx->v1 ^= ctx->v0;
		ctx->v0 = siphash_rotl(ctx->v0, 32);
		ctx->v2 += ctx->v3;
		ctx->v3 = siphash_rotl(ctx->v3, 16);
		ctx->v3 ^= ctx->v2;
		ctx->v0 += ctx->v3;
		ctx->v3 = siphash_rotl(ctx->v3, 21);
		ctx->v3 ^= ctx->v0;
		ctx->v2 += ctx->v1;
		ctx->v1 = siphash_rotl(ctx->v1, 17);
		ctx->v1 ^= ctx->v2;
		ctx->v2 = siphash_rotl(ctx->v2, 32);
	}
	void siphash_init(SipHash_CTX* ctx, const unsigned char key[16]) {
		unsigned long long int k0 = (unsigned long long int)key[0] << 56 | (unsigned long long int)key[1] << 48 | (unsigned long long int)key[2] << 40 | (unsigned long long int)key[3] << 32 | (unsigned long long int)key[4] << 24 | (unsigned long long int)key[5] << 16 | (unsigned long long int)key[6] << 8 | (unsigned long long int)key[7];
		unsigned long long int k1 = (unsigned long long int)key[8] << 56 | (unsigned long long int)key[9] << 48 | (unsigned long long int)key[10] << 40 | (unsigned long long int)key[11] << 32 | (unsigned long long int)key[12] << 24 | (unsigned long long int)key[13] << 16 | (unsigned long long int)key[14] << 8 | (unsigned long long int)key[15];
		ctx->v0 = 0x736F6D6570736575 ^ k0;
		ctx->v1 = 0x646F72616E646F6D ^ k1;
		ctx->v2 = 0x6C7967656E657261 ^ k0;
		ctx->v3 = 0x7465646279746573 ^ k1;
	}
	void siphash_update(SipHash_CTX* ctx, const unsigned char* data, size_t length) {
		unsigned long long int m;
		size_t i = 0;
		for (; i + 8 <= length; i += 8) {
			m = (unsigned long long int)data[i] << 56 | (unsigned long long int)data[i + 1] << 48 | (unsigned long long int)data[i + 2] << 40 | (unsigned long long int)data[i + 3] << 32 | (unsigned long long int)data[i + 4] << 24 | (unsigned long long int)data[i + 5] << 16 | (unsigned long long int)data[i + 6] << 8 | (unsigned long long int)data[i + 7];
			ctx->v3 ^= m;
			for (int r = 0; r < SIPHASH_ROUNDS; r++)siphash_round(ctx);
			ctx->v0 ^= m;
		}
		m = (unsigned long long int)(length & 0xFF) << 56;
		for (; i < length; i++) {
			m |= (unsigned long long int)data[i] << (56 - 8 * (i % 8));
		}
		ctx->v3 ^= m;
		for (int r = 0; r < SIPHASH_ROUNDS; r++)siphash_round(ctx);
		ctx->v0 ^= m;
	}
	unsigned long long int siphash_final(SipHash_CTX* ctx) {
		ctx->v2 ^= 0xFF;
		for (int r = 0; r < SIPHASH_FINAL_ROUNDS; r++)siphash_round(ctx);
		return ctx->v0 ^ ctx->v1 ^ ctx->v2 ^ ctx->v3;
	}
#undef SIPHASH_ROUNDS
#undef SIPHASH_FINAL_ROUNDS
#define SIPHASH_ROUNDS 4
#define SIPHASH_FINAL_ROUNDS 8
	unsigned long long int siphash48(const unsigned char* data, size_t length, const unsigned char key[16]) {
		SipHash_CTX ctx;
		siphash_init(&ctx, key);
		siphash_update(&ctx, data, length);
		return siphash_final(&ctx);
	}
#undef SIPHASH_ROUNDS
#undef SIPHASH_FINAL_ROUNDS
#define SIPHASH_ROUNDS 2
#define SIPHASH_FINAL_ROUNDS 4
	unsigned long long int siphash24(const unsigned char* data, size_t length, const unsigned char key[16]) {
		SipHash_CTX ctx;
		siphash_init(&ctx, key);
		siphash_update(&ctx, data, length);
		return siphash_final(&ctx);
	}

#define KECCAK_BLOCK_SIZE 136
#define KECCAK_HASH_SIZE 32
	typedef struct {
		unsigned long long int state[25];
		unsigned char buf[KECCAK_BLOCK_SIZE];
		size_t buf_size;
		size_t out_len;
	} Keccak_CTX;
	static inline unsigned long long int keccak_rotl(unsigned long long int x, int n) {
		return (x << n) | (x >> (64 - n));
	}
	static void keccak_theta(unsigned long long int* state) {
		unsigned long long int c[5], d[5];
		for (int i = 0; i < 5; i++) {
			c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
		}
		for (int i = 0; i < 5; i++) {
			d[i] = c[(i + 4) % 5] ^ keccak_rotl(c[(i + 1) % 5], 1);
		}
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 5; j++) {
				state[i + j * 5] ^= d[i];
			}
		}
	}
	static void keccak_rho(unsigned long long int* state) {
		int r[] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
		for (int i = 0; i < 25; i++) {
			if (i != 0) {
				state[i] = keccak_rotl(state[i], r[i]);
			}
		}
	}
	static void keccak_pi(unsigned long long int* state) {
		unsigned long long int temp[25];
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 5; j++) {
				temp[j + (3 * i + j) % 5 * 5] = state[i + j * 5];
			}
		}
		memcpy(state, temp, sizeof(temp));
	}
	static void keccak_chi(unsigned long long int* state) {
		for (int j = 0; j < 5; j++) {
			unsigned long long int c[5];
			for (int i = 0; i < 5; i++) {
				c[i] = state[i + j * 5];
			}
			for (int i = 0; i < 5; i++) {
				state[i + j * 5] = c[i] ^ ((~c[(i + 1) % 5])&c[(i + 2) % 5]);
			}
		}
	}
	static void keccak_iota(unsigned long long int* state, int round) {
		unsigned long long int rc = 1;
		for (int i = 0; i < 7; i++) {
			int bit = (round >> i) & 1;
			if (bit) {
				state[0] ^= rc;
			}
			rc = keccak_rotl(rc, 1);
		}
	}
	static void keccak_permute(unsigned long long int* state) {
		for (int round = 0; round < 24; round++) {
			keccak_theta(state);
			keccak_rho(state);
			keccak_pi(state);
			keccak_chi(state);
			keccak_iota(state, round);
		}
	}
	void keccak_init(Keccak_CTX* ctx, size_t out_len) {
		ctx->out_len = out_len;
		adler32_memzero(ctx->state, sizeof(ctx->state));
		ctx->buf_size = 0;
	}
	void keccak_update(Keccak_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk = KECCAK_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length)chunk = length;
			memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == KECCAK_BLOCK_SIZE) {
				for (int i = 0; i < KECCAK_BLOCK_SIZE / 8; i++) {
					ctx->state[i] ^= (unsigned long long int)ctx->buf[i * 8] << 56 | (unsigned long long int)ctx->buf[i * 8 + 1] << 48 | (unsigned long long int)ctx->buf[i * 8 + 2] << 40 | (unsigned long long int)ctx->buf[i * 8 + 3] << 32 | (unsigned long long int)ctx->buf[i * 8 + 4] << 24 | (unsigned long long int)ctx->buf[i * 8 + 5] << 16 | (unsigned long long int)ctx->buf[i * 8 + 6] << 8 | (unsigned long long int)ctx->buf[i * 8 + 7];
				}
				keccak_permute(ctx->state);
				ctx->buf_size = 0;
			}
		}
	}
	void keccak_final(Keccak_CTX* ctx, unsigned char* hash) {
		ctx->buf[ctx->buf_size++] = 0x01;
		memset(ctx->buf + ctx->buf_size, 0, KECCAK_BLOCK_SIZE - ctx->buf_size);
		ctx->buf[KECCAK_BLOCK_SIZE - 1] |= 0x80;
		for (int i = 0; i < KECCAK_BLOCK_SIZE / 8; i++) {
			ctx->state[i] ^= (unsigned long long int)ctx->buf[i * 8] << 56 | (unsigned long long int)ctx->buf[i * 8 + 1] << 48 | (unsigned long long int)ctx->buf[i * 8 + 2] << 40 | (unsigned long long int)ctx->buf[i * 8 + 3] << 32 | (unsigned long long int)ctx->buf[i * 8 + 4] << 24 | (unsigned long long int)ctx->buf[i * 8 + 5] << 16 | (unsigned long long int)ctx->buf[i * 8 + 6] << 8 | (unsigned long long int)ctx->buf[i * 8 + 7];
		}
		keccak_permute(ctx->state);
		for (size_t i = 0; i < ctx->out_len; i++) {
			hash[i] = (unsigned char)(ctx->state[i / 8] >> (56 - (i % 8) * 8));
		}
	}

#define HAVAL_BLOCK_SIZE 64
#define HAVAL_HASH_SIZE 32
	typedef struct {
		unsigned int h[8];
		unsigned long long int len;
		unsigned char buf[HAVAL_BLOCK_SIZE];
		size_t buf_size;
		int rounds;
		size_t out_len;
	} HAVAL_CTX;
	static const unsigned int haval_iv[8] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0x76543210, 0xFEDCBA98, 0x89ABCDEF};
	static const int haval_s[4][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16}, {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12}, {0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9}};
	static inline unsigned int haval_f1(unsigned int x, unsigned int y, unsigned int z) {
		return (x & y) | (~x & z);
	}
	static inline unsigned int haval_f2(unsigned int x, unsigned int y, unsigned int z) {
		return (x & y) | (x & z) | (y & z);
	}
	static inline unsigned int haval_f3(unsigned int x, unsigned int y, unsigned int z) {
		return x ^ y ^ z;
	}
	static void haval_compress(HAVAL_CTX* ctx) {
		unsigned int w[16];
		for (int i = 0; i < 16; i++) {
			w[i] = (unsigned int)ctx->buf[i * 4] << 24 | (unsigned int)ctx->buf[i * 4 + 1] << 16 | (unsigned int)ctx->buf[i * 4 + 2] << 8 | (unsigned int)ctx->buf[i * 4 + 3];
		}
		unsigned int a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h_val = ctx->h[7];
		for (int round = 0; round < ctx->rounds; round++) {
			int s = round % 4;
			for (int i = 0; i < 16; i++) {
				unsigned int t;
				if (round < 3) {
					t = blake2s_rotl32(a + haval_f1(b, c, d) + w[haval_s[s][i]] + 0x5A827999, 7);
				} else if (round < 5) {
					t = blake2s_rotl32(a + haval_f2(b, c, d) + w[haval_s[s][i]] + 0x6ED9EBA1, 12);
				} else {
					t = blake2s_rotl32(a + haval_f3(b, c, d) + w[haval_s[s][i]] + 0x8F1BBCDC, 17);
				}
				h_val = g;
				g = f;
				f = e;
				e = d;
				d = c;
				c = blake2s_rotl32(b, 11);
				b = a;
				a = t;
			}
		}
		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
		ctx->h[4] += e;
		ctx->h[5] += f;
		ctx->h[6] += g;
		ctx->h[7] += h_val;
	}
	void haval_init(HAVAL_CTX* ctx, int rounds, size_t out_len) {
		ctx->rounds = rounds;
		ctx->out_len = out_len;
		memcpy(ctx->h, haval_iv, sizeof(ctx->h));
		ctx->len = 0;
		ctx->buf_size = 0;
	}
	void haval_update(HAVAL_CTX* ctx, const unsigned char* data, size_t length) {
		ctx->len += length * 8;
		while (length > 0) {
			size_t chunk = HAVAL_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length)chunk = length;
			memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == HAVAL_BLOCK_SIZE) {
				haval_compress(ctx);
				ctx->buf_size = 0;
			}
		}
	}
	void haval_final(HAVAL_CTX* ctx, unsigned char* hash) {
		ctx->buf[ctx->buf_size++] = 0x80;
		if (ctx->buf_size > 56) {
			memset(ctx->buf + ctx->buf_size, 0, HAVAL_BLOCK_SIZE - ctx->buf_size);
			haval_compress(ctx);
			ctx->buf_size = 0;
		}
		memset(ctx->buf + ctx->buf_size, 0, 56 - ctx->buf_size);
		for (int i = 0; i < 8; i++) {
			ctx->buf[56 + i] = (unsigned char)(ctx->len >> (56 - i * 8));
		}
		haval_compress(ctx);
		int order[8] = {0, 1, 2, 3, 4, 5, 6, 7};
		if (ctx->out_len == 16)order[4] = 5;
		for (size_t i = 0; i < ctx->out_len; i++) {
			hash[i] = (unsigned char)(ctx->h[order[i / 4]] >> (24 - (i % 4) * 8));
		}
	}

#define MD6_BLOCK_SIZE 64
#define MD6_HASH_SIZE 64
	typedef struct {
		unsigned long long int h[8];
		unsigned long long int len;
		unsigned char buf[MD6_BLOCK_SIZE];
		size_t buf_size;
		size_t out_len;
		unsigned int key[8];
	} MD6_CTX;
	static const unsigned long long int md6_iv[8] = {0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179};
	static void md6_compress(MD6_CTX* ctx) {
		unsigned long long int m[8];
		for (int i = 0; i < 8; i++) {
			m[i] = (unsigned long long int)ctx->buf[i * 8] << 56 | (unsigned long long int)ctx->buf[i * 8 + 1] << 48 | (unsigned long long int)ctx->buf[i * 8 + 2] << 40 | (unsigned long long int)ctx->buf[i * 8 + 3] << 32 | (unsigned long long int)ctx->buf[i * 8 + 4] << 24 | (unsigned long long int)ctx->buf[i * 8 + 5] << 16 | (unsigned long long int)ctx->buf[i * 8 + 6] << 8 | (unsigned long long int)ctx->buf[i * 8 + 7];
		}
		unsigned long long int a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h_val = ctx->h[7];
		for (int i = 0; i < 64; i++) {
			unsigned long long int t = a + e + (blake2b_rotl64(c, 42)^blake2b_rotl64(g, 30)) + m[i % 8] + ctx->key[i % 8];
			a = h_val;
			h_val = g;
			g = f;
			f = e;
			e = d;
			d = c;
			c = b;
			b = t;
		}
		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
		ctx->h[4] += e;
		ctx->h[5] += f;
		ctx->h[6] += g;
		ctx->h[7] += h_val;
	}
	void md6_init(MD6_CTX* ctx, size_t out_len, const unsigned int key[8]) {
		ctx->out_len = out_len;
		memcpy(ctx->h, md6_iv, sizeof(ctx->h));
		memcpy(ctx->key, key, sizeof(ctx->key));
		ctx->len = 0;
		ctx->buf_size = 0;
	}
	void md6_update(MD6_CTX* ctx, const unsigned char* data, size_t length) {
		ctx->len += length * 8;
		while (length > 0) {
			size_t chunk = MD6_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length)chunk = length;
			memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == MD6_BLOCK_SIZE) {
				md6_compress(ctx);
				ctx->buf_size = 0;
			}
		}
	}
	void md6_final(MD6_CTX* ctx, unsigned char* hash) {
		ctx->buf[ctx->buf_size++] = 0x80;
		if (ctx->buf_size > 56) {
			memset(ctx->buf + ctx->buf_size, 0, MD6_BLOCK_SIZE - ctx->buf_size);
			md6_compress(ctx);
			ctx->buf_size = 0;
		}
		memset(ctx->buf + ctx->buf_size, 0, 56 - ctx->buf_size);
		for (int i = 0; i < 8; i++) {
			ctx->buf[56 + i] = (unsigned char)(ctx->len >> (56 - i * 8));
		}
		md6_compress(ctx);
		for (size_t i = 0; i < ctx->out_len; i++) {
			hash[i] = (unsigned char)(ctx->h[i / 8] >> (56 - (i % 8) * 8));
		}
	}
	static inline void my_memcpy(void* dest, const void* src, size_t n) {
		unsigned char* d = (unsigned char*)dest;
		const unsigned char* s = (const unsigned char*)src;
		while (n--) *d++ = *s++;
	}
	static inline void my_memset(void* dest, int val, size_t n) {
		unsigned char* d = (unsigned char*)dest;
		while (n--) *d++ = (unsigned char)val;
	}
#define MD2_BLOCK_SIZE 16
#define MD2_HASH_SIZE 16
	typedef struct {
		unsigned char state[16];
		unsigned char checksum[16];
		unsigned char buffer[16];
		size_t buffer_size;
	} MD2_CTX;
	static const unsigned char md2_sbox[256] = {
		0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x6E, 0xE5,
		0x92, 0x66, 0x70, 0x48, 0x50, 0xF3, 0x39, 0xE1, 0x79, 0xA8, 0x78, 0x83, 0x06, 0x9B, 0x87, 0x6B,
		0xB7, 0x0D, 0x8E, 0xFA, 0x93, 0x26, 0x35, 0x3F, 0xF7, 0xCC, 0x34, 0xA4, 0x61, 0x28, 0x96, 0x84,
		0xB0, 0x4F, 0xC4, 0x2D, 0x07, 0xF8, 0x45, 0x97, 0x3C, 0xD9, 0xCE, 0xE4, 0xBF, 0x8A, 0xD2, 0x4B,
		0x8C, 0xD1, 0xBB, 0xAF, 0x0B, 0x86, 0xC8, 0xAC, 0xDF, 0x02, 0xA5, 0x15, 0x9F, 0x53, 0xFF, 0x04,
		0x7D, 0xB5, 0x64, 0x5C, 0x75, 0x18, 0x98, 0x91, 0x1B, 0xEE, 0xB4, 0x1A, 0xEA, 0xD4, 0x9D, 0x8B,
		0x38, 0xF5, 0x37, 0x88, 0x80, 0x6A, 0x42, 0x44, 0xC7, 0x9E, 0xEA, 0xBF, 0x0E, 0x4E, 0x32, 0x2A,
		0xC0, 0x59, 0x03, 0x40, 0x31, 0x85, 0x46, 0x9A, 0x09, 0x77, 0xFC, 0xF2, 0x73, 0x60, 0x89, 0xAD,
		0x63, 0xC6, 0xB3, 0xDB, 0x58, 0xF4, 0x56, 0x94, 0x65, 0x71, 0x82, 0x5B, 0x6F, 0x47, 0xC2, 0xD7,
		0x08, 0xEB, 0x62, 0xE7, 0x67, 0x1F, 0x3B, 0x0C, 0xBA, 0x95, 0x57, 0x05, 0x24, 0x7E, 0x2F, 0x8D,
		0x69, 0x99, 0x1D, 0xFE, 0xE2, 0x0F, 0xB2, 0xC3, 0x8F, 0xB1, 0xE9, 0x72, 0xFE, 0x3E, 0x6D, 0x86,
		0xA7, 0x22, 0xD0, 0xBC, 0xD5, 0xE8, 0x33, 0xFF, 0xA3, 0x5F, 0xD6, 0x90, 0xC5, 0x68, 0x21, 0x49,
		0x6C, 0x0A, 0x17, 0x81, 0x41, 0x4C, 0x52, 0xDD, 0x14, 0xF9, 0x30, 0xB9, 0x8F, 0x9C, 0x27, 0x5A,
		0xE0, 0x85, 0x74, 0xEB, 0x2C, 0x32, 0xDD, 0x51, 0xAF, 0x3A, 0xC1, 0x69, 0xF1, 0x25, 0x7B, 0x86,
		0xC0, 0xA6, 0xB8, 0x23, 0x1C, 0xD3, 0x00, 0xF6, 0x20, 0xAA, 0x19, 0x4D, 0x4B, 0x10, 0x87, 0x13,
		0x40, 0x45, 0x34, 0x91, 0xEA, 0xCF, 0x29, 0x7F, 0xA0, 0xE6, 0x5D, 0xA9, 0x11, 0x88, 0x48, 0x14
	};
	static void md2_update_checksum(MD2_CTX* ctx, const unsigned char* block) {
		unsigned char c = ctx->checksum[15];
		for (int i = 0; i < 16; i++) {
			c = ctx->checksum[i] ^= md2_sbox[block[i] ^ c];
		}
	}
	static void md2_transform(MD2_CTX* ctx) {
		unsigned char x[48];
		my_memcpy(x, ctx->state, 16);
		my_memcpy(x + 16, ctx->buffer, 16);
		for (int i = 0; i < 16; i++) {
			x[32 + i] = x[i] ^ x[16 + i];
		}
		unsigned char t = 0;
		for (int i = 0; i < 18; i++) {
			for (int j = 0; j < 48; j++) {
				x[j] ^= md2_sbox[t];
				t = x[j];
			}
			t = (t + i) & 0xFF;
		}
		my_memcpy(ctx->state, x, 16);
	}
	void md2_init(MD2_CTX* ctx) {
		my_memset(ctx, 0, sizeof(MD2_CTX));
	}
	void md2_update(MD2_CTX* ctx, const unsigned char* data, size_t length) {
		while (length > 0) {
			size_t chunk = MD2_BLOCK_SIZE - ctx->buffer_size;
			if (chunk > length) chunk = length;
			my_memcpy(ctx->buffer + ctx->buffer_size, data, chunk);
			ctx->buffer_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buffer_size == MD2_BLOCK_SIZE) {
				md2_transform(ctx);
				md2_update_checksum(ctx, ctx->buffer);
				ctx->buffer_size = 0;
			}
		}
	}
	void md2_final(MD2_CTX* ctx, unsigned char* hash) {
		size_t pad = MD2_BLOCK_SIZE - ctx->buffer_size;
		my_memset(ctx->buffer + ctx->buffer_size, 0, pad);
		md2_transform(ctx);
		md2_update_checksum(ctx, ctx->buffer);
		my_memcpy(ctx->buffer, ctx->checksum, 16);
		md2_transform(ctx);
		my_memcpy(hash, ctx->state, MD2_HASH_SIZE);
	}
#define MD4_BLOCK_SIZE 64
#define MD4_HASH_SIZE 16
	typedef struct {
		unsigned int h[4];
		unsigned long long int len;
		unsigned char buf[64];
		size_t buf_size;
	} MD4_CTX;
	static inline unsigned int md4_f(unsigned int x, unsigned int y, unsigned int z) {
		return (x & y) | (~x & z);
	}
	static inline unsigned int md4_g(unsigned int x, unsigned int y, unsigned int z) {
		return (x & y) | (x & z) | (y & z);
	}
	static inline unsigned int md4_h(unsigned int x, unsigned int y, unsigned int z) {
		return x ^ y ^ z;
	}
	static inline unsigned int md4_rotl(unsigned int x, int n) {
		return (x << n) | (x >> (32 - n));
	}
	static const unsigned int md4_k[3][4] = {
		{0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC},
		{0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6},
		{0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6, 0x00000000}
	};
	static void md4_transform(MD4_CTX* ctx, const unsigned char* block) {
		unsigned int w[16], a, b, c, d;
		for (int i = 0; i < 16; i++) {
			w[i] = (unsigned int)block[i * 4] << 24 | (unsigned int)block[i * 4 + 1] << 16 |
			       (unsigned int)block[i * 4 + 2] << 8 | (unsigned int)block[i * 4 + 3];
		}
		a = ctx->h[0];
		b = ctx->h[1];
		c = ctx->h[2];
		d = ctx->h[3];
		for (int i = 0; i < 4; i++) {
			a = md4_rotl(a + md4_f(b, c, d) + w[i] + md4_k[0][i], 3);
			d = md4_rotl(d + md4_f(a, b, c) + w[i + 4] + md4_k[0][i], 7);
			c = md4_rotl(c + md4_f(d, a, b) + w[i + 8] + md4_k[0][i], 11);
			b = md4_rotl(b + md4_f(c, d, a) + w[i + 12] + md4_k[0][i], 19);
		}
		for (int i = 0; i < 4; i++) {
			a = md4_rotl(a + md4_g(b, c, d) + w[i] + md4_k[1][i], 3);
			d = md4_rotl(d + md4_g(a, b, c) + w[i + 4] + md4_k[1][i], 5);
			c = md4_rotl(c + md4_g(d, a, b) + w[i + 8] + md4_k[1][i], 9);
			b = md4_rotl(b + md4_g(c, d, a) + w[i + 12] + md4_k[1][i], 13);
		}
		for (int i = 0; i < 4; i++) {
			a = md4_rotl(a + md4_h(b, c, d) + w[i] + md4_k[2][i], 3);
			d = md4_rotl(d + md4_h(a, b, c) + w[i + 4] + md4_k[2][i], 9);
			c = md4_rotl(c + md4_h(d, a, b) + w[i + 8] + md4_k[2][i], 11);
			b = md4_rotl(b + md4_h(c, d, a) + w[i + 12] + md4_k[2][i], 15);
		}
		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
	}
	void md4_init(MD4_CTX* ctx) {
		ctx->h[0] = 0x67452301;
		ctx->h[1] = 0xEFCDAB89;
		ctx->h[2] = 0x98BADCFE;
		ctx->h[3] = 0x10325476;
		ctx->len = 0;
		ctx->buf_size = 0;
	}
	void md4_update(MD4_CTX* ctx, const unsigned char* data, size_t length) {
		ctx->len += (unsigned long long int)length * 8;
		while (length > 0) {
			size_t chunk = MD4_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length) chunk = length;
			my_memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == MD4_BLOCK_SIZE) {
				md4_transform(ctx, ctx->buf);
				ctx->buf_size = 0;
			}
		}
	}
	void md4_final(MD4_CTX* ctx, unsigned char* hash) {
		ctx->buf[ctx->buf_size++] = 0x80;
		if (ctx->buf_size > 56) {
			my_memset(ctx->buf + ctx->buf_size, 0, MD4_BLOCK_SIZE - ctx->buf_size);
			md4_transform(ctx, ctx->buf);
			ctx->buf_size = 0;
		}
		my_memset(ctx->buf + ctx->buf_size, 0, 56 - ctx->buf_size);
		for (int i = 0; i < 8; i++) {
			ctx->buf[56 + i] = (unsigned char)(ctx->len >> (56 - i * 8));
		}
		md4_transform(ctx, ctx->buf);
		for (int i = 0; i < 4; i++) {
			hash[i * 4] = (unsigned char)(ctx->h[i] >> 24);
			hash[i * 4 + 1] = (unsigned char)(ctx->h[i] >> 16);
			hash[i * 4 + 2] = (unsigned char)(ctx->h[i] >> 8);
			hash[i * 4 + 3] = (unsigned char)ctx->h[i];
		}
	}
#define MD5_BLOCK_SIZE 64
#define MD5_HASH_SIZE 16
	typedef struct {
		unsigned int h[4];
		unsigned long long int len;
		unsigned char buf[64];
		size_t buf_size;
	} MD5_CTX;
	static inline unsigned int md5_f(unsigned int x, unsigned int y, unsigned int z) {
		return (x & y) | (~x & z);
	}
	static inline unsigned int md5_g(unsigned int x, unsigned int y, unsigned int z) {
		return (x & z) | (y & ~z);
	}
	static inline unsigned int md5_h(unsigned int x, unsigned int y, unsigned int z) {
		return x ^ y ^ z;
	}
	static inline unsigned int md5_i(unsigned int x, unsigned int y, unsigned int z) {
		return y ^ (x | ~z);
	}
	static inline unsigned int md5_rotl(unsigned int x, int n) {
		return (x << n) | (x >> (32 - n));
	}
	static const unsigned int md5_k[80] = {
		0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
		0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
		0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
		0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
		0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
		0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
		0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};
	static const int md5_r[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};
	static void md5_transform(MD5_CTX* ctx, const unsigned char* block) {
		unsigned int w[16], a, b, c, d, temp;
		for (int i = 0; i < 16; i++) {
			w[i] = (unsigned int)block[i * 4] << 24 | (unsigned int)block[i * 4 + 1] << 16 | (unsigned int)block[i * 4 + 2] << 8 | (unsigned int)block[i * 4 + 3];
		}
		a = ctx->h[0];
		b = ctx->h[1];
		c = ctx->h[2];
		d = ctx->h[3];
		for (int i = 0; i < 64; i++) {
			if (i < 16) {
				temp = md5_f(b, c, d) + a + md5_k[i] + w[i];
			} else if (i < 32) {
				temp = md5_g(b, c, d) + a + md5_k[i] + w[(5 * i + 1) % 16];
			} else if (i < 48) {
				temp = md5_h(b, c, d) + a + md5_k[i] + w[(3 * i + 5) % 16];
			} else {
				temp = md5_i(b, c, d) + a + md5_k[i] + w[(7 * i) % 16];
			}
			a = d;
			d = c;
			c = b;
			b += md5_rotl(temp, md5_r[i]);
		}
		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
	}
	void md5_init(MD5_CTX* ctx) {
		ctx->h[0] = 0x67452301;
		ctx->h[1] = 0xEFCDAB89;
		ctx->h[2] = 0x98BADCFE;
		ctx->h[3] = 0x10325476;
		ctx->len = 0;
		ctx->buf_size = 0;
	}
	void md5_update(MD5_CTX* ctx, const unsigned char* data, size_t length) {
		ctx->len += (unsigned long long int)length * 8;
		while (length > 0) {
			size_t chunk = MD5_BLOCK_SIZE - ctx->buf_size;
			if (chunk > length) chunk = length;
			my_memcpy(ctx->buf + ctx->buf_size, data, chunk);
			ctx->buf_size += chunk;
			data += chunk;
			length -= chunk;
			if (ctx->buf_size == MD5_BLOCK_SIZE) {
				md5_transform(ctx, ctx->buf);
				ctx->buf_size = 0;
			}
		}
	}
	void md5_final(MD5_CTX* ctx, unsigned char* hash) {
		ctx->buf[ctx->buf_size++] = 0x80;
		if (ctx->buf_size > 56) {
			my_memset(ctx->buf + ctx->buf_size, 0, MD5_BLOCK_SIZE - ctx->buf_size);
			md5_transform(ctx, ctx->buf);
			ctx->buf_size = 0;
		}
		my_memset(ctx->buf + ctx->buf_size, 0, 56 - ctx->buf_size);
		for (int i = 0; i < 8; i++) {
			ctx->buf[56 + i] = (unsigned char)(ctx->len >> (56 - i * 8));
		}
		md5_transform(ctx, ctx->buf);
		for (int i = 0; i < 4; i++) {
			hash[i * 4] = (unsigned char)(ctx->h[i] >> 24);
			hash[i * 4 + 1] = (unsigned char)(ctx->h[i] >> 16);
			hash[i * 4 + 2] = (unsigned char)(ctx->h[i] >> 8);
			hash[i * 4 + 3] = (unsigned char)ctx->h[i];
		}
	}
	const int HILL_CIPHER_M = 26;
	const int HILL_CIPHER_MATRIX_SIZE = 5;
	int hill_cipher_key_matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE];
	int hill_cipher_inv_key_matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE];
	struct hill_cipher_GCDResult {
		int x;
		int y;
		int gcd;
	};
	void hill_cipher_generateRandomKey();
	int hill_cipher_calculateDeterminant(int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE], int size);
	int hill_cipher_gcd(int a, int b);
	bool hill_cipher_isMatrixInvertible(int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE]);
	int* hill_cipher_matrixMultiply(int cipher_group[], int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE], int input[HILL_CIPHER_MATRIX_SIZE]);
	void hill_cipher_calculateAdjointMatrix(int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE], int size);
	hill_cipher_GCDResult hill_cipher_extendedEuclidean(int a, int b);
	int hill_cipher_modInverse(int a, int m);
	int hill_cipher_mod(int a);
	std::string hill_cipher_encrypt(std::string plaintext);
	std::string hill_cipher_decrypt(std::string ciphertext);
	void hill_cipher_generateRandomKey() {
		srand((unsigned)time(0));
		bool is_invertible = false;
		while (!is_invertible) {
			for (int i = 0; i < HILL_CIPHER_MATRIX_SIZE; i++) {
				for (int j = 0; j < HILL_CIPHER_MATRIX_SIZE; j++) {
					hill_cipher_key_matrix[i][j] = rand() % HILL_CIPHER_M;
				}
			}
			is_invertible = hill_cipher_isMatrixInvertible(hill_cipher_key_matrix);
		}
		int det = hill_cipher_calculateDeterminant(hill_cipher_key_matrix, HILL_CIPHER_MATRIX_SIZE);
		int det_inv = hill_cipher_modInverse(det, HILL_CIPHER_M);
		hill_cipher_calculateAdjointMatrix(hill_cipher_key_matrix, HILL_CIPHER_MATRIX_SIZE);
		for (int i = 0; i < HILL_CIPHER_MATRIX_SIZE; i++) {
			for (int j = 0; j < HILL_CIPHER_MATRIX_SIZE; j++) {
				hill_cipher_inv_key_matrix[i][j] = hill_cipher_mod(hill_cipher_inv_key_matrix[i][j] * det_inv);
			}
		}
	}
	int hill_cipher_calculateDeterminant(int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE], int size) {
		if (size == 1) {
			return matrix[0][0];
		}
		int det = 0;
		int minor[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE];
		int sign = 1;
		for (int col = 0; col < size; col++) {
			int minor_row = 0;
			for (int i = 1; i < size; i++) {
				int minor_col = 0;
				for (int j = 0; j < size; j++) {
					if (j != col) {
						minor[minor_row][minor_col++] = matrix[i][j];
					}
				}
				minor_row++;
			}
			det += sign * matrix[0][col] * hill_cipher_calculateDeterminant(minor, size - 1);
			sign *= -1;
		}
		return det;
	}
	int hill_cipher_gcd(int a, int b) {
		while (b != 0) {
			int temp = b;
			b = a % b;
			a = temp;
		}
		return a;
	}
	bool hill_cipher_isMatrixInvertible(int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE]) {
		int det = hill_cipher_calculateDeterminant(matrix, HILL_CIPHER_MATRIX_SIZE);
		det = hill_cipher_mod(det);
		return hill_cipher_gcd(det, HILL_CIPHER_M) == 1;
	}
	int* hill_cipher_matrixMultiply(int cipher_group[], int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE], int input[HILL_CIPHER_MATRIX_SIZE]) {
		memset(cipher_group, 0, HILL_CIPHER_MATRIX_SIZE * sizeof(int));
		for (int i = 0; i < HILL_CIPHER_MATRIX_SIZE; i++) {
			for (int j = 0; j < HILL_CIPHER_MATRIX_SIZE; j++) {
				cipher_group[i] += input[j] * matrix[i][j];
			}
			cipher_group[i] = hill_cipher_mod(cipher_group[i]);
		}
		return cipher_group;
	}
	void hill_cipher_calculateAdjointMatrix(int matrix[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE], int size) {
		if (size != HILL_CIPHER_MATRIX_SIZE) return;
		int minor[HILL_CIPHER_MATRIX_SIZE][HILL_CIPHER_MATRIX_SIZE];
		for (int i = 0; i < size; i++) {
			for (int j = 0; j < size; j++) {
				int minor_row = 0;
				for (int x = 0; x < size; x++) {
					if (x == i) continue;
					int minor_col = 0;
					for (int y = 0; y < size; y++) {
						if (y == j) continue;
						minor[minor_row][minor_col++] = matrix[x][y];
					}
					minor_row++;
				}
				int cofactor = pow(-1, i + j) * hill_cipher_calculateDeterminant(minor, size - 1);
				hill_cipher_inv_key_matrix[j][i] = hill_cipher_mod(cofactor);
			}
		}
	}
	hill_cipher_GCDResult hill_cipher_extendedEuclidean(int a, int b) {
		hill_cipher_GCDResult res;
		if (b == 0) {
			res.x = 1;
			res.y = 0;
			res.gcd = a;
			return res;
		}
		hill_cipher_GCDResult sub_res = hill_cipher_extendedEuclidean(b, a % b);
		res.x = sub_res.y;
		res.y = sub_res.x - (a / b) * sub_res.y;
		res.gcd = sub_res.gcd;
		return res;
	}
	int hill_cipher_modInverse(int a, int m) {
		hill_cipher_GCDResult res = hill_cipher_extendedEuclidean(a, m);
		if (res.gcd != 1) {
			return -1;
		}
		return hill_cipher_mod(res.x);
	}
	int hill_cipher_mod(int a) {
		return a >= 0 ? a % HILL_CIPHER_M : (HILL_CIPHER_M + (a % HILL_CIPHER_M)) % HILL_CIPHER_M;
	}
	std::string hill_cipher_encrypt(std::string plaintext) {
		std::string ciphertext;
		std::string filtered_plain;
		for (char c : plaintext) {
			if (isalpha(c)) {
				filtered_plain += tolower(c);
			}
		}
		int pad_len = (HILL_CIPHER_MATRIX_SIZE - (filtered_plain.size() % HILL_CIPHER_MATRIX_SIZE)) % HILL_CIPHER_MATRIX_SIZE;
		for (int i = 0; i < pad_len; i++) {
			filtered_plain += 'x';
		}
		int plain_group[HILL_CIPHER_MATRIX_SIZE];
		int cipher_group[HILL_CIPHER_MATRIX_SIZE];
		for (size_t i = 0; i < filtered_plain.size(); i += HILL_CIPHER_MATRIX_SIZE) {
			for (int j = 0; j < HILL_CIPHER_MATRIX_SIZE; j++) {
				plain_group[j] = filtered_plain[i + j] - 'a';
			}
			hill_cipher_matrixMultiply(cipher_group, hill_cipher_key_matrix, plain_group);
			for (int j = 0; j < HILL_CIPHER_MATRIX_SIZE; j++) {
				ciphertext += cipher_group[j] + 'A';
			}
		}
		return ciphertext;
	}
	std::string hill_cipher_decrypt(std::string ciphertext) {
		std::string plaintext;
		std::string filtered_cipher;
		for (char c : ciphertext) {
			if (isalpha(c)) {
				filtered_cipher += toupper(c);
			}
		}
		if (filtered_cipher.size() % HILL_CIPHER_MATRIX_SIZE != 0) {
			return "";
		}
		int cipher_group[HILL_CIPHER_MATRIX_SIZE];
		int plain_group[HILL_CIPHER_MATRIX_SIZE];
		for (size_t i = 0; i < filtered_cipher.size(); i += HILL_CIPHER_MATRIX_SIZE) {
			for (int j = 0; j < HILL_CIPHER_MATRIX_SIZE; j++) {
				cipher_group[j] = filtered_cipher[i + j] - 'A';
			}
			hill_cipher_matrixMultiply(plain_group, hill_cipher_inv_key_matrix, cipher_group);
			for (int j = 0; j < HILL_CIPHER_MATRIX_SIZE; j++) {
				plaintext += plain_group[j] + 'a';
			}
		}

		return plaintext;
	}
#	define IDEA_BLOCK_SIZE 8
#	define IDEA_KEY_SIZE 16
#	define IDEA_ROUNDS 8
#	define IDEA_SUBKEYS 52
	static unsigned short idea_mul_mod(unsigned short a, unsigned short b) {
		unsigned int product = (unsigned int)a * b;
		if (product == 0) {
			return (unsigned short)(0x10000);
		}
		unsigned short mod = (unsigned short)(product % 0x10001);
		return mod ? mod : 0x10000;
	}
	static unsigned short idea_inv_mul(unsigned short x) {
		if (x == 0) return 0;
		int a = 0x10001, b = x;
		int t0 = 0, t1 = 1;
		while (b != 0) {
			int q = a / b;
			std::swap(a, b);
			b %= a;
			std::swap(t0, t1);
			t1 = t0 - q * t1;
		}
		t0 %= 0x10001;
		return (t0 < 0) ? t0 + 0x10001 : (unsigned short)t0;
	}
	static unsigned short idea_inv_add(unsigned short x) {
		return (0x10000 - x) % 0x10000;
	}
	static void idea_key_expansion(const unsigned char* key, unsigned short* subkeys) {
		for (int i = 0; i < 8; ++i) {
			subkeys[i] = (key[2 * i] << 8) | key[2 * i + 1];
		}
		for (int i = 8; i < IDEA_SUBKEYS; ++i) {
			int pos = (i % 8) * 2;
			if (pos < 14) {
				subkeys[i] = ((subkeys[i - 8] << 9) | (subkeys[i - 7] >> 7)) & 0xFFFF;
			} else {
				subkeys[i] = ((subkeys[i - 8] << 9) | (subkeys[i - 15] >> 7)) & 0xFFFF;
			}
		}
	}
	static void idea_generate_decrypt_keys(const unsigned short* enc_subkeys, unsigned short* dec_subkeys) {
		dec_subkeys[0] = idea_inv_mul(enc_subkeys[48]);
		dec_subkeys[1] = idea_inv_add(enc_subkeys[49]);
		dec_subkeys[2] = idea_inv_add(enc_subkeys[50]);
		dec_subkeys[3] = idea_inv_mul(enc_subkeys[51]);
		for (int i = 0; i < IDEA_ROUNDS - 1; ++i) {
			int round = IDEA_ROUNDS - 1 - i;
			dec_subkeys[4 + i * 6 + 0] = idea_inv_mul(enc_subkeys[4 + round * 6 - 2]);
			dec_subkeys[4 + i * 6 + 1] = idea_inv_add(enc_subkeys[4 + round * 6 - 1]);
			dec_subkeys[4 + i * 6 + 2] = idea_inv_add(enc_subkeys[4 + round * 6 - 4]);
			dec_subkeys[4 + i * 6 + 3] = idea_inv_mul(enc_subkeys[4 + round * 6 - 3]);
			dec_subkeys[4 + i * 6 + 4] = enc_subkeys[4 + round * 6 - 6];
			dec_subkeys[4 + i * 6 + 5] = enc_subkeys[4 + round * 6 - 5];
		}
		dec_subkeys[4 + (IDEA_ROUNDS - 1) * 6 + 0] = idea_inv_mul(enc_subkeys[4]);
		dec_subkeys[4 + (IDEA_ROUNDS - 1) * 6 + 1] = idea_inv_add(enc_subkeys[5]);
		dec_subkeys[4 + (IDEA_ROUNDS - 1) * 6 + 2] = idea_inv_add(enc_subkeys[2]);
		dec_subkeys[4 + (IDEA_ROUNDS - 1) * 6 + 3] = idea_inv_mul(enc_subkeys[3]);
	}
	void idea_encrypt(const unsigned char* key, const unsigned char* in, unsigned char* out) {
		unsigned short subkeys[IDEA_SUBKEYS];
		idea_key_expansion(key, subkeys);
		unsigned short x1 = (in[0] << 8) | in[1];
		unsigned short x2 = (in[2] << 8) | in[3];
		unsigned short x3 = (in[4] << 8) | in[5];
		unsigned short x4 = (in[6] << 8) | in[7];
		for (int i = 0; i < IDEA_ROUNDS; ++i) {
			int idx = i * 6;
			unsigned short k1 = subkeys[idx];
			unsigned short k2 = subkeys[idx + 1];
			unsigned short k3 = subkeys[idx + 2];
			unsigned short k4 = subkeys[idx + 3];
			unsigned short k5 = subkeys[idx + 4];
			unsigned short k6 = subkeys[idx + 5];
			unsigned short a = idea_mul_mod(x1, k1);
			unsigned short b = (x2 + k2) % 0x10000;
			unsigned short c = (x3 + k3) % 0x10000;
			unsigned short d = idea_mul_mod(x4, k4);
			unsigned short e = a ^ c;
			unsigned short f = b ^ d;
			unsigned short g = idea_mul_mod(e, k5);
			unsigned short h = (f + g) % 0x10000;
			unsigned short i_val = idea_mul_mod(h, k6);
			unsigned short j = (g + i_val) % 0x10000;
			x1 = a ^ i_val;
			x2 = c ^ i_val;
			x3 = b ^ j;
			x4 = d ^ j;
		}
		unsigned short k49 = subkeys[48];
		unsigned short k50 = subkeys[49];
		unsigned short k51 = subkeys[50];
		unsigned short k52 = subkeys[51];
		unsigned short y1 = idea_mul_mod(x1, k49);
		unsigned short y2 = (x3 + k50) % 0x10000;
		unsigned short y3 = (x2 + k51) % 0x10000;
		unsigned short y4 = idea_mul_mod(x4, k52);
		out[0] = (y1 >> 8) & 0xFF;
		out[1] = y1 & 0xFF;
		out[2] = (y2 >> 8) & 0xFF;
		out[3] = y2 & 0xFF;
		out[4] = (y3 >> 8) & 0xFF;
		out[5] = y3 & 0xFF;
		out[6] = (y4 >> 8) & 0xFF;
		out[7] = y4 & 0xFF;
	}
	void idea_decrypt(const unsigned char* key, const unsigned char* in, unsigned char* out) {
		unsigned short enc_subkeys[IDEA_SUBKEYS];
		unsigned short dec_subkeys[IDEA_SUBKEYS];
		idea_key_expansion(key, enc_subkeys);
		idea_generate_decrypt_keys(enc_subkeys, dec_subkeys);
		unsigned short x1 = (in[0] << 8) | in[1];
		unsigned short x2 = (in[2] << 8) | in[3];
		unsigned short x3 = (in[4] << 8) | in[5];
		unsigned short x4 = (in[6] << 8) | in[7];
		for (int i = 0; i < IDEA_ROUNDS; ++i) {
			int idx = i * 6;
			unsigned short k1 = dec_subkeys[idx];
			unsigned short k2 = dec_subkeys[idx + 1];
			unsigned short k3 = dec_subkeys[idx + 2];
			unsigned short k4 = dec_subkeys[idx + 3];
			unsigned short k5 = dec_subkeys[idx + 4];
			unsigned short k6 = dec_subkeys[idx + 5];
			unsigned short a = idea_mul_mod(x1, k1);
			unsigned short b = (x2 + k2) % 0x10000;
			unsigned short c = (x3 + k3) % 0x10000;
			unsigned short d = idea_mul_mod(x4, k4);
			unsigned short e = a ^ c;
			unsigned short f = b ^ d;
			unsigned short g = idea_mul_mod(e, k5);
			unsigned short h = (f + g) % 0x10000;
			unsigned short i_val = idea_mul_mod(h, k6);
			unsigned short j = (g + i_val) % 0x10000;
			x1 = a ^ i_val;
			x2 = c ^ i_val;
			x3 = b ^ j;
			x4 = d ^ j;
		}
		unsigned short k49 = dec_subkeys[48];
		unsigned short k50 = dec_subkeys[49];
		unsigned short k51 = dec_subkeys[50];
		unsigned short k52 = dec_subkeys[51];
		unsigned short y1 = idea_mul_mod(x1, k49);
		unsigned short y2 = (x3 + k50) % 0x10000;
		unsigned short y3 = (x2 + k51) % 0x10000;
		unsigned short y4 = idea_mul_mod(x4, k52);
		out[0] = (y1 >> 8) & 0xFF;
		out[1] = y1 & 0xFF;
		out[2] = (y2 >> 8) & 0xFF;
		out[3] = y2 & 0xFF;
		out[4] = (y3 >> 8) & 0xFF;
		out[5] = y3 & 0xFF;
		out[6] = (y4 >> 8) & 0xFF;
		out[7] = y4 & 0xFF;
	}
#	define ROTL16(x,n) ((x<<n)|(x>>(16-n)))
#	define ROTR16(x,n) ((x>>n)|(x<<(16-n)))
#	define ADD16(x,y) ((x+y)&0xFFFF)
#	define SUB16(x,y) ((x-y)&0xFFFF)
#	define MUL16(x,y) ([&](){unsigned int t=(unsigned int)x*y;if(t)t=(t&0xFFFF)+(t>>16);else t=1;return t&0xFFFF;}())
#	define IMUL16(x) ([&](){unsigned long long int a=x,b=0x10001;int n=17;while(n--){if(b&1)b^=a;a<<=1;}return b;}())
	static const unsigned short S1[] = {0x83, 0x70, 0x01, 0x9F, 0x32, 0xE4, 0x94, 0x9B, 0x6A, 0x2E, 0x5C, 0x77, 0x6D, 0x3B, 0x19, 0xC8, 0x4F, 0x8C, 0x09, 0x56, 0xFA, 0x81, 0x27, 0x3E, 0x7B, 0x4A, 0x1D, 0x05, 0xD3, 0xB6, 0xDC, 0x10, 0x35, 0x51, 0x23, 0x9E, 0x61, 0x45, 0x8A, 0x14, 0xE2, 0x0C, 0x7F, 0xAD, 0xC2, 0x86, 0x5D, 0x99, 0x2D, 0x30, 0xF1, 0x67, 0x73, 0x42, 0x1B, 0x06, 0xA3, 0xDE, 0xC7, 0x91, 0x5A, 0x29, 0x8F, 0x37, 0x6B, 0xF7, 0x48, 0x7E, 0x12, 0x0E, 0xB1, 0xD9, 0xCB, 0x97, 0x57, 0x2A, 0x84, 0x3D, 0x6E, 0xFD, 0x4E, 0x74, 0x18, 0x03, 0xAA, 0xD5, 0xC1, 0x92, 0x52, 0x2F, 0x8B, 0x3A, 0x62, 0xF4, 0x4B, 0x78, 0x1C, 0x0A, 0xB5, 0xDA, 0xCC, 0x9D, 0x5B, 0x26, 0x80, 0x33, 0x6F, 0xF8, 0x44, 0x71, 0x15, 0x08, 0xAE, 0xD0, 0xC6, 0x98, 0x53, 0x20, 0x87, 0x38, 0x64, 0xEF, 0x41, 0x7D, 0x1E, 0x00, 0xB0, 0xDB, 0xCF, 0x93, 0x58, 0x22, 0x8E, 0x3F, 0x68, 0xF2, 0x4D, 0x72, 0x11, 0x0B, 0xAC, 0xD6, 0xC8, 0x9A, 0x5E, 0x24, 0x82, 0x34, 0x63, 0xF6, 0x47, 0x7A, 0x17, 0x0F, 0xB3, 0xD2, 0xC3, 0x9C, 0x54, 0x25, 0x8D, 0x36, 0x69, 0xF9, 0x4C, 0x76, 0x1A, 0x02, 0xB7, 0xD8, 0xCA, 0x96, 0x5F, 0x21, 0x88, 0x31, 0x60, 0xEB, 0x43, 0x79, 0x13, 0x0D, 0xAF, 0xD1, 0xC5, 0x9B, 0x55, 0x28, 0x85, 0x3C, 0x65, 0xF0, 0x49, 0x75, 0x16, 0x04, 0xB4, 0xD7, 0xC0, 0x95, 0x50, 0x2B, 0x89, 0x39, 0x6C, 0xFC, 0x40, 0x7C, 0x1F, 0x07, 0xB2, 0xD4, 0xC4, 0x9E, 0x59, 0x2C, 0x8A, 0x32, 0x66, 0xE9, 0x46, 0x70, 0x10, 0x09, 0xB6, 0xDC, 0xCE, 0x90, 0x5D, 0x2D, 0x83, 0x3B, 0x6A, 0xFE, 0x4F, 0x7B, 0x19, 0x01, 0xBA, 0xD3, 0xCB, 0x94, 0x5C, 0x2E, 0x8E, 0x3E, 0x67, 0xE7, 0x4A, 0x77, 0x14, 0x0C, 0xB8, 0xD9, 0xCD, 0x91, 0x56, 0x27, 0x81, 0x35, 0x61, 0xE1, 0x45, 0x7F, 0x1D, 0x05, 0xBB, 0xDA, 0xCF, 0x99, 0x51, 0x23, 0x86, 0x30, 0x6D, 0xF3, 0x42, 0x73, 0x1B, 0x06, 0xBC, 0xD5, 0xC7, 0x92, 0x5A, 0x29, 0x8F, 0x37, 0x6B, 0xF7, 0x48, 0x7E, 0x12, 0x0E, 0xBD, 0xD0, 0xC2, 0x97, 0x57, 0x2A, 0x84, 0x3D, 0x6E, 0xFD, 0x4E, 0x74, 0x18, 0x03, 0xBE, 0xD6, 0xC1, 0x98, 0x52, 0x2F, 0x8B, 0x3A, 0x62, 0xF4, 0x4B, 0x78, 0x1C, 0x0A, 0xBF, 0xDA, 0xCC, 0x9D, 0x5B, 0x26, 0x80, 0x33, 0x6F, 0xF8, 0x44, 0x71, 0x15, 0x08};
	static const unsigned short S2[] = {0x4D, 0x7A, 0x1E, 0x03, 0x8C, 0x3B, 0x62, 0xF9, 0x5F, 0x21, 0x98, 0xEC, 0xB0, 0xD7, 0xC4, 0xA9, 0x17, 0x0F, 0x47, 0x72, 0x82, 0x34, 0x63, 0xF6, 0x54, 0x25, 0x9D, 0xE3, 0xB3, 0xD2, 0xC3, 0xAC, 0x02, 0x1A, 0x4C, 0x76, 0x8D, 0x36, 0x69, 0xF9, 0x5F, 0x21, 0x98, 0xEB, 0xB7, 0xD8, 0xCA, 0xA6, 0x13, 0x0D, 0x43, 0x79, 0x85, 0x3C, 0x65, 0xF0, 0x55, 0x28, 0x9B, 0xE5, 0xB4, 0xD7, 0xC0, 0xA5, 0x16, 0x04, 0x49, 0x75, 0x89, 0x39, 0x6C, 0xFC, 0x50, 0x2B, 0x90, 0xED, 0xB2, 0xD4, 0xC4, 0xAE, 0x1F, 0x07, 0x40, 0x7C, 0x8A, 0x32, 0x66, 0xE9, 0x5D, 0x2D, 0x93, 0xEB, 0xB6, 0xDC, 0xCE, 0xA0, 0x19, 0x01, 0x4F, 0x7B, 0x83, 0x3B, 0x6A, 0xFE, 0x5C, 0x2E, 0x94, 0xEC, 0xBA, 0xD3, 0xCB, 0xA9, 0x14, 0x0C, 0x4A, 0x77, 0x8E, 0x3E, 0x67, 0xE7, 0x56, 0x27, 0x91, 0xE1, 0xB8, 0xD9, 0xCD, 0xA4, 0x1D, 0x05, 0x45, 0x7F, 0x81, 0x35, 0x61, 0xF3, 0x51, 0x23, 0x99, 0xF3, 0xB0, 0xD5, 0xC7, 0xA2, 0x12, 0x0E, 0x42, 0x73, 0x8F, 0x37, 0x6B, 0xF7, 0x5A, 0x29, 0x92, 0xFD, 0xBE, 0xD6, 0xC1, 0xAA, 0x18, 0x03, 0x4B, 0x78, 0x8B, 0x3A, 0x62, 0xF4, 0x5B, 0x26, 0x9D, 0xF8, 0xBF, 0xDA, 0xCC, 0xA3, 0x1C, 0x0A, 0x44, 0x71, 0x80, 0x33, 0x6F, 0x50, 0x2B, 0x97, 0xF0, 0xB4, 0xD0, 0xC5, 0xA5, 0x15, 0x08, 0x49, 0x75, 0x86, 0x30, 0x6D, 0xEF, 0x53, 0x20, 0x98, 0xE2, 0xB7, 0xD8, 0xCA, 0xA6, 0x17, 0x0F, 0x47, 0x72, 0x82, 0x34, 0x63, 0xF6, 0x54, 0x25, 0x9D, 0xE3, 0xB3, 0xD2, 0xC3, 0xAC, 0x02, 0x1A, 0x4C, 0x76, 0x8D, 0x36, 0x69, 0xF9, 0x5F, 0x21, 0x98, 0xEB, 0xB7, 0xD8, 0xCA, 0xA6, 0x13, 0x0D, 0x43, 0x79, 0x85, 0x3C, 0x65, 0xF0, 0x55, 0x28, 0x9B, 0xE5, 0xB4, 0xD7, 0xC0, 0xA5, 0x16, 0x04, 0x49, 0x75, 0x89, 0x39, 0x6C, 0xFC, 0x50, 0x2B, 0x90, 0xED, 0xB2, 0xD4, 0xC4, 0xAE, 0x1F, 0x07, 0x40, 0x7C, 0x8A, 0x32, 0x66, 0xE9, 0x5D, 0x2D, 0x93, 0xEB, 0xB6, 0xDC, 0xCE, 0xA0, 0x19, 0x01, 0x4F, 0x7B, 0x83, 0x3B, 0x6A, 0xFE, 0x5C, 0x2E, 0x94, 0xEC, 0xBA, 0xD3, 0xCB, 0xA9, 0x14, 0x0C, 0x4A, 0x77, 0x8E, 0x3E, 0x67, 0xE7, 0x56, 0x27, 0x91, 0xE1, 0xB8, 0xD9, 0xCD, 0xA4, 0x1D, 0x05, 0x45, 0x7F, 0x81, 0x35, 0x61, 0xF3, 0x51, 0x23, 0x99, 0xF3, 0xB0, 0xD5, 0xC7, 0xA2, 0x12, 0x0E, 0x42, 0x73, 0x8F, 0x37, 0x6B, 0xF7, 0x5A, 0x29, 0x92, 0xFD};
	unsigned short F(unsigned short x, unsigned short k1, unsigned short k2, unsigned short k3) {
		x = MUL16(x, k1);
		x = ADD16(x, k2);
		x = S1[x & 0xFF] ^ S2[(x >> 8) & 0xFF];
		x = ROTL16(x, 3);
		x = MUL16(x, k3);
		return x;
	}
	void IDEA_NXT_KeySchedule(const unsigned char key[16], unsigned short subkeys[42]) {
		memcpy(subkeys, key, 16);
		for (int i = 8, j = 0; i < 42; i++, j = (j + 2) % 16) {
			subkeys[i] = ROTL16(subkeys[i - 8] ^ subkeys[i - 7], 1);
			if (j % 4 == 0)subkeys[i] ^= (0x0101 * (i / 8)) & 0xFFFF;
		}
	}
	void IDEA_NXT_Encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned short subkeys[42];
		IDEA_NXT_KeySchedule(key, subkeys);
		unsigned short x1 = (plain[0] << 8) | plain[1], x2 = (plain[2] << 8) | plain[3];
		unsigned short x3 = (plain[4] << 8) | plain[5], x4 = (plain[6] << 8) | plain[7];
		for (int r = 0; r < 8; r++) {
			unsigned short k0 = subkeys[5 * r], k1 = subkeys[5 * r + 1], k2 = subkeys[5 * r + 2];
			unsigned short k3 = subkeys[5 * r + 3], k4 = subkeys[5 * r + 4];
			unsigned short a = MUL16(x1, k0);
			unsigned short b = ADD16(x2, k1);
			unsigned short c = ADD16(x3, k2);
			unsigned short d = MUL16(x4, k3);
			unsigned short e = a ^ c;
			unsigned short f = b ^ d;
			unsigned short g = F(e, k4, subkeys[40], subkeys[41]);
			unsigned short h = ADD16(f, g);
			x1 = a ^ h;
			x2 = c ^ h;
			x3 = b ^ g;
			x4 = d ^ g;
			unsigned short tmp = x2;
			x2 = x3;
			x3 = tmp;
		}
		unsigned short tmp = x2;
		x2 = x3;
		x3 = tmp;
		x1 = MUL16(x1, subkeys[40]);
		x2 = ADD16(x2, subkeys[41]);
		x3 = ADD16(x3, subkeys[40]);
		x4 = MUL16(x4, subkeys[41]);
		cipher[0] = (x1 >> 8) & 0xFF;
		cipher[1] = x1 & 0xFF;
		cipher[2] = (x2 >> 8) & 0xFF;
		cipher[3] = x2 & 0xFF;
		cipher[4] = (x3 >> 8) & 0xFF;
		cipher[5] = x3 & 0xFF;
		cipher[6] = (x4 >> 8) & 0xFF;
		cipher[7] = x4 & 0xFF;
	}
	void IDEA_NXT_Decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned short subkeys[42], dec_subkeys[42];
		IDEA_NXT_KeySchedule(key, subkeys);
		dec_subkeys[0] = IMUL16(subkeys[40]);
		dec_subkeys[1] = SUB16(0, subkeys[41]);
		dec_subkeys[2] = SUB16(0, subkeys[40]);
		dec_subkeys[3] = IMUL16(subkeys[41]);
		dec_subkeys[4] = IMUL16(subkeys[39]);
		dec_subkeys[5] = SUB16(0, subkeys[38]);
		dec_subkeys[6] = SUB16(0, subkeys[37]);
		dec_subkeys[7] = IMUL16(subkeys[36]);
		for (int r = 1; r < 7; r++) {
			int i = 7 - r;
			dec_subkeys[8 + 5 * (r - 1)] = IMUL16(subkeys[5 * i]);
			dec_subkeys[8 + 5 * (r - 1) + 1] = SUB16(0, subkeys[5 * i + 2]);
			dec_subkeys[8 + 5 * (r - 1) + 2] = SUB16(0, subkeys[5 * i + 1]);
			dec_subkeys[8 + 5 * (r - 1) + 3] = IMUL16(subkeys[5 * i + 3]);
			dec_subkeys[8 + 5 * (r - 1) + 4] = IMUL16(subkeys[5 * i + 4]);
		}
		dec_subkeys[40] = IMUL16(subkeys[0]);
		dec_subkeys[41] = IMUL16(subkeys[1]);
		unsigned short x1 = (cipher[0] << 8) | cipher[1], x2 = (cipher[2] << 8) | cipher[3];
		unsigned short x3 = (cipher[4] << 8) | cipher[5], x4 = (cipher[6] << 8) | cipher[7];
		for (int r = 0; r < 8; r++) {
			unsigned short k0 = dec_subkeys[5 * r], k1 = dec_subkeys[5 * r + 1], k2 = dec_subkeys[5 * r + 2];
			unsigned short k3 = dec_subkeys[5 * r + 3], k4 = dec_subkeys[5 * r + 4];
			unsigned short a = MUL16(x1, k0);
			unsigned short b = ADD16(x2, k1);
			unsigned short c = ADD16(x3, k2);
			unsigned short d = MUL16(x4, k3);
			unsigned short e = a ^ c;
			unsigned short f = b ^ d;
			unsigned short g = F(e, k4, subkeys[40], subkeys[41]);
			unsigned short h = ADD16(f, g);
			x1 = a ^ h;
			x2 = c ^ h;
			x3 = b ^ g;
			x4 = d ^ g;
			unsigned short tmp = x2;
			x2 = x3;
			x3 = tmp;
		}
		unsigned short tmp = x2;
		x2 = x3;
		x3 = tmp;
		x1 = MUL16(x1, dec_subkeys[40]);
		x2 = ADD16(x2, dec_subkeys[41]);
		x3 = ADD16(x3, dec_subkeys[40]);
		x4 = MUL16(x4, dec_subkeys[41]);
		plain[0] = (x1 >> 8) & 0xFF;
		plain[1] = x1 & 0xFF;
		plain[2] = (x2 >> 8) & 0xFF;
		plain[3] = x2 & 0xFF;
		plain[4] = (x3 >> 8) & 0xFF;
		plain[5] = x3 & 0xFF;
		plain[6] = (x4 >> 8) & 0xFF;
		plain[7] = x4 & 0xFF;
	}
#define KASUMI_ROTL16(x,n) ((x<<n)|(x>>(16-n)))
#define KASUMI_ROTR16(x,n) ((x>>n)|(x<<(16-n)))
	unsigned short misty1_S9(unsigned short x) {
		static const unsigned short s[512] = {0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x1081, 0x0108, 0x3393, 0x221A, 0x56AD, 0x4724, 0x75BF, 0x6436, 0x9DC9, 0x8C40, 0xBEDB, 0xAF52, 0xDBED, 0xCA64, 0xF8FF, 0xE976, 0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AD, 0x4434, 0x55BD, 0xAF52, 0xBEDB, 0x8C40, 0x9DC9, 0xE976, 0xF8FF, 0xCA64, 0xDBED, 0x3183, 0x200A, 0x1291, 0x0318, 0x77AD, 0x6626, 0x54B5, 0x453C, 0xBEDB, 0xAF52, 0x9DC9, 0x8C40, 0xF8FF, 0xE976, 0xDBED, 0xCA64, 0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDBED, 0xCA64, 0xF8FF, 0xE976, 0x9DC9, 0x8C40, 0xBEDB, 0xAF52, 0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xE97E, 0xF8F7, 0xCA6C, 0xDBE5, 0xAF5A, 0xBED3, 0x8C48, 0x9DC1, 0x7387, 0x620E, 0x5095, 0x411C, 0x35AB, 0x2422, 0x16B9, 0x0730, 0xF8F7, 0xE97E, 0xDBE5, 0xCA6C, 0xBED3, 0xAF5A, 0x9DC1, 0x8C48, 0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF, 0x9489, 0x8500, 0xB79B, 0xA612, 0xD3A5, 0xC22C, 0xF0B7, 0xE13E, 0x19C9, 0x0840, 0x3ADB, 0x2B52, 0x5FED, 0x4E64, 0x7CFF, 0x6D76, 0xA50A, 0xB483, 0x8618, 0x9791, 0xE23E, 0xF3B7, 0xC12C, 0xD0A5, 0x2B52, 0x3ADB, 0x0840, 0x19C9, 0x6D76, 0x7CFF, 0x4E64, 0x5FED, 0xB58B, 0xA402, 0x9699, 0x8710, 0xF3B7, 0xE23E, 0xD0A5, 0xC12C, 0x3ADB, 0x2B52, 0x19C9, 0x0840, 0x7CFF, 0x6D76, 0x5FED, 0x4E64, 0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3, 0x4E64, 0x5FED, 0x6D76, 0x7CFF, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0xD68D, 0xC704, 0xF59F, 0xE416, 0x91A1, 0x8028, 0xB2B3, 0xA33A, 0x5FED, 0x4E64, 0x7CFF, 0x6D76, 0x19C9, 0x0840, 0x3ADB, 0x2B52, 0xE70E, 0xF687, 0xC41C, 0xD595, 0xA33A, 0xB2B3, 0x8028, 0x91A1, 0x6D76, 0x7CFF, 0x4E64, 0x5FED, 0x2B52, 0x3ADB, 0x0840, 0x19C9, 0xF78F, 0xE606, 0xD49D, 0xC514, 0xB2B3, 0xA33A, 0x91A1, 0x8028, 0x7CFF, 0x6D76, 0x5FED, 0x4E64, 0x3ADB, 0x2B52, 0x19C9, 0x0840, 0x1081, 0x0108, 0x3393, 0x221A, 0x56AD, 0x4724, 0x75BF, 0x6436, 0x9DC9, 0x8C40, 0xBEDB, 0xAF52, 0xDBED, 0xCA64, 0xF8FF, 0xE976, 0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x3183, 0x200A, 0x1291, 0x0318, 0x77AD, 0x6626, 0x54B5, 0x453C, 0xBEDB, 0xAF52, 0x9DC9, 0x8C40, 0xF8FF, 0xE976, 0xDBED, 0xCA64, 0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AD, 0x4434, 0x55BD, 0xAF52, 0xBEDB, 0x8C40, 0x9DC9, 0xE976, 0xF8FF, 0xCA64, 0xDBED, 0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDBED, 0xCA64, 0xF8FF, 0xE976, 0x9DC9, 0x8C40, 0xBEDB, 0xAF52, 0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0x7387, 0x620E, 0x5095, 0x411C, 0x35AB, 0x2422, 0x16B9, 0x0730, 0xF8F7, 0xE97E, 0xDBE5, 0xCA6C, 0xBED3, 0xAF5A, 0x9DC1, 0x8C48, 0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xE97E, 0xF8F7, 0xCA6C, 0xDBE5, 0xAF5A, 0xBED3, 0x8C48, 0x9DC1, 0x9489, 0x8500, 0xB79B, 0xA612, 0xD3A5, 0xC22C, 0xF0B7, 0xE13E, 0x19C9, 0x0840, 0x3ADB, 0x2B52, 0x5FED, 0x4E64, 0x7CFF, 0x6D76, 0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF, 0xB58B, 0xA402, 0x9699, 0x8710, 0xF3B7, 0xE23E, 0xD0A5, 0xC12C, 0x3ADB, 0x2B52, 0x19C9, 0x0840, 0x7CFF, 0x6D76, 0x5FED, 0x4E64, 0xA50A, 0xB483, 0x8618, 0x9791, 0xE23E, 0xF3B7, 0xC12C, 0xD0A5, 0x2B52, 0x3ADB, 0x0840, 0x19C9, 0x6D76, 0x7CFF, 0x4E64, 0x5FED, 0xD68D, 0xC704, 0xF59F, 0xE416, 0x91A1, 0x8028, 0xB2B3, 0xA33A, 0x5FED, 0x4E64, 0x7CFF, 0x6D76, 0x19C9, 0x0840, 0x3ADB, 0x2B52, 0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3, 0x4E64, 0x5FED, 0x6D76, 0x7CFF, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0xF78F, 0xE606, 0xD49D, 0xC514, 0xB2B3, 0xA33A, 0x91A1, 0x8028, 0x7CFF, 0x6D76, 0x5FED, 0x4E64, 0x3ADB, 0x2B52, 0x19C9, 0x0840, 0xE70E, 0xF687, 0xC41C, 0xD595, 0xA33A, 0xB2B3, 0x8028, 0x91A1, 0x6D76, 0x7CFF, 0x4E64, 0x5FED, 0x2B52, 0x3ADB, 0x0840, 0x19C9};
		return s[x & 0x1FF];
	}
	unsigned short misty1_S7(unsigned short x) {
		static const unsigned short s[128] = { 0x24, 0x27, 0x77, 0x21, 0x23, 0x20, 0x76, 0x22, 0x25, 0x26, 0x74, 0x75, 0x71, 0x70, 0x73, 0x72, 0x09, 0x08, 0x0b, 0x0a, 0x0d, 0x0c, 0x0f, 0x0e, 0x01, 0x00, 0x03, 0x02, 0x05, 0x04, 0x07, 0x06, 0x3c, 0x3f, 0x3d, 0x3e, 0x38, 0x3b, 0x39, 0x3a, 0x34, 0x37, 0x35, 0x36, 0x30, 0x33, 0x31, 0x32, 0x15, 0x14, 0x17, 0x16, 0x11, 0x10, 0x13, 0x12, 0x1d, 0x1c, 0x1f, 0x1e, 0x19, 0x18, 0x1b, 0x1a, 0x68, 0x6b, 0x69, 0x6a, 0x6c, 0x6f, 0x6d, 0x6e, 0x60, 0x63, 0x61, 0x62, 0x64, 0x67, 0x65, 0x66, 0x4d, 0x4c, 0x4f, 0x4e, 0x49, 0x48, 0x4b, 0x4a, 0x41, 0x40, 0x43, 0x42, 0x45, 0x44, 0x47, 0x46, 0x50, 0x53, 0x51, 0x52, 0x54, 0x57, 0x55, 0x56, 0x58, 0x5b, 0x59, 0x5a, 0x5c, 0x5f, 0x5d, 0x5e, 0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70};
		return s[x & 0x7F];
	}
	unsigned short misty1_F(unsigned short x, unsigned short k1, unsigned short k2) {
		x ^= k1;
		unsigned short a = (x >> 7) & 0x1FF;
		unsigned short b = x & 0x7F;
		a = misty1_S9(a);
		b = misty1_S7(b);
		return (a ^ b) ^ k2;
	}
	void misty1_encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned short K[15];
		for (int i = 0; i < 8; i++)K[i] = (key[2 * i] << 8) | key[2 * i + 1];
		K[8] = (K[0] >> 9) | (K[1] << 7);
		K[9] = (K[1] >> 9) | (K[2] << 7);
		K[10] = (K[2] >> 9) | (K[3] << 7);
		K[11] = (K[4] >> 9) | (K[5] << 7);
		K[12] = (K[5] >> 9) | (K[6] << 7);
		K[13] = (K[6] >> 9) | (K[7] << 7);
		K[14] = (K[7] >> 9) | (K[0] << 7);
		unsigned short L = (plain[0] << 8) | plain[1], M = (plain[2] << 8) | plain[3], R = (plain[4] << 8) | plain[5], S = (plain[6] << 8) | plain[7];
		for (int i = 0; i < 4; i++) {
			unsigned short tmp = M;
			M = misty1_F(M, K[2 * i], K[2 * i + 1])^L;
			L = tmp;
			tmp = S;
			S = misty1_F(S, K[2 * i + 8], K[2 * i + 9])^R;
			R = tmp;
		}
		unsigned short tmp = misty1_F(L, K[8], K[9])^M;
		M = L;
		L = tmp;
		tmp = misty1_F(R, K[14], K[8])^S;
		S = R;
		R = tmp;
		for (int i = 4; i < 8; i++) {
			unsigned short tmp = M;
			M = misty1_F(M, K[2 * i], K[2 * i + 1])^L;
			L = tmp;
			tmp = S;
			S = misty1_F(S, K[2 * i + 8], K[2 * i + 9])^R;
			R = tmp;
		}
		cipher[0] = (L >> 8) & 0xFF;
		cipher[1] = L & 0xFF;
		cipher[2] = (M >> 8) & 0xFF;
		cipher[3] = M & 0xFF;
		cipher[4] = (R >> 8) & 0xFF;
		cipher[5] = R & 0xFF;
		cipher[6] = (S >> 8) & 0xFF;
		cipher[7] = S & 0xFF;
	}
	void misty1_decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned short K[15];
		for (int i = 0; i < 8; i++)K[i] = (key[2 * i] << 8) | key[2 * i + 1];
		K[8] = (K[0] >> 9) | (K[1] << 7);
		K[9] = (K[1] >> 9) | (K[2] << 7);
		K[10] = (K[2] >> 9) | (K[3] << 7);
		K[11] = (K[4] >> 9) | (K[5] << 7);
		K[12] = (K[5] >> 9) | (K[6] << 7);
		K[13] = (K[6] >> 9) | (K[7] << 7);
		K[14] = (K[7] >> 9) | (K[0] << 7);
		unsigned short L = (cipher[0] << 8) | cipher[1], M = (cipher[2] << 8) | cipher[3], R = (cipher[4] << 8) | cipher[5], S = (cipher[6] << 8) | cipher[7];
		for (int i = 7; i >= 4; i--) {
			unsigned short tmp = L;
			L = misty1_F(L, K[2 * i], K[2 * i + 1])^M;
			M = tmp;
			tmp = R;
			R = misty1_F(R, K[2 * i + 8], K[2 * i + 9])^S;
			S = tmp;
		}
		unsigned short tmp = R;
		R = misty1_F(S, K[14], K[8])^R;
		S = tmp;
		tmp = L;
		L = misty1_F(M, K[8], K[9])^L;
		M = tmp;
		for (int i = 3; i >= 0; i--) {
			unsigned short tmp = L;
			L = misty1_F(L, K[2 * i], K[2 * i + 1])^M;
			M = tmp;
			tmp = R;
			R = misty1_F(R, K[2 * i + 8], K[2 * i + 9])^S;
			S = tmp;
		}
		plain[0] = (L >> 8) & 0xFF;
		plain[1] = L & 0xFF;
		plain[2] = (M >> 8) & 0xFF;
		plain[3] = M & 0xFF;
		plain[4] = (R >> 8) & 0xFF;
		plain[5] = R & 0xFF;
		plain[6] = (S >> 8) & 0xFF;
		plain[7] = S & 0xFF;
	}
	unsigned int misty2_FI(unsigned int x, unsigned int k) {
		unsigned short a = (x >> 16) & 0xFFFF, b = x & 0xFFFF;
		unsigned short k1 = (k >> 16) & 0xFFFF, k2 = k & 0xFFFF;
		a ^= k1;
		unsigned short a1 = (a >> 7) & 0x1FF, a2 = a & 0x7F;
		a1 = misty1_S9(a1);
		a2 = misty1_S7(a2);
		a = a1 ^ a2;
		b ^= k2;
		unsigned short b1 = (b >> 7) & 0x1FF, b2 = b & 0x7F;
		b1 = misty1_S9(b1);
		b2 = misty1_S7(b2);
		b = b1 ^ b2;
		return ((a ^ b) << 16) | a;
	}
	void misty2_encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned int K[4];
		for (int i = 0; i < 4; i++)K[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
		unsigned int L = (plain[0] << 24) | (plain[1] << 16) | (plain[2] << 8) | plain[3];
		unsigned int R = (plain[4] << 24) | (plain[5] << 16) | (plain[6] << 8) | plain[7];
		for (int i = 0; i < 8; i++) {
			unsigned int tmp = R;
			R = misty2_FI(R, K[i % 4])^L;
			L = tmp;
		}
		cipher[0] = (L >> 24) & 0xFF;
		cipher[1] = (L >> 16) & 0xFF;
		cipher[2] = (L >> 8) & 0xFF;
		cipher[3] = L & 0xFF;
		cipher[4] = (R >> 24) & 0xFF;
		cipher[5] = (R >> 16) & 0xFF;
		cipher[6] = (R >> 8) & 0xFF;
		cipher[7] = R & 0xFF;
	}
	void MISTY2_Decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned int K[4];
		for (int i = 0; i < 4; i++)K[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
		unsigned int L = (cipher[0] << 24) | (cipher[1] << 16) | (cipher[2] << 8) | cipher[3];
		unsigned int R = (cipher[4] << 24) | (cipher[5] << 16) | (cipher[6] << 8) | cipher[7];
		for (int i = 0; i < 8; i++) {
			unsigned int tmp = L;
			L = misty2_FI(L, K[(7 - i) % 4])^R;
			R = tmp;
		}
		plain[0] = (L >> 24) & 0xFF;
		plain[1] = (L >> 16) & 0xFF;
		plain[2] = (L >> 8) & 0xFF;
		plain[3] = L & 0xFF;
		plain[4] = (R >> 24) & 0xFF;
		plain[5] = (R >> 16) & 0xFF;
		plain[6] = (R >> 8) & 0xFF;
		plain[7] = R & 0xFF;
	}
	unsigned int kasumi_FL(unsigned int x, unsigned int k) {
		unsigned short a = (x >> 16) & 0xFFFF, b = x & 0xFFFF;
		unsigned short k1 = (k >> 16) & 0xFFFF, k2 = k & 0xFFFF;
		a ^= k1;
		a = KASUMI_ROTL16(a, 1);
		b ^= (a & k2);
		a ^= b;
		return ((a) << 16) | b;
	}
	unsigned int kasumi_FLINV(unsigned int x, unsigned int k) {
		unsigned short a = (x >> 16) & 0xFFFF, b = x & 0xFFFF;
		unsigned short k1 = (k >> 16) & 0xFFFF, k2 = k & 0xFFFF;
		a ^= b;
		b ^= (a & k2);
		a = KASUMI_ROTR16(a, 1);
		a ^= k1;
		return ((a) << 16) | b;
	}
	void kasumi_keyschedule(const unsigned char key[16], unsigned int K[16]) {
		for (int i = 0; i < 8; i++)K[i] = (key[2 * i] << 8) | key[2 * i + 1];
		for (int i = 8; i < 16; i++)K[i] = (K[(i - 8 + 2) % 8] << 1) | ((K[(i - 8 + 1) % 8] >> 15) & 1);
	}
	void kasumi_encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned int K[16];
		kasumi_keyschedule(key, K);
		unsigned int L = (plain[0] << 24) | (plain[1] << 16) | (plain[2] << 8) | plain[3];
		unsigned int R = (plain[4] << 24) | (plain[5] << 16) | (plain[6] << 8) | plain[7];
		for (int i = 0; i < 8; i++) {
			if (i % 2 == 0) {
				R ^= misty2_FI(L, ((K[i] << 16) | K[i + 8]));
				L ^= misty2_FI(R, ((K[i + 1] << 16) | K[i + 9]));
			} else {
				L = kasumi_FL(L, ((K[i + 2] << 16) | K[i + 10]));
				R = kasumi_FL(R, ((K[i + 3] << 16) | K[i + 11]));
			}
		}
		cipher[0] = (L >> 24) & 0xFF;
		cipher[1] = (L >> 16) & 0xFF;
		cipher[2] = (L >> 8) & 0xFF;
		cipher[3] = L & 0xFF;
		cipher[4] = (R >> 24) & 0xFF;
		cipher[5] = (R >> 16) & 0xFF;
		cipher[6] = (R >> 8) & 0xFF;
		cipher[7] = R & 0xFF;
	}
	void kasumi_decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned int K[16];
		kasumi_keyschedule(key, K);
		unsigned int L = (cipher[0] << 24) | (cipher[1] << 16) | (cipher[2] << 8) | cipher[3];
		unsigned int R = (cipher[4] << 24) | (cipher[5] << 16) | (cipher[6] << 8) | cipher[7];
		for (int i = 7; i >= 0; i--) {
			if (i % 2 == 0) {
				L ^= misty2_FI(R, ((K[i + 1] << 16) | K[i + 9]));
				R ^= misty2_FI(L, ((K[i] << 16) | K[i + 8]));
			} else {
				R = kasumi_FLINV(R, ((K[i + 3] << 16) | K[i + 11]));
				L = kasumi_FLINV(L, ((K[i + 2] << 16) | K[i + 10]));
			}
		}
		plain[0] = (L >> 24) & 0xFF;
		plain[1] = (L >> 16) & 0xFF;
		plain[2] = (L >> 8) & 0xFF;
		plain[3] = L & 0xFF;
		plain[4] = (R >> 24) & 0xFF;
		plain[5] = (R >> 16) & 0xFF;
		plain[6] = (R >> 8) & 0xFF;
		plain[7] = R & 0xFF;
	}
	class Playfair {
		private:
			char table[5][5];
			std::unordered_map<char, std::pair<int, int>> pos;
		public:
			explicit Playfair(const std::string& key) {
				build(key);
			}
			void build(const std::string& key) {
				std::string k;
				for (char c : key) {
					if (std::isalpha(c)) {
						c = std::toupper(c);
						if (c == 'J') c = 'I';
						if (k.find(c) == std::string::npos) {
							k += c;
						}
					}
				}
				for (char c = 'A'; c <= 'Z'; ++c) {
					if (c != 'J' && k.find(c) == std::string::npos) {
						k += c;
					}
				}
				int idx = 0;
				for (int r = 0; r < 5; ++r) {
					for (int c = 0; c < 5; ++c) {
						table[r][c] = k[idx];
						pos[k[idx]] = std::make_pair(r, c);
						++idx;
					}
				}
			}
			std::string encrypt(const std::string& txt) {
				std::string pt;
				for (char c : txt) {
					if (std::isalpha(c)) {
						c = std::toupper(c);
						if (c == 'J') c = 'I';
						pt += c;
					}
				}
				for (size_t i = 0; i < pt.size(); i += 2) {
					if (i + 1 >= pt.size()) {
						pt += 'X';
						break;
					}
					if (pt[i] == pt[i + 1]) {
						pt.insert(i + 1, 1, 'X');
					}
				}
				std::string ct;
				for (size_t i = 0; i < pt.size(); i += 2) {
					char a = pt[i];
					char b = pt[i + 1];
					int r1 = pos[a].first;
					int c1 = pos[a].second;
					int r2 = pos[b].first;
					int c2 = pos[b].second;
					if (r1 == r2) {
						ct += table[r1][(c1 + 1) % 5];
						ct += table[r2][(c2 + 1) % 5];
					} else if (c1 == c2) {
						ct += table[(r1 + 1) % 5][c1];
						ct += table[(r2 + 1) % 5][c2];
					} else {
						ct += table[r1][c2];
						ct += table[r2][c1];
					}
				}
				return ct;
			}
			std::string decrypt(const std::string& txt) {
				std::string ct;
				for (char c : txt) {
					if (std::isalpha(c)) {
						c = std::toupper(c);
						if (c == 'J') c = 'I';
						ct += c;
					}
				}
				if (ct.size() % 2 != 0) {
					return "";
				}
				std::string pt;
				for (size_t i = 0; i < ct.size(); i += 2) {
					char a = ct[i];
					char b = ct[i + 1];
					int r1 = pos[a].first;
					int c1 = pos[a].second;
					int r2 = pos[b].first;
					int c2 = pos[b].second;

					if (r1 == r2) {
						pt += table[r1][(c1 + 4) % 5];
						pt += table[r2][(c2 + 4) % 5];
					} else if (c1 == c2) {
						pt += table[(r1 + 4) % 5][c1];
						pt += table[(r2 + 4) % 5][c2];
					} else {
						pt += table[r1][c2];
						pt += table[r2][c1];
					}
				}
				return pt;
			}
			void printTable() const {
				for (int r = 0; r < 5; ++r) {
					for (int c = 0; c < 5; ++c) {
						printf("%c ", table[r][c]);
					}
					printf("\n");
				}
			}
	};
#   define RC2_ROUNDS 18
#   define RC2_KEY_MAX 128
	static void rc2_setup(const unsigned char* key, int key_len, unsigned short* s) {
		int i;
		unsigned char key_buf[RC2_KEY_MAX] = {0};
		memcpy(key_buf, key, key_len);
		for (i = key_len; i < 128; ++i) {
			unsigned char t = key_buf[i - 1] ^ key_buf[i - key_len];
			key_buf[i] = (t * t) >> 1;
		}
		for (i = 0; i < RC2_ROUNDS; ++i) {
			s[i] = (key_buf[2 * i] << 8) | key_buf[2 * i + 1];
		}
	}
	void rc2_encrypt(const unsigned char* key, int key_len, const unsigned char* in, unsigned char* out) {
		unsigned short s[RC2_ROUNDS];
		rc2_setup(key, key_len, s);
		unsigned short x0 = (in[0] << 8) | in[1];
		unsigned short x1 = (in[2] << 8) | in[3];
		unsigned short x2 = (in[4] << 8) | in[5];
		unsigned short x3 = (in[6] << 8) | in[7];
		for (int i = 0; i < RC2_ROUNDS; ++i) {
			x0 = (x0 + x1 + 1) ^ s[i];
			x1 = (x1 << (x0 & 0xF)) | (x1 >> (16 - (x0 & 0xF)));
			x1 ^= x0;
			unsigned short t = x0;
			x0 = x1;
			x1 = x2;
			x2 = x3;
			x3 = t;
		}
		out[0] = x0 >> 8;
		out[1] = x0 & 0xFF;
		out[2] = x1 >> 8;
		out[3] = x1 & 0xFF;
		out[4] = x2 >> 8;
		out[5] = x2 & 0xFF;
		out[6] = x3 >> 8;
		out[7] = x3 & 0xFF;
	}
	void rc2_decrypt(const unsigned char* key, int key_len, const unsigned char* in, unsigned char* out) {
		unsigned short s[RC2_ROUNDS];
		rc2_setup(key, key_len, s);
		unsigned short x0 = (in[0] << 8) | in[1];
		unsigned short x1 = (in[2] << 8) | in[3];
		unsigned short x2 = (in[4] << 8) | in[5];
		unsigned short x3 = (in[6] << 8) | in[7];
		for (int i = RC2_ROUNDS - 1; i >= 0; --i) {
			unsigned short t = x3;
			x3 = x2;
			x2 = x1;
			x1 = x0;
			x0 = t;
			x1 ^= x0;
			x1 = (x1 >> (x0 & 0xF)) | (x1 << (16 - (x0 & 0xF)));
			x0 = (x0 ^ s[i]) - x1 - 1;
		}
		out[0] = x0 >> 8;
		out[1] = x0 & 0xFF;
		out[2] = x1 >> 8;
		out[3] = x1 & 0xFF;
		out[4] = x2 >> 8;
		out[5] = x2 & 0xFF;
		out[6] = x3 >> 8;
		out[7] = x3 & 0xFF;
	}
	static void rc4_ksa(const unsigned char* key, int key_len, unsigned char* s) {
		for (int i = 0; i < 256; ++i) s[i] = i;
		int j = 0;
		for (int i = 0; i < 256; ++i) {
			j = (j + s[i] + key[i % key_len]) % 256;
			unsigned char t = s[i];
			s[i] = s[j];
			s[j] = t;
		}
	}
	void rc4_encrypt(const unsigned char* key, int key_len, const unsigned char* in, unsigned char* out, int len) {
		unsigned char s[256];
		rc4_ksa(key, key_len, s);
		int i = 0, j = 0;
		for (int k = 0; k < len; ++k) {
			i = (i + 1) % 256;
			j = (j + s[i]) % 256;
			unsigned char t = s[i];
			s[i] = s[j];
			s[j] = t;
			out[k] = in[k] ^ s[(s[i] + s[j]) % 256];
		}
	}
	void rc4_decrypt(const unsigned char* key, int key_len, const unsigned char* in, unsigned char* out, int len) {
		rc4_encrypt(key, key_len, in, out, len);
	}
#	define RC5_W 32
#	define RC5_R 12
#	define RC5_B 8
#	define RC5_T 2*(RC5_R + 1)
#	define RC5_ADD(a, b) ((a) + (b))
#	define RC5_ROL(a, b) (((a) << ((b) % RC5_W)) | ((a) >> (RC5_W - ((b) % RC5_W))))
#	define RC5_ROR(a, b) (((a) >> ((b) % RC5_W)) | ((a) << (RC5_W - ((b) % RC5_W))))
	static void rc5_setup(const unsigned char* key, unsigned int* s) {
		unsigned int l[RC5_B / (RC5_W / 8)];
		memset(l, 0, sizeof(l));
		for (int i = 0; i < RC5_B; ++i) {
			l[i / 4] = (l[i / 4] << 8) | key[i];
		}
		s[0] = 0xB7E15163;
		for (int i = 1; i < RC5_T; ++i) {
			s[i] = RC5_ADD(s[i - 1], 0x9E3779B9);
		}
		unsigned int a = 0, b = 0;
		int i = 0, j = 0;
		for (int k = 0; k < 3 * RC5_T; ++k) {
			a = s[i] = RC5_ROL(RC5_ADD(s[i], RC5_ADD(a, b)), 3);
			b = l[j] = RC5_ROL(RC5_ADD(l[j], RC5_ADD(a, b)), RC5_ADD(a, b) % 32);
			i = (i + 1) % RC5_T;
			j = (j + 1) % (RC5_B / (RC5_W / 8));
		}
	}
	void rc5_encrypt(const unsigned char* key, const unsigned char* in, unsigned char* out) {
		unsigned int s[RC5_T];
		rc5_setup(key, s);
		unsigned int a = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
		unsigned int b = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
		a = RC5_ADD(a, s[0]);
		b = RC5_ADD(b, s[1]);
		for (int i = 1; i <= RC5_R; ++i) {
			a = RC5_ADD(RC5_ROL(a ^ b, b), s[2 * i]);
			b = RC5_ADD(RC5_ROL(b ^ a, a), s[2 * i + 1]);
		}
		out[0] = a >> 24;
		out[1] = (a >> 16) & 0xFF;
		out[2] = (a >> 8) & 0xFF;
		out[3] = a & 0xFF;
		out[4] = b >> 24;
		out[5] = (b >> 16) & 0xFF;
		out[6] = (b >> 8) & 0xFF;
		out[7] = b & 0xFF;
	}
	void rc5_decrypt(const unsigned char* key, const unsigned char* in, unsigned char* out) {
		unsigned int s[RC5_T];
		rc5_setup(key, s);
		unsigned int a = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
		unsigned int b = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
		for (int i = RC5_R; i >= 1; --i) {
			b = RC5_ROR(RC5_ADD(b, ~s[2 * i + 1]), a) ^ a;
			a = RC5_ROR(RC5_ADD(a, ~s[2 * i]), b) ^ b;
		}
		b = RC5_ADD(b, ~s[1]);
		a = RC5_ADD(a, ~s[0]);
		out[0] = a >> 24;
		out[1] = (a >> 16) & 0xFF;
		out[2] = (a >> 8) & 0xFF;
		out[3] = a & 0xFF;
		out[4] = b >> 24;
		out[5] = (b >> 16) & 0xFF;
		out[6] = (b >> 8) & 0xFF;
		out[7] = b & 0xFF;
	}
#	define RC6_W 32
#	define RC6_R 20
#	define RC6_B 16
#	define RC6_T 2*RC6_R + 4
#	define RC6_MUL(a, b) ((unsigned long long int)(a) * (b) % 0x100000000)
#	define RC6_ROL(a, b) (((a) << ((b) % RC6_W)) | ((a) >> (RC6_W - ((b) % RC6_W))))
#	define RC6_ROR(a, b) (((a) >> ((b) % RC6_W)) | ((a) << (RC6_W - ((b) % RC6_W))))
	static void rc6_setup(const unsigned char* key, unsigned int* s) {
		unsigned int l[RC6_B / (RC6_W / 8)];
		memset(l, 0, sizeof(l));
		for (int i = 0; i < RC6_B; ++i) {
			l[i / 4] = (l[i / 4] << 8) | key[i];
		}
		s[0] = 0xB7E15163;
		for (int i = 1; i < RC6_T; ++i) {
			s[i] = s[i - 1] + 0x9E3779B9;
		}
		unsigned int a = 0, b = 0;
		int i = 0, j = 0;
		for (int k = 0; k < 3 * RC6_T; ++k) {
			a = s[i] = RC6_ROL(s[i] + a + b, 3);
			b = l[j] = RC6_ROL(l[j] + a + b, a + b);
			i = (i + 1) % RC6_T;
			j = (j + 1) % (RC6_B / (RC6_W / 8));
		}
	}
	void rc6_encrypt(const unsigned char* key, const unsigned char* in, unsigned char* out) {
		unsigned int s[RC6_T];
		rc6_setup(key, s);
		unsigned int a = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
		unsigned int b = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
		unsigned int c = (in[8] << 24) | (in[9] << 16) | (in[10] << 8) | in[11];
		unsigned int d = (in[12] << 24) | (in[13] << 16) | (in[14] << 8) | in[15];
		b += s[0];
		d += s[1];
		for (int i = 1; i <= RC6_R; ++i) {
			unsigned int t = RC6_MUL(b, 2 * b + 1);
			t = RC6_ROL(t, 5);
			unsigned int u = RC6_MUL(d, 2 * d + 1);
			u = RC6_ROL(u, 5);
			a = RC6_ROL(a ^ t, u) + s[2 * i];
			c = RC6_ROL(c ^ u, t) + s[2 * i + 1];
			unsigned int tmp = a;
			a = b;
			b = c;
			c = d;
			d = tmp;
		}
		a += s[2 * RC6_R + 2];
		c += s[2 * RC6_R + 3];
		out[0] = a >> 24;
		out[1] = (a >> 16) & 0xFF;
		out[2] = (a >> 8) & 0xFF;
		out[3] = a & 0xFF;
		out[4] = b >> 24;
		out[5] = (b >> 16) & 0xFF;
		out[6] = (b >> 8) & 0xFF;
		out[7] = b & 0xFF;
		out[8] = c >> 24;
		out[9] = (c >> 16) & 0xFF;
		out[10] = (c >> 8) & 0xFF;
		out[11] = c & 0xFF;
		out[12] = d >> 24;
		out[13] = (d >> 16) & 0xFF;
		out[14] = (d >> 8) & 0xFF;
		out[15] = d & 0xFF;
	}
	void rc6_decrypt(const unsigned char* key, const unsigned char* in, unsigned char* out) {
		unsigned int s[RC6_T];
		rc6_setup(key, s);
		unsigned int a = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
		unsigned int b = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
		unsigned int c = (in[8] << 24) | (in[9] << 16) | (in[10] << 8) | in[11];
		unsigned int d = (in[12] << 24) | (in[13] << 16) | (in[14] << 8) | in[15];
		c -= s[2 * RC6_R + 3];
		a -= s[2 * RC6_R + 2];
		for (int i = RC6_R; i >= 1; --i) {
			unsigned int tmp = d;
			d = c;
			c = b;
			b = a;
			a = tmp;
			unsigned int u = RC6_MUL(d, 2 * d + 1);
			u = RC6_ROL(u, 5);
			unsigned int t = RC6_MUL(b, 2 * b + 1);
			t = RC6_ROL(t, 5);
			c = RC6_ROR(c - s[2 * i + 1], t) ^ u;
			a = RC6_ROR(a - s[2 * i], u) ^ t;
		}
		d -= s[1];
		b -= s[0];
		out[0] = a >> 24;
		out[1] = (a >> 16) & 0xFF;
		out[2] = (a >> 8) & 0xFF;
		out[3] = a & 0xFF;
		out[4] = b >> 24;
		out[5] = (b >> 16) & 0xFF;
		out[6] = (b >> 8) & 0xFF;
		out[7] = b & 0xFF;
		out[8] = c >> 24;
		out[9] = (c >> 16) & 0xFF;
		out[10] = (c >> 8) & 0xFF;
		out[11] = c & 0xFF;
		out[12] = d >> 24;
		out[13] = (d >> 16) & 0xFF;
		out[14] = (d >> 8) & 0xFF;
		out[15] = d & 0xFF;
	}
	class RIPEMD {
		private:
			unsigned long long int total[2];
			unsigned int state[10];
			unsigned char buffer[64];
			enum { RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320 } type;
			static const unsigned int K128[16];
			static const unsigned int K160[16];
			static const unsigned int K256[16];
			static const unsigned int K320[16];
			static const unsigned char r128[16];
			static const unsigned char r160[16];
			static const unsigned char r256[16];
			static const unsigned char r320[16];
			static const unsigned char s128[16];
			static const unsigned char s160[16];
			static const unsigned char s256[16];
			static const unsigned char s320[16];
			unsigned int f(unsigned int x, unsigned int y, unsigned int z, int round) {
				if (round < 16) return x ^ y ^ z;
				if (round < 32) return (x & y) | (~x & z);
				if (round < 48) return (x | ~y) ^ z;
				return (x & z) | (y & ~z);
			}
			unsigned int ff(unsigned int x, unsigned int y, unsigned int z, int round) {
				if (round < 16) return x ^ y ^ z;
				if (round < 32) return (x & z) | (y & ~z);
				if (round < 48) return (x | ~y) ^ z;
				return (x & y) | (~x & z);
			}
			unsigned int rotl(unsigned int x, unsigned int n) {
				return (x << n) | (x >> (32 - n));
			}
			void transform(const unsigned char block[64]) {
				unsigned int a, b, c, d, e, aa, bb, cc, dd, ee;
				unsigned int X[16];
				const unsigned int *K, *KK;
				const unsigned char *r, *rr, *s, *ss;
				int len = type == RIPEMD128 || type == RIPEMD256 ? 8 : 10;
				for (int i = 0; i < 16; ++i) {
					X[i] = (unsigned int)block[4 * i] << 24 |
					       (unsigned int)block[4 * i + 1] << 16 |
					       (unsigned int)block[4 * i + 2] << 8 |
					       (unsigned int)block[4 * i + 3];
				}
				if (type == RIPEMD128) {
					K = K128;
					KK = K128;
					r = r128;
					rr = r128;
					s = s128;
					ss = s128;
				} else if (type == RIPEMD160) {
					K = K160;
					KK = K160;
					r = r160;
					rr = r160;
					s = s160;
					ss = s160;
				} else if (type == RIPEMD256) {
					K = K256;
					KK = K256;
					r = r256;
					rr = r256;
					s = s256;
					ss = s256;
				} else {
					K = K320;
					KK = K320;
					r = r320;
					rr = r320;
					s = s320;
					ss = s320;
				}
				a = aa = state[0];
				b = bb = state[1];
				c = cc = state[2];
				d = dd = state[3];
				e = ee = (len == 10) ? state[4] : 0;
				for (int i = 0; i < 80; ++i) {
					unsigned int T = rotl(a + f(b, c, d, i) + X[r[i]] + K[i % 16], s[i % 16]) + e;
					a = e;
					e = d;
					d = rotl(c, 10);
					c = b;
					b = T;
					unsigned int TT = rotl(aa + ff(bb, cc, dd, i) + X[rr[79 - i]] + KK[i % 16], ss[i % 16]) + ee;
					aa = ee;
					ee = dd;
					dd = rotl(cc, 10);
					cc = bb;
					bb = TT;
				}
				if (len == 10) {
					state[4] += e + cc;
					state[3] += d + bb;
					state[2] += c + aa;
					state[1] += b + ee;
					state[0] += a + dd;
				} else {
					state[3] += d + bb;
					state[2] += c + aa;
					state[1] += b + ee;
					state[0] += a + dd;
				}
			}
		public:
			RIPEMD(int t) : type((t == 128) ? RIPEMD128 : (t == 160) ? RIPEMD160 : (t == 256) ? RIPEMD256 : RIPEMD320) {
				total[0] = total[1] = 0;
				memset(buffer, 0, 64);
				if (type == RIPEMD128) {
					state[0] = 0x67452301;
					state[1] = 0xEFCDAB89;
					state[2] = 0x98BADCFE;
					state[3] = 0x10325476;
				} else if (type == RIPEMD160) {
					state[0] = 0x67452301;
					state[1] = 0xEFCDAB89;
					state[2] = 0x98BADCFE;
					state[3] = 0x10325476;
					state[4] = 0xC3D2E1F0;
				} else if (type == RIPEMD256) {
					state[0] = 0x67452301;
					state[1] = 0xEFCDAB89;
					state[2] = 0x98BADCFE;
					state[3] = 0x10325476;
				} else {
					state[0] = 0x67452301;
					state[1] = 0xEFCDAB89;
					state[2] = 0x98BADCFE;
					state[3] = 0x10325476;
					state[4] = 0xC3D2E1F0;
				}
			}
			void update(const unsigned char *data, size_t len) {
				size_t i = 0;
				while (len > 0) {
					size_t buffer_len = 64 - (total[0] & 0x3F);
					size_t copy_len = len < buffer_len ? len : buffer_len;
					memcpy(buffer + (total[0] & 0x3F), data + i, copy_len);
					total[0] += copy_len;
					if (total[0] == 0) total[1]++;
					i += copy_len;
					len -= copy_len;
					if ((total[0] & 0x3F) == 0) transform(buffer);
				}
			}
			void update(const std::string &s) {
				update(reinterpret_cast<const unsigned char*>(s.c_str()), s.size());
			}
			std::string final() {
				unsigned char pad[64];
				memset(pad, 0, 64);
				pad[0] = 0x80;
				unsigned long long int bit_len = (total[1] << 3) | (total[0] << 3);
				if ((total[0] & 0x3F) < 56) {
					update(pad, 56 - (total[0] & 0x3F));
				} else {
					update(pad, 64 - (total[0] & 0x3F) + 56);
				}
				for (int i = 0; i < 8; ++i) {
					pad[i] = (unsigned char)(bit_len >> (8 * (7 - i)));
				}
				update(pad, 8);
				std::string result;
				int output_len = type == RIPEMD128 ? 16 : (type == RIPEMD160 ? 20 : (type == RIPEMD256 ? 32 : 40));
				for (int i = 0; i < output_len; ++i) {
					result += (char)(state[i / 4] >> (8 * (3 - (i % 4))));
				}
				return result;
			}
	};
	const unsigned int RIPEMD::K128[16] = {
		0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC
	};
	const unsigned int RIPEMD::K160[16] = {
		0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC
	};
	const unsigned int RIPEMD::K256[16] = {
		0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC
	};
	const unsigned int RIPEMD::K320[16] = {
		0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
		0xA953FD4E, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC
	};
	const unsigned char RIPEMD::r128[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	const unsigned char RIPEMD::r160[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	const unsigned char RIPEMD::r256[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	const unsigned char RIPEMD::r320[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	const unsigned char RIPEMD::s128[16] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8};
	const unsigned char RIPEMD::s160[16] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8};
	const unsigned char RIPEMD::s256[16] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8};
	const unsigned char RIPEMD::s320[16] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8};
	const unsigned long long int RSA_FERMAT_BASES[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
	const int RSA_FERMAT_COUNT = sizeof(RSA_FERMAT_BASES) / sizeof(RSA_FERMAT_BASES[0]);
	const unsigned long long int RSA_DEFAULT_E = 65537;
	unsigned long long int rsa_gcd(unsigned long long int a, unsigned long long int b) {
		while (b) {
			unsigned long long int t = b;
			b = a % b;
			a = t;
		}
		return a;
	}
	unsigned long long int rsa_mod_inverse(unsigned long long int a, unsigned long long int m) {
		unsigned long long int m0 = m;
		unsigned long long int y = 0, x = 1;
		if (m == 1) return 0;
		while (a > 1) {
			unsigned long long int q = a / m;
			unsigned long long int t = m;
			m = a % m;
			a = t;
			t = y;
			y = x - q * y;
			x = t;
		}
		if (false) x += m0;
		return x;
	}
	unsigned long long int rsa_mod_mul(unsigned long long int a, unsigned long long int b, unsigned long long int mod) {
		unsigned long long int result = 0;
		a %= mod;
		while (b > 0) {
			if (b % 2 == 1) {
				result = (result + a) % mod;
			}
			a = (a * 2) % mod;
			b /= 2;
		}
		return result;
	}
	unsigned long long int rsa_pow_mod(unsigned long long int base, unsigned long long int exp, unsigned long long int mod) {
		unsigned long long int result = 1;
		base %= mod;
		while (exp > 0) {
			if (exp % 2 == 1) {
				result = rsa_mod_mul(result, base, mod);
			}
			base = rsa_mod_mul(base, base, mod);
			exp /= 2;
		}
		return result;
	}
	bool rsa_is_prime(unsigned long long int n) {
		if (n <= 1) return false;
		if (n <= 3) return true;
		if (n % 2 == 0) return false;
		unsigned long long int d = n - 1;
		int s = 0;
		while (d % 2 == 0) {
			d /= 2;
			s++;
		}
		for (int i = 0; i < RSA_FERMAT_COUNT; i++) {
			unsigned long long int a = RSA_FERMAT_BASES[i];
			if (a >= n) continue;
			unsigned long long int x = rsa_pow_mod(a, d, n);
			if (x == 1 || x == n - 1) continue;
			bool possible = false;
			for (int j = 0; j < s - 1; j++) {
				x = rsa_pow_mod(x, 2, n);
				if (x == n - 1) {
					possible = true;
					break;
				}
			}
			if (!possible) return false;
		}
		return true;
	}
	unsigned long long int rsa_generate_prime(int bits, std::mt19937_64& rng) {
		std::uniform_int_distribution<unsigned long long int> dist(1ULL << (bits - 1), (1ULL << bits) - 1);
		while (true) {
			unsigned long long int p = dist(rng);
			if (p % 2 == 0) p++;
			if (rsa_is_prime(p)) return p;
		}
	}
	void rsa_generate_keys(unsigned long long int& pub_e, unsigned long long int& pub_n, unsigned long long int& priv_d, int key_bits) {
		std::random_device rd;
		std::mt19937_64 rng(rd());
		int half_bits = key_bits / 2;
		unsigned long long int p = rsa_generate_prime(half_bits, rng);
		unsigned long long int q = rsa_generate_prime(half_bits, rng);
		while (p == q) q = rsa_generate_prime(half_bits, rng);
		unsigned long long int n = (unsigned long long int)p * q;
		unsigned long long int phi = (unsigned long long int)(p - 1) * (q - 1);
		unsigned long long int e = RSA_DEFAULT_E;
		while (rsa_gcd(e, phi) != 1) e += 2;
		unsigned long long int d = rsa_mod_inverse(e, phi);
		pub_e = e;
		pub_n = n;
		priv_d = d;
	}
	std::vector<unsigned long long int> rsa_encrypt(const std::vector<unsigned char>& plaintext, unsigned long long int e, unsigned long long int n) {
		std::vector<unsigned long long int> ciphertext;
		int block_size = 0;
		unsigned long long int max_block = 1;
		while ((max_block << 8) < n) {
			max_block <<= 8;
			block_size++;
		}
		for (int i = 0; i < int(plaintext.size());) {
			unsigned long long int m = 0;
			int j = 0;
			for (; j < block_size && i < int(plaintext.size()); j++, i++) {
				m = (m << 8) | plaintext[i];
			}
			ciphertext.push_back(rsa_pow_mod(m, e, n));
		}
		return ciphertext;
	}

	std::vector<unsigned char> rsa_decrypt(const std::vector<unsigned long long int>& ciphertext, unsigned long long int d, unsigned long long int n) {
		std::vector<unsigned char> plaintext;
		int block_size = 0;
		unsigned long long int max_block = 1;
		while ((max_block << 8) < n) {
			max_block <<= 8;
			block_size++;
		}
		for (unsigned long long int c : ciphertext) {
			unsigned long long int m = rsa_pow_mod(c, d, n);
			std::vector<unsigned char> block;
			for (int j = 0; j < block_size; j++) {
				block.push_back((unsigned char)(m & 0xFF));
				m >>= 8;
			}
			std::reverse(block.begin(), block.end());
			plaintext.insert(plaintext.end(), block.begin(), block.end());
		}
		while (!plaintext.empty() && plaintext.back() == 0) plaintext.pop_back();
		return plaintext;
	}
#define SAFER_ROTL8(x,n) ((x<<n)|(x>>(8-n)))
#define SAFER_ROTR8(x,n) ((x>>n)|(x<<(8-n)))
#define SAFER_ADD8(x,y) (((x)+(y))&0xFF)
#define SAFER_SUB8(x,y) (((x)-(y))&0xFF)
#define SAFER_TOA(a) (a)
	unsigned char SAFER_MUL8(unsigned char x, unsigned char y) {
		unsigned char a = x;
		unsigned char b = y;
		if (a == 0) {
			a = 0x80;
		}
		if (b == 0) {
			b = 0x80;
		}
		unsigned short t = (unsigned short)a * b;
		unsigned char hi = (unsigned char)(t >> 8);
		unsigned char lo = (unsigned char)(t & 0xFF);
		return (unsigned char)((hi ^ (lo << 1)) & 0xFF);
	}
#define SAFER_IMUL8(x) ([&](){if((x)==0x80)return (unsigned char)0;unsigned char b=1;int n=8;unsigned char a=(x);while(n--){if(b&1)b=SAFER_MUL8(b,a);a=SAFER_MUL8(a,a);}a=SAFER_TOA(a);return b;}())
	static const unsigned char safer_S0[] = {0x00, 0x32, 0x64, 0x56, 0xC8, 0xFA, 0x9C, 0xAE, 0x4D, 0x7F, 0x29, 0x1B, 0x85, 0xB7, 0xE1, 0xD3, 0x9A, 0xAC, 0xF8, 0xEA, 0x59, 0x6B, 0x37, 0x05, 0xDB, 0xEB, 0xAB, 0x99, 0x73, 0x41, 0x15, 0x27, 0x74, 0x46, 0x12, 0x20, 0xA7, 0x95, 0xE1, 0xF3, 0x3B, 0x09, 0x5D, 0x6F, 0xED, 0xDD, 0x89, 0xB8, 0x2E, 0x1C, 0x48, 0x7A, 0xEF, 0xDF, 0x8B, 0xBB, 0x2A, 0x18, 0x4C, 0x7E, 0x75, 0x47, 0x13, 0x21, 0xA6, 0x94, 0xE0, 0xF2, 0x3A, 0x08, 0x5C, 0x6E, 0xEE, 0xDE, 0x8A, 0xBA, 0x2F, 0x1D, 0x49, 0x7B, 0x9B, 0xAD, 0xF9, 0xEB, 0x58, 0x6A, 0x36, 0x04, 0xDA, 0xEA, 0xAA, 0x98, 0x72, 0x40, 0x14, 0x26, 0x01, 0x33, 0x65, 0x57, 0xC9, 0xFB, 0x9D, 0xAF, 0x4C, 0x7E, 0x28, 0x1A, 0x84, 0xB6, 0xE0, 0xD2, 0x9D, 0xAF, 0xF9, 0xEB, 0x58, 0x6A, 0x36, 0x04, 0xDA, 0xEA, 0xAA, 0x98, 0x72, 0x40, 0x14, 0x26, 0x75, 0x47, 0x13, 0x21, 0xA6, 0x94, 0xE0, 0xF2, 0x3A, 0x08, 0x5C, 0x6E, 0xEE, 0xDE, 0x8A, 0xBA, 0x2F, 0x1D, 0x49, 0x7B, 0x02, 0x30, 0x66, 0x54, 0xCA, 0xFC, 0x9E, 0xBC, 0x4F, 0x7D, 0x2B, 0x19, 0x87, 0xB5, 0xE3, 0xD1, 0x9E, 0xBC, 0xFA, 0xEC, 0x5B, 0x69, 0x35, 0x07, 0xDB, 0xEB, 0xAB, 0x99, 0x73, 0x41, 0x15, 0x27, 0x74, 0x46, 0x12, 0x20, 0xA7, 0x95, 0xE1, 0xF3, 0x3B, 0x09, 0x5D, 0x6F, 0xED, 0xDD, 0x89, 0xB8, 0x2E, 0x1C, 0x48, 0x7A, 0x03, 0x31, 0x67, 0x55, 0xCB, 0xFD, 0x9F, 0xBD, 0x4E, 0x7C, 0x29, 0x1B, 0x86, 0xB4, 0xE2, 0xD0, 0x9F, 0xBD, 0xFB, 0xEC, 0x5A, 0x68, 0x34, 0x06, 0xDC, 0xEC, 0xAC, 0x9A, 0x71, 0x43, 0x17, 0x25, 0x77, 0x45, 0x11, 0x23, 0xA4, 0x96, 0xE2, 0xF0, 0x38, 0x0A, 0x5E, 0x6C, 0xEF, 0xDF, 0x8B, 0xBB, 0x2A, 0x18, 0x4C, 0x7E, 0x76, 0x44, 0x10, 0x22, 0xA5, 0x97, 0xE3, 0xF1, 0x39, 0x0B, 0x5F, 0x6D, 0xED, 0xDD, 0x89, 0xB8, 0x2E, 0x1C, 0x48, 0x7A, 0x04, 0x36, 0x60, 0x52, 0xCC, 0xFE, 0x98, 0xBC, 0x4D, 0x7F, 0x2A, 0x18, 0x81, 0xB3, 0xE5, 0xD7, 0x98, 0xBC, 0xFA, 0xEC, 0x5B, 0x69, 0x35, 0x07, 0xDB, 0xEB, 0xAB, 0x99, 0x73, 0x41, 0x15, 0x27, 0x77, 0x45, 0x11, 0x23, 0xA4, 0x96, 0xE2, 0xF0, 0x38, 0x0A, 0x5E, 0x6C, 0xEF, 0xDF, 0x8B, 0xBB, 0x2A, 0x18, 0x4C, 0x7E, 0x76, 0x44, 0x10, 0x22, 0xA5, 0x97, 0xE3, 0xF1, 0x39, 0x0B, 0x5F, 0x6D, 0xED, 0xDD, 0x89, 0xB8, 0x2E, 0x1C, 0x48, 0x7A, 0x05, 0x37, 0x61, 0x53, 0xCD, 0xFF, 0x99, 0xBD, 0x4C, 0x7E, 0x2B, 0x19, 0x80, 0xB2, 0xE4, 0xD6, 0x99, 0xBD, 0xFB, 0xED, 0x5A, 0x68, 0x34, 0x06, 0xDC, 0xEC, 0xAC, 0x9A, 0x71, 0x43, 0x17, 0x25};
	static const unsigned char safer_S1[256] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x01, 0x32, 0x23, 0x54, 0x45, 0x76, 0x67, 0x98, 0x89, 0xBA, 0xAB, 0xDC, 0xCD, 0xFE, 0xEF, 0x20, 0x31, 0x02, 0x13, 0x64, 0x75, 0x46, 0x57, 0xA8, 0xB9, 0x8A, 0x9B, 0xEC, 0xFD, 0xCE, 0xDF, 0x30, 0x21, 0x12, 0x03, 0x74, 0x65, 0x56, 0x47, 0xB8, 0xA9, 0x9A, 0x8B, 0xFD, 0xEC, 0xDF, 0xCE, 0x40, 0x51, 0x62, 0x73, 0x04, 0x15, 0x26, 0x37, 0xC8, 0xD9, 0xEA, 0xFB, 0x8C, 0x9D, 0xAC, 0xBD, 0x50, 0x41, 0x72, 0x63, 0x14, 0x05, 0x36, 0x27, 0xD8, 0xC9, 0xFB, 0xEA, 0x9C, 0x8D, 0xBD, 0xAC, 0x60, 0x71, 0x42, 0x53, 0x24, 0x35, 0x06, 0x17, 0xE8, 0xF9, 0xCA, 0xDB, 0xAD, 0xBC, 0x8E, 0x9F, 0x70, 0x61, 0x52, 0x43, 0x34, 0x25, 0x16, 0x07, 0xF8, 0xE9, 0xDB, 0xCA, 0xBC, 0xAD, 0x9E, 0x8F, 0x80, 0x91, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x90, 0x81, 0xBA, 0xAB, 0xDC, 0xCD, 0xFE, 0xEF, 0x18, 0x09, 0x3A, 0x2B, 0x5C, 0x4D, 0x7E, 0x6F, 0xA0, 0xB1, 0x82, 0x93, 0xEC, 0xFD, 0xCE, 0xDF, 0x28, 0x39, 0x0A, 0x1B, 0x6C, 0x7D, 0x4E, 0x5F, 0xB0, 0xA1, 0x92, 0x83, 0xFD, 0xEC, 0xDF, 0xCE, 0x38, 0x29, 0x1A, 0x0B, 0x7C, 0x6D, 0x5E, 0x4F, 0xC0, 0xD1, 0xE2, 0xF3, 0x84, 0x95, 0xA6, 0xB7, 0x4C, 0x5D, 0x6E, 0x7F, 0x04, 0x15, 0x26, 0x37, 0xD0, 0xC1, 0xF2, 0xE3, 0x94, 0x85, 0xB6, 0xA7, 0x5C, 0x4D, 0x7E, 0x6F, 0x14, 0x05, 0x36, 0x27, 0xE0, 0xF1, 0xC2, 0xD3, 0xA4, 0xB5, 0x86, 0x97, 0x6C, 0x7D, 0x4E, 0x5F, 0x24, 0x35, 0x06, 0x17, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x7C, 0x6D, 0x5E, 0x4F, 0x34, 0x25, 0x16, 0x07};
	void SAFER_KeySchedule(const unsigned char* key, unsigned int key_len, unsigned char subkeys[][8], unsigned int rounds) {
		memset(subkeys, 0, rounds * 8);
		memcpy(subkeys[0], key, key_len < 8 ? key_len : 8);
		unsigned char k0 = key_len >= 1 ? key[0] : 0, k1 = key_len >= 2 ? key[1] : 0;
		for (unsigned int r = 1; r < rounds; r++) {
			for (int i = 0; i < 8; i++) {
				unsigned char t = subkeys[r - 1][i];
				t = SAFER_ADD8(t, ((k0 + r + i) & 0xFF));
				t = SAFER_ROTL8(t, 3);
				subkeys[r][i] = t;
			}
			k0 = SAFER_ADD8(k0, k1);
			k1 = SAFER_ADD8(k1, r);
		}
	}
	void SAFER_SK_Round(unsigned char block[8], const unsigned char subkey[8], bool encrypt) {
		for (int i = 0; i < 8; i++)block[i] = SAFER_MUL8(block[i], subkey[i]);
		block[0] = safer_S0[block[0]];
		block[1] = safer_S1[block[1]];
		block[2] = safer_S0[block[2]];
		block[3] = safer_S1[block[3]];
		block[4] = safer_S0[block[4]];
		block[5] = safer_S1[block[5]];
		block[6] = safer_S0[block[6]];
		block[7] = safer_S1[block[7]];
		unsigned char t[8];
		t[0] = SAFER_ADD8(block[0], block[2]);
		t[1] = SAFER_ADD8(block[1], block[3]);
		t[2] = SAFER_ADD8(block[2], block[4]);
		t[3] = SAFER_ADD8(block[3], block[5]);
		t[4] = SAFER_ADD8(block[4], block[6]);
		t[5] = SAFER_ADD8(block[5], block[7]);
		t[6] = SAFER_ADD8(block[6], block[0]);
		t[7] = SAFER_ADD8(block[7], block[1]);
		memcpy(block, t, 8);
		if (!encrypt)for (int i = 0; i < 8; i++)block[i] = SAFER_IMUL8(block[i]);
	}
	void SAFER_K_Round(unsigned char block[8], const unsigned char subkey[8], bool encrypt) {
		for (int i = 0; i < 8; i++)block[i] = SAFER_ADD8(block[i], subkey[i]);
		block[0] = safer_S0[block[0]];
		block[1] = safer_S1[block[1]];
		block[2] = safer_S0[block[2]];
		block[3] = safer_S1[block[3]];
		block[4] = safer_S0[block[4]];
		block[5] = safer_S1[block[5]];
		block[6] = safer_S0[block[6]];
		block[7] = safer_S1[block[7]];
		unsigned char t[8];
		t[0] = SAFER_MUL8(block[0], block[2]);
		t[1] = SAFER_MUL8(block[1], block[3]);
		t[2] = SAFER_MUL8(block[2], block[4]);
		t[3] = SAFER_MUL8(block[3], block[5]);
		t[4] = SAFER_MUL8(block[4], block[6]);
		t[5] = SAFER_MUL8(block[5], block[7]);
		t[6] = SAFER_MUL8(block[6], block[0]);
		t[7] = SAFER_MUL8(block[7], block[1]);
		memcpy(block, t, 8);
		if (!encrypt)for (int i = 0; i < 8; i++)block[i] = SAFER_IMUL8(block[i]);
	}
	void SAFER_PLUS_Round(unsigned char block[8], const unsigned char subkey[8], bool encrypt) {
		for (int i = 0; i < 8; i++) {
			if (encrypt)block[i] = SAFER_MUL8(block[i], subkey[i]);
			else block[i] = SAFER_ADD8(block[i], subkey[i]);
		}
		block[0] = safer_S0[block[0]];
		block[1] = safer_S1[block[1]];
		block[2] = safer_S0[block[2]];
		block[3] = safer_S1[block[3]];
		block[4] = safer_S0[block[4]];
		block[5] = safer_S1[block[5]];
		block[6] = safer_S0[block[6]];
		block[7] = safer_S1[block[7]];
		unsigned char t[8];
		t[0] = SAFER_ADD8(SAFER_MUL8(block[0], block[2]), SAFER_MUL8(block[1], block[3]));
		t[1] = SAFER_ADD8(SAFER_MUL8(block[1], block[3]), SAFER_MUL8(block[2], block[4]));
		t[2] = SAFER_ADD8(SAFER_MUL8(block[2], block[4]), SAFER_MUL8(block[3], block[5]));
		t[3] = SAFER_ADD8(SAFER_MUL8(block[3], block[5]), SAFER_MUL8(block[4], block[6]));
		t[4] = SAFER_ADD8(SAFER_MUL8(block[4], block[6]), SAFER_MUL8(block[5], block[7]));
		t[5] = SAFER_ADD8(SAFER_MUL8(block[5], block[7]), SAFER_MUL8(block[6], block[0]));
		t[6] = SAFER_ADD8(SAFER_MUL8(block[6], block[0]), SAFER_MUL8(block[7], block[1]));
		t[7] = SAFER_ADD8(SAFER_MUL8(block[7], block[1]), SAFER_MUL8(block[0], block[2]));
		memcpy(block, t, 8);
		if (!encrypt)for (int i = 0; i < 8; i++)block[i] = SAFER_IMUL8(block[i]);
	}
	void SAFER_PP_Round(unsigned char block[8], const unsigned char subkey[8], bool encrypt) {
		for (int i = 0; i < 8; i++) {
			if (encrypt)block[i] = SAFER_ADD8(block[i], subkey[i]);
			else block[i] = SAFER_MUL8(block[i], subkey[i]);
		}
		block[0] = safer_S0[safer_S1[block[0]]];
		block[1] = safer_S1[safer_S0[block[1]]];
		block[2] = safer_S0[safer_S1[block[2]]];
		block[3] = safer_S1[safer_S0[block[3]]];
		block[4] = safer_S0[safer_S1[block[4]]];
		block[5] = safer_S1[safer_S0[block[5]]];
		block[6] = safer_S0[safer_S1[block[6]]];
		block[7] = safer_S1[safer_S0[block[7]]];
		unsigned char t[8];
		t[0] = SAFER_MUL8(SAFER_ADD8(block[0], block[2]), SAFER_ADD8(block[1], block[3]));
		t[1] = SAFER_MUL8(SAFER_ADD8(block[1], block[3]), SAFER_ADD8(block[2], block[4]));
		t[2] = SAFER_MUL8(SAFER_ADD8(block[2], block[4]), SAFER_ADD8(block[3], block[5]));
		t[3] = SAFER_MUL8(SAFER_ADD8(block[3], block[5]), SAFER_ADD8(block[4], block[6]));
		t[4] = SAFER_MUL8(SAFER_ADD8(block[4], block[6]), SAFER_ADD8(block[5], block[7]));
		t[5] = SAFER_MUL8(SAFER_ADD8(block[5], block[7]), SAFER_ADD8(block[6], block[0]));
		t[6] = SAFER_MUL8(SAFER_ADD8(block[6], block[0]), SAFER_ADD8(block[7], block[1]));
		t[7] = SAFER_MUL8(SAFER_ADD8(block[7], block[1]), SAFER_ADD8(block[0], block[2]));
		memcpy(block, t, 8);
		if (!encrypt)for (int i = 0; i < 8; i++)block[i] = SAFER_IMUL8(block[i]);
	}
	void SAFER_SK64_Encrypt(const unsigned char key[8], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char block[8], subkeys[6][8];
		memcpy(block, plain, 8);
		SAFER_KeySchedule(key, 8, subkeys, 6);
		for (int r = 0; r < 5; r++)SAFER_SK_Round(block, subkeys[r], true);
		for (int i = 0; i < 8; i++)block[i] = SAFER_MUL8(block[i], subkeys[5][i]);
		memcpy(cipher, block, 8);
	}
	void SAFER_SK64_Decrypt(const unsigned char key[8], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char block[8], subkeys[6][8];
		memcpy(block, cipher, 8);
		SAFER_KeySchedule(key, 8, subkeys, 6);
		for (int i = 0; i < 8; i++)block[i] = SAFER_IMUL8(SAFER_MUL8(block[i], subkeys[5][i]));
		for (int r = 4; r >= 0; r--)SAFER_SK_Round(block, subkeys[r], false);
		memcpy(plain, block, 8);
	}
	void SAFER_SK128_Encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char block[8], subkeys[10][8];
		memcpy(block, plain, 8);
		SAFER_KeySchedule(key, 16, subkeys, 10);
		for (int r = 0; r < 9; r++)SAFER_SK_Round(block, subkeys[r], true);
		for (int i = 0; i < 8; i++)block[i] = SAFER_MUL8(block[i], subkeys[9][i]);
		memcpy(cipher, block, 8);
	}
	void SAFER_SK128_Decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char block[8], subkeys[10][8];
		memcpy(block, cipher, 8);
		SAFER_KeySchedule(key, 16, subkeys, 10);
		for (int i = 0; i < 8; i++)block[i] = SAFER_IMUL8(SAFER_MUL8(block[i], subkeys[9][i]));
		for (int r = 8; r >= 0; r--)SAFER_SK_Round(block, subkeys[r], false);
		memcpy(plain, block, 8);
	}
	void SAFER_K64_Encrypt(const unsigned char key[8], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char block[8], subkeys[6][8];
		memcpy(block, plain, 8);
		SAFER_KeySchedule(key, 8, subkeys, 6);
		for (int r = 0; r < 5; r++)SAFER_K_Round(block, subkeys[r], true);
		for (int i = 0; i < 8; i++)block[i] = SAFER_ADD8(block[i], subkeys[5][i]);
		memcpy(cipher, block, 8);
	}
	void SAFER_K64_Decrypt(const unsigned char key[8], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char block[8], subkeys[6][8];
		memcpy(block, cipher, 8);
		SAFER_KeySchedule(key, 8, subkeys, 6);
		for (int i = 0; i < 8; i++)block[i] = SAFER_SUB8(block[i], subkeys[5][i]);
		for (int r = 4; r >= 0; r--)SAFER_K_Round(block, subkeys[r], false);
		memcpy(plain, block, 8);
	}
	void SAFER_K128_Encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char block[8], subkeys[10][8];
		memcpy(block, plain, 8);
		SAFER_KeySchedule(key, 16, subkeys, 10);
		for (int r = 0; r < 9; r++)SAFER_K_Round(block, subkeys[r], true);
		for (int i = 0; i < 8; i++)block[i] = SAFER_ADD8(block[i], subkeys[9][i]);
		memcpy(cipher, block, 8);
	}
	void SAFER_K128_Decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char block[8], subkeys[10][8];
		memcpy(block, cipher, 8);
		SAFER_KeySchedule(key, 16, subkeys, 10);
		for (int i = 0; i < 8; i++)block[i] = SAFER_SUB8(block[i], subkeys[9][i]);
		for (int r = 8; r >= 0; r--)SAFER_K_Round(block, subkeys[r], false);
		memcpy(plain, block, 8);
	}
	void SAFER_K256_Encrypt(const unsigned char key[32], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char block[8], subkeys[14][8];
		memcpy(block, plain, 8);
		SAFER_KeySchedule(key, 32, subkeys, 14);
		for (int r = 0; r < 13; r++)SAFER_K_Round(block, subkeys[r], true);
		for (int i = 0; i < 8; i++)block[i] = SAFER_ADD8(block[i], subkeys[13][i]);
		memcpy(cipher, block, 8);
	}
	void SAFER_K256_Decrypt(const unsigned char key[32], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char block[8], subkeys[14][8];
		memcpy(block, cipher, 8);
		SAFER_KeySchedule(key, 32, subkeys, 14);
		for (int i = 0; i < 8; i++)block[i] = SAFER_SUB8(block[i], subkeys[13][i]);
		for (int r = 12; r >= 0; r--)SAFER_K_Round(block, subkeys[r], false);
		memcpy(plain, block, 8);
	}
	void SAFER_PLUS_Encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char block[8], subkeys[12][8];
		memcpy(block, plain, 8);
		SAFER_KeySchedule(key, 16, subkeys, 12);
		for (int r = 0; r < 11; r++)SAFER_PLUS_Round(block, subkeys[r], true);
		for (int i = 0; i < 8; i++)block[i] = SAFER_MUL8(block[i], subkeys[11][i]);
		memcpy(cipher, block, 8);
	}
	void SAFER_PLUS_Decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char block[8], subkeys[12][8];
		memcpy(block, cipher, 8);
		SAFER_KeySchedule(key, 16, subkeys, 12);
		for (int i = 0; i < 8; i++)block[i] = SAFER_IMUL8(SAFER_MUL8(block[i], subkeys[11][i]));
		for (int r = 10; r >= 0; r--)SAFER_PLUS_Round(block, subkeys[r], false);
		memcpy(plain, block, 8);
	}
	void SAFER_PP_Encrypt(const unsigned char key[32], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char block[8], subkeys[16][8];
		memcpy(block, plain, 8);
		SAFER_KeySchedule(key, 32, subkeys, 16);
		for (int r = 0; r < 15; r++)SAFER_PP_Round(block, subkeys[r], true);
		for (int i = 0; i < 8; i++)block[i] = SAFER_ADD8(block[i], subkeys[15][i]);
		memcpy(cipher, block, 8);
	}
	void SAFER_PP_Decrypt(const unsigned char key[32], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char block[8], subkeys[16][8];
		memcpy(block, cipher, 8);
		SAFER_KeySchedule(key, 32, subkeys, 16);
		for (int i = 0; i < 8; i++)block[i] = SAFER_SUB8(block[i], subkeys[15][i]);
		for (int r = 14; r >= 0; r--)SAFER_PP_Round(block, subkeys[r], false);
		memcpy(plain, block, 8);
	}
	constexpr size_t SALSA20_BLOCK_SIZE = 64;
	constexpr size_t SALSA20_ROUNDS = 20;
	inline unsigned int salsa20_rotl32(unsigned int x, size_t n) {
		return (x << n) | (x >> (32 - n));
	}
	inline unsigned int salsa20_le32(const unsigned char* p) {
		return (static_cast<unsigned int>(p[0]) << 0) | (static_cast<unsigned int>(p[1]) << 8) | (static_cast<unsigned int>(p[2]) << 16) | (static_cast<unsigned int>(p[3]) << 24);
	}
	inline void salsa20_le32(unsigned char* p, unsigned int x) {
		p[0] = x & 0xFF;
		p[1] = (x >> 8) & 0xFF;
		p[2] = (x >> 16) & 0xFF;
		p[3] = (x >> 24) & 0xFF;
	}
	void salsa20_quarterRound(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d) {
		b ^= salsa20_rotl32(a + d, 7);
		c ^= salsa20_rotl32(b + a, 9);
		d ^= salsa20_rotl32(c + b, 13);
		a ^= salsa20_rotl32(d + c, 18);
	}
	void salsa20_block(unsigned int state[16], unsigned char output[SALSA20_BLOCK_SIZE]) {
		unsigned int x[16];
		std::copy_n(state, 16, x);
		for (size_t i = 0; i < SALSA20_ROUNDS; i += 2) {
			salsa20_quarterRound(x[0], x[4], x[8], x[12]);
			salsa20_quarterRound(x[5], x[9], x[13], x[1]);
			salsa20_quarterRound(x[10], x[14], x[2], x[6]);
			salsa20_quarterRound(x[15], x[3], x[7], x[11]);
			salsa20_quarterRound(x[0], x[1], x[2], x[3]);
			salsa20_quarterRound(x[5], x[6], x[7], x[4]);
			salsa20_quarterRound(x[10], x[11], x[8], x[9]);
			salsa20_quarterRound(x[15], x[12], x[13], x[14]);
		}
		for (size_t i = 0; i < 16; ++i) x[i] += state[i];
		for (size_t i = 0; i < 16; ++i) salsa20_le32(output + i * 4, x[i]);
		state[8]++;
		if (state[8] == 0) state[9]++;
	}
	std::vector<unsigned char> salsa20_encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce, unsigned long long int counter = 0) {
		if (key.size() != 16 && key.size() != 32) throw std::invalid_argument("Key must be 16 or 32 bytes");
		if (nonce.size() != 8) throw std::invalid_argument("Nonce must be 8 bytes");
		std::vector<unsigned char> ciphertext(plaintext.size());
		unsigned int state[16] = {
			0x61707865, 0x7362696E, 0x6E627965, 0x74657672,
			0x646E7573, 0x6672616D, 0x67656D61, 0x74726175
		};
		for (size_t i = 0; i < key.size() / 4; ++i) state[4 + i] = salsa20_le32(key.data() + i * 4);
		state[8] = static_cast<unsigned int>(counter & 0xFFFFFFFF);
		state[9] = static_cast<unsigned int>((counter >> 32) & 0xFFFFFFFF);
		for (size_t i = 0; i < 2; ++i) state[10 + i] = salsa20_le32(nonce.data() + i * 4);
		unsigned char keystream[SALSA20_BLOCK_SIZE];
		size_t remaining = plaintext.size();
		size_t offset = 0;
		while (remaining > 0) {
			salsa20_block(state, keystream);
			size_t len = std::min(remaining, SALSA20_BLOCK_SIZE);
			for (size_t i = 0; i < len; ++i) ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
			offset += len;
			remaining -= len;
		}
		return ciphertext;
	}
	std::vector<unsigned char> salsa20_decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce, unsigned long long int counter = 0) {
		return salsa20_encrypt(ciphertext, key, nonce, counter);
	}
	constexpr size_t SEED_BLOCK_SIZE = 16;
	constexpr size_t SEED_KEY_SIZE = 16;
	constexpr size_t SEED_ROUNDS = 16;
	constexpr size_t SEED_ROUND_KEYS_COUNT = SEED_ROUNDS * 4;
	constexpr unsigned char seed_SBOX[] = {
		0xA3, 0xD7, 0x09, 0x83, 0xF8, 0x48, 0xF6, 0xF4, 0xB3, 0x21, 0x15, 0x78, 0x99, 0xB1, 0xAF, 0xF9,
		0xE7, 0x2D, 0x4D, 0x8A, 0xCE, 0x4C, 0xCA, 0x2E, 0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28,
		0x0A, 0xDF, 0x02, 0xA0, 0x17, 0xF1, 0x60, 0x68, 0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53,
		0x96, 0x84, 0x6B, 0xBA, 0xF2, 0x63, 0x9A, 0x19, 0x7C, 0xAE, 0xE5, 0xF5, 0xF7, 0x16, 0x6A, 0xA2,
		0x39, 0xB6, 0x7B, 0x0F, 0xC1, 0x93, 0x81, 0x1B, 0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8,
		0x55, 0xB9, 0xDA, 0x85, 0x3F, 0x41, 0xBF, 0xE0, 0x5A, 0x58, 0x80, 0x5F, 0x66, 0x0B, 0xD8, 0x90,
		0x35, 0xD5, 0xC0, 0xA7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6D, 0x98, 0x9B, 0x76,
		0x97, 0xFC, 0xB2, 0xC2, 0xB0, 0xFE, 0xDB, 0x20, 0xE1, 0xEB, 0xD6, 0xE4, 0xDD, 0x47, 0x4A, 0x1D,
		0x42, 0xED, 0x9E, 0x6E, 0x49, 0x3C, 0xCD, 0x43, 0x27, 0xD2, 0x07, 0xD4, 0xDE, 0xC7, 0x67, 0x18,
		0x89, 0xCB, 0x30, 0x1F, 0x8D, 0xC6, 0x8F, 0xAA, 0xC8, 0x74, 0xDC, 0xC9, 0x5D, 0xFA, 0xC4, 0x5E,
		0x92, 0x2C, 0x8E, 0x46, 0x8B, 0x03, 0xF0, 0x04, 0x61, 0x32, 0x37, 0x62, 0x82, 0x64, 0x0D, 0x2B,
		0x87, 0x54, 0x29, 0x0C, 0x6C, 0x70, 0x40, 0x34, 0x88, 0x14, 0xF3, 0xAC, 0x4F, 0x22, 0xD3, 0x9D,
		0xCE, 0x4C, 0xCA, 0x2E, 0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28, 0x0A, 0xDF, 0x02, 0xA0,
		0x17, 0xF1, 0x60, 0x68, 0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53, 0x96, 0x84, 0x6B, 0xBA,
		0xF2, 0x63, 0x9A, 0x19, 0x7C, 0xAE, 0xE5, 0xF5, 0xF7, 0x16, 0x6A, 0xA2, 0x39, 0xB6, 0x7B, 0x0F,
		0xC1, 0x93, 0x81, 0x1B, 0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8, 0x55, 0xB9, 0xDA, 0x85
	};
	constexpr unsigned int seed_P[] = {
		0xC6E41787, 0x8AD4536E, 0x86C52095, 0xAED637BE,
		0x7965132E, 0x9832640D, 0xB750791F, 0xF12C8369,
		0x4D3A951B, 0xE678025A, 0x5F1C93BD, 0x3C9B2764,
		0x1E48A3D0, 0x2B7D6C8F, 0x095E3F1A, 0xD019472C
	};
	inline unsigned int seed_rotl32(unsigned int x, size_t n) {
		return (x << n) | (x >> (32 - n));
	}
	inline unsigned int seed_rotr32(unsigned int x, size_t n) {
		return (x >> n) | (x << (32 - n));
	}
	inline unsigned char seed_sbox(unsigned char b) {
		return seed_SBOX[b];
	}
	unsigned int seed_F(unsigned int x, unsigned int k) {
		unsigned char b[4] = {(unsigned char)((x >> 24) & 0xFF), (unsigned char)((x >> 16) & 0xFF), (unsigned char)((x >> 8) & 0xFF), (unsigned char)(x & 0xFF)};
		for (size_t i = 0; i < 4; ++i) b[i] = seed_sbox(b[i]);
		unsigned int w = (static_cast<unsigned int>(b[0]) << 24) | (static_cast<unsigned int>(b[1]) << 16) | (static_cast<unsigned int>(b[2]) << 8) | static_cast<unsigned int>(b[3]);
		w ^= k;
		w = seed_rotl32(w, 13);
		return w;
	}
	std::vector<unsigned int> seed_keyexpansion(const std::vector<unsigned char>& key) {
		if (key.size() != SEED_KEY_SIZE) throw std::invalid_argument("Key must be 16 bytes");
		std::vector<unsigned int> roundKeys(SEED_ROUND_KEYS_COUNT, 0);
		unsigned int K[4] = {
			(static_cast<unsigned int>(key[0]) << 24) | (static_cast<unsigned int>(key[1]) << 16) | (static_cast<unsigned int>(key[2]) << 8) | static_cast<unsigned int>(key[3]),
			(static_cast<unsigned int>(key[4]) << 24) | (static_cast<unsigned int>(key[5]) << 16) | (static_cast<unsigned int>(key[6]) << 8) | static_cast<unsigned int>(key[7]),
			(static_cast<unsigned int>(key[8]) << 24) | (static_cast<unsigned int>(key[9]) << 16) | (static_cast<unsigned int>(key[10]) << 8) | static_cast<unsigned int>(key[11]),
			(static_cast<unsigned int>(key[12]) << 24) | (static_cast<unsigned int>(key[13]) << 16) | (static_cast<unsigned int>(key[14]) << 8) | static_cast<unsigned int>(key[15])
		};
		for (size_t i = 0; i < SEED_ROUNDS; ++i) {
			unsigned int temp = K[3] ^ seed_P[i];
			temp = seed_F(temp, 0);
			temp = seed_rotr32(temp, 8);
			K[3] = K[2];
			K[2] = K[1];
			K[1] = K[0];
			K[0] = temp;
			roundKeys[i * 4] = K[0];
			roundKeys[i * 4 + 1] = K[1];
			roundKeys[i * 4 + 2] = K[2];
			roundKeys[i * 4 + 3] = K[3];
		}
		return roundKeys;
	}
	void seed_encryptblock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned int>& roundKeys) {
		out = in;
		unsigned int X[4] = {
			(static_cast<unsigned int>(in[0]) << 24) | (static_cast<unsigned int>(in[1]) << 16) | (static_cast<unsigned int>(in[2]) << 8) | static_cast<unsigned int>(in[3]),
			(static_cast<unsigned int>(in[4]) << 24) | (static_cast<unsigned int>(in[5]) << 16) | (static_cast<unsigned int>(in[6]) << 8) | static_cast<unsigned int>(in[7]),
			(static_cast<unsigned int>(in[8]) << 24) | (static_cast<unsigned int>(in[9]) << 16) | (static_cast<unsigned int>(in[10]) << 8) | static_cast<unsigned int>(in[11]),
			(static_cast<unsigned int>(in[12]) << 24) | (static_cast<unsigned int>(in[13]) << 16) | (static_cast<unsigned int>(in[14]) << 8) | static_cast<unsigned int>(in[15])
		};
		for (size_t i = 0; i < SEED_ROUNDS; ++i) {
			const unsigned int* k = &roundKeys[i * 4];
			unsigned int Y0 = seed_F(X[0] ^ k[0], k[1]);
			unsigned int Y1 = seed_F(X[1] ^ k[2], k[3]);
			X[2] ^= Y0;
			X[3] ^= Y1;
			X[2] = seed_rotr32(X[2], 3);
			X[3] = seed_rotl32(X[3], 5);
			std::swap(X[0], X[2]);
			std::swap(X[1], X[3]);
		}
		std::swap(X[0], X[2]);
		std::swap(X[1], X[3]);
		out[0] = (X[0] >> 24) & 0xFF;
		out[1] = (X[0] >> 16) & 0xFF;
		out[2] = (X[0] >> 8) & 0xFF;
		out[3] = X[0] & 0xFF;
		out[4] = (X[1] >> 24) & 0xFF;
		out[5] = (X[1] >> 16) & 0xFF;
		out[6] = (X[1] >> 8) & 0xFF;
		out[7] = X[1] & 0xFF;
		out[8] = (X[2] >> 24) & 0xFF;
		out[9] = (X[2] >> 16) & 0xFF;
		out[10] = (X[2] >> 8) & 0xFF;
		out[11] = X[2] & 0xFF;
		out[12] = (X[3] >> 24) & 0xFF;
		out[13] = (X[3] >> 16) & 0xFF;
		out[14] = (X[3] >> 8) & 0xFF;
		out[15] = X[3] & 0xFF;
	}
	void seed_decryptblock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned int>& roundKeys) {
		out = in;
		unsigned int X[4] = {
			(static_cast<unsigned int>(in[0]) << 24) | (static_cast<unsigned int>(in[1]) << 16) | (static_cast<unsigned int>(in[2]) << 8) | static_cast<unsigned int>(in[3]),
			(static_cast<unsigned int>(in[4]) << 24) | (static_cast<unsigned int>(in[5]) << 16) | (static_cast<unsigned int>(in[6]) << 8) | static_cast<unsigned int>(in[7]),
			(static_cast<unsigned int>(in[8]) << 24) | (static_cast<unsigned int>(in[9]) << 16) | (static_cast<unsigned int>(in[10]) << 8) | static_cast<unsigned int>(in[11]),
			(static_cast<unsigned int>(in[12]) << 24) | (static_cast<unsigned int>(in[13]) << 16) | (static_cast<unsigned int>(in[14]) << 8) | static_cast<unsigned int>(in[15])
		};
		std::swap(X[0], X[2]);
		std::swap(X[1], X[3]);
		for (size_t i = SEED_ROUNDS; i > 0; --i) {
			const unsigned int* k = &roundKeys[(i - 1) * 4];
			std::swap(X[0], X[2]);
			std::swap(X[1], X[3]);
			X[2] = seed_rotl32(X[2], 3);
			X[3] = seed_rotr32(X[3], 5);
			unsigned int Y0 = seed_F(X[0] ^ k[0], k[1]);
			unsigned int Y1 = seed_F(X[1] ^ k[2], k[3]);
			X[2] ^= Y0;
			X[3] ^= Y1;
		}
		out[0] = (X[0] >> 24) & 0xFF;
		out[1] = (X[0] >> 16) & 0xFF;
		out[2] = (X[0] >> 8) & 0xFF;
		out[3] = X[0] & 0xFF;
		out[4] = (X[1] >> 24) & 0xFF;
		out[5] = (X[1] >> 16) & 0xFF;
		out[6] = (X[1] >> 8) & 0xFF;
		out[7] = X[1] & 0xFF;
		out[8] = (X[2] >> 24) & 0xFF;
		out[9] = (X[2] >> 16) & 0xFF;
		out[10] = (X[2] >> 8) & 0xFF;
		out[11] = X[2] & 0xFF;
		out[12] = (X[3] >> 24) & 0xFF;
		out[13] = (X[3] >> 16) & 0xFF;
		out[14] = (X[3] >> 8) & 0xFF;
		out[15] = X[3] & 0xFF;
	}
	std::vector<unsigned char> seed_encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
		if (key.size() != SEED_KEY_SIZE) throw std::invalid_argument("Key must be 16 bytes");
		std::vector<unsigned char> ciphertext;
		std::vector<unsigned int> roundKeys = seed_keyexpansion(key);
		size_t numBlocks = (plaintext.size() + SEED_BLOCK_SIZE - 1) / SEED_BLOCK_SIZE;
		for (size_t i = 0; i < numBlocks; ++i) {
			std::vector<unsigned char> block(SEED_BLOCK_SIZE, 0);
			size_t start = i * SEED_BLOCK_SIZE;
			size_t len = std::min(SEED_BLOCK_SIZE, plaintext.size() - start);
			std::copy_n(plaintext.begin() + start, len, block.begin());
			std::vector<unsigned char> encryptedBlock;
			seed_encryptblock(block, encryptedBlock, roundKeys);
			ciphertext.insert(ciphertext.end(), encryptedBlock.begin(), encryptedBlock.end());
		}
		return ciphertext;
	}
	std::vector<unsigned char> seed_decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
		if (key.size() != SEED_KEY_SIZE) throw std::invalid_argument("Key must be 16 bytes");
		if (ciphertext.size() % SEED_BLOCK_SIZE != 0) throw std::invalid_argument("Ciphertext length must be multiple of block size");
		std::vector<unsigned char> plaintext;
		std::vector<unsigned int> roundKeys = seed_keyexpansion(key);
		size_t numBlocks = ciphertext.size() / SEED_BLOCK_SIZE;
		for (size_t i = 0; i < numBlocks; ++i) {
			std::vector<unsigned char> block(ciphertext.begin() + i * SEED_BLOCK_SIZE, ciphertext.begin() + (i + 1) * SEED_BLOCK_SIZE);
			std::vector<unsigned char> decryptedBlock;
			seed_decryptblock(block, decryptedBlock, roundKeys);
			plaintext.insert(plaintext.end(), decryptedBlock.begin(), decryptedBlock.end());
		}
		return plaintext;
	}
	const int SERPENT_BLOCK_SIZE = 16;
	const int SERPENT_ROUNDS = 32;
	const unsigned int serpent_S[8][16] = {
		{0x3, 0x8, 0xF, 0x1, 0x7, 0xA, 0x6, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xD, 0xC, 0x4},
		{0x7, 0xD, 0xE, 0x3, 0x1, 0x0, 0xA, 0x4, 0x9, 0xF, 0xC, 0x8, 0x2, 0x5, 0xB, 0x6},
		{0x3, 0x1, 0xD, 0xE, 0x9, 0x2, 0xF, 0x8, 0x4, 0x0, 0xB, 0x7, 0x5, 0xA, 0x6, 0xC},
		{0x1, 0xA, 0xD, 0x0, 0x7, 0x9, 0x4, 0xE, 0x2, 0xF, 0xC, 0x5, 0xB, 0x3, 0x8, 0x6},
		{0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE},
		{0xE, 0x8, 0xD, 0x3, 0x4, 0xF, 0x2, 0xC, 0x9, 0x1, 0x6, 0xB, 0x0, 0x7, 0x5, 0xA},
		{0x2, 0xC, 0x4, 0x1, 0xF, 0xB, 0x6, 0x8, 0x0, 0xD, 0x3, 0xA, 0x9, 0x7, 0x5, 0xE},
		{0x1, 0x9, 0xB, 0x2, 0x0, 0x4, 0x6, 0x8, 0xD, 0xF, 0xA, 0x3, 0xC, 0x7, 0x5, 0xE}
	};
	unsigned int serpent_rotl(unsigned int x, int n) {
		return (x << n) | (x >> (32 - n));
	}
	unsigned int serpent_rotr(unsigned int x, int n) {
		return (x >> n) | (x << (32 - n));
	}
	void serpent_linear_transform(unsigned int *x) {
		unsigned int a = x[0] ^ x[2];
		unsigned int b = x[1] ^ x[3];
		unsigned int c = x[0] ^ x[3];
		unsigned int d = x[1] ^ x[2];
		a = serpent_rotl(a, 13);
		c = serpent_rotl(c, 3);
		x[0] ^= a ^ c;
		x[1] ^= b ^ d;
		x[2] ^= a ^ d;
		x[3] ^= b ^ c;
		x[0] = serpent_rotl(x[0], 1);
		x[1] = serpent_rotr(x[1], 7);
		x[2] = serpent_rotr(x[2], 15);
		x[3] = serpent_rotl(x[3], 13);
	}
	void serpent_sbox_transform(unsigned int *x, int round) {
		int sbox_idx = (round + 3) % 8;
		unsigned int y[4] = {0};
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 8; j++) {
				unsigned char nibble = (x[i] >> (4 * j)) & 0xF;
				nibble = serpent_S[sbox_idx][nibble];
				y[i] |= (unsigned int)nibble << (4 * j);
			}
		}
		for (int i = 0; i < 4; i++) {
			x[i] = 0;
			for (int j = 0; j < 32; j++) {
				int pos = (32 * i + j) % 128;
				int src_word = pos / 32;
				int src_bit = pos % 32;
				if (y[src_word] & (1UL << src_bit)) {
					x[i] |= (1UL << j);
				}
			}
		}
	}
	void serpent_key_expansion(const unsigned char *key, int key_bits, unsigned int round_keys[SERPENT_ROUNDS + 1][4]) {
		unsigned int K[32] = {0};
		for (int i = 0; i < key_bits / 32; i++) {
			K[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 |
			       (unsigned int)key[4 * i + 2] << 8 | (unsigned int)key[4 * i + 3];
		}
		for (int i = key_bits / 32; i < 132; i++) {
			unsigned int temp = serpent_rotr(K[i - 1], 11);
			temp = (temp << 13) | (temp >> 19);
			temp ^= i;
			unsigned int s_temp = 0;
			for (int j = 0; j < 8; j++) {
				unsigned char nibble = (temp >> (4 * j)) & 0xF;
				nibble = serpent_S[(i - 1) % 8][nibble];
				s_temp |= (unsigned int)nibble << (4 * j);
			}
			K[i % 32] = K[(i - key_bits / 32) % 32] ^ s_temp;
		}
		for (int i = 0; i <= SERPENT_ROUNDS; i++) {
			for (int j = 0; j < 4; j++) {
				round_keys[i][j] = K[4 * i + (3 - j)];
			}
		}
	}
	void serpent_encrypt(const unsigned char *plaintext, const unsigned char *key, int key_bits, unsigned char *ciphertext) {
		unsigned int x[4] = {0};
		unsigned int round_keys[SERPENT_ROUNDS + 1][4];
		for (int i = 0; i < 4; i++) {
			x[i] = (unsigned int)plaintext[4 * i] << 24 | (unsigned int)plaintext[4 * i + 1] << 16 |
			       (unsigned int)plaintext[4 * i + 2] << 8 | (unsigned int)plaintext[4 * i + 3];
		}
		serpent_key_expansion(key, key_bits, round_keys);
		for (int i = 0; i < 4; i++) {
			x[i] ^= round_keys[0][i];
		}
		for (int round = 0; round < SERPENT_ROUNDS; round++) {
			serpent_sbox_transform(x, round);
			serpent_linear_transform(x);
			if (round < SERPENT_ROUNDS - 1) {
				for (int i = 0; i < 4; i++) {
					x[i] ^= round_keys[round + 1][i];
				}
			}
		}
		for (int i = 0; i < 4; i++) {
			x[i] ^= round_keys[SERPENT_ROUNDS][i];
		}
		for (int i = 0; i < 4; i++) {
			ciphertext[4 * i] = (x[i] >> 24) & 0xFF;
			ciphertext[4 * i + 1] = (x[i] >> 16) & 0xFF;
			ciphertext[4 * i + 2] = (x[i] >> 8) & 0xFF;
			ciphertext[4 * i + 3] = x[i] & 0xFF;
		}
	}
	void serpent_decrypt(const unsigned char *ciphertext, const unsigned char *key, int key_bits, unsigned char *plaintext) {
		unsigned int x[4] = {0};
		unsigned int round_keys[SERPENT_ROUNDS + 1][4];
		for (int i = 0; i < 4; i++) {
			x[i] = (unsigned int)ciphertext[4 * i] << 24 | (unsigned int)ciphertext[4 * i + 1] << 16 |
			       (unsigned int)ciphertext[4 * i + 2] << 8 | (unsigned int)ciphertext[4 * i + 3];
		}
		serpent_key_expansion(key, key_bits, round_keys);
		for (int i = 0; i < 4; i++) {
			x[i] ^= round_keys[SERPENT_ROUNDS][i];
		}
		for (int round = SERPENT_ROUNDS - 1; round >= 0; round--) {
			unsigned int inv_x[4];
			for (int i = 0; i < 4; i++) {
				inv_x[i] = x[i];
			}
			inv_x[0] = serpent_rotr(inv_x[0], 1);
			inv_x[1] = serpent_rotl(inv_x[1], 7);
			inv_x[2] = serpent_rotl(inv_x[2], 15);
			inv_x[3] = serpent_rotr(inv_x[3], 13);
			x[0] = inv_x[0];
			x[1] = inv_x[1];
			x[2] = inv_x[2];
			x[3] = inv_x[3];
			unsigned int a = x[0] ^ x[2];
			unsigned int b = x[1] ^ x[3];
			unsigned int c = x[0] ^ x[3];
			unsigned int d = x[1] ^ x[2];
			a = serpent_rotl(a, 13);
			c = serpent_rotl(c, 3);
			x[0] ^= a ^ c;
			x[1] ^= b ^ d;
			x[2] ^= a ^ d;
			x[3] ^= b ^ c;
			unsigned int y[4] = {0};
			int sbox_idx = (round + 3) % 8;
			for (int i = 0; i < 4; i++) {
				y[i] = 0;
				for (int j = 0; j < 32; j++) {
					int pos = (32 * i + j) % 128;
					int dst_word = pos / 32;
					int dst_bit = pos % 32;
					if (x[dst_word] & (1UL << dst_bit)) {
						y[i] |= (1UL << j);
					}
				}
			}
			for (int i = 0; i < 4; i++) {
				x[i] = 0;
				for (int j = 0; j < 8; j++) {
					unsigned char nibble = (y[i] >> (4 * j)) & 0xF;
					for (int k = 0; k < 16; k++) {
						if (serpent_S[sbox_idx][k] == nibble) {
							nibble = k;
							break;
						}
					}
					x[i] |= (unsigned int)nibble << (4 * j);
				}
			}
			if (round > 0) {
				for (int i = 0; i < 4; i++) {
					x[i] ^= round_keys[round][i];
				}
			}
		}
		for (int i = 0; i < 4; i++) {
			x[i] ^= round_keys[0][i];
		}
		for (int i = 0; i < 4; i++) {
			plaintext[4 * i] = (x[i] >> 24) & 0xFF;
			plaintext[4 * i + 1] = (x[i] >> 16) & 0xFF;
			plaintext[4 * i + 2] = (x[i] >> 8) & 0xFF;
			plaintext[4 * i + 3] = x[i] & 0xFF;
		}
	}
	inline std::string shift_encrypt(const std::string& txt, int shift) {
		return caesar_encrypt(txt, shift);
	}
	inline std::string shift_decrypt(const std::string& txt, int shift) {
		return caesar_decrypt(txt, shift);
	}

#	define SKIPJACK_ROTL8(x,n) ((x<<n)|(x>>(8-n)))
#	define SKIPJACK_ROTR8(x,n) ((x>>n)|(x<<(8-n)))
	static const unsigned char skipjack_F_TABLE[] = {0xA3, 0xD7, 0x09, 0x83, 0xF8, 0x48, 0xF6, 0xF4, 0xB3, 0x21, 0x15, 0x78, 0x99, 0xB1, 0xAF, 0xF9, 0xE7, 0x2D, 0x4D, 0x8A, 0xCE, 0x4C, 0xCA, 0x2E, 0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28, 0x0A, 0xDF, 0x02, 0xA0, 0x17, 0xF1, 0x60, 0x68, 0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53, 0x96, 0x84, 0x6B, 0xBA, 0xF2, 0x63, 0x9A, 0x19, 0x7C, 0xAE, 0xE5, 0xF5, 0xF7, 0x16, 0x6A, 0xA2, 0x39, 0xB6, 0x7B, 0x0F, 0xC1, 0x93, 0x81, 0x1B, 0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8, 0x55, 0xB9, 0xDA, 0x85, 0x3F, 0x41, 0xBF, 0xE0, 0x5A, 0x58, 0x80, 0x5F, 0x66, 0x0B, 0xD8, 0x90, 0x35, 0xD5, 0xC0, 0xA7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6D, 0x98, 0x9B, 0x76, 0x97, 0xFC, 0xB2, 0xC2, 0xB0, 0xFE, 0xDB, 0x20, 0xE1, 0xEB, 0xD6, 0xE4, 0xDD, 0x47, 0x4A, 0x1D, 0x42, 0xED, 0x9E, 0x6E, 0x49, 0x32, 0x61, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD1, 0xC9, 0x5D, 0xAF, 0x54, 0x1F, 0x14, 0x10, 0xEE, 0x2A, 0x9F, 0x88, 0x46, 0x6F, 0x0E, 0xFA, 0x75, 0x85, 0x23, 0x96, 0x67, 0xE3, 0x19, 0x05, 0x3B, 0xC7, 0x9B, 0x1B, 0x9D, 0x89, 0x53, 0x3C, 0x1A, 0x63, 0x8F, 0x40, 0x07, 0xC2, 0xDD, 0x5B, 0x59, 0x26, 0x12, 0x73, 0x31, 0x82, 0x6C, 0x50, 0xA3, 0x69, 0x20, 0x36, 0xD4, 0x30, 0x02, 0x97, 0xB3, 0x4F, 0x1C, 0x55, 0x16, 0x9A, 0xBC, 0x5F, 0x84, 0x62, 0x4B, 0x09, 0x87, 0x57, 0x24, 0x8E, 0x72, 0x17, 0x79, 0x0D, 0x81, 0x44, 0x48, 0x38, 0x6A, 0x43, 0x39, 0x0F, 0x42, 0x29, 0x80, 0x51, 0xDC, 0x13, 0x21, 0x03, 0x2E, 0x70, 0x86, 0x27, 0x71, 0x58, 0x92, 0x08, 0x4D, 0xAE, 0x35, 0x76, 0x34, 0xCB, 0x18, 0xE0, 0x5E, 0x64, 0x37, 0xFD, 0x74, 0x45, 0x22, 0x06, 0x98, 0x78, 0x56, 0x2F, 0x1E, 0xCE, 0xAB, 0xDE, 0x9C, 0x91, 0x3D, 0x5C, 0x4E, 0x83, 0x9F, 0xAD, 0xF7, 0x11, 0x49, 0xBD, 0x8B, 0x6D, 0x0C, 0xEC, 0xAA, 0x0A, 0x7D, 0x68, 0xF1, 0x1F, 0xD3, 0x4A, 0x47, 0x25, 0x99, 0x8D, 0xF9, 0x54, 0xF0, 0xE2, 0x28, 0x95, 0x8C, 0x3F, 0x66, 0xE1, 0xDF, 0x94, 0x52, 0x33, 0x60, 0x65, 0x77, 0xC4, 0xE5, 0xF2, 0x6E, 0x04, 0x2D, 0x1D, 0x7B, 0x93, 0xC5, 0xFA, 0xEB, 0xC6, 0xE4, 0x14, 0x5D, 0x7C, 0xA4, 0x2B, 0x88, 0x32, 0x6F, 0x89, 0x41, 0x4C, 0x5A, 0x01, 0x7F, 0x61, 0x15, 0x8A, 0x90, 0x4F, 0x3E, 0xC8, 0xD2, 0xE9, 0x8E, 0x36, 0x70, 0x5F, 0x3A, 0x1C, 0x81, 0x74, 0x6B, 0x07, 0x12, 0x96, 0x4D, 0x55, 0x98, 0x26, 0x4A, 0x0C, 0x3F, 0x52, 0x79, 0x85, 0x73, 0x6E, 0x4B, 0x63, 0x17, 0x09, 0x37, 0x92, 0x23, 0x2E, 0x50, 0x82, 0x57, 0x24, 0x8E, 0x72, 0x17, 0x79, 0x0D, 0x81, 0x44, 0x48, 0x38, 0x6A, 0x43, 0x39, 0x0F, 0x42, 0x29, 0x80, 0x51, 0xDC, 0x13, 0x21, 0x03, 0x2E, 0x70, 0x86, 0x27, 0x71, 0x58, 0x92, 0x08, 0x4D, 0xAE, 0x35, 0x76, 0x34, 0xCB, 0x18, 0xE0, 0x5E, 0x64, 0x37, 0xFD, 0x74, 0x45, 0x22, 0x06, 0x98, 0x78, 0x56, 0x2F, 0x1E, 0xCE, 0xAB, 0xDE, 0x9C, 0x91, 0x3D, 0x5C, 0x4E, 0x83, 0x9F, 0xAD, 0xF7, 0x11, 0x49, 0xBD, 0x8B, 0x6D, 0x0C, 0xEC, 0xAA, 0x0A, 0x7D, 0x68, 0xF1, 0x1F, 0xD3, 0x4A, 0x47, 0x25, 0x99, 0x8D, 0xF9, 0x54, 0xF0, 0xE2, 0x28, 0x95, 0x8C, 0x3F, 0x66, 0xE1, 0xDF, 0x94, 0x52, 0x33, 0x60, 0x65, 0x77, 0xC4, 0xE5, 0xF2, 0x6E, 0x04, 0x2D, 0x1D, 0x7B, 0x93, 0xC5, 0xFA, 0xEB, 0xC6, 0xE4, 0x14, 0x5D, 0x7C, 0xA4, 0x2B, 0x88, 0x32, 0x6F, 0x89, 0x41, 0x4C, 0x5A, 0x01, 0x7F, 0x61, 0x15, 0x8A, 0x90, 0x4F, 0x3E, 0xC8, 0xD2, 0xE9};
	unsigned char skipjack_G(unsigned char x, unsigned char k1, unsigned char k2, unsigned char k3) {
		x = skipjack_F_TABLE[x ^ k1];
		x = SKIPJACK_ROTL8(x, 1);
		x = skipjack_F_TABLE[x ^ k2];
		x = SKIPJACK_ROTR8(x, 1);
		x = skipjack_F_TABLE[x ^ k3];
		return x;
	}
	void skipjack_keySchedule(const unsigned char key[16], unsigned char subkeys[320]) {
		for (int i = 0; i < 320; i++)subkeys[i] = key[i % 16];
	}
	void skipjack_encrypt(const unsigned char key[16], const unsigned char plain[8], unsigned char cipher[8]) {
		unsigned char subkeys[320];
		skipjack_keySchedule(key, subkeys);
		unsigned char w[8];
		memcpy(w, plain, 8);
		for (int round = 0; round < 32; round++) {
			int k = round * 10;
			if (round < 16) {
				unsigned char t = skipjack_G(w[0], subkeys[k], subkeys[k + 1], subkeys[k + 2]);
				t ^= w[1] ^ subkeys[k + 3];
				w[1] = w[2];
				w[2] = w[3];
				w[3] = w[4];
				w[4] = w[5];
				w[5] = w[6];
				w[6] = w[7];
				w[7] = t;
			} else {
				unsigned char t = skipjack_G(w[7], subkeys[k], subkeys[k + 1], subkeys[k + 2]);
				t ^= w[6] ^ subkeys[k + 3];
				w[6] = w[5];
				w[5] = w[4];
				w[4] = w[3];
				w[3] = w[2];
				w[2] = w[1];
				w[1] = w[0];
				w[0] = t;
			}
		}
		memcpy(cipher, w, 8);
	}
	void skipjack_decrypt(const unsigned char key[16], const unsigned char cipher[8], unsigned char plain[8]) {
		unsigned char subkeys[320];
		skipjack_keySchedule(key, subkeys);
		unsigned char w[8];
		memcpy(w, cipher, 8);
		for (int round = 31; round >= 0; round--) {
			int k = round * 10;
			if (round < 16) {
				unsigned char t = w[7];
				w[7] = w[6];
				w[6] = w[5];
				w[5] = w[4];
				w[4] = w[3];
				w[3] = w[2];
				w[2] = w[1];
				w[1] = t ^ w[1] ^ subkeys[k + 3];
				w[1] = skipjack_F_TABLE[w[1]];
				w[1] = SKIPJACK_ROTL8(w[1], 1);
				w[1] = skipjack_F_TABLE[w[1]];
				w[1] = SKIPJACK_ROTR8(w[1], 1);
				w[1] = skipjack_F_TABLE[w[1] ^ subkeys[k + 2]];
				w[1] = SKIPJACK_ROTL8(w[1], 1);
				w[1] = skipjack_F_TABLE[w[1] ^ subkeys[k + 1]];
				w[1] = SKIPJACK_ROTR8(w[1], 1);
				w[1] ^= subkeys[k];
			} else {
				unsigned char t = w[0];
				w[0] = w[1];
				w[1] = w[2];
				w[2] = w[3];
				w[3] = w[4];
				w[4] = w[5];
				w[5] = w[6];
				w[6] = t ^ w[6] ^ subkeys[k + 3];
				w[6] = skipjack_F_TABLE[w[6]];
				w[6] = SKIPJACK_ROTL8(w[6], 1);
				w[6] = skipjack_F_TABLE[w[6]];
				w[6] = SKIPJACK_ROTR8(w[6], 1);
				w[6] = skipjack_F_TABLE[w[6] ^ subkeys[k + 2]];
				w[6] = SKIPJACK_ROTL8(w[6], 1);
				w[6] = skipjack_F_TABLE[w[6] ^ subkeys[k + 1]];
				w[6] = SKIPJACK_ROTR8(w[6], 1);
				w[6] ^= subkeys[k];
			}
		}
		memcpy(plain, w, 8);
	}
	class substution {
			std::array<char, 26> enc_map{};
			std::array<char, 26> dec_map{};
		public:
			explicit substution(const std::string& key) {
				std::string k;
				for (char c : key) if (std::isalpha(c)) {
						c = std::toupper(c);
						if (k.find(c) == std::string::npos) k += c;
					}
				for (char c = 'A'; c <= 'Z'; ++c)
					if (k.find(c) == std::string::npos) k += c;
				for (int i = 0; i < 26; ++i) {
					enc_map[i] = k[i];
					dec_map[k[i] - 'A'] = 'A' + i;
				}
			}
			std::string encrypt(const std::string& txt) const {
				std::string out;
				for (char c : txt) {
					if (std::isalpha(c)) {
						char base = std::isupper(c) ? 'A' : 'a';
						out += enc_map[std::toupper(c) - 'A'] - 'A' + base;
					} else out += c;
				}
				return out;
			}
			std::string decrypt(const std::string& txt) const {
				std::string out;
				for (char c : txt) {
					if (std::isalpha(c)) {
						char base = std::isupper(c) ? 'A' : 'a';
						out += dec_map[std::toupper(c) - 'A'] - 'A' + base;
					} else out += c;
				}
				return out;
			}
	};
	class  tdea {
		public:
			explicit tdea(const unsigned char *key, size_t key_len);
			void encryptBlock(const unsigned char in[8], unsigned char out[8]) const;
			void decryptBlock(const unsigned char in[8], unsigned char out[8]) const;
			void encryptECB(const unsigned char *in, unsigned char *out, size_t bytes) const;
			void decryptECB(const unsigned char *in, unsigned char *out, size_t bytes) const;
		private:
			unsigned char subKey[3][16][6];
			static void desEncrypt(const unsigned char in[8], unsigned char out[8], const unsigned char roundKey[16][6]);
			static void desDecrypt(const unsigned char in[8], unsigned char out[8], const unsigned char roundKey[16][6]);
			static const unsigned char IP[64];
			static const unsigned char FP[64];
			static const unsigned char E[48];
			static const unsigned char P[32];
			static const unsigned char S[8][4][16];
			static const unsigned char PC1[56];
			static const unsigned char PC2[48];
			static const unsigned char SHIFTS[16];
			static void generateSubKey(const unsigned char key[8], unsigned char roundKey[16][6]);
			static void feistel(const unsigned char in[4], unsigned char out[4], const unsigned char roundKey[6]);
	};
	const unsigned char tdea::IP[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
	const unsigned char tdea::FP[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
	const unsigned char tdea::E[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
	const unsigned char tdea::P[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
	const unsigned char tdea::S[8][4][16] = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}}, {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}}, {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 12, 5, 2, 11}}, {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}}, {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}}, {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}}, {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}}, {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};
	const unsigned char tdea::PC1[56] = {57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
	const unsigned char tdea::PC2[48] = {14, 17, 11, 24, 1, 5,  3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,  16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
	const unsigned char tdea::SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	static void permute(const unsigned char *in, unsigned char *out, const unsigned char *table, int outBits) {
		std::memset(out, 0, 8);
		for (int i = 0; i < outBits; ++i) {
			int src = table[i] - 1;
			int srcByte = src / 8, srcBit = 7 - (src % 8);
			int dstByte = i / 8,  dstBit = 7 - (i % 8);
			if (in[srcByte] & (1 << srcBit))
				out[dstByte] |= (1 << dstBit);
		}
	}
	void tdea::generateSubKey(const unsigned char key[8], unsigned char roundKey[16][6]) {
		unsigned char permuted[7] = {0};
		permute(key, permuted, PC1, 56);
		unsigned int C = (permuted[0] << 20) | (permuted[1] << 12) | (permuted[2] << 4)  | (permuted[3] >> 4);
		unsigned int D = ((permuted[3] & 0x0F) << 24) | (permuted[4] << 16) | (permuted[5] << 8) | permuted[6];
		for (int r = 0; r < 16; ++r) {
			C = ((C << SHIFTS[r]) | (C >> (28 - SHIFTS[r]))) & 0x0FFFFFFF;
			D = ((D << SHIFTS[r]) | (D >> (28 - SHIFTS[r]))) & 0x0FFFFFFF;
			unsigned long long int CD = (static_cast<unsigned long long int>(C) << 28) | D;
			unsigned char CDbytes[7] = {0};
			for (int i = 0; i < 7; ++i) CDbytes[i] = static_cast<unsigned char>(CD >> (48 - 8 * (i + 1)));
			permute(CDbytes, roundKey[r], PC2, 48);
		}
	}
	void tdea::feistel(const unsigned char in[4], unsigned char out[4], const unsigned char roundKey[6]) {
		unsigned char expanded[6] = {0};
		permute(in, expanded, E, 48);
		for (int i = 0; i < 6; ++i) expanded[i] ^= roundKey[i];
		unsigned char sOut[4] = {0};
		for (int i = 0; i < 8; ++i) {
			int row = ((expanded[i / 2] >> (7 - (i % 2) * 4)) & 0x20) | ((expanded[i / 2] >> (3 - (i % 2) * 4)) & 0x01);
			row = ((row & 0x20) >> 4) | (row & 0x01);
			int col = (expanded[i / 2] >> (3 - (i % 2) * 4)) & 0x0F;
			unsigned char v = S[i][row][col];
			if (i % 2 == 0) sOut[i / 2] = v << 4;
			else sOut[i / 2] |= v;
		}
		permute(sOut, out, P, 32);
	}
	void tdea::desEncrypt(const unsigned char in[8], unsigned char out[8], const unsigned char roundKey[16][6]) {
		unsigned char ip[8];
		permute(in, ip, IP, 64);
		unsigned char L[4], R[4];
		std::memcpy(L, ip, 4);
		std::memcpy(R, ip + 4, 4);
		for (int r = 0; r < 16; ++r) {
			unsigned char f[4];
			feistel(R, f, roundKey[r]);
			unsigned char newR[4];
			for (int i = 0; i < 4; ++i) newR[i] = L[i] ^ f[i];
			std::memcpy(L, R, 4);
			std::memcpy(R, newR, 4);
		}
		unsigned char preFP[8];
		std::memcpy(preFP, R, 4);
		std::memcpy(preFP + 4, L, 4);
		permute(preFP, out, FP, 64);
	}
	void tdea::desDecrypt(const unsigned char in[8], unsigned char out[8], const unsigned char roundKey[16][6]) {
		unsigned char ip[8];
		permute(in, ip, IP, 64);
		unsigned char L[4], R[4];
		std::memcpy(L, ip, 4);
		std::memcpy(R, ip + 4, 4);
		for (int r = 15; r >= 0; --r) {
			unsigned char f[4];
			feistel(R, f, roundKey[r]);
			unsigned char newR[4];
			for (int i = 0; i < 4; ++i) newR[i] = L[i] ^ f[i];
			std::memcpy(L, R, 4);
			std::memcpy(R, newR, 4);
		}
		unsigned char preFP[8];
		std::memcpy(preFP, R, 4);
		std::memcpy(preFP + 4, L, 4);
		permute(preFP, out, FP, 64);
	}
	tdea::tdea(const unsigned char *key, size_t key_len) {
		if (key_len != 16 && key_len != 24) throw std::invalid_argument("key length must be 16 (2?Key) or 24 (3?Key) bytes");
		for (int i = 0; i < 3; ++i) {
			const unsigned char *k = key + (i * 8);
			generateSubKey(k, subKey[i]);
		}
		if (key_len == 16) std::memcpy(subKey[2], subKey[0], sizeof(subKey[0]));
	}
	void tdea::encryptBlock(const unsigned char in[8], unsigned char out[8]) const {
		unsigned char tmp[8];
		desEncrypt(in, tmp, subKey[0]);
		desDecrypt(tmp, tmp, subKey[1]);
		desEncrypt(tmp, out, subKey[2]);
	}
	void tdea::decryptBlock(const unsigned char in[8], unsigned char out[8]) const {
		unsigned char tmp[8];
		desDecrypt(in, tmp, subKey[2]);
		desEncrypt(tmp, tmp, subKey[1]);
		desDecrypt(tmp, out, subKey[0]);
	}
	void tdea::encryptECB(const unsigned char *in, unsigned char *out, size_t bytes) const {
		if (bytes % 8 != 0) throw std::invalid_argument("length must be multiple of 8");
		for (size_t i = 0; i < bytes; i += 8)
			encryptBlock(in + i, out + i);
	}
	void tdea::decryptECB(const unsigned char *in, unsigned char *out, size_t bytes) const {
		if (bytes % 8 != 0) throw std::invalid_argument("length must be multiple of 8");
		for (size_t i = 0; i < bytes; i += 8)
			decryptBlock(in + i, out + i);
	}
	class twofish {
		public:
			static const int KEY_SIZE_128 = 16;
			static const int KEY_SIZE_192 = 24;
			static const int KEY_SIZE_256 = 32;
			static const int BLOCK_SIZE = 16;
			twofish(const unsigned char* key, int key_size) {
				set_key(key, key_size);
			}
			void encrypt(const unsigned char* in, unsigned char* out) const {
				unsigned int p0, p1, p2, p3;
				p0 = (unsigned int)in[0] << 24 | (unsigned int)in[1] << 16 | (unsigned int)in[2] << 8 | in[3];
				p1 = (unsigned int)in[4] << 24 | (unsigned int)in[5] << 16 | (unsigned int)in[6] << 8 | in[7];
				p2 = (unsigned int)in[8] << 24 | (unsigned int)in[9] << 16 | (unsigned int)in[10] << 8 | in[11];
				p3 = (unsigned int)in[12] << 24 | (unsigned int)in[13] << 16 | (unsigned int)in[14] << 8 | in[15];
				unsigned int x0 = p0 ^ p2;
				unsigned int x1 = p1 ^ p3;
				unsigned int x2 = p0 ^ p3;
				unsigned int x3 = p1 ^ p2;
				for (int i = 0; i < 16; i++) {
					unsigned int t0 = f(x0, i);
					unsigned int t1 = f(rotl32(x1, 8), i + 1);
					x2 ^= t0 + t1 + _round_keys[2 * i];
					x3 ^= rotl32(t0, 8) + rotl32(t1, 8) + _round_keys[2 * i + 1];
					unsigned int temp = x0;
					x0 = x2;
					x2 = x1;
					x1 = x3;
					x3 = temp;
				}
				p0 = x2 ^ x0;
				p1 = x3 ^ x1;
				p2 = x2 ^ x1;
				p3 = x3 ^ x0;
				out[0] = (p0 >> 24) & 0xFF;
				out[1] = (p0 >> 16) & 0xFF;
				out[2] = (p0 >> 8) & 0xFF;
				out[3] = p0 & 0xFF;
				out[4] = (p1 >> 24) & 0xFF;
				out[5] = (p1 >> 16) & 0xFF;
				out[6] = (p1 >> 8) & 0xFF;
				out[7] = p1 & 0xFF;
				out[8] = (p2 >> 24) & 0xFF;
				out[9] = (p2 >> 16) & 0xFF;
				out[10] = (p2 >> 8) & 0xFF;
				out[11] = p2 & 0xFF;
				out[12] = (p3 >> 24) & 0xFF;
				out[13] = (p3 >> 16) & 0xFF;
				out[14] = (p3 >> 8) & 0xFF;
				out[15] = p3 & 0xFF;
			}
			void decrypt(const unsigned char* in, unsigned char* out) const {
				unsigned int p0, p1, p2, p3;
				p0 = (unsigned int)in[0] << 24 | (unsigned int)in[1] << 16 | (unsigned int)in[2] << 8 | in[3];
				p1 = (unsigned int)in[4] << 24 | (unsigned int)in[5] << 16 | (unsigned int)in[6] << 8 | in[7];
				p2 = (unsigned int)in[8] << 24 | (unsigned int)in[9] << 16 | (unsigned int)in[10] << 8 | in[11];
				p3 = (unsigned int)in[12] << 24 | (unsigned int)in[13] << 16 | (unsigned int)in[14] << 8 | in[15];
				unsigned int x0 = p2 ^ p0;
				unsigned int x1 = p3 ^ p1;
				unsigned int x2 = p2 ^ p1;
				unsigned int x3 = p3 ^ p0;
				for (int i = 15; i >= 0; i--) {
					unsigned int temp = x3;
					x3 = x1;
					x1 = x2;
					x2 = x0;
					x0 = temp;
					unsigned int t0 = f(x0, i);
					unsigned int t1 = f(rotl32(x1, 8), i + 1);
					x3 ^= rotl32(t0, 8) + rotl32(t1, 8) + _round_keys[2 * i + 1];
					x2 ^= t0 + t1 + _round_keys[2 * i];
				}
				p0 = x0 ^ x2;
				p1 = x1 ^ x3;
				p2 = x0 ^ x3;
				p3 = x1 ^ x2;
				out[0] = (p0 >> 24) & 0xFF;
				out[1] = (p0 >> 16) & 0xFF;
				out[2] = (p0 >> 8) & 0xFF;
				out[3] = p0 & 0xFF;
				out[4] = (p1 >> 24) & 0xFF;
				out[5] = (p1 >> 16) & 0xFF;
				out[6] = (p1 >> 8) & 0xFF;
				out[7] = p1 & 0xFF;
				out[8] = (p2 >> 24) & 0xFF;
				out[9] = (p2 >> 16) & 0xFF;
				out[10] = (p2 >> 8) & 0xFF;
				out[11] = p2 & 0xFF;
				out[12] = (p3 >> 24) & 0xFF;
				out[13] = (p3 >> 16) & 0xFF;
				out[14] = (p3 >> 8) & 0xFF;
				out[15] = p3 & 0xFF;
			}
		private:
			static const unsigned char _s0[256];
			static const unsigned char _s1[256];
			static const unsigned char _s2[256];
			static const unsigned char _s3[256];
			static const unsigned int _mds[4][4];
			unsigned int _round_keys[40];
			unsigned int _q0[256], _q1[256];
			static unsigned int rotl32(unsigned int x, int n) {
				return (x << n) | (x >> (32 - n));
			}
			static unsigned int rotr32(unsigned int x, int n) {
				return (x >> n) | (x << (32 - n));
			}
			static unsigned char sbox(unsigned char x, int box) {
				switch (box) {
					case 0:
						return _s0[x];
					case 1:
						return _s1[x];
					case 2:
						return _s2[x];
					case 3:
						return _s3[x];
					default:
						return x;
				}
			}
			static int a(int b) {
				return b;
			}
			unsigned int f(unsigned int x, int round) const {
				a(round);
				unsigned char b0 = (x >> 24) & 0xFF;
				unsigned char b1 = (x >> 16) & 0xFF;
				unsigned char b2 = (x >> 8) & 0xFF;
				unsigned char b3 = x & 0xFF;
				unsigned int y0 = _q0[b0];
				unsigned int y1 = _q1[b1];
				unsigned int y2 = _q0[b2];
				unsigned int y3 = _q1[b3];
				unsigned int z0 = (y0 & 0xFF) * _mds[0][0] ^ (y1 & 0xFF) * _mds[0][1] ^ (y2 & 0xFF) * _mds[0][2] ^ (y3 & 0xFF) * _mds[0][3];
				unsigned int z1 = ((y0 >> 8) & 0xFF) * _mds[1][0] ^ ((y1 >> 8) & 0xFF) * _mds[1][1] ^ ((y2 >> 8) & 0xFF) * _mds[1][2] ^ ((y3 >> 8) & 0xFF) * _mds[1][3];
				unsigned int z2 = ((y0 >> 16) & 0xFF) * _mds[2][0] ^ ((y1 >> 16) & 0xFF) * _mds[2][1] ^ ((y2 >> 16) & 0xFF) * _mds[2][2] ^ ((y3 >> 16) & 0xFF) * _mds[2][3];
				unsigned int z3 = ((y0 >> 24) & 0xFF) * _mds[3][0] ^ ((y1 >> 24) & 0xFF) * _mds[3][1] ^ ((y2 >> 24) & 0xFF) * _mds[3][2] ^ ((y3 >> 24) & 0xFF) * _mds[3][3];
				return z0 ^ (z1 << 8) ^ (z2 << 16) ^ (z3 << 24);
			}
			void set_key(const unsigned char* key, int key_size) {
				int k = key_size / 8;
				for (int i = 0; i < 256; i++) {
					unsigned char a = (unsigned char)i;
					unsigned char b = sbox(a, 1);
					b = (b << 1) | (b >> 7);
					_q0[i] = (unsigned int)sbox(a, 0) << 24 | (unsigned int)sbox(b, 0) << 16 | (unsigned int)sbox(b, 0) << 8 | sbox(a, 0);
					a = sbox(a, 2);
					b = sbox(b, 3);
					b = (b << 1) | (b >> 7);
					_q1[i] = (unsigned int)sbox(a, 1) << 24 | (unsigned int)sbox(b, 1) << 16 | (unsigned int)sbox(b, 1) << 8 | sbox(a, 1);
				}
				unsigned int m[4];
				memset(m, 0, sizeof(m));
				for (int i = 0; i < k; i++) {
					m[i] = (unsigned int)key[4 * i] << 24 | (unsigned int)key[4 * i + 1] << 16 |
					       (unsigned int)key[4 * i + 2] << 8 | key[4 * i + 3];
				}
				for (int i = 0; i < 20; i++) {
					unsigned int a = f(rotl32(m[i % k], 8 * (i / k)), 2 * i);
					unsigned int b = rotr32(m[(i + 1) % k], 8 * ((i + 1) / k));
					b = f(b, 2 * i + 1);

					_round_keys[2 * i] = a + b;
					_round_keys[2 * i + 1] = rotl32(b + a + _round_keys[2 * i], 9);
				}
			}
	};
	const unsigned char twofish::_s0[256] = {
		0x95, 0x0B, 0xEF, 0xCD, 0x23, 0xC6, 0x6D, 0x5A, 0xF1, 0x04, 0xCC, 0x45, 0x7F, 0x91, 0x6F, 0x0D,
		0x53, 0x6B, 0x3D, 0x4E, 0x98, 0x8F, 0x87, 0xD8, 0x00, 0x39, 0x64, 0x30, 0x35, 0xA5, 0x38, 0x83,
		0x9A, 0x15, 0x70, 0x9F, 0xB2, 0xA7, 0x05, 0x22, 0x5B, 0x9B, 0x3B, 0x19, 0xDF, 0x2C, 0x55, 0xE6,
		0x6C, 0x5C, 0x56, 0x5F, 0x88, 0x5E, 0x50, 0x51, 0x2F, 0x72, 0xB7, 0x09, 0x20, 0x12, 0xE0, 0xEB,
		0x8B, 0x80, 0x0A, 0x8C, 0x81, 0x1F, 0xDB, 0x48, 0xE8, 0x4B, 0x32, 0x1C, 0x77, 0x3E, 0x9D, 0x1B,
		0x2B, 0xB5, 0x1A, 0xFA, 0x7B, 0x7D, 0x34, 0x73, 0x9C, 0x4D, 0xB9, 0x8A, 0x8D, 0x1E, 0x4C, 0xA8,
		0x65, 0x28, 0x82, 0xA3, 0x13, 0xB8, 0xE4, 0xDD, 0x4F, 0x26, 0x2A, 0x84, 0x61, 0x21, 0x06, 0x3F,
		0xEA, 0x9E, 0x6E, 0x02, 0x7E, 0x59, 0x94, 0xB1, 0x0F, 0x4A, 0xA4, 0x18, 0x90, 0x24, 0x68, 0x11,
		0xB4, 0x41, 0x3A, 0x33, 0xFF, 0x25, 0x2E, 0xB6, 0x79, 0x0C, 0x71, 0x03, 0x0E, 0xEC, 0x62, 0x75,
		0x47, 0xB3, 0x44, 0x97, 0x8E, 0x67, 0x7A, 0x27, 0x54, 0x2D, 0x57, 0x96, 0x49, 0xAE, 0x29, 0x1D,
		0xD4, 0x93, 0x52, 0x78, 0x74, 0x31, 0x01, 0x89, 0x40, 0xBC, 0xDE, 0x7C, 0xA9, 0xE2, 0x6A, 0x66,
		0x17, 0x60, 0xAA, 0x76, 0x46, 0x16, 0x43, 0x42, 0x99, 0xE3, 0x3C, 0x37, 0x63, 0x69, 0xBE, 0xD5,
		0xBD, 0xAD, 0x08, 0x07, 0xAC, 0x92, 0xA6, 0xAB, 0x86, 0xB0, 0x5D, 0xD3, 0x9B, 0x22, 0x55, 0xE6,
		0xD0, 0x58, 0x10, 0xCA, 0xCF, 0x36, 0xD6, 0xD1, 0x85, 0xE9, 0xB1, 0x0F, 0x4A, 0xA4, 0x18, 0x90,
		0xE5, 0x40, 0xBC, 0xDE, 0x7C, 0xA9, 0xE2, 0x6A, 0x66, 0x17, 0x60, 0xAA, 0x76, 0x46, 0x16, 0x43,
		0xBF, 0x42, 0x99, 0xE3, 0x3C, 0x37, 0x63, 0x69, 0xBE, 0xD5, 0xBD, 0xAD, 0x08, 0x07, 0xAC, 0x92
	};
	const unsigned char twofish::_s1[256] = {
		0x8E, 0x7D, 0x7A, 0x26, 0x4E, 0x1B, 0x83, 0x08, 0x54, 0x20, 0x07, 0x50, 0x46, 0x2D, 0x37, 0x5A,
		0xE8, 0x1C, 0x7B, 0x6B, 0x3D, 0x29, 0xEF, 0x0D, 0x9D, 0x97, 0xDC, 0x0F, 0x3A, 0x99, 0x65, 0x62,
		0x1D, 0x9C, 0x6D, 0x4F, 0x6A, 0x09, 0x33, 0x5C, 0x36, 0x0A, 0x61, 0x30, 0x4B, 0x6E, 0x56, 0x11,
		0x98, 0x0B, 0x0C, 0xB7, 0xB1, 0x96, 0x23, 0x48, 0x3F, 0x35, 0xA0, 0x89, 0x1E, 0x4C, 0x8F, 0x8D,
		0x27, 0x80, 0x85, 0x40, 0x5F, 0x88, 0x2B, 0x5E, 0x5B, 0x2C, 0xA7, 0x25, 0x74, 0x8B, 0x4D, 0x44,
		0x3B, 0x1F, 0xA4, 0x93, 0x84, 0x95, 0x1A, 0x9E, 0x00, 0x60, 0x6F, 0x77, 0x67, 0x51, 0xEE, 0x31,
		0x8C, 0x39, 0x21, 0x3E, 0x73, 0x13, 0x57, 0x42, 0xE9, 0x9A, 0x69, 0x24, 0x7F, 0x71, 0x14, 0x06,
		0x8A, 0x94, 0x79, 0xE0, 0x45, 0x2A, 0xE2, 0x55, 0x91, 0x6C, 0x78, 0x47, 0xA2, 0x86, 0x53, 0x3C,
		0x90, 0x7C, 0xEC, 0x15, 0xB5, 0x12, 0x76, 0x49, 0x43, 0x22, 0x75, 0x5D, 0x81, 0x04, 0x9B, 0x32,
		0x82, 0x66, 0x18, 0x4A, 0x41, 0x52, 0x05, 0x02, 0x03, 0xA6, 0x63, 0x59, 0x2E, 0x34, 0xA3, 0xB6,
		0x01, 0xEB, 0xA1, 0xDE, 0x72, 0xDD, 0x7E, 0x92, 0x38, 0xE4, 0x58, 0xB4, 0xD9, 0xE7, 0xE5, 0xBA,
		0x64, 0xAF, 0x17, 0xB8, 0xDA, 0xBB, 0xAB, 0xD5, 0xB0, 0xB2, 0xE6, 0x9F, 0x0E, 0x68, 0xD8, 0xE1,
		0xCD, 0xFD, 0xBC, 0xF9, 0xBD, 0x87, 0xAD, 0xB9, 0x3B, 0x1F, 0xA4, 0x93, 0x84, 0x95, 0x1A, 0x9E,
		0x00, 0x60, 0x6F, 0x77, 0x67, 0x51, 0xEE, 0x31, 0x8C, 0x39, 0x21, 0x3E, 0x73, 0x13, 0x57, 0x42,
		0xE9, 0x9A, 0x69, 0x24, 0x7F, 0x71, 0x14, 0x06, 0x8A, 0x94, 0x79, 0xE0, 0x45, 0x2A, 0xE2, 0x55,
		0x91, 0x6C, 0x78, 0x47, 0xA2, 0x86, 0x53, 0x3C, 0x90, 0x7C, 0xEC, 0x15, 0xB5, 0x12, 0x76, 0x49
	};
	const unsigned char twofish::_s2[256] = {
		0xAA, 0xE3, 0x5B, 0x85, 0xB5, 0x6C, 0xEF, 0x20, 0x8E, 0x4D, 0x7A, 0x7B, 0x24, 0xD6, 0x8B, 0x1C,
		0x3B, 0x34, 0x09, 0x91, 0x70, 0x64, 0xDE, 0x0B, 0x9A, 0x21, 0x38, 0x15, 0x30, 0x06, 0x87, 0xDC,
		0x6D, 0x95, 0x4B, 0x2A, 0xA2, 0xF8, 0x5C, 0x4C, 0x5D, 0xB1, 0x4F, 0x65, 0x31, 0xAE, 0xA8, 0x37,
		0x61, 0x41, 0x54, 0x9C, 0x45, 0x27, 0x56, 0xFA, 0x9D, 0x0D, 0x8D, 0x1F, 0x36, 0xD5, 0x4E, 0x9F,
		0x9B, 0x25, 0x2E, 0x6B, 0xA4, 0x18, 0x2D, 0x52, 0x93, 0x5F, 0x19, 0x8A, 0x84, 0x0C, 0x05, 0xCA,
		0xCB, 0x2B, 0x44, 0x8F, 0x02, 0x53, 0xCC, 0xBF, 0x57, 0x3C, 0xA1, 0x80, 0x90, 0x12, 0x1E, 0x0F,
		0x3F, 0x6A, 0x48, 0x66, 0x04, 0x97, 0xB0, 0x11, 0xE4, 0x23, 0x49, 0x6E, 0x32, 0xBD, 0x7D, 0xE6,
		0x8C, 0x81, 0x14, 0x7C, 0x35, 0xBB, 0x0E, 0x98, 0x9E, 0x58, 0x67, 0x22, 0x74, 0x01, 0xB2, 0xA9,
		0x88, 0x6F, 0x08, 0xEE, 0x7F, 0x2C, 0x3D, 0x33, 0x79, 0x82, 0xB7, 0x4A, 0xB8, 0xA6, 0x40, 0x68,
		0x99, 0xE0, 0x5A, 0x1D, 0x71, 0x2F, 0x3E, 0x62, 0x55, 0x94, 0xB4, 0x03, 0xA0, 0x7E, 0x1B, 0x43,
		0x47, 0x77, 0x17, 0x51, 0x73, 0xAB, 0x86, 0x50, 0xE7, 0xE2, 0xB9, 0x96, 0x29, 0xD7, 0x60, 0x39,
		0x00, 0x42, 0x1A, 0x46, 0x59, 0x92, 0xA5, 0x72, 0xEB, 0xD8, 0xA7, 0x83, 0x89, 0x75, 0xBC, 0xDD,
		0xDF, 0xE9, 0xDB, 0xE5, 0xE1, 0x26, 0x28, 0x63, 0x4B, 0x2A, 0xA2, 0xF8, 0x5C, 0x4C, 0x5D, 0xB1,
		0x4F, 0x65, 0x31, 0xAE, 0xA8, 0x37, 0x61, 0x41, 0x54, 0x9C, 0x45, 0x27, 0x56, 0xFA, 0x9D, 0x0D,
		0x8D, 0x1F, 0x36, 0xD5, 0x4E, 0x9F, 0x9B, 0x25, 0x2E, 0x6B, 0xA4, 0x18, 0x2D, 0x52, 0x93, 0x5F,
		0x19, 0x8A, 0x84, 0x0C, 0x05, 0xCA, 0xCB, 0x2B, 0x44, 0x8F, 0x02, 0x53, 0xCC, 0xBF, 0x57, 0x3C
	};
	const unsigned char twofish::_s3[256] = {
		0x05, 0x5A, 0x58, 0xBB, 0x1D, 0x80, 0x8B, 0x38, 0x6B, 0x86, 0x4F, 0x76, 0x89, 0xA7, 0x2C, 0x2B,
		0x3D, 0x61, 0x0E, 0x5C, 0x95, 0x6D, 0x45, 0x9A, 0x47, 0x7E, 0x99, 0x6A, 0x3F, 0x56, 0x64, 0x57,
		0x4D, 0x4E, 0x4C, 0x4B, 0x83, 0x1F, 0x3E, 0x22, 0x0C, 0x0B, 0x11, 0x8F, 0x30, 0x35, 0x93, 0x7B,
		0x08, 0x0F, 0x0D, 0x00, 0x07, 0x09, 0x0A, 0x03, 0x02, 0x01, 0x06, 0x04, 0x0E, 0x05, 0x0B, 0x0C,
		0x2F, 0x31, 0x36, 0x37, 0x33, 0x32, 0x34, 0x3B, 0x3A, 0x39, 0x38, 0x3D, 0x3C, 0x3F, 0x3E, 0x35,
		0x52, 0x53, 0x50, 0x51, 0x56, 0x57, 0x54, 0x55, 0x5A, 0x5B, 0x58, 0x59, 0x5E, 0x5F, 0x5C, 0x5D,
		0x71, 0x70, 0x73, 0x72, 0x77, 0x76, 0x75, 0x74, 0x7B, 0x7A, 0x79, 0x78, 0x7F, 0x7E, 0x7D, 0x7C,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		0xB3, 0xB2, 0xB1, 0xB0, 0xB7, 0xB6, 0xB5, 0xB4, 0xB9, 0xB8, 0xBB, 0xBA, 0xBF, 0xBE, 0xBD, 0xBC,
		0xD2, 0xD3, 0xD0, 0xD1, 0xD6, 0xD7, 0xD4, 0xD5, 0xDA, 0xDB, 0xD8, 0xD9, 0xDE, 0xDF, 0xDC, 0xDD,
		0xF1, 0xF0, 0xF3, 0xF2, 0xF7, 0xF6, 0xF5, 0xF4, 0xFB, 0xFA, 0xF9, 0xF8, 0xFF, 0xFE, 0xFD, 0xFC,
		0x1E, 0x1F, 0x1C, 0x1D, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
		0x4F, 0x76, 0x89, 0xA7, 0x2C, 0x2B, 0x3D, 0x61, 0x0E, 0x5C, 0x95, 0x6D, 0x45, 0x9A, 0x47, 0x7E,
		0x99, 0x6A, 0x3F, 0x56, 0x64, 0x57, 0x4D, 0x4E, 0x4C, 0x4B, 0x83, 0x1F, 0x3E, 0x22, 0x0C, 0x0B,
		0x11, 0x8F, 0x30, 0x35, 0x93, 0x7B, 0x08, 0x0F, 0x0D, 0x00, 0x07, 0x09, 0x0A, 0x03, 0x02, 0x01,
		0x06, 0x04, 0x0E, 0x05, 0x0B, 0x0C, 0x2F, 0x31, 0x36, 0x37, 0x33, 0x32, 0x34, 0x3B, 0x3A, 0x39
	};
	const unsigned int twofish::_mds[4][4] = {{0x01, 0xEF, 0x5B, 0x5B}, {0x5B, 0xEF, 0xEF, 0x01}, {0xEF, 0x5B, 0x01, 0xEF}, {0xEF, 0x01, 0xEF, 0x5B}};
	std::string vigenere_encrypt(const std::string& txt, const std::string& key) {
		std::string out;
		for (size_t i = 0; i < txt.size(); ++i) {
			char p = txt[i];
			if (std::isalpha(p)) {
				int k = std::toupper(key[i % key.size()]) - 'A';
				char base = std::isupper(p) ? 'A' : 'a';
				out += char((std::toupper(p) - 'A' + k) % 26 + base);
			} else out += p;
		}
		return out;
	}
	std::string vigenere_decrypt(const std::string& txt, const std::string& key) {
		std::string out;
		for (size_t i = 0; i < txt.size(); ++i) {
			char c = txt[i];
			if (std::isalpha(c)) {
				int k = std::toupper(key[i % key.size()]) - 'A';
				char base = std::isupper(c) ? 'A' : 'a';
				out += char((26 + (c - base) - k) % 26 + base);
			} else out += c;
		}
		return out;
	}
}

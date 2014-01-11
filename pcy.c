#include "pcy.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#define PCY_STUB if (PCY_STUB_ON)

unsigned char *pcy_data;

pcy_cryptokey genkey()
{
	pcy_cryptokey ret = {0};
	int i, x, j;
	char tmp, *s1, *s2;
	srand(time(0));
	ret.c1 = rand() % 127;
	ret.c2 = rand() % 255;
	ret.c3 = rand() % 32;
	ret.c4 = rand() % 32;
	ret.c5 = rand() % 255;
	x = rand() % 120 + 1;
	for (i = 0; i < x; i++)
	{
		j = rand() % 5 + 1;
		if (j == 1) s1 = &ret.c1;
		if (j == 2) s1 = &ret.c2;
		if (j == 3) s1 = &ret.c3;
		if (j == 4) s1 = &ret.c4;
		if (j == 5) s1 = &ret.c5;
		j = rand() % 5 + 1;
		if (j == 1) s2 = &ret.c1;
		if (j == 2) s2 = &ret.c2;
		if (j == 3) s2 = &ret.c3;
		if (j == 4) s2 = &ret.c4;
		if (j == 5) s2 = &ret.c5;
		tmp = *s1;
		*s1 = *s2;
		*s2 = tmp;
	}
	return ret;
}

void printkey(pcy_cryptokey *key, FILE *f)
{
	fwrite(&*key, sizeof(pcy_cryptokey), 1, f);
	fflush(f);
}

void printkeydata(pcy_cryptokey key)
{
	unsigned char tmp, tmp2;
	int i;
	tmp = 0;
	if (key.c1 & (1 << 0)) tmp |= (1 << 0);
	if (key.c1 & (1 << 1)) tmp |= (1 << 1);
	if (key.c1 & (1 << 2)) tmp |= (1 << 2);
	if (key.c1 & (1 << 3)) tmp |= (1 << 3);
	printf("OTP: 0x%02x\n", tmp);
	tmp = 0;
	if (key.c1 & (1 << 4)) tmp |= (1 << 0);
	if (key.c1 & (1 << 5)) tmp |= (1 << 1);
	if (key.c1 & (1 << 6)) tmp |= (1 << 2);
	if (key.c1 & (1 << 7)) tmp |= (1 << 3);
	printf("Bit pattern: 0x%02x\n", tmp);
	tmp = key.c2;
	if (tmp & (1 << 7))
	{
		printf("Byte swapping is enabled\n");
		tmp ^= (1 << 7);
		printf("Frequency of byte swap: 0x%02x\n", tmp);
	}
	else
		printf("Byte swapping is DISABLED\n");
	printf("OTP Frequency: 0x%02x\n", key.c3 & 0xFF);
	printf("Bit pattern frequency: 0x%02x\n", key.c4 & 0xFF);
	tmp = 0;
	if (key.c5 & (1 << 0)) tmp |= (1 << 0);
	if (key.c5 & (1 << 1)) tmp |= (1 << 1);
	if (key.c5 & (1 << 2)) tmp |= (1 << 2);
	printf("Encryption order: 0x%02x\n", tmp);
	tmp = 0;
	if (key.c5 & (1 << 3)) tmp |= (1 << 0);
	if (key.c5 & (1 << 4)) tmp |= (1 << 1);
	if (key.c5 & (1 << 5)) tmp |= (1 << 2);
	if (key.c5 & (1 << 6)) tmp |= (1 << 3);
	if (key.c5 & (1 << 7)) tmp |= (1 << 4);
	printf("Padding frequency: 0x%02x\n", tmp);
}

void do_otp(const pcy_cryptokey key, unsigned int *size, char mode)
{
	int i, fq, pad = 0;
	unsigned char tmp = 0;
	PCY_STUB printf("\tdo_otp\n");
	if (key.c1 & (1 << 0)) tmp |= (1 << 0);
	if (key.c1 & (1 << 1)) tmp |= (1 << 1);
	if (key.c1 & (1 << 2)) tmp |= (1 << 2);
	if (key.c1 & (1 << 3)) tmp |= (1 << 3);
	fq = key.c3 & 0xFF;
	pad = tmp & 0xFF;
	for (i = 1; i < *size; i++)
		if (i % fq == 0)
		{
			if (mode == 0) { pcy_data[i] = pcy_data[i] + pad; continue; }
			if (mode == 1) { pcy_data[i] = pcy_data[i] - pad; continue; }
		}
}

void do_bitpattern(const pcy_cryptokey key, unsigned int *size, char mode)
{
	unsigned char tmp;
	int i, fq;
	PCY_STUB printf("\tdo_bitpattern\n");
	fq = key.c4 & 0xFF;
	if (fq < 2) fq = 2;
	tmp = 0;
	if (key.c1 & (1 << 4)) tmp |= (1 << 0);
	if (key.c1 & (1 << 5)) tmp |= (1 << 1);
	if (key.c1 & (1 << 6)) tmp |= (1 << 2);
	if (key.c1 & (1 << 7)) tmp |= (1 << 3);
	PCY_STUB printf("\t\tfq: %d, pattern: %02x, size: %d\n", fq, tmp, *size);
	for (i = 0; i < *size; i++)
	{
		if (i % fq == 0 && i > 0)
		{
			pcy_data[i] ^= tmp;
		}
	}
}

void do_padding(const pcy_cryptokey key, unsigned int *size, char mode)
{
	int  n, napp = 0;
	unsigned char tmp, *newd, fq = 0;
	PCY_STUB printf("\tdo_padding\n");
	srand(time(0));
	if (key.c5 & (1 << 3)) tmp |= (1 << 0);
	if (key.c5 & (1 << 4)) tmp |= (1 << 1);
	if (key.c5 & (1 << 5)) tmp |= (1 << 2);
	if (key.c5 & (1 << 6)) tmp |= (1 << 3);
	if (key.c5 & (1 << 7)) tmp |= (1 << 4);
	fq = tmp;
	if (fq < 10 || fq > *size)
		return;
	newd = (unsigned char *)malloc(*size * 2); //prevent memory leak
	for (n = 0; n < *size; n++)
	{
		if (n % fq == 0 && n > 0)
		{
			if (mode == 0)
				newd[n + napp] = rand() % 127;
			napp++;
		}
		if (mode == 0)
			newd[n+napp] = pcy_data[n];
		else
			newd[n] = pcy_data[n+napp];
	}
	if (mode == 0)
	{
		*size += napp;
		for (n = 0; n < *size; n++)
			pcy_data[n] = newd[n];
	}
	else
	{
		*size -= napp;
		for (n = 0; n < *size; n++)
			pcy_data[n] = newd[n];
	}
	free(newd);
}

void do_byteswap(const pcy_cryptokey key, unsigned int *size, char mode)
{
	int fq, n;
	char tmp = key.c2;
	unsigned char tmp2;
	PCY_STUB printf("\tdo_byteswap\n");
	if (!(tmp & (1 << 7)))
		return;
	tmp ^= (1 << 7);
	fq = tmp;
	for (n = 0; n < *size; n++)
	{
		if (n % fq == 0 && n > 0)
		{
			tmp2 = pcy_data[n];
			pcy_data[n] = pcy_data[n + 1];
			pcy_data[n + 1] = tmp2;
		}
	}
}

void do_crypt(pcy_cryptokey key, unsigned char *buf, unsigned int *size, char mode) /*mode = 0 for encrypt, anything else for decrypt*/
{
	unsigned char tmp = 0;
	int i;
	void (*fns[5])(const pcy_cryptokey key, unsigned int *size, char mode);
	pcy_data = buf;
	if (key.c5 & (1 << 0)) tmp |= (1 << 0);
	if (key.c5 & (1 << 1)) tmp |= (1 << 1);
	if (key.c5 & (1 << 2)) tmp |= (1 << 2);
	if (tmp == 0)
	{
		fns[0] = &do_otp;
		fns[1] = &do_bitpattern;
		fns[2] = &do_padding;
		fns[3] = &do_byteswap;
	}
	else if (tmp == 1)
	{
		fns[3] = &do_otp;
		fns[2] = &do_bitpattern;
		fns[1] = &do_padding;
		fns[0] = &do_byteswap;
	}
	else if (tmp == 2)
	{
		fns[0] = &do_otp;
		fns[1] = &do_byteswap;
		fns[2] = &do_padding;
		fns[3] = &do_bitpattern;
	}
	else if (tmp == 3)
	{
		fns[1] = &do_otp;
		fns[0] = &do_bitpattern;
		fns[3] = &do_padding;
		fns[2] = &do_byteswap;
	}
	else if (tmp == 4)
	{
		fns[2] = &do_otp;
		fns[0] = &do_bitpattern;
		fns[3] = &do_padding;
		fns[1] = &do_byteswap;
	}
	else if (tmp == 5)
	{
		fns[1] = &do_otp;
		fns[3] = &do_bitpattern;
		fns[2] = &do_padding;
		fns[0] = &do_byteswap;
	}
	else if (tmp == 6)
	{
		fns[3] = &do_otp;
		fns[1] = &do_bitpattern;
		fns[2] = &do_padding;
		fns[0] = &do_byteswap;
	}
	else if (tmp == 7)
	{
		fns[3] = &do_otp;
		fns[0] = &do_bitpattern;
		fns[1] = &do_padding;
		fns[2] = &do_byteswap;
	}
	if (mode == 0)
		for (i = 0; i < 4; i++)
			fns[i](key, size, mode);
	if (mode == 1)
		for (i = 3; i >= 0; i--)
			fns[i](key, size, mode);
}

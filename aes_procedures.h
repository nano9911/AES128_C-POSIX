/*
*	Author: Adnan Hleihel
*	Created at: 19/11/2020
*	Last Modefied: 27/11/2020
*	Title: AES encryption and decryption procedure header
*/

#include "aes_enc_dec_stages.h"
#include "aes_key_schedule.h"

unsigned char IV[16];

void encrypt_block(unsigned char *ptr)
{
//	Initial Round [plain XOR key(W0-W3)]
	for (int i = 0; i < 16; i++)
	{	ptr[i] ^= key[i];	}

//	9 Main Rounds
	for (int i = 0; i < 9; i++)
	{
		subbytes(ptr, 16);
		shiftrows(ptr);		
		mixcolumns(ptr);
		for (int e = 0; e < 16; e++)
		{	ptr[e] ^= roundkey[i][e];	}	
	}

//	Final Round
	subbytes(ptr, 16);
	shiftrows(ptr);

//	XOR last roundkey(W40-W43)
	for (int i = 0; i < 16; i++)
{	ptr[i] ^= roundkey[9][i];	}
}

void decrypt_block(unsigned char *ptr)
{
//	initial round [cipher xor last round key(W40-W43)]
	for (int i = 0; i < 16; i++)
		ptr[i] ^= roundkey[9][i];

//	9 Main Rounds
	for (int i = 8; i >=0; i--)
	{
		invshiftrows(ptr);
		invsubbytes(ptr, 16);
		for (int e = 0; e < 16; e++)
		{	ptr[e] ^= roundkey[i][e];	}
		invmixcolumns(ptr);
	}
	
//	Final Round
	invsubbytes(ptr, 16);
	invshiftrows(ptr);

//	XOR with original key (W0-W4)
	for (int i = 0; i < 16; i++)
	{	ptr[i] ^= key[i];	}
}

int getiv(char *fn)
{
	FILE *fp = NULL;
	if ((fp = fopen(fn, "r")) <= 0)	return  (-1);
	for (int i = 0; i < 16; i++)
	{	IV[i] = (unsigned char)getc(fp);	if (IV[i] < 0)	return (-2);	}

	printf("\n[*] IV from file:");
	for (int i = 0; i < 4; i++)
	{
		printf("\n0x%X\t", IV[i+0]);
		printf("0x%X\t", IV[i+4]);
		printf("0x%X\t", IV[i+8]);
		printf("0x%X", IV[i+12]);
	}
	fclose(fp);
	return 0;
}

void ivrndgen()
{
	unsigned char h;
	srand(0);
	for (int i = 0; i < 16; i++)
	{
		IV[i] = (unsigned char)rand();	h = (unsigned char)((signed char)IV[i] >> 7);
		IV[i] ^= 0x1B & h;
	}

	printf("\n[*] Randomly generated IV:");
	for (int i = 0; i < 4; i++)
	{
		printf("\n0x%X\t", IV[i+0]);
		printf("0x%X\t", IV[i+4]);
		printf("0x%X\t", IV[i+8]);
		printf("0x%X", IV[i+12]);
	}
}

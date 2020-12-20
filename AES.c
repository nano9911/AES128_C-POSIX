/*
*	Author: Adnan Hleihel
*	Created at: 15/11/2020
*	Last Modefied: 28/11/2020
*	Title: AES ecb_encryption implementation
*
*	argv[0] = ./aes	argv[1] = -ecb or argv[1] = -ctr	argv[2] = -e --> argv[3] = plaintext file	or	argv[2] = -d --> argv[3] = ciphertext file
*	argv[4] = -k	argv[5] = key file or r for random
*	optional:		argv[6] = -iv	argv[7] = IV file or r for random
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "aes_procedures.h"

#define PLAIN_FILE_NAME "output/plain.txt"
#define CIPHER_FILE_NAME "output/encrypted.aes"

#define READ_BUFF_SIZE  10
#define WRITE_BUFF_SIZE  10

static int count1 = 0, count2 = 0, InP1 = 0, OutP1 = 0,  InP2 = 0, OutP2 = 0, size = 0, extra = 0;
unsigned char buff1[READ_BUFF_SIZE][16], buff2[WRITE_BUFF_SIZE][16];
static unsigned char threads_status = 0;
static int rderr = 0, wrerr = 0, encerr = 0, decerr = 0;

pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER, m2 = PTHREAD_MUTEX_INITIALIZER;

int getfilesize(char *fl);
void *read(void *fn);
void *ecb_encrypt();
void *ctr_encrypt();
void *ctr_encrypt();
void *ecb_decrypt();
void *ctr_decrypt();
void *write();

int main (int argc, char *argv[])
{
//	handling inputs
	if ((argc != 6 && (argv[1][1] == 'e' && argv[1][1] == 'c' && argv[1][1] == 'b'))
		|| ((argv[1][1] == 'c' && argv[1][2] == 't' && argv[1][3] == 'r') && argc != 8))
	{	fprintf(stderr, "Usage: ./aes -[ecb/ctr] -[e/d] [filename] -k [keyfile/r(for random)]\noptional: -iv [ivfile/r (for random)] (IV in char)\n");	exit(-1);	}

//	Getting or Generating key
	if (argv[4][0] == '-' && argv[4][1] == 'k')
	{
		if (argv[5][0] == 'r' && argv[5][1] == 0)
		{
			genrndkey();
		}

		else
		{
			int getkeystat = 1;
			getkeystat = getkey(argv[5]);
			if(getkeystat < 0)
			{
				if (getkeystat == -1)	
				{	fprintf(stderr, "Error: %s key file doesn't exist or can't be accessed\n", argv[5]);	exit(-1);}
				if(getkeystat == -2)
				{	fprintf(stderr, "Error: Failed to read data from %s file\n", argv[5]);	exit(-1);	}
			}
			else if (getkeystat == 0)
				genroundkeys();
		}
	}

//	Get the file size in bytes, and in states
	if ((size = getfilesize(argv[3])) <= 0)
	{
		if (size == 0)
		{	fprintf(stderr, "ERROR: %s is empty.\n", argv[3]);		exit(-1);	}
	//	Handling getfilesize proccess errors
		else if (size == -1)
		{	fprintf(stderr, "ERROR: %s file doesn't exist or can't be accessed\n", argv[3]);		exit(-1);	}

		else if (size == -3)
		{	fprintf(stderr, "ERROR: fseek failed.\n");	exit(-1);	}

		else if (size == -4)
		{	fprintf(stderr, "ERROR: ftell failed.\n");	exit(-1);	}
	}

//	Here Starts the real work
	int *optype = NULL;
	if (argv[1][0] == '-' && argv[1][1] == 'e' && argv[1][2] == 'c' && argv[1][3] == 'b' && argv[1][4] == 0)
	{
		printf("\n\n***\tECB Mode\t***\n");
		if (argv[2][0] == '-' && argv[2][1] == 'e' && argv[2][2] == 0)
		{
			printf("**\tencrypting\t**\n\n");	optype = (int *)1;
			pthread_t readthr, encthr, writethr;
			pthread_create(&readthr, NULL, read, argv[3]);
			pthread_create(&encthr, NULL, ecb_encrypt, NULL);
			pthread_create(&writethr, NULL, write, (void *)optype);

			pthread_join(readthr, NULL);
			pthread_join(encthr, NULL);
			pthread_join(writethr, NULL);
		}

		else if (argv[2][0] == '-' && argv[2][1] == 'd' && argv[2][2] == 0)
		{
			printf("**\tdecrypting\t**\n\n");	optype = (int *)2;
			pthread_t readthr, writethr, decthr;
			pthread_create(&readthr, NULL, read, argv[3]);
			pthread_create(&decthr, NULL, ecb_decrypt, NULL);
			pthread_create(&writethr, NULL, write, (void *)optype);

			pthread_join(readthr, NULL);
			pthread_join(decthr, NULL);
			pthread_join(writethr, NULL);
		}
	}
	
	else if (argv[1][0] == '-' && argv[1][1] == 'c' && argv[1][2] == 't' && argv[1][3] == 'r' && argv[1][4] == 0 
			&& argv[6][0] == '-' && argv[6][1] == 'i' && argv[6][2] == 'v')
	{
		//IV = (unsigned char *)malloc(16);
		int getivstat = 1;
		if (argv[7][0] == 'r')
		{	ivrndgen();	}
		else
		{
			getivstat = getiv(argv[7]);
			if (getivstat < 0)
			{
				if (getivstat == -1)
				{	fprintf(stderr, "\nError: %s iv file doesn't exist or can't access it\n", argv[7]);	exit(-1);}
				else if (getivstat == -2)
				{	fprintf(stderr, "\nError: Failed to read data from %s iv file\n", argv[7]);	exit(-1);	}
			}
		}
		printf("\n\n***\tCTR Mode\t***\n");
		if (argv[2][0] == '-' && argv[2][1] == 'e' && argv[2][2] == 0)
		{
			printf("**\tencrypting\t**\n\n");
			pthread_t readthr, encthr, writethr;	optype = (int *)1;
			pthread_create(&readthr, NULL, read, argv[3]);
			pthread_create(&encthr, NULL, ctr_encrypt, NULL);
			pthread_create(&writethr, NULL, write, (void *)optype);

			pthread_join(readthr, NULL);
			pthread_join(encthr, NULL);
			pthread_join(writethr, NULL);
		}
		else if (argv[2][0] == '-' && argv[2][1] == 'd' && argv[2][2] == 0)
		{
			printf("**\tdecrypting\t**\n\n");	optype = (int *)2;
			pthread_t readthr, writethr, decthr;
			pthread_create(&readthr, NULL, read, argv[3]);
			pthread_create(&decthr, NULL, ctr_decrypt, NULL);
			pthread_create(&writethr, NULL, write, (void *)optype);

			pthread_join(readthr, NULL);
			pthread_join(decthr, NULL);
			pthread_join(writethr, NULL);
		}
	}

	else
	{
		printf("\nargv[0]=%s\targv[1]=%s\targv[2]=%s\targv[3]=%s\n", argv[0], argv[1], argv[2], argv[3]);
		printf("\nXXX\tNo mode is selected orwrong syntax used\tXXX\n");
	}

	for (int i = 0; i < READ_BUFF_SIZE; i++)
	{
		for (int e = 0; e < 16; e++)
		{
			buff1[i][e] ^= buff1[i][e];
		}
	}
	for (int i = 0; i < WRITE_BUFF_SIZE; i++)
	{
		for (int e = 0; e < 16; e++)
		{
			buff2[i][e] ^= buff2[i][e];
		}
	}

	size = 0;	OutP1 ^= OutP1;	OutP2 ^= OutP2;	InP1 ^= InP1;	InP2 ^= InP2;
	if (threads_status != 0) {printf("\nAn ERROR occured in on of the threads and threads where terminated\n");}

	printf("\n");
	return 0;
}

int getfilesize(char *fl)
{
	int sz = 0;
//	open text file to check for file size
	FILE *plain = NULL;
	if ((plain = fopen(fl, "r")) <= 0)	return -1;

//	seek to the end of file to find the size of it, then close it
	if (fseek(plain, 0, SEEK_END) != 0)
	{	fclose(plain);	return -3;	}

	if ((sz = ftell(plain)) == -1)
	{	fclose(plain);	return -4;	}

	fclose(plain);
	
	printf("\n\n***\t%s size: %d Bytes,  ", fl,sz);
	/* Here extra is used for further dissecions about padding */
	extra = sz % 16;
	if (extra == 0)	{sz /= 16;}
	else	{sz = (sz / 16) + 1;}
	printf("%d Blocks\t***\n", sz);

	return sz;
}

void *read(void *fn)
{
	FILE *fp = fopen((char *)fn, "r"); /* File to read from */
	if(fp == NULL)	{threads_status = 0XFF;	pthread_exit(NULL);}

	/* tobuff is like a prebuffer to use and not affect on original buffer */
	unsigned char *tobuff = (unsigned char *)malloc(16);
	if (tobuff == NULL)	{threads_status = 0XFF;	fclose(fp);	pthread_exit(NULL);}
	printf("\n\t\t\t");
	for (int i = 0; i < size; i++)
	{
		/* Read from file */
		if ((i != (size-1)) || extra == 0)	{
			for (int e = 0; e < 16; e++)	{	tobuff[e] = getc(fp);	}
		}
		/* Padding */
		else if (extra > 0 && i == (size - 1))	{	
			for (int e = 0; e < extra; e++)	{	tobuff[e] = getc(fp);	}
			for (int e = extra; e < 16; e++)	{	tobuff[e] = 0x00;	}
		}
		
		if(threads_status != 0)	{free(tobuff);	fclose(fp);	pthread_exit(0);}
		/* Wait if Buffer is Full */
		while (count1 == READ_BUFF_SIZE)
		{	if(threads_status != 0)	{free(tobuff);	fclose(fp);	pthread_exit(0);}	}
		/* Write to buffer from prebuffer which contains data written from file */
		for (int e = 0; e < 16; e++)
		{	buff1[InP1][e] = tobuff[e];	tobuff[e] ^= tobuff[e];	}
//		printf("[*] read thread\tmoved block %d to buffer 1\n", i);

		if (i != 0)	{for (int e = 0; e < 25; e++)	{printf("\b");}	}
		printf("%08d Blocks encrypted", i+1);
		
		InP1 = (InP1 + 1) % READ_BUFF_SIZE;
		pthread_mutex_lock(&m1);
		count1++;
		pthread_mutex_unlock(&m1);
	}

	/* Clear PreBuffer and close file */
	fclose(fp); free(tobuff);
	pthread_exit(0);
}

void *ecb_encrypt()
{
	/* temporary small buffer to read from first buffer
	edit it, then move to the other buffer */
	unsigned char *toenc = (unsigned char *)malloc(16);
	if (toenc == NULL)	{threads_status = 0XFF;	pthread_exit(NULL);}

	for (int i = 0; i < size; i++)
	{	/* Wait if Buffer is Empty */
		while (count1 == 0)
		{	if(threads_status != 0)	{free(toenc);	pthread_exit(0);}	}
		/* Read data from buffer to ecb_encrypt it, XOR it with it self to delete original file from buffer */
		for (int e = 0; e < 16; e++)
		{	toenc[e] = buff1[OutP1][e];	}
//		printf("[*] ecb_encrypt thread\tread block %d from buffer 1 to temp-buffer\n", i);
		
		OutP1 = (OutP1 + 1) % READ_BUFF_SIZE;
		pthread_mutex_lock(&m1);
		count1--;
		pthread_mutex_unlock(&m1);

		/* Operate on data by reference to ecb_encrypt */
		encrypt_block(toenc);

		if(threads_status != 0)	{free(toenc);	pthread_exit(0);}

		/* Wait if Buffer is full */
		while (count2 == WRITE_BUFF_SIZE)
		{	if(threads_status != 0)	{free(toenc);	pthread_exit(0);}	}

		/* Move ecb_encrypted data to the write buffer to write it on file */
		for (int e = 0 ; e < 16; e++)
		{	buff2[InP2][e] = toenc[e];	toenc[e] ^= toenc[e];	}
		
		InP2 = (InP2 + 1) % WRITE_BUFF_SIZE;
		pthread_mutex_lock(&m2);
		count2++;
		pthread_mutex_unlock(&m2);
	}

	free(toenc);
	pthread_exit(NULL);
}

void *ecb_decrypt()
{
	/* temporary small buffer to read from first buffer
	edit it, then move to the other buffer */
	unsigned char *todec = (unsigned char *)malloc(16);
	if (todec == NULL)	{threads_status = 0XFF;	pthread_exit(NULL);}

	for (int i = 0; i < size; i++)
	{	/* Wait if Buffer is Empty */
		while (count1 == 0)
		{	if(threads_status != 0)	{free(todec);	pthread_exit(0);}	}

		/* Read data from buffer to ecb_encrypt it, XOR it with it self to delete original file from buffer */
		for (int e = 0; e < 16; e++)
		{	todec[e] = buff1[OutP1][e];	}

		OutP1 = (OutP1 + 1) % READ_BUFF_SIZE;
		pthread_mutex_lock(&m1);
		count1--;
		pthread_mutex_unlock(&m1);
		
		/* Operate on data by reference to ecb_decrypt */
		decrypt_block(todec);

		if(threads_status != 0)	{free(todec);	pthread_exit(0);}
		/* Wait if Buffer is full */
		while (count2 == WRITE_BUFF_SIZE)
		{	if(threads_status != 0)	{free(todec);	pthread_exit(0);}	}
		
		/* Move ecb_decrypted data to the write buffer to write it on file */
		for (int e = 0 ; e < 16; e++)
		{	buff2[InP2][e] = todec[e];	todec[e] ^= todec[e];	}

		InP2 = (InP2 + 1) % WRITE_BUFF_SIZE;
		pthread_mutex_lock(&m2);
		count2++;
		pthread_mutex_unlock(&m2);
	}

	free(todec);
	pthread_exit(NULL);
}

void *ctr_encrypt()
{
	/* tobuff is like a prebuffer to use without affecting the original buffer */
	unsigned char *toenc = (unsigned char *)malloc(16);
	if (toenc == NULL)	{threads_status = 0XFF;	pthread_exit(NULL);}

	for (int i = 0; i < size; i++)
	{
		/* Wait if buffer is busy or empty */
		while(count1 == 0)
		{	if(threads_status != 0)	{free(toenc);	pthread_exit(0);}	}

		/* Read from the shared buffer with read thread, then clean memory for protection */
		for (int e = 0; e < 16; e++)
		{	toenc[e] = buff1[OutP1][e];	}

		OutP1 = (OutP1 + 1) % READ_BUFF_SIZE;
		pthread_mutex_lock(&m1);
		count1--;
		pthread_mutex_unlock(&m1);

		/* encrypt IV + number of block */
		encrypt_block(IV);
		/* XORing Plain text with [IV+block number] */
		for (int e = 0; e < 16; e++)	{	toenc[e] ^= IV[e];	}

		/* IV + 1 */
		for (int e = 0; e < 16; e++)
		{
			if (IV[e] == 0xFF)	{IV[e] = 0x00;}
			else	{IV[e] += 1;	break;}
		}

		if(threads_status != 0)	{free(toenc);	pthread_exit(0);}
		/* Wait if Buffer2 is full */
		while (count2 == WRITE_BUFF_SIZE)
		{	if(threads_status != 0)	{free(toenc);	pthread_exit(0);}	}
		/* Move ctr_encrypted data to the write buffer to write it on file */
		for (int e = 0 ; e < 16; e++)
		{	buff2[InP2][e] = toenc[e];	toenc[e] ^= toenc[e];	}

		InP2 = (InP2 + 1) % WRITE_BUFF_SIZE;
		pthread_mutex_lock(&m2);
		count2++;
		pthread_mutex_unlock(&m2);
	}

	free(toenc);
	pthread_exit(NULL);
}

void *ctr_decrypt()
{
	/* tobuff is like a prebuffer to use and not affect on original buffer */
	unsigned char *todec = (unsigned char *)malloc(16);
	if (todec == NULL)	{threads_status = 0XFF;	pthread_exit(NULL);}

	for (int i = 0; i < size; i++)
	{
		/* Wait if buffer1 is busy or empty */
		while(count1 == 0)
		{	if(threads_status != 0)	{free(todec);	pthread_exit(0);}	}

		/* Read from the shared buffer with read thread, then clean memory for protection */
		for (int e = 0; e < 16; e++)
		{	todec[e] = buff1[OutP1][e];	}

		OutP1 = (OutP1 + 1) % READ_BUFF_SIZE;
		pthread_mutex_lock(&m1);
		count1--;
		pthread_mutex_unlock(&m1);

		/* encrypt IV + number of block */
		encrypt_block(IV);
		/* XORing Ciphertext text with [IV+block number] */
		for (int e = 0; e < 16; e++)	{	todec[e] ^= IV[e];	}
		/* IV + 1 */
		for (int e = 0; e < 16; e++)
		{
			if (IV[e] == 0xFF)	{IV[e] = 0x00;}
			else	{IV[e] += 1;	break;}
		}

		if(threads_status != 0)	{free(todec);	pthread_exit(0);}
		/* Wait if Buffer2 is full */
		while (count2 == WRITE_BUFF_SIZE)
		{	if(threads_status != 0)	{free(todec);	pthread_exit(0);}	}

		/* Move ctr_decrypted data to the write buffer to write it on file */
		for (int e = 0 ; e < 16; e++)
		{	buff2[InP2][e] = todec[e];	todec[e] ^= todec[e];	}

		InP2 = (InP2 + 1) % WRITE_BUFF_SIZE;
		pthread_mutex_lock(&m2);
		count2++;
		pthread_mutex_unlock(&m2);
	}

	free(todec);
	pthread_exit(NULL);
}

void *write(void *todo)
{
	/* file to write data on after operated on it */
	FILE *fp = NULL;
	if (todo == (int *)1)
		fp = fopen(CIPHER_FILE_NAME, "w");
	else if (todo == (int *)2)
		fp = fopen(PLAIN_FILE_NAME, "w");

	if(fp == NULL)	{threads_status = 0XFF;	pthread_exit(NULL);}

	/* tofile is like a prebuffer to use and not affect on original buffer */
	unsigned char *tofile = (unsigned char *)malloc(16);
	if (tofile == NULL)	{threads_status = 0XFF;	fclose(fp);	pthread_exit(NULL);}

	for (int i = 0; i < size; i++)
	{
		/* Wait if Buffer 2is Empty */
		while(count2 == 0)
		{	if(threads_status != 0)	{free(tofile);	fclose(fp);	pthread_exit(0);}	}
		if(threads_status != 0)	{free(tofile);	fclose(fp);	pthread_exit(0);}

		/* Read data from buffer to ecb_encrypt it, XOR it with it self to delete original file from buffer */
		for (int e = 0; e < 16; e++)
		{	tofile[e] = buff2[OutP2][e];		}

		OutP2 = (OutP2 + 1) % WRITE_BUFF_SIZE;
		pthread_mutex_lock(&m2);
		count2--;
		pthread_mutex_unlock(&m2);

		/* move data to the file from the prebuffer */
		if (todo == (int *)2)
		{	if (i != (size-1))
			{	for (int e = 0; e < 16; e++)
				{	fprintf(fp, "%c", tofile[e]);	tofile[e] ^= tofile[e];	}
			}
			else	
			{	for (int e = 0; e < 16; e++)
				{		if (tofile[e] == 0x00)	{break;}
					fprintf(fp, "%c", tofile[e]);	tofile[e] ^= tofile[e];
				}
			}
		}
		else if (todo == (int *)1)
		{	for (int e = 0; e < 16; e++)
			{	fprintf(fp, "%c", tofile[e]);	tofile[e] ^= tofile[e];	}
		}
	}

	fclose(fp);	free(tofile);
	pthread_exit(NULL);
}

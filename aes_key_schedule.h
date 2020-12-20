/*
*	Author: Adnan Hleihel
*	Created at: 18/11/2020
*	Last Modefied: 27/11/2020
*	Title: AES Key [Scheduling/Generating] header (addroundkey - genrndkey - getkey)
*/

//	rcon table (10 rounds --> each has 4 elements)
const unsigned char rcon[10][4] ={{0x01, 0x00, 0x00, 0x00},	{0x02, 0x00, 0x00, 0x00},
								{0x04, 0x00, 0x00, 0x00},	{0x08, 0x00, 0x00, 0x00},
								{0x10, 0x00, 0x00, 0x00},	{0x20, 0x00, 0x00, 0x00},
								{0x40, 0x00, 0x00, 0x00},	{0x80, 0x00, 0x00, 0x00},
								{0x1B, 0x00, 0x00, 0x00},	{0x36, 0x00, 0x00,0x00}};

unsigned char key[16];

unsigned char roundkey[10][16];

void addroundkey(unsigned char *nw, unsigned char *old, int round)
{
//	initial step is to use last column from last key (old)
//	to generate the first column of the new key (nw)

//	tmp is the base column where we will XOR with it to generate the next column
//	then it will take it's value to generate the next
	unsigned char tmp[4] = {old[13], old[14], old[15], old[12]};
//	Sub-Byte is used in the generation of the first column only
	subbytes(tmp, 4);

//	generating first column from old first column XOR with tmp and rcon appropiate column
//	for the the round number passsed
	nw[0] = old[0] ^ tmp[0] ^ rcon[round][0];	tmp[0] = nw[0];
	nw[1] = old[1] ^ tmp[1] ^ rcon[round][1];	tmp[1] = nw[1];
	nw[2] = old[2] ^ tmp[2] ^ rcon[round][2];	tmp[2] = nw[2];
	nw[3] = old[3] ^ tmp[3] ^ rcon[round][3];	tmp[3] = nw[3];

//	generating the rest of the columns by XOR with the last one generated
	for (int i = 4; i < 16; i += 4)
	{
		nw[i]     = old[i]     ^ tmp[0];	tmp[0] = nw[i];
		nw[i+1] = old[i+1] ^ tmp[1];	tmp[1] = nw[i+1];
		nw[i+2] = old[i+2] ^ tmp[2];	tmp[2] = nw[i+2];
		nw[i+3] = old[i+3] ^ tmp[3];	tmp[3] = nw[i+3];
	}
	
	for (int i = 0; i < 4; i++)
		tmp[i] ^= tmp[i];
}

//	generate all round keys, starting from original key
void genroundkeys()
{
	addroundkey(roundkey[0], key, 0);

	for (int i = 1; i < 10; i++)
	{
		addroundkey(roundkey[i], roundkey[i-1], i);
	}
}

void genrndkey()
{
	srand(0);
	unsigned char h;
	for (int i = 0; i < 16; i++)
	{
		key[i] = rand();	h = (unsigned char)((signed char)key[i] >> 7);
		key[i] ^= 0x1B & h;
	}
	
	printf("\n[*] Random key generated :");
	for (int i = 0; i < 4; i++)
	{
		printf("\n0x%X\t", key[i+0]);
		printf("0x%X\t", key[i+4]);
		printf("0x%X\t", key[i+8]);
		printf("0x%X", key[i+12]);
	}
}

int getkey(char *fn)
{
	FILE *fp = fopen(fn, "r");
	if (fp <= 0)	return (-1);
	for (int i = 0; i < 16; i++)
	{	if ((key[i] = (unsigned char)getc(fp)) < 0)	return (-2);	}

	printf("\n[*] key from file:");
	for (int i = 0; i < 4; i++)
	{
		printf("\n0x%X\t", key[i+0]);
		printf("0x%X\t", key[i+4]);
		printf("0x%X\t", key[i+8]);
		printf("0x%X", key[i+12]);
	}

	return 0;
}

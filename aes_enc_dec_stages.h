/*
*	Author: Adnan Hleihel
*	Created at: 15/11/2020
*	Last Modefied: 27/11/2020
*	Title: AES encryption/decryption header (inv/subbyte - inv/shiftrows - inv/mixcolumn)
*/

const unsigned char subtable[16][16] = {
 									//	    00       10       20       30       40       50       60       70       80       90       A0       B0       C0       D0       E0       F0
								/*00*/	{0x63, 0xCA, 0xB7, 0x04, 0x09, 0x53, 0xD0, 0x51, 0xCD, 0x60, 0xE0, 0xE7, 0xBA, 0x70, 0xE1, 0x8C},
								/*01*/	{0x7C, 0x82, 0xFD, 0xC7, 0x83, 0xD1, 0xEF, 0xA3, 0x0C, 0x81, 0x32, 0xC8, 0x78, 0x3E, 0xF8, 0xA1},
								/*02*/	{0x77, 0xC9, 0x93, 0x23, 0x2C, 0x00, 0xAA, 0x40, 0x13, 0x4F, 0x3A, 0x37, 0x25, 0xB5, 0x98, 0x89},
								/*03*/	{0x7B, 0x7D, 0x26, 0xC3, 0x1A, 0xED, 0xFB, 0x8F, 0xEC, 0xDC, 0x0A, 0x6D, 0x2E, 0x66, 0x11, 0x0D},
								/*04*/	{0xF2, 0xFA, 0x36, 0x18, 0x1B, 0x20, 0x43, 0x92, 0x5F, 0x22, 0x49, 0x8D, 0x1C, 0x48, 0x69, 0xBF},
								/*05*/	{0x6B, 0x59, 0x3F, 0x96, 0x6E, 0xFC, 0x4D, 0x9D, 0x97, 0x2A, 0x06, 0xD5, 0xA6, 0x03, 0xD9, 0xE6},
								/*06*/	{0x6F, 0x47, 0xF7, 0x05, 0x5A, 0xB1, 0x33, 0x38, 0x44, 0x90, 0x24, 0x4E, 0xB4, 0xF6, 0x8E, 0x42},
								/*07*/	{0xC5, 0xF0, 0xCC, 0x9A, 0xA0, 0x5B, 0x85, 0xF5, 0x17, 0x88, 0x5C, 0xA9, 0xC6, 0x0E, 0x94, 0x68},
								/*08*/	{0x30, 0xAD, 0x34, 0x07, 0x52, 0x6A, 0x45, 0xBC, 0xC4, 0x46, 0xC2, 0x6C, 0xE8, 0x61, 0x9B, 0x41},
								/*09*/	{0x01, 0xD4, 0xA5, 0x12, 0x3B, 0xCB, 0xF9, 0xB6, 0xA7, 0xEE, 0xD3, 0x56, 0xDD, 0x35, 0x1E, 0x99},
								/*0A*/	{0x67, 0xA2, 0xE5, 0x80, 0xD6, 0xBE, 0x02, 0xDA, 0x7E, 0xB8, 0xAC, 0xF4, 0x74, 0x57, 0x87, 0x2D},
								/*0B*/	{0x2B, 0xAF, 0xF1, 0xE2, 0xB3, 0x39, 0x7F, 0x21, 0x3D, 0x14, 0x62, 0xEA, 0x1F, 0xB9, 0xE9, 0x0F},
								/*0C*/	{0xFE, 0x9C, 0x71, 0xEB, 0x29, 0x4A, 0x50, 0x10, 0x64, 0xDE, 0x91, 0x65, 0x4B, 0x86, 0xCE, 0xB0},
								/*0D*/	{0xD7, 0xA4, 0xD8, 0x27, 0xE3, 0x4C, 0x3C, 0xFF, 0x5D, 0x5E, 0x95, 0x7A, 0xBD, 0xC1, 0x55, 0x54},
								/*0E*/	{0xAB, 0x72, 0x31, 0xB2, 0x2F, 0x58, 0x9F, 0xF3, 0x19, 0x0B, 0xE4, 0xAE, 0x8B, 0x1D, 0x28, 0XBB},
								/*0F*/	{0x76, 0xC0, 0x15, 0x75, 0x84, 0xCF, 0xA8, 0xD2, 0x73, 0xDB, 0x79, 0x08, 0x8A, 0x9E, 0xDF, 0x16}
								};

const unsigned char invsubtable[16][16] = {
									//        00       10       20       30       40       50       60       70       80       90       A0       B0       C0       D0       E0       F0
								/*00*/	{0x52, 0x7C, 0x54, 0x08, 0x72, 0x6C, 0x90, 0xD0, 0x3A, 0x96, 0x47, 0xFC, 0x1F, 0x60, 0xA0, 0x17},
								/*01*/	{0x09, 0xE3, 0x7B, 0x2E, 0xF8, 0x70, 0xD8, 0x2C, 0x91, 0xAC, 0xF1, 0x56, 0xDD, 0x51, 0xE0, 0x2B},
								/*02*/	{0x6A, 0x39, 0x94, 0xA1, 0xF6, 0x48, 0xAB, 0x1E, 0x11, 0x74, 0x1A, 0x3E, 0xA8, 0x7F, 0x3B, 0x04},
								/*03*/	{0xD5, 0x82, 0x32, 0x66, 0x64, 0x50, 0x00, 0x8F, 0x41, 0x22, 0x71, 0x4B, 0x33, 0xA9, 0x4D, 0x7E},
								/*04*/	{0x30, 0x9B, 0xA6, 0x28, 0x86, 0xFD, 0x8C, 0xCA, 0x4F, 0xE7, 0x1D, 0xC6, 0x88, 0x19, 0xAE, 0xBA},
								/*05*/	{0x36, 0x2F, 0xC2, 0xD9, 0x68, 0xED, 0xBC, 0x3F, 0x67, 0xAD, 0x29, 0xD2, 0x07, 0xB5, 0x2A, 0x77},
								/*06*/	{0xA5, 0xFF, 0x23, 0x24, 0x98, 0xB9, 0xD3, 0x0F, 0xDC, 0x35, 0xC5, 0x79, 0xC7, 0x4A, 0xF5, 0xD6},
								/*07*/	{0x38, 0x87, 0x3D, 0xB2, 0x16, 0xDA, 0x0A, 0x02, 0xEA, 0x85, 0x89, 0x20, 0x31, 0x0D, 0xB0, 0x26},
								/*08*/	{0xBF, 0x34, 0xEE, 0x76, 0xD4, 0x5E, 0xF7, 0xC1, 0x97, 0xE2, 0x6F, 0x9A, 0xB1, 0x2D, 0xC8, 0xE1},
								/*09*/	{0x40, 0x8E, 0x4C, 0x5B, 0xA4, 0x15, 0xE4, 0xAF, 0xF2, 0xF9, 0xB7, 0xDB, 0x12, 0xE5, 0xEB, 0x69},
								/*0A*/	{0xA3, 0x43, 0x95, 0xA2, 0x5C, 0x46, 0x58, 0xBD, 0xCF, 0x37, 0x62, 0xC0, 0x10, 0x7A, 0xBB, 0x14},
								/*0B*/	{0x9E, 0x44, 0x0B, 0x49, 0xCC, 0x57, 0x05, 0x03, 0xCE, 0xE8, 0x0E, 0xFE, 0x59, 0x9F, 0x3C, 0x63},
								/*0C*/	{0x81, 0xC4, 0x42, 0x6D, 0x5D, 0xA7, 0xB8, 0x01, 0xF0, 0x1C, 0xAA, 0x78, 0x27, 0x93, 0x83, 0x55},
								/*0D*/	{0xF3, 0xDE, 0xFA, 0x8B, 0x65, 0x8D, 0xB3, 0x13, 0xB4, 0x75, 0x18, 0xCD, 0x80, 0xC9, 0x53, 0x21},
								/*0E*/	{0xD7, 0xE9, 0xC3, 0xD1, 0xB6, 0x9D, 0x45, 0x8A, 0xE6, 0xDF, 0xBE, 0x5A, 0xEC, 0x9C, 0x99, 0x0C},
								/*0F*/	{0xFB, 0xCB, 0x4E, 0x25, 0x92, 0x84, 0x06, 0x6B, 0x73, 0x6E, 0x1B, 0xF4, 0x5F, 0xEF, 0x61, 0x7D},
							};

/*
*	Rijndael Bytes Substitution using S-Box
*	[s] is to define who is calling to do it right
*	if SubByte level from a round pass (s = 16) a hall state
*	if SubByte for AddRoundKey pass (s = 4) a column from a state
*/
void subbytes(unsigned char *ptr, int s)
{
	unsigned char col, row;

	for (int i = 0; i < s; i++)
	{
		col = ptr[i];	row = ptr[i];
//		column --> high 4 bits   &	row --> low 4 bits
		col = (col >> 4) & 0x0F;	row = row & 0x0F;
		ptr[i] = subtable[row][col];
		col ^= col;	row ^= row;
	}
}

//	Rijndael Inverse Bytes Substitution using Inverse S-Box
void invsubbytes(unsigned char *ptr, int s)
{
	unsigned char col, row;

	for (int i = 0; i < s; i++)
	{
		col = ptr[i];	row = ptr[i];
//		column is the high 4 bits   &	row is the low 4 bits
		col = (col >> 4) & 0x0F;	row = row & 0x0F;
		ptr[i] = invsubtable[row][col];
		col ^= col;	row ^= row;
	}
}

//	Shift Rows
void shiftrows(unsigned char *ptr)
{
	unsigned char tmp1, tmp2;

//	Row 2 shifting [1 --> 13 |  5 --> 1 | 9 --> 5 | 13 --> 9]
	tmp1 = ptr[1];
	ptr[1] = ptr[5];	ptr[5] = ptr[9];	ptr[9] = ptr[13];
	ptr[13] = tmp1;

//	Row 3 shifting [2 <--> 10 | 6 <--> 14]
	tmp1 = ptr[2], tmp2 = ptr[6];
	ptr[2] = ptr[10];	ptr[10] = tmp1;
	ptr[6] = ptr[14];	ptr[14] = tmp2;

//	Row 4 shifting [15 --> 3 | 3 --> 7 | 7 --> 11 | 11 --> 15]
	tmp1 = ptr[15];
	ptr[15] = ptr[11];	ptr[11] = ptr[7];	ptr[7] = ptr[3];
	ptr[3] = tmp1;
}

//	Inverse Shift Rows
void invshiftrows(unsigned char *ptr)
{
	unsigned char tmp1, tmp2;

//	Row 2 shifting [13 --> 1 |  1 --> 5 | 5 --> 9 | 9 --> 13]
	tmp1 = ptr[13];
	ptr[13] = ptr[9]; ptr[9] = ptr[5]; ptr[5] = ptr[1];
	ptr[1] = tmp1;

//	Row 3 shifting [2 <--> 10 | 6 <--> 14]
	tmp1 = ptr[2], tmp2 = ptr[6];
	ptr[2] = ptr[10];	ptr[10] = tmp1;
	ptr[6] = ptr[14];	ptr[14] = tmp2;

//	Row 4 shifting [3 --> 15 | 7 --> 3 | 11 --> 7 | 15 --> 11]
	tmp1 = ptr[3];
	ptr[3] = ptr[7]; ptr[7] = ptr[11]; ptr[11] = ptr[15];
	ptr[15] = tmp1;
}

//	You can find (Rijndael MixColumns) description and implementation here:
// 	https://en.wikipedia.org/wiki/Rijndael_MixColumns
//	I used there implementation in mixcolumns only, and added some explanations on it.
void mixcolumns(unsigned char *ptr)
{
	unsigned char mul1[4], mul2[4];
	unsigned char h;
	for (int i = 0; i < 16; i += 4)
	{
		for (int e = 0; e < 4; e++)
		{
			mul1[e] = ptr[i+e];	/* multiplied by 1 */
			mul2[e] = ptr[i+e] << 1;	h = (unsigned char)((signed char)ptr[i+e] >> 7);
			mul2[e] ^= 0x1B & h;	/* multiplied by 2 // h is to check and keep it in GF(2**8) */
			// 0x11B = %1 0001 1011 = x^8 + x^4 + x^3 + x + 1
		}
		/* mul2[i] (XOR) mul1[i] = ptr[i] multiplied by 3 */
		ptr[i]     = mul2[0] ^ mul1[3] ^ mul1[2] ^ mul2[1] ^ mul1[1];
		ptr[i+1] = mul2[1] ^ mul1[0] ^ mul1[3] ^ mul2[2] ^ mul1[2];
		ptr[i+2] = mul2[2] ^ mul1[1] ^ mul1[0] ^ mul2[3] ^ mul1[3];
		ptr[i+3] = mul2[3] ^ mul1[2] ^ mul1[1] ^ mul2[0] ^ mul1[0];

		for (int e = 0; e < 4; e++)
		{	mul1[e] ^= mul1[e];	mul2[e] ^= mul2[e];	}
	}
}

/*
*	Inverse Mix Column
*	x * 9 = x * (8 + 1) = x * 8 + x * 1
*	x * B = x * 11 = x * (8 + 2 + 1) = x * 8 + x * 2 + x * 1
*	x * D = x * 13 = x * (8 * 4 * 1) = x * 8 + x * 4 + x * 1
*	x * E = x * 14 = x * (8 + 4 + 2) = x * 8 + x * 4 + x * 1
*
*	* 2 = << 1		+ x = XOR x = ^x
*/

void invmixcolumns(unsigned char *ptr)
{
	unsigned char mul1[4], mul2[4], mul4[4], mul8[4], mul9[4], mulB[4], mulD[4], mulE[4];
	unsigned char h;
	/*	h is used here after each shift lift 1-bit
	*	to keep it in GF(2**8),
	*	where it shifts (the 8-bit unsigned char value
	*	before shifted) 7 bits and sign extend it.
	*	If it's all ones, it means that when it shifted lift one
	*	bit should  (mod (X^4 + X^3 + X + 1))*/
	for (int i = 0; i < 16; i += 4)
	{
		for (int e = 0; e < 4; e++)
		{
			mul1[e] = ptr[i+e];	mul2[e] = ptr[i+e] << 1;
			h = (unsigned char)((signed char)mul1[e] >> 7);
			mul2[e] ^= 0x1B & h;	mul4[e] = mul2[e] << 1;
			h = (unsigned char)((signed char)mul2[e] >> 7);
			mul4[e] ^= 0x1B & h;	mul8[e] = mul4[e] << 1;
			h = (unsigned char)((signed char)mul4[e] >> 7);
			mul8[e] ^= 0x1B & h;

			mul9[e] = mul8[e] ^ mul1[e];
			mulB[e] = mul8[e] ^ mul2[e] ^ mul1[e];
			mulD[e] = mul8[e] ^ mul4[e] ^ mul1[e];
			mulE[e] = mul8[e] ^ mul4[e] ^ mul2[e];
		}
		ptr[i]     = mulE[0] ^ mulB[1] ^ mulD[2] ^ mul9[3];
		ptr[i+1] = mulE[1] ^ mulB[2] ^ mulD[3] ^ mul9[0];
		ptr[i+2] = mulE[2] ^ mulB[3] ^ mulD[0] ^ mul9[1];
		ptr[i+3] = mulE[3] ^ mulB[0] ^ mulD[1] ^ mul9[2];

		for (int e = 0; e < 4; e++)
		{	mul1[e] ^= mul1[e];	mul2[e] ^= mul2[e];	mul4[e] ^= mul4[e];	mul8[e] ^= mul8[e];
			mul9[e] ^= mul9[e];	mulB[e] ^= mulB[e];	mulD[e] ^= mulD[e];	mulE[e] ^= mulE[e];	}
	}
}

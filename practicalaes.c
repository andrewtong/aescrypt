//include header files
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define Columncount 4
#define Cipherkeylength 16
#define Rounds 10

//Program Options
//d - decrypt (exe, d, cipher, input file) - outputs decrypted file EBC
//d - decrypt (exe, d, cipher, input file, iv) - outputs decrypted file CBC
//e - encrypt (exe, d, cipher, input file) - outputs encrypted file EBC
//e - encrypt (exe, e, cipher, input file, iv) - outputs encrypted file CBC

//s - specific directory retrieval EBC(exe, s, cipher, inputfile, filetype)
//s - specific directory retrieval CBC(exe, s, cipher, inputfile, filetype, iv)

static uint8_t xorvector[16];
static uint8_t state[4][4];
static uint8_t roundkey[4][44];
static uint8_t cipherkey[16];
static int CBC = 0;

static const uint8_t sbox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t inversesbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t Rcon[256] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };

static uint8_t SBoxSub (uint8_t hex){
    return sbox[hex];
}

static uint8_t ISBoxSub (uint8_t hex){
    return inversesbox[hex];
}

static void RoundKeyExpansion (void){

//First 16 bytes of the round key is a copy of the cipher key
    int i, j;
    uint8_t placeholder[4];
    for (i = 0; i < Columncount; i++){
        roundkey[0][i] = cipherkey[4*i + 0];
        roundkey[1][i] = cipherkey[4*i + 1];
        roundkey[2][i] = cipherkey[4*i + 2];
        roundkey[3][i] = cipherkey[4*i + 3];
    }

//Take last existing column, solve for the remainder of the round keys
//Note that first column is a swap, substitution with Rcon, than add
//The remainder of the columns are addition to Rcon

//Aggregate of one, because these are to count from 1 to 10, as 0 was solved above
    for (i = 4; i < (Rounds + 1) * Columncount; i++){

        //Now if the column count is divisible by 4, then you rotate the last letter to the start
        //column count is equal to i

        //Afterwards, you then perform a s box substitution
        if (i % 4 == 0){
            for (j = 0; j < 4; j++){
                placeholder[j] = roundkey[j][i-1];
            }
            uint8_t tempholder;
            tempholder = placeholder[0];
            placeholder[0] = placeholder[1];
            placeholder[1] = placeholder[2];
            placeholder[2] = placeholder[3];
            placeholder[3] = tempholder;

            placeholder[0] = SBoxSub(placeholder[0]);
            placeholder[1] = SBoxSub(placeholder[1]);
            placeholder[2] = SBoxSub(placeholder[2]);
            placeholder[3] = SBoxSub(placeholder[3]);

            //Rcon [1x4] is then added to all columns that are of multiple of 4 (AKA start of each round key)
            //Note that only the first index of Rcon is non zero, and that 0x8d (Rcon[0]) is skipped!
            //Round Key 1 would include 0x01 to the first hex value

            placeholder[0] = placeholder[0] ^ Rcon[i/4];

            roundkey[0][i] = placeholder[0] ^ roundkey[0][i - 4];
            roundkey[1][i] = placeholder[1] ^ roundkey[1][i - 4];
            roundkey[2][i] = placeholder[2] ^ roundkey[2][i - 4];
            roundkey[3][i] = placeholder[3] ^ roundkey[3][i - 4];
        } else {
            roundkey[0][i] = roundkey[0][i-4] ^ roundkey[0][i - 1];
            roundkey[1][i] = roundkey[1][i-4] ^ roundkey[1][i - 1];
            roundkey[2][i] = roundkey[2][i-4] ^ roundkey[2][i - 1];
            roundkey[3][i] = roundkey[3][i-4] ^ roundkey[3][i - 1];
        }
    }


}

//Rounds 1 - 10
//SubBytes
//Shift Rows
//Mix Columns
//Add Round Key

//Round 11
//SubBytes
//Shift Rows
//Add Round Key

static void ShiftRows(void){
    //shift the rows in the 16 byte holder state
    //First row, no rotations
    //Second row, rotate over by 1 byte (1 2 3 4 becomes 2 3 4 1)
    //Third row, rotate over by 2 bytes (1 2 3 4 becomes 3 4 1 2 )
    //Fourth row, rotate over by 3 bytes (1 2 3 4 becomes 4 1 2 3)

    uint8_t rowholder[1][3];

    rowholder[0][0] = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = rowholder[0][0];

    rowholder[0][0] = state[2][0];
    rowholder[0][1] = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = rowholder[0][0];
    state[2][3] = rowholder[0][1];

    rowholder[0][0] = state[3][0];
    rowholder[0][1] = state[3][1];
    rowholder[0][2] = state[3][2];
    state[3][0] = state[3][3];
    state[3][1] = rowholder[0][0];
    state[3][2] = rowholder[0][1];
    state[3][3] = rowholder[0][2];

}

static void InverseShiftRows(void){
    //ShiftRows, but backwards
    uint8_t inverserowholder[1][3];

    //Shift second row all elements right once, rotate over
    inverserowholder[0][0] = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = inverserowholder[0][0];

    //Shift third row to the right twice, rotate over
    inverserowholder[0][0] = state[2][3];
    inverserowholder[0][1] = state[2][2];
    state[2][3] = state[2][1];
    state[2][2] = state[2][0];
    state[2][1] = inverserowholder[0][0];
    state[2][0] = inverserowholder[0][1];

    //Shift fourth row to the right three times, rotate over
    inverserowholder[0][0] = state[3][3];
    inverserowholder[0][1] = state[3][2];
    inverserowholder[0][2] = state[3][1];
    state[3][3] = state[3][0];
    state[3][2] = inverserowholder[0][0];
    state[3][1] = inverserowholder[0][1];
    state[3][0] = inverserowholder[0][2];
}

//MixColumns multiplies a column of 4 bytes by a 4x4 matrix of the form
//{ 02 03 01 01
//  01 02 03 01
//  01 01 02 03
//  03 01 01 02 }

//see https://en.wikipedia.org/wiki/Rijndael_mix_columns for explanation
//The concept here is that you would want to do 2 + 2 + 1 + 1 + 1
//where you solely use multipliers of 1 or 2, creating 2 by using a bitshift.
static void MixColumns(void){
    uint8_t singlestate[4][4];
    uint8_t doublestate[4][4];
    uint8_t tempholder;
    int i, j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++){
            singlestate[j][i] = state[j][i];
            tempholder = (unsigned char)((signed char)state[j][i] >> 7);
            doublestate[j][i] = state[j][i] << 1;
            doublestate[j][i] ^= 0x1B & tempholder;
        }
        state[0][i] = doublestate[0][i] ^ singlestate[3][i] ^ singlestate[2][i] ^ doublestate[1][i] ^ singlestate[1][i];
        state[1][i] = doublestate[1][i] ^ singlestate[0][i] ^ singlestate[3][i] ^ doublestate[2][i] ^ singlestate[2][i];
        state[2][i] = doublestate[2][i] ^ singlestate[1][i] ^ singlestate[0][i] ^ doublestate[3][i] ^ singlestate[3][i];
        state[3][i] = doublestate[3][i] ^ singlestate[2][i] ^ singlestate[1][i] ^ doublestate[0][i] ^ singlestate[0][i];

    }
}

//InverseMixColumns multiplies a column of 4 bytes by a 4x4 matrix of the form
//{ 14 11 13 09
//  09 14 11 13
//  13 09 14 11
//  11 13 09 14 }

//Method referenced from https://github.com/kokke/tiny-AES128-C/blob/master/aes.c
//To do this, a function Multiply is defined using bit shifts
//This may be edited out later for another method,

//http://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns
static uint8_t Multiply(uint8_t x, int y){
    uint8_t returnvalue, highbit;

    if (y == 9){
        // (((x * 2) * 2) * 2) + x
        highbit = (unsigned char)((signed char)x >> 7);
        returnvalue = x << 1;
        returnvalue  ^= 0x1B & highbit;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

        returnvalue ^= x;


    } else if (y == 11) {
        //((((x * 2) * 2) + x) * 2) + x
        highbit = (unsigned char)((signed char)x >> 7);
        returnvalue = x << 1;
        returnvalue  ^= 0x1B & highbit;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

        returnvalue ^= x;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

        returnvalue ^= x;

    } else if (y == 13) {
        //((((x * 2) + x) * 2) * 2) + x
        highbit = (unsigned char)((signed char)x >> 7);
        returnvalue = x << 1;
        returnvalue  ^= 0x1B & highbit;

        returnvalue ^= x;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

        returnvalue ^= x;

    } else if (y == 14) {
        //((((x * 2) + x) * 2) + x) * 2
        highbit = (unsigned char)((signed char)x >> 7);
        returnvalue = x << 1;
        returnvalue  ^= 0x1B & highbit;

        returnvalue ^= x;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

        returnvalue ^= x;

        highbit = (unsigned char)((signed char)returnvalue >> 7);
        returnvalue = returnvalue << 1;
        returnvalue ^= 0x1B & highbit;

    } else {
        returnvalue = 0x00;
    }

    return returnvalue;
}


static void InverseMixColumns(void){
    int i,j;
    uint8_t tempholder[4];
    for ( i = 0; i < 4; i++){
        for ( j = 0; j < 4; j++){
            tempholder[j] = state[j][i];

        }
        state[0][i] = Multiply(tempholder[0], 14) ^ Multiply(tempholder[1], 11) ^ Multiply(tempholder[2], 13) ^ Multiply(tempholder[3], 9);
        state[1][i] = Multiply(tempholder[0], 9) ^ Multiply(tempholder[1], 14) ^ Multiply(tempholder[2], 11) ^ Multiply(tempholder[3], 13);
        state[2][i] = Multiply(tempholder[0], 13) ^ Multiply(tempholder[1], 9) ^ Multiply(tempholder[2], 14) ^ Multiply(tempholder[3], 11);
        state[3][i] = Multiply(tempholder[0], 11) ^ Multiply(tempholder[1], 13) ^ Multiply(tempholder[2], 9) ^ Multiply(tempholder[3], 14);
    }
}

static void AddRoundKey(int round){
    int i, j;
    for (i = 0; i < 4; i++){
        for ( j = 0; j < 4; j++){
            state[j][i] ^= roundkey[j][i + 4*round];
        }
    }

}

static void SubstituteBytes(void){
    int i, j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++){
            (state)[i][j]  = SBoxSub((state)[i][j]);
        }
    }
}

static void InverseSubstituteBytes(void){
    int i, j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++){
            (state)[i][j]  = ISBoxSub((state)[i][j]);
        }
    }
}

static void PrintState(void){
    int i,j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++){
            printf("%02X\n", state[j][i]);
        }
    }
}

static void IVxor(){
    int i,j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++){
            state[j][i] = xorvector[i*4 + j] ^ state[j][i];
        }
    }
}

static void EBCEncryptRounds(void){
    int i;
    RoundKeyExpansion();
    AddRoundKey(0);
    for (i = 1; i < Rounds; i++){
        SubstituteBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(i);
    }
    SubstituteBytes();
    ShiftRows();
    AddRoundKey(i);
}

static void EBCDecryptRounds(void){
    int i;
    RoundKeyExpansion();
    AddRoundKey(10);
    InverseShiftRows();
    InverseSubstituteBytes();

    for (i = 9; i > 0; i--){
        AddRoundKey(i);
        InverseMixColumns();
        InverseShiftRows();
        InverseSubstituteBytes();
    }
    AddRoundKey(i);
}

static void CBCEncryptRounds(){
    IVxor();
    EBCEncryptRounds();
    int i,j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++){
            xorvector[4*i + j] = state[j][i];
        }
    }
}

static void CBCDecryptRounds(){
    uint8_t ivbuffer[16];
    int i,j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++){
            ivbuffer[4*j + i] = state[j][i];
        }
    }
    EBCDecryptRounds();
    IVxor();
    for (i = 0; i < 16; i++){
        xorvector[i] = ivbuffer[i];
    }
}

//Outdated function, used when cipher key was stored in a text file.
int converthexvalue(uint8_t h){
    int value = (int)h;
    if(value < 58 && value > 47){
        return value - 48;
    }
    if(value < 103 && value > 96){
        return value- 87;
    }
    return value;
}

static void RetrieveCipherKey(char* cipherdirectory){
    FILE *keydata = fopen(cipherdirectory, "rb");
    if (keydata == NULL){
        perror("Error");
        printf("Error occurred while retrieving cipher key.");
    }
    int read = 0;
    int i;
    uint8_t buffer[16];
    read = fread(buffer, 1, 16, keydata);
    for (i = 0; i < 16; i++){
        if (i < read){
            cipherkey[i] = buffer[i];
        } else {
            cipherkey[i] = (uint8_t)0x00;
        }
    }
    fclose(keydata);
}

static char* SearchOutputFileName(char* outputfilename){
    int outputexists = 1;
    int iteration = 0;
    while(outputexists == 1){
        if (access(outputfilename, F_OK) != -1){
            //create new outputfilename and loop again
            char *strbase = "output (";
            char *strend = ")";
            char outputfilestr[20];
            char iterationvalue[10];

            iteration++;

            strcpy(outputfilestr, "output (");
            itoa(iteration,iterationvalue, 10);
            strcat(outputfilestr, iterationvalue);
            strcat(outputfilestr, strend);
            outputfilename = malloc(1 + strlen(outputfilestr));
            strcpy(outputfilename, outputfilestr);
            outputfilename[1 + strlen(outputfilestr)] = '\0';

            free(strbase);
            free(strend);
        } else {
            outputexists = 0;
        }
    }
    return outputfilename;
}


static void StoreIVVector(char *basedirectory, char *ivfilename){
    char *ivdirectory;
    if((ivdirectory = malloc(strlen(basedirectory)+strlen(ivfilename)+1)) != NULL){
        ivdirectory[0] = '\0';   // ensures the memory is an empty string
        strcat(ivdirectory, basedirectory);
        strcat(ivdirectory, ivfilename);
    } else {
        perror("Error");
        printf("Error occurred with allocating memory while searching for initialization vector.");
    }

    FILE *ivdata = fopen(ivdirectory, "rb");
    if (ivdata == NULL){
        perror("Error");
        printf("Error occurred while retrieving initialization vector.");
    }

    int read = 0;
    uint8_t buffer[16];
    read = fread(buffer, 1, 16, ivdata);
    int i;
    for (i = 0; i < 16; i++){
        if (i < read){
            xorvector[i] = buffer[i];
        } else {
            xorvector[i] = (uint8_t)0x00;
        }
    }
    fclose(ivdata);
}

int main(int argc, char *argv[]){
    //Retrieve Key
    char *cipherdirectory;
    char *targetdirectory;
    char *basedirectory = "C:\\Users\\Andrew\\cworkspace\\PracticalAES\\";

    if((cipherdirectory = malloc(strlen(basedirectory)+strlen(argv[2])+1)) != NULL){
        cipherdirectory[0] = '\0';   // ensures the memory is an empty string
        strcat(cipherdirectory, basedirectory);
        strcat(cipherdirectory, argv[2]);
    } else {
        perror("Error");
        printf("Error occurred with allocating memory while searching for cipher key.");
        return 0;
    }

    RetrieveCipherKey(cipherdirectory);

    //Checks to see if input and output files are valid
    if((targetdirectory = malloc(strlen(basedirectory)+strlen(argv[3])+1)) != NULL){
        targetdirectory[0] = '\0';   // ensures the memory is an empty string
        strcat(targetdirectory, basedirectory);
        strcat(targetdirectory, argv[3]);
    } else {
        perror("Error");
        printf("Error occurred with allocating memory while searching for binary file.");
    }

    FILE *inputfile, *outputfile;
    inputfile = fopen(targetdirectory, "rb");
    char *outputfilename = "output";
    outputfilename = SearchOutputFileName(outputfilename);
    outputfile = fopen(outputfilename, "ab+");

    if (inputfile == NULL || outputfile == NULL){
        printf("Error occurred while opening input or output files.\n");
        return 0;
    }

    int counted = 0;
    int read = 0;
    uint8_t buffer[16];
    int i;

    if (strcmp(argv[1],"d") == 0){
        if (argc == 4){
            //EBC decrypt
        } else if (argc == 5) {
            //CBC decrypt
            CBC = 1;
            StoreIVVector(basedirectory, argv[4]);
        } else {
            printf("Input format for decryption is invalid.\n");
        }
        while((read = fread(buffer, 1, 16, inputfile)) > 0){
            counted = counted + read;
            for(i=0; i < 16; i++){
                if (i < read){
                    state[i%4][(int)i/4] = buffer[i];
                } else {
                    state[i%4][(int)i/4] = (uint8_t)0x00;
                }
            }
            if (CBC){
                CBCDecryptRounds();
            } else {
                EBCDecryptRounds();
            }
            for(i=0; i < 16; i++){
                fwrite(&state[i%4][(int)i/4],sizeof(uint8_t), 1, outputfile);
            }
        }
    } else if (strcmp(argv[1],"e") == 0) {
        if (argc == 4){
            //EBC encrypt
        } else if (argc == 5) {
            //CBC encrypt
            CBC = 1;
            StoreIVVector(basedirectory, argv[4]);
        } else {
            printf("Input format for encryption is invalid.\n");
        }
        while((read = fread(buffer, 1, 16, inputfile)) > 0){
            counted = counted + read;
            for(i=0; i < 16; i++){
                if (i < read){
                    state[i%4][(int)i/4] = buffer[i];
                } else {
                    state[i%4][(int)i/4] = (uint8_t)0x00;
                }
            }
            if (CBC){
                CBCEncryptRounds();
            } else {
                EBCEncryptRounds();
            }

            for(i=0; i < 16; i++){
                fwrite(&state[i%4][(int)i/4],sizeof(uint8_t), 1, outputfile);
            }
        }
    } else if (strcmp(argv[1],"s") == 0) {
        //Currently in progress
        printf("Search function is currently not supported.\n");
    } else {
        printf("Invalid input format.\n");
    }

    fclose(inputfile);
    fclose(outputfile);
    return 0;
}

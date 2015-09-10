#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <string.h>
//#include header file


//NOTE THAT FOR 2D ARRAYS, MATRICES ARE COUNTED BY I,J, WHERE I IS THE ROW, AND J IS THE COLUMN!

//typedef uint8_t state_t[4][4];
//static state_t* state;

static uint8_t state[8][8];


static uint8_t roundkey[4][44];

static uint8_t cipherkey[16];



#define Columncount 4
#define Cipherkeylength 16
#define Rounds 10

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


static void RoundKeyExpansion (void){

//First 16 bytes of the round key is a copy of the cipher key
    int i, j, k;
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
//            printf("%02X", placeholder[0]);
//            printf("%02X", placeholder[1]);
//            printf("%02X", placeholder[2]);
//            printf("%02X\n", placeholder[3]);

            placeholder[0] = SBoxSub(placeholder[0]);
            placeholder[1] = SBoxSub(placeholder[1]);
            placeholder[2] = SBoxSub(placeholder[2]);
            placeholder[3] = SBoxSub(placeholder[3]);
//            printf("lalalalalalalallalaal\n");
//            printf("%02X", placeholder[0]);
//            printf("%02X", placeholder[1]);
//            printf("%02X", placeholder[2]);
//            printf("%02X\n", placeholder[3]);

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

//    for (i = 0 ; i< 4; i++){
//        for (j = 0; j < 4; j++){
//            printf("%02X", state[j][i]);
//        }
//    }
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

static void EncryptRounds(void){
    int i;
    int j, k;
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

static void DecryptRounds(void){
}


//d - decrypt (d, file, output file location) - outputs decrypted file
//e - encrypt (e, cipher, file, output file location) - outputs encrypted file
//r - retrieve directories (r, file) - outputs as text(?)
//s - specific directory retrieval (s, file, specific directory, output file location)

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


int main(int argc, char *argv[]){
    uint8_t temperino;
    temperino = SBoxSub(0x19);
    printf("%02X\n", temperino);
    //Retrieve Key
    char *cipherdirectory;
    char *targetdirectory;
    char *basedirectory = "C:\\Users\\Andrew\\cworkspace\\AESdecrypt\\";

    if((cipherdirectory = malloc(strlen(basedirectory)+strlen(argv[2])+1)) != NULL){
    cipherdirectory[0] = '\0';   // ensures the memory is an empty string
    strcat(cipherdirectory, basedirectory);
    strcat(cipherdirectory, argv[2]);
    } else {
        perror("Error");
        printf("Error occurred with allocating memory while searching for cipher key.");
    }
    printf(cipherdirectory);
    FILE *keydata = fopen(cipherdirectory, "rt");
    if (keydata == NULL){
        perror("Error");
        printf("Error occurred while retrieving cipher key.");
        return 0;
    }
    uint8_t leftvalue, rightvalue, hexvalue;
    int i;
    for (i = 0; i < 16; i++){
        leftvalue = converthexvalue(fgetc(keydata));
        rightvalue = converthexvalue(fgetc(keydata));
        hexvalue = leftvalue << 4 | rightvalue;
        cipherkey[i] = hexvalue;
    }
    fclose(keydata);

    //Test to determine if cipher is read correctly
    for (i = 0; i < 16; i++){
        printf("%02X", cipherkey[i]);
    }

    printf(argv[1]);
    printf( "argc = %d\n", argc );

    if (strcmp(argv[1], "d") == 0 && argc == 4){
        //perform decrpytion

    } else if (strcmp(argv[1], "e") == 0 && argc == 4){

        //perform encryption
        if((targetdirectory = malloc(strlen(basedirectory)+strlen(argv[3])+1)) != NULL){
        targetdirectory[0] = '\0';   // ensures the memory is an empty string
        strcat(targetdirectory, basedirectory);
        strcat(targetdirectory, argv[3]);
        printf(targetdirectory);
        } else {
            perror("Error");
            printf("Error occurred with allocating memory while searching for binary file.");
        }

        FILE *inputfile, *outputfile;
        //char file = argv[2];
        inputfile = fopen(targetdirectory, "rb");
        outputfile = fopen("output", "ab+");
        if (inputfile == NULL){
            perror("Error");
            printf("Error occurred while opening file.");
            return 0;
        }
        int counted = 0;
        int read = 0;
        uint8_t buffer[16];
        int i;
        while((read = fread(buffer, 1, 16, inputfile)) > 0){
        //printf("%d\n", read);

            for(i=0; i < 16; i++){
                if (read != EOF){
                    //memcpy(*state[(int)i/4][(int)i%4], &buffer[i], sizeof(buffer[i]));
                    state[i%4][(int)i/4] = buffer[i];
                    //counted += 1;

                } else {
                    state[i%4][(int)i/4] = (uint8_t)0x00;
                }
            }
            //Perform rijndaels with the current state
            EncryptRounds();

            //Scan for keywords

            //Write to file

            for(i=0; i < 16; i++){
                //printf("%02X", state[i%4][(int)i/4]);
                fwrite(&state[i%4][(int)i/4],sizeof(uint8_t), 1, outputfile);
            }

        }



//    } else if (argv[1] == std::string("r") && argc == 3){
//        //performs directory retrieval
//
//    } else if (argv[1] == std::string("s") && argc == 5){
//        //performs specific directory retrieval

    fclose(inputfile);
    fclose(outputfile);

    } else {
        printf( "Invalid input parameters.\n" );
    }
    return 0;
}




//general encrypt function

//general decrypt function

//function for retrieving all directories (without content)

//function for retrieving a particular directory

//

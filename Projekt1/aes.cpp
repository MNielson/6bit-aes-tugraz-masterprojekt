#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <string.h>
#include "aes.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 5       // The number of rounds in AES Cipher.


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

static const uint8_t sbox[64] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x00, 0x36, 0x30, 0x0d, 0x0f, 0x12, 0x35, 0x23, 0x19, 0x3f, 0x2d, 0x34, 0x03, 0x14, 0x29, 0x21,
  0x3b, 0x24, 0x02, 0x22, 0x0a, 0x08, 0x39, 0x25, 0x3c, 0x13, 0x2a, 0x0e, 0x32, 0x1a, 0x3a, 0x18,
  0x27, 0x1b, 0x15, 0x11, 0x10, 0x1d, 0x01, 0x3e, 0x2f, 0x28, 0x33, 0x38, 0x07, 0x2b, 0x2c, 0x26,
  0x1f, 0x0b, 0x04, 0x1c, 0x3d, 0x2e, 0x05, 0x31, 0x09, 0x06, 0x17, 0x20, 0x1e, 0x0c, 0x37, 0x16 };

static const uint8_t mul2[64] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
	0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d, 0x13, 0x11, 0x17, 0x15, 0x1b, 0x19, 0x1f, 0x1d,
	0x23, 0x21, 0x27, 0x25, 0x2b, 0x29, 0x2f, 0x2d, 0x33, 0x31, 0x37, 0x35, 0x3b, 0x39, 0x3f, 0x3d };

static const uint8_t mul3[64] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
	0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
	0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a, 0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32,
	0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a, 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02 };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^6)
static const uint8_t Rcon[11] = {
  0x43, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0C, 0x18 };

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

#define getSBoxValue(num) (sbox[(num)])


// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}


// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round,state_t* state,uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }

#ifdef _DEBUG
  for (int i = 0; i < 4; i++)
  {
	  for (int j = 0; j < 4; j++)
	  {
		  if ((*state)[i][j] > 0x3f)
			  std::cerr << "Element over 6 bit detected." << std::endl;
	  }
  }
#endif

}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }

#ifdef _DEBUG
  for (int i = 0; i < 4; i++)
  {
	  for (int j = 0; j < 4; j++)
	  {
		  if ((*state)[i][j] > 0x3f)
			  std::cerr << "Element over 6 bit detected." << std::endl;
	  }
  }
#endif

#ifdef _DEBUG
  for (int i = 0; i < 4; i++)
  {
	  for (int j = 0; j < 4; j++)
	  {
		  if ((*state)[i][j] > 0x3f)
			  std::cerr << "Element over 6 bit detected." << std::endl;
	  }
  }
#endif
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp0;
  uint8_t temp1;
  uint8_t temp2;

  // Rotate first row 1 columns to left
  temp0			 = (*state)[1][0];

  (*state)[1][0] = (*state)[1][1];
  (*state)[1][1] = (*state)[1][2];
  (*state)[1][2] = (*state)[1][3];
  (*state)[1][3] = temp0;

  // Rotate second row 2 columns to left
  temp0 = (*state)[2][0];
  temp1 = (*state)[2][1];

  (*state)[2][0] = (*state)[2][2];
  (*state)[2][1] = (*state)[2][3];
  (*state)[2][2] = temp0;
  (*state)[2][3] = temp1;

  // Rotate second row 3 columns to left
  
  temp0 = (*state)[3][0];
  temp1 = (*state)[3][1];
  temp2 = (*state)[3][2];

  (*state)[3][0] = (*state)[3][3];
  (*state)[3][1] = temp0;
  (*state)[3][2] = temp1;
  (*state)[3][3] = temp2;


#ifdef _DEBUG
  for (int i = 0; i < 4; i++)
  {
	  for (int j = 0; j < 4; j++)
	  {
		  if ((*state)[i][j] > 0x3f)
			  std::cerr << "Element over 6 bit detected." << std::endl;
	  }
  }
#endif
}


static void MixColumns(state_t* state)
{
  for (int i = 0; i < 4; i++){
	  (*state)[0][i] = (uint8_t)mul2[(*state)[0][i]] ^ mul3[(*state)[1][i]] ^      (*state)[2][i]  ^      (*state)[3][i];
	  (*state)[1][i] = (uint8_t)     (*state)[0][i]  ^ mul2[(*state)[1][i]] ^ mul3[(*state)[2][i]] ^      (*state)[3][i];
	  (*state)[2][i] = (uint8_t)     (*state)[0][i]  ^      (*state)[1][i]  ^ mul2[(*state)[2][i]] ^ mul3[(*state)[3][i]];
	  (*state)[3][i] = (uint8_t)mul3[(*state)[0][i]] ^      (*state)[1][i]  ^      (*state)[2][i]  ^ mul2[(*state)[3][i]];
  }

#ifdef _DEBUG
  for (int i = 0; i < 4; i++)
  {
	  for (int j = 0; j < 4; j++)
	  {
		  if ((*state)[i][j] > 0x3f)
			  std::cerr << "Element over 6 bit detected." << std::endl;
	  }
  }
#endif
}


uint8_t GalMul(uint8_t a, uint8_t b)
{
	// Galois Field (2^6) Multiplication of two Bytes
	uint8_t p = 0;
	uint8_t counter;
	uint8_t hi_bit_set;
	for (counter = 0; counter < 8; counter++) {
		if ((b & 1) != 0) {
			p = p ^ a;
		}
		hi_bit_set = (uint8_t)(a & 0x40);
		a <<= 1;
		if (hi_bit_set != 0) {
			a = a ^ 0x43; /* x^6 + x + 1 */
		}
		b >>= 1;
	}
	return p;
}


// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, uint8_t* RoundKey, uint8_t rounds)
{
  uint8_t round = 0;
  
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey); 

  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = 1; round < rounds; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(rounds, state, RoundKey);
}



void AES_ECB_encrypt(struct AES_ctx *ctx,const uint8_t* buf, uint8_t rounds)
{
	Cipher((state_t*)buf, ctx->RoundKey, rounds);
}




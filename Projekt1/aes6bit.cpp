#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <iomanip>

#include "aes6bit.h"


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/


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

/*
// remove me
static const uint8_t Rcon[22] = {
	0x43, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0C, 0x18, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0C, 0x18 };
*/
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

void AES6BIT::AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{

  KeyExpansion(ctx->RoundKey, key);
#ifdef FULL_LOG
  std::cout << "Key: " << std::endl;
  printKey(key, 16);

  std::cout << "Expanded Key: " << std::endl;
  printKey(ctx->RoundKey, AES_keyExpSize);

#endif
}


// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AES6BIT::AddRoundKey(uint8_t round,state_t* state,uint8_t* RoundKey)
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
void AES6BIT::SubBytes(state_t* state)
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
void AES6BIT::ShiftRows(state_t* state)
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


void AES6BIT::MixColumns(state_t* state)
{
	uint8_t tstate[4][4] = { { 0, 0, 0, 0 },{ 0, 0, 0, 0 },{ 0, 0, 0, 0 },{ 0, 0, 0, 0 } };
	for (int i = 0; i < 4; i++){
	  tstate[0][i] = (uint8_t) (mul2[(*state)[0][i]] ^ mul3[(*state)[1][i]] ^      (*state)[2][i]  ^      (*state)[3][i] );
	  tstate[1][i] = (uint8_t) (     (*state)[0][i]  ^ mul2[(*state)[1][i]] ^ mul3[(*state)[2][i]] ^      (*state)[3][i] );
	  tstate[2][i] = (uint8_t) (     (*state)[0][i]  ^      (*state)[1][i]  ^ mul2[(*state)[2][i]] ^ mul3[(*state)[3][i]]);
	  tstate[3][i] = (uint8_t) (mul3[(*state)[0][i]] ^      (*state)[1][i]  ^      (*state)[2][i]  ^ mul2[(*state)[3][i]]);
	}
	
	for (int i = 0; i < 4; i++) {
	  for (int j = 0; j < 4; j++)
		  (*state)[i][j] = tstate[i][j];
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


uint8_t AES6BIT::GalMul(uint8_t a, uint8_t b)
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
void AES6BIT::Cipher(state_t* state, uint8_t* RoundKey, uint8_t rounds)
{
  uint8_t round = 0;
  
  // Add the First round key to the state before starting the rounds.
  //printState(0, "Before AddRoundKey", state);
  AddRoundKey(0, state, RoundKey); 
  //printState(0, "After AddRoundKey", state);

  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = 1; round < rounds; ++round)
  {
#ifdef FULL_LOG
	printState(round, "Before SubBytes", state);
#endif
    SubBytes(state);
#ifdef FULL_LOG
	printState(round, "After SubBytes", state);
#endif

#ifdef FULL_LOG
	printState(round, "Before ShiftRows", state);
#endif
	ShiftRows(state);
#ifdef FULL_LOG
	printState(round, "After ShiftRows", state);
#endif
	
#ifdef FULL_LOG
	printState(round, "Before MixColumns", state);
#endif
    MixColumns(state);
#ifdef FULL_LOG
	printState(round, "After MixColumns", state);
#endif
	
#ifdef FULL_LOG
	printState(round, "Before AddRoundKey", state);
#endif
    AddRoundKey(round, state, RoundKey);
#ifdef FULL_LOG
	printState(round, "After AddRoundKey", state);
#endif

  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
#ifdef FULL_LOG
  printState(rounds, "Before SubBytes", state);
#endif
  SubBytes(state);
#ifdef FULL_LOG
  printState(round, "After SubBytes", state);
#endif

#ifdef FULL_LOG
  printState(rounds, "Before ShiftRows", state);
#endif
  ShiftRows(state);
#ifdef FULL_LOG
  printState(rounds, "After ShiftRows", state);
#endif

#ifdef FULL_LOG
  //printState(rounds, "Before AddRoundKey", state);
#endif
  AddRoundKey(rounds, state, RoundKey);
#ifdef FULL_LOG
  printState(rounds, "After AddRoundKey / Before Finishing", state);
#endif
}



void AES6BIT::AES_ECB_encrypt(struct AES_ctx *ctx,const uint8_t* buf, uint8_t rounds)
{
	Cipher((state_t*)buf, ctx->RoundKey, rounds);
}


void AES6BIT::printState(state_t* state)
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			/*
			std::cout << std::showbase // show the 0x prefix
				      << std::internal // fill between the prefix and the number
				      << std::hex
				      << std::setfill('0'); // fill with 0s
					  */
			std::cout << std::hex << static_cast<int>((*state)[i][j]) << " ";
		}
		std::cout << std::endl;
	}
}

void AES6BIT::printKey(const uint8_t * key, int size)
{
	for (int i = 0; i < size; i++)
	{
		/*
		std::cout << std::showbase // show the 0x prefix
			<< std::internal // fill between the prefix and the number
			<< std::setw(2) << std::setfill('0'); // fill with 0s
		*/
		std::cout << std::hex << static_cast<int>(key[i]) << " ";
		if ((i > 0) && ((i + 1) % 4 == 0))
			std::cout << std::endl;
		if ((size > 16) && (i > 0) && ((i + 1) % 16 == 0))
			std::cout << std::endl;
	}
	std::cout << std::endl;
}



void AES6BIT::printState(int round, std::string step, state_t* state)
{
	std::cout << "Round " << round << std::endl;
	std::cout << step << ": " << std::endl << std::endl;
	printState(state);
	std::cout << std::endl;
}
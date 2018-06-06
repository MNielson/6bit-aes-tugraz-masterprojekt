#ifndef _AES6BIT_H_
#define _AES6BIT_H_

#include <stdint.h>
#include <string>
#include <sstream>


#define AES128 1
#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only
#define AES_KEYLEN 16   // Key length in bytes
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 5       // The number of rounds in AES Cipher.
//#define AES_keyExpSize 256
//#define AES_keyExpSize 176
#define AES_keyExpSize 96


// state - array holding the intermediate results during encryption.
typedef uint8_t state_t[4][4];

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
};

class AES6BIT {
public:
	// buffer size is exactly AES_BLOCKLEN bytes; 
	// you need only AES_init_ctx as IV is not used in ECB 
	// NB: ECB is considered insecure for most uses
	void AES_ECB_encrypt(struct AES_ctx* ctx, const uint8_t* buf, uint8_t rounds);
	void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
	void Cipher(state_t* state, uint8_t* RoundKey, uint8_t rounds);
	void SubBytes(state_t* state);
	uint8_t GalMul(uint8_t a, uint8_t b);

	void ShiftRows(state_t* state);
	void MixColumns(state_t* state);
	void AddRoundKey(uint8_t round, state_t* state, uint8_t* RoundKey);

private:
	//static std::string AES6BIT::toString(state_t* state);
	void printKey(const uint8_t* key, int size);
	void printState(state_t* state);
	void printState(int round, std::string step, state_t* state);

};


#endif //_AES6BIT_H_
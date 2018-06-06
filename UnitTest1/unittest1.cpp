#include "stdafx.h"
#include "CppUnitTest.h"
#include "../Projekt1/aes6bit.h"
#include "../Projekt1/aes6bit.cpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTest1
{		
	TEST_CLASS(AES_6bit_tests)
	{
	public:
		
		TEST_METHOD(SubBytesTest)
		{
			uint8_t state1[16];
			uint8_t state2[16];
			uint8_t state3[16];
			uint8_t state4[16];


			static const uint8_t sbox[64] = {
				//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
				0x00, 0x36, 0x30, 0x0d, 0x0f, 0x12, 0x35, 0x23, 0x19, 0x3f, 0x2d, 0x34, 0x03, 0x14, 0x29, 0x21,
				0x3b, 0x24, 0x02, 0x22, 0x0a, 0x08, 0x39, 0x25, 0x3c, 0x13, 0x2a, 0x0e, 0x32, 0x1a, 0x3a, 0x18,
				0x27, 0x1b, 0x15, 0x11, 0x10, 0x1d, 0x01, 0x3e, 0x2f, 0x28, 0x33, 0x38, 0x07, 0x2b, 0x2c, 0x26,
				0x1f, 0x0b, 0x04, 0x1c, 0x3d, 0x2e, 0x05, 0x31, 0x09, 0x06, 0x17, 0x20, 0x1e, 0x0c, 0x37, 0x16 };


			for (int i = 0; i < 16; i++)
			{
				state1[i] = i;
				state2[i] = i+16;
				state3[i] = i+32;
				state4[i] = i+48;
			}

			AES6BIT aes;
			aes.SubBytes((state_t*)state1);
			aes.SubBytes((state_t*)state2);
			aes.SubBytes((state_t*)state3);
			aes.SubBytes((state_t*)state4);

			for (int i = 0; i < 16; i++)
			{
				Assert::AreEqual(state1[i], sbox[i]);
				Assert::AreEqual(state2[i], sbox[i+16]);
				Assert::AreEqual(state3[i], sbox[i+32]);
				Assert::AreEqual(state4[i], sbox[i+48]);
			}

		}
		
		TEST_METHOD(ShiftRowsTest)
		{
			uint8_t state[16];
			for (int i = 0; i < 16; i++)
				state[i] = i;

			AES6BIT aes;
			aes.ShiftRows((state_t*)state);
			Assert::AreEqual(state[ 0], (uint8_t)  0);
			Assert::AreEqual(state[ 1], (uint8_t)  1);
			Assert::AreEqual(state[ 2], (uint8_t)  2);
			Assert::AreEqual(state[ 3], (uint8_t)  3);

			Assert::AreEqual(state[ 4], (uint8_t)  5);
			Assert::AreEqual(state[ 5], (uint8_t)  6);
			Assert::AreEqual(state[ 6], (uint8_t)  7);
			Assert::AreEqual(state[ 7], (uint8_t)  4);

			Assert::AreEqual(state[ 8], (uint8_t) 10);
			Assert::AreEqual(state[ 9], (uint8_t) 11);
			Assert::AreEqual(state[10], (uint8_t)  8);
			Assert::AreEqual(state[11], (uint8_t)  9);

			Assert::AreEqual(state[12], (uint8_t) 15);
			Assert::AreEqual(state[13], (uint8_t) 12);
			Assert::AreEqual(state[14], (uint8_t) 13);
			Assert::AreEqual(state[15], (uint8_t) 14);
		}

		
		TEST_METHOD(MixColumnsTest)
		{
			uint8_t state[16];
			for (int i = 0; i < 16; i++)
				state[i] = 0;

			state[ 0] = 1; state[ 1] = 11; state[ 2] = 1; state[ 3] = 10;
			state[ 4] = 2; state[ 5] = 11; state[ 6] = 2; state[ 7] = 20;
			state[ 8] = 3; state[ 9] = 11; state[10] = 3; state[11] = 30;
			state[12] = 4; state[13] = 11; state[14] = 4; state[15] = 40;


			AES6BIT aes;
	
			aes.MixColumns((state_t*)state);

			Assert::AreEqual(state[ 0], (uint8_t)  3); Assert::AreEqual(state[ 1], (uint8_t) 11); Assert::AreEqual(state[ 2], (uint8_t) 3);  Assert::AreEqual(state[ 3], (uint8_t)30);
			Assert::AreEqual(state[ 4], (uint8_t)  4); Assert::AreEqual(state[ 5], (uint8_t) 11); Assert::AreEqual(state[ 6], (uint8_t) 4);  Assert::AreEqual(state[ 7], (uint8_t)40);
			Assert::AreEqual(state[ 8], (uint8_t)  9); Assert::AreEqual(state[ 9], (uint8_t) 11); Assert::AreEqual(state[10], (uint8_t) 9);  Assert::AreEqual(state[11], (uint8_t)25);
			Assert::AreEqual(state[12], (uint8_t) 10); Assert::AreEqual(state[13], (uint8_t) 11); Assert::AreEqual(state[14], (uint8_t) 10); Assert::AreEqual(state[15], (uint8_t) 7);
			
		}
		/*
		TEST_METHOD(AddRoundKeyTest)
		{
			// TODO: Testcode hier eingeben
			int a = 1;
			Assert::AreEqual(a, a);
		}
		*/
	};
}
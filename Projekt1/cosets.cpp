#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <list>
#include <vector>
#include <fstream>
#include <string>
#include <math.h>
#include <iomanip>

#define TWO_P_24 16777216

#include "aes.h"

typedef struct {
	double mean;
	double variance;
	double skew;
} StatisticResult;

static uint64_t computeCoset(void);
static void computeStatistics(uint64_t numSets, int numThreads);
StatisticResult computeStatisticResult(std::list<uint64_t> cosets);
void printUsage(std::string name);

std::mutex mtx;
std::list<uint64_t> cosets;


int main(int argc, char* argv[])
{

	if (argc != 3)
	{
		printUsage(argv[0]);
	}
	else
	{
		int numSets = atoi(argv[1]);
		int numThreads = atoi(argv[2]);
		srand((unsigned int)time(NULL));
		computeStatistics(numSets, numThreads);
		/*
		uint8_t mul2[64];
		uint8_t mul3[64];
		for (int i = 0; i < 64; i++)
		{
			mul2[i] = GalMul((uint8_t)i, (uint8_t)2);
			mul3[i] = GalMul((uint8_t)i, (uint8_t)3);

		}
		for (int i = 0; i < 64; i++)
		{

			printf("0x%.2x, ", mul2[i]);

		}
		printf("\n\n");
		for (int i = 0; i < 64; i++)
		{
			printf("0x%.2x, ", mul3[i]);

		}
		*/
	}

    return 0;
}

static void computeCosets(uint64_t numSets)
{
	while (true)
	{
		uint64_t coset = computeCoset();
		mtx.lock();
		cosets.push_back(coset);
		mtx.unlock();
		if (cosets.size() >= numSets)
			return;
	}
}

static uint64_t computeCoset(void)
{
	
	uint8_t* res = (uint8_t*)calloc(TWO_P_24, sizeof(uint8_t));

	//create context
	struct AES_ctx ctx;
	uint8_t key[16];
	uint8_t const_state[16];
	uint8_t state[16];
	
	for (int i = 0; i < 16; i++)
	{
		key[i] = rand() & 0x3f;
		const_state[i] = rand() & 0x3f;
	}

	AES_init_ctx(&ctx, key);

	//compute 2^24 sets
	for (int i = 0; i < TWO_P_24; i++)
	{
		for (int j = 0; j < 16; j++)
		{
			state[j] = const_state[j];
		}

		uint8_t t1 = (uint8_t)(i >> 0)  & 0x3f;
		uint8_t t2 = (uint8_t)(i >> 6)  & 0x3f;
		uint8_t t3 = (uint8_t)(i >> 12) & 0x3f;
		uint8_t t4 = (uint8_t)(i >> 18) & 0x3f;

		state[0]  = t1;
		state[5]  = t2;
		state[10] = t3;
		state[15] = t4;

		AES_ECB_encrypt(&ctx, state, 5);
#ifdef _DEBUG
		for (int j = 0; j < 16; j++)
		{
			if (state[j] > 0x3f)
				std::cerr << "Element over 6 bit detected." << std::endl;
		}
#endif

		uint32_t x1 = state[0];
		uint32_t x2 = state[13];
		uint32_t x3 = state[10];
		uint32_t x4 = state[7];

		uint32_t diag = (x1 << 0) + (x2 << 6) + (x3 << 12) + (x4 << 18);
#ifdef _DEBUG
		if (diag > 16777215)
			std::cerr << "Diag over 24 bit detected." << std::endl;
#endif
		res[diag] = res[diag] + 1;
	}

	//all sets computed
	//compute collisions
	uint64_t collisions = 0;
	uint64_t elems = 0;
	uint64_t tmp = 0;
	for (int i = 0; i < TWO_P_24; i++)
	{
		tmp = 0;
		if (res[i] > 1)
		{
			tmp = (res[i] * (res[i] - 1)) / 2;
			elems = elems + res[i];
		}
		collisions += tmp;
	}
#ifdef _DEBUG
	if (collisions % 8)
		std::cerr << "Error: " << collisions << " is not a multiple of 8." << std::endl;
	else
		std::cout << " :) " << std::endl;
#endif

	free(res);
	return collisions;
}

static void computeStatistics(uint64_t numSets, int numThreads)
{
	auto begin = std::chrono::high_resolution_clock::now();
#ifdef _DEBUG
	std::cout << "Computing statistics with " << numSets << " sets and " << numThreads << " threads." << std::endl;
#endif

	std::vector<std::thread> threads;
	for (int i = 0; i < numThreads; ++i)
	{
		threads.push_back(std::thread(computeCosets, numSets));
	}
	for (unsigned int i = 0; i < threads.size(); ++i)
	{
		if (threads[i].joinable())
			threads.at(i).join();
	}
	auto end = std::chrono::high_resolution_clock::now();
	std::cout << "Finished " << cosets.size() << " cosets with " << numThreads << " thread(s) in " << std::chrono::duration_cast<std::chrono::minutes>(end - begin).count() << " minutes." << std::endl;

#ifdef _DEBUG
	time_t d_seconds;
	std::string d_filename = "debug-" + std::to_string(time(&d_seconds)) + ".txt";
	std::ofstream d_file(d_filename, std::ofstream::out);
	for (uint64_t elem : cosets)
	{
		d_file << elem << std::endl;
	}
	d_file.close();
#endif
	StatisticResult res = computeStatisticResult(cosets);
	
	time_t seconds;
	std::string filename = "results-" + std::to_string(time(&seconds)) + ".txt";
	std::ofstream file(filename, std::ofstream::out);
	file << "Computed from " << cosets.size() << " cosets." << std::endl;
	file << "Mean: " << res.mean << std::endl;
	file << "Variance: " << res.variance << std::endl;
	file << "Skew: " << res.skew << std::endl;
	file.close();

	return;
}

StatisticResult computeStatisticResult(std::list<uint64_t> cosets)
{
	StatisticResult sRes;
	uint64_t numSets = cosets.size();
	//compute mean
	double tMean = 0;
	for (uint64_t elem : cosets)
	{
		tMean += elem;
	}
	sRes.mean = tMean / numSets;

	//compute variance
	double tVariance = 0;
	for (uint64_t elem : cosets)
	{
		tVariance += pow(elem - sRes.mean, 2);
	}
	sRes.variance = tVariance / (numSets - 1);

	//compute skew
	double tL = 0;
	for (uint64_t elem : cosets)
	{
		tL += pow(elem - sRes.mean, 3);
	}
	double tSkew = tL / numSets;
	sRes.skew = tSkew / pow(sRes.variance, 1.5);

	return sRes;
}

void printUsage(std::string name)
{
	std::cout << name << " #COSETS #THREADS"<< std::endl;
	std::cout << "Ex. "<< name << " 64 2" << std::endl;
}
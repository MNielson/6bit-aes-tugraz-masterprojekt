#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
//disable warnings for localtime. If localtime used in threads, use localtime_s instead (on windows) or mutex otherwise
#define _CRT_SECURE_NO_WARNINGS
#include <ctime>
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
#include <random>

#define TWO_P_24 16777216
#define USE_C_RNG 0
//#define TWO_P_24 1
#include "aes6bit.h"
#include "mt19937a.h"

#if defined (_MSC_VER)  // Visual studio
#define thread_local __declspec( thread )
#elif defined (__GCC__) // GCC
#define thread_local __thread
#endif


typedef struct {
	double mean;
	double variance;
	double skew;
} StatisticResult;

static uint64_t computeCoset(void);
static void computeStatistics(uint64_t numSets, int numThreads);
StatisticResult computeStatisticResult(std::list<uint64_t> cosets);
void printUsage(std::string name);
int intRand(const int & min, const int & max);

std::mutex mtx;
std::list<uint64_t> cosets;


inline std::tm localtime_xp(std::time_t timer)
{
	std::tm bt{};
#if defined(__unix__)
	localtime_r(&timer, &bt);
#elif defined(_MSC_VER)
	localtime_s(&bt, &timer);
#else
	static std::mutex mtx;
	std::lock_guard<std::mutex> lock(mtx);
	bt = *std::localtime(&timer);
#endif
	return bt;
}

// default = "YYYY-MM-DD HH:MM:SS"
inline std::string time_stamp(const std::string& fmt = "%F %T")
{
	auto bt = localtime_xp(std::time(0));
	char buf[64];
	return{ buf, std::strftime(buf, sizeof(buf), fmt.c_str(), &bt) };
}


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
		if (USE_C_RNG) 
		{
			srand((unsigned int)time(NULL));
		}
		else
		{
			unsigned long init[4] = { 0x123, 0x234, 0x345, 0x456 };
			int length = 4;
			init_by_array(init, length);
		}

		computeStatistics(numSets, numThreads);
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
	AES6BIT aes;
	
	for (int i = 0; i < 16; i++)
	{
		if (USE_C_RNG)
		{
			key[i]         = intRand(0, 63);
			const_state[i] = intRand(0, 63);
		}
		else
		{
			key[i]         = (uint8_t)(genrand_int32() & 0x3F);
			const_state[i] = (uint8_t)(genrand_int32() & 0x3F);
		}
		
	}

	aes.AES_init_ctx(&ctx, key);

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

		aes.AES_ECB_encrypt(&ctx, state, Nr);
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
	if (Nr <= 12 && collisions % 8)
		std::cerr << "Error: " << collisions << " is not a multiple of 8." << std::endl;
#endif

	free(res);
	return collisions;
}

static void computeStatistics(uint64_t numSets, int numThreads)
{
	auto begin = std::chrono::high_resolution_clock::now();
	auto startTime = time_stamp();


	std::cout << "Computing statistics with " << numSets << " sets and " << numThreads << " threads." << std::endl;


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
	auto endTime = time_stamp();
	std::cout << "Finished " << cosets.size() << " cosets with " << numThreads << " thread(s) in " << std::chrono::duration_cast<std::chrono::minutes>(end - begin).count() << " minutes." << std::endl;

	time_t d_seconds;
	std::string d_filename = "debug-" + std::to_string(time(&d_seconds)) + ".txt";
	std::ofstream d_file(d_filename, std::ofstream::out);


	d_file << "Started " << startTime << std::endl;
	d_file << "Started " << endTime   << std::endl;


	d_file << "Writing " << cosets.size() << "cosets:" << std::endl;
	for (uint64_t elem : cosets)
	{
		d_file << elem << std::endl;
	}
	d_file.close();

	StatisticResult res = computeStatisticResult(cosets);
	
	time_t seconds;
	std::string filename = "results-" + std::to_string(time(&seconds)) + ".txt";
	std::ofstream file(filename, std::ofstream::out);
	file << "Computed from " << cosets.size() << " cosets" << " computed between " << startTime << " and " << endTime << "." << std::endl;
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

/* Thread-safe function that returns a random number between min and max (inclusive).
This function takes ~142% the time that calling rand() would take. For this extra
cost you get a better uniform distribution and thread-safety. */
int intRand(const int & min, const int & max) {
	static thread_local std::mt19937* generator = nullptr;
	std::hash<std::thread::id> hasher;
	if (!generator)
		generator = new std::mt19937(clock() + (unsigned int)hasher(std::this_thread::get_id()));
	std::uniform_int_distribution<int> distribution(min, max);
	return distribution(*generator);
}

	

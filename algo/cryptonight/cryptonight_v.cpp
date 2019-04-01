extern "C" {
	#include "miner.h"

	#if defined(__arm__) || defined(_MSC_VER)
	#ifndef NOASM
	#define NOASM
	#endif
	#endif

	#include "crypto/oaes_lib.h"
	#include "crypto/c_keccak.h"
	#include "crypto/c_groestl.h"
	#include "crypto/c_blake256.h"
	#include "crypto/c_jh.h"
	#include "crypto/c_skein.h"
	#include "crypto/int-util.h"
	#include "crypto/hash-ops.h"

	#if USE_INT128

	#if __GNUC__ == 4 && __GNUC_MINOR__ >= 4 && __GNUC_MINOR__ < 6
	typedef unsigned int uint128_t __attribute__ ((__mode__ (TI)));
	#elif defined (_MSC_VER)
	/* only for mingw64 on windows */
	#undef  USE_INT128
	#define USE_INT128 (0)
	#else
	typedef __uint128_t uint128_t;
	#endif

	#endif

	#define LITE 0
	#if LITE /* cryptonight-light */
	#define MEMORY (1 << 20)
	#define ITER   (1 << 19)
	#else
	#define MEMORY (1 << 21) /* 2 MiB */
	#define ITER   (1 << 20)
	#endif

	#define AES_BLOCK_SIZE  16
	#define AES_KEY_SIZE    32 /*16*/
	#define INIT_SIZE_BLK   8
	#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

	#pragma pack(push, 1)
	union cn_slow_hash_state {
		union hash_state hs;
		struct {
			uint8_t k[64];
			uint8_t init[INIT_SIZE_BYTE];
		};
	};
	#pragma pack(pop)
	
	#if defined _MSC_VER || defined XMRIG_ARM
	#define ABI_ATTRIBUTE
	#else
	#define ABI_ATTRIBUTE __attribute__((ms_abi))
	#endif

	#include <unistd.h>

	#ifdef __GNUC__
	#   include <x86intrin.h>
	#else
	#   include <intrin.h>
	#   define __restrict__ __restrict
	#endif

	#include "crypto/c_groestl.h"
	#include "crypto/c_blake256.h"
	#include "crypto/c_jh.h"
	#include "crypto/c_skein.h"
		
	enum Assembly {
		ASM_NONE,
		ASM_AUTO,
		ASM_INTEL,
		ASM_RYZEN,
		ASM_BULLDOZER,
		ASM_MAX
	};

	enum Variant {
		VARIANT_AUTO = -1, // Autodetect
		VARIANT_0    =  0,  // Original CryptoNight or CryptoNight-Heavy
		VARIANT_1    =  1,  // CryptoNight variant 1 also known as Monero7 and CryptoNightV7
		VARIANT_2    =  8,  // CryptoNight variant 2
		VARIANT_4    = 13, // CryptoNightR (Monero's variant 4)
		VARIANT_MAX
	};

	struct cryptonight_ctx;
	typedef void(*cn_mainloop_fun_ms_abi)(cryptonight_ctx*) ABI_ATTRIBUTE;

	struct cryptonight_r_data {
		int variant;
		uint64_t height;

		bool match(const int v, const uint64_t h) const { return (v == variant) && (h == height); }
	};

	#include <stdlib.h>
	#include <sys/mman.h>

	void *Mem__allocateExecutableMemory(size_t size)
	{
	#   if defined(__APPLE__)
		return mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
	#   else
		return mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	#   endif
	}
	void Mem__flushInstructionCache(void *p, size_t size)
	{
	#   ifndef __FreeBSD__
		__builtin___clear_cache(reinterpret_cast<char*>(p), reinterpret_cast<char*>(p) + size);
	#   endif
	}

	struct cryptonight_ctx {
		
		cryptonight_ctx()
		{
			memory = static_cast<uint8_t*>(_mm_malloc(MEMORY * 2, 16));

			uint8_t* p = reinterpret_cast<uint8_t*>(Mem__allocateExecutableMemory(0x4000));
			generated_code  = reinterpret_cast<cn_mainloop_fun_ms_abi>(p);
			generated_code_data.variant = VARIANT_MAX;
			generated_code_data.height = (uint64_t)(-1);
		}
		
		~cryptonight_ctx()
		{
			_mm_free(memory);
		}
		
		alignas(16) uint8_t state[224];
		alignas(16) uint8_t *memory;

		uint8_t unused[40];
		const uint32_t* saes_table;

		cn_mainloop_fun_ms_abi generated_code;
		cryptonight_r_data generated_code_data;
	};
}

#include "cryptonight_v.h"
#include "crypto/soft_aes.h"

static inline void do_blake_hash(const uint8_t *input, size_t len, uint8_t *output) {
    blake256_hash(output, input, len);
}


static inline void do_groestl_hash(const uint8_t *input, size_t len, uint8_t *output) {
    groestl(input, len * 8, output);
}


static inline void do_jh_hash(const uint8_t *input, size_t len, uint8_t *output) {
    jh_hash(32 * 8, input, 8 * len, output);
}


static inline void do_skein_hash(const uint8_t *input, size_t len, uint8_t *output) {
    xmr_skein(input, output);
}


void (* const extra_hashes[4])(const uint8_t *, size_t, uint8_t *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};


#if defined(__x86_64__) || defined(_M_AMD64)
#   ifdef __GNUC__
static inline uint64_t __umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
    unsigned __int128 r = (unsigned __int128) a * (unsigned __int128) b;
    *hi = r >> 64;
    return (uint64_t) r;
}
#   else
    #define __umul128 _umul128
#   endif
#elif defined(__i386__) || defined(_M_IX86)
static inline int64_t _mm_cvtsi128_si64(__m128i a)
{
    return ((uint64_t)(uint32_t)_mm_cvtsi128_si32(a) | ((uint64_t)(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(a, 4)) << 32));
}

static inline __m128i _mm_cvtsi64_si128(int64_t a) {
    return _mm_set_epi64x(0, a);
}

static inline uint64_t __umul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi) {
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = multiplier >> 32;
    uint64_t b = multiplier & 0xFFFFFFFF;
    uint64_t c = multiplicand >> 32;
    uint64_t d = multiplicand & 0xFFFFFFFF;

    //uint64_t ac = a * c;
    uint64_t ad = a * d;
    //uint64_t bc = b * c;
    uint64_t bd = b * d;

    uint64_t adbc = ad + (b * c);
    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);
    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
    *product_hi = (a * c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

    return product_lo;
}
#endif


// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = _mm_aeskeygenassist_si128(*xout0, 0x00);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<uint8_t rcon>
static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = soft_aeskeygenassist<rcon>(*xout2);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = soft_aeskeygenassist<0x00>(*xout0);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3, __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
    __m128i xout0 = _mm_load_si128(memory);
    __m128i xout2 = _mm_load_si128(memory + 1);
    *k0 = xout0;
    *k1 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x01>(&xout0, &xout2) : aes_genkey_sub<0x01>(&xout0, &xout2);
    *k2 = xout0;
    *k3 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x02>(&xout0, &xout2) : aes_genkey_sub<0x02>(&xout0, &xout2);
    *k4 = xout0;
    *k5 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x04>(&xout0, &xout2) : aes_genkey_sub<0x04>(&xout0, &xout2);
    *k6 = xout0;
    *k7 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x08>(&xout0, &xout2) : aes_genkey_sub<0x08>(&xout0, &xout2);
    *k8 = xout0;
    *k9 = xout2;
}


static FORCEINLINE void soft_aesenc(void* __restrict ptr, const void* __restrict key, const uint32_t* __restrict t)
{
    uint32_t x0 = ((const uint32_t*)(ptr))[0];
    uint32_t x1 = ((const uint32_t*)(ptr))[1];
    uint32_t x2 = ((const uint32_t*)(ptr))[2];
    uint32_t x3 = ((const uint32_t*)(ptr))[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8;
    t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8;
    t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8;
    t += 256;

    y0 ^= t[x3];
    y1 ^= t[x0];
    y2 ^= t[x1];
    y3 ^= t[x2];

    ((uint32_t*)ptr)[0] = y0 ^ ((uint32_t*)key)[0];
    ((uint32_t*)ptr)[1] = y1 ^ ((uint32_t*)key)[1];
    ((uint32_t*)ptr)[2] = y2 ^ ((uint32_t*)key)[2];
    ((uint32_t*)ptr)[3] = y3 ^ ((uint32_t*)key)[3];
}

static FORCEINLINE __m128i soft_aesenc(const void* __restrict ptr, const __m128i key, const uint32_t* __restrict t)
{
    uint32_t x0 = ((const uint32_t*)(ptr))[0];
    uint32_t x1 = ((const uint32_t*)(ptr))[1];
    uint32_t x2 = ((const uint32_t*)(ptr))[2];
    uint32_t x3 = ((const uint32_t*)(ptr))[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8;
    t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8;
    t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8;

    y0 ^= t[x3 + 256];
    y1 ^= t[x0 + 256];
    y2 ^= t[x1 + 256];
    y3 ^= t[x2 + 256];

    return _mm_xor_si128(_mm_set_epi32(y3, y2, y1, y0), key);
}

template<bool SOFT_AES>
void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7);

template<>
NOINLINE void aes_round<true>(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    *x0 = soft_aesenc((uint32_t*)x0, key, (const uint32_t*)saes_table);
    *x1 = soft_aesenc((uint32_t*)x1, key, (const uint32_t*)saes_table);
    *x2 = soft_aesenc((uint32_t*)x2, key, (const uint32_t*)saes_table);
    *x3 = soft_aesenc((uint32_t*)x3, key, (const uint32_t*)saes_table);
    *x4 = soft_aesenc((uint32_t*)x4, key, (const uint32_t*)saes_table);
    *x5 = soft_aesenc((uint32_t*)x5, key, (const uint32_t*)saes_table);
    *x6 = soft_aesenc((uint32_t*)x6, key, (const uint32_t*)saes_table);
    *x7 = soft_aesenc((uint32_t*)x7, key, (const uint32_t*)saes_table);
}

template<>
FORCEINLINE void aes_round<false>(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    *x0 = _mm_aesenc_si128(*x0, key);
    *x1 = _mm_aesenc_si128(*x1, key);
    *x2 = _mm_aesenc_si128(*x2, key);
    *x3 = _mm_aesenc_si128(*x3, key);
    *x4 = _mm_aesenc_si128(*x4, key);
    *x5 = _mm_aesenc_si128(*x5, key);
    *x6 = _mm_aesenc_si128(*x6, key);
    *x7 = _mm_aesenc_si128(*x7, key);
}

inline void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
    __m128i tmp0 = x0;
    x0 = _mm_xor_si128(x0, x1);
    x1 = _mm_xor_si128(x1, x2);
    x2 = _mm_xor_si128(x2, x3);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_xor_si128(x4, x5);
    x5 = _mm_xor_si128(x5, x6);
    x6 = _mm_xor_si128(x6, x7);
    x7 = _mm_xor_si128(x7, tmp0);
}

template<size_t MEM, bool SOFT_AES>
static inline void cn_explode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = _mm_load_si128(input + 4);
    xin1 = _mm_load_si128(input + 5);
    xin2 = _mm_load_si128(input + 6);
    xin3 = _mm_load_si128(input + 7);
    xin4 = _mm_load_si128(input + 8);
    xin5 = _mm_load_si128(input + 9);
    xin6 = _mm_load_si128(input + 10);
    xin7 = _mm_load_si128(input + 11);

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8) {
        aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

        _mm_store_si128(output + i + 0, xin0);
        _mm_store_si128(output + i + 1, xin1);
        _mm_store_si128(output + i + 2, xin2);
        _mm_store_si128(output + i + 3, xin3);
        _mm_store_si128(output + i + 4, xin4);
        _mm_store_si128(output + i + 5, xin5);
        _mm_store_si128(output + i + 6, xin6);
        _mm_store_si128(output + i + 7, xin7);
    }
}

template<size_t MEM, bool SOFT_AES>
static inline void cn_implode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = _mm_load_si128(output + 4);
    xout1 = _mm_load_si128(output + 5);
    xout2 = _mm_load_si128(output + 6);
    xout3 = _mm_load_si128(output + 7);
    xout4 = _mm_load_si128(output + 8);
    xout5 = _mm_load_si128(output + 9);
    xout6 = _mm_load_si128(output + 10);
    xout7 = _mm_load_si128(output + 11);

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
    {
        xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
        xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
        xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
        xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
        xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
        xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
        xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
        xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

        aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    }

    _mm_store_si128(output + 4, xout0);
    _mm_store_si128(output + 5, xout1);
    _mm_store_si128(output + 6, xout2);
    _mm_store_si128(output + 7, xout3);
    _mm_store_si128(output + 8, xout4);
    _mm_store_si128(output + 9, xout5);
    _mm_store_si128(output + 10, xout6);
    _mm_store_si128(output + 11, xout7);
}


static inline __m128i aes_round_tweak_div(const __m128i &in, const __m128i &key)
{
    alignas(16) uint32_t k[4];
    alignas(16) uint32_t x[4];

    _mm_store_si128((__m128i*) k, key);
    _mm_store_si128((__m128i*) x, _mm_xor_si128(in, _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff)));

    #define BYTE(p, i) ((unsigned char*)&x[p])[i]
    k[0] ^= saes_table[0][BYTE(0, 0)] ^ saes_table[1][BYTE(1, 1)] ^ saes_table[2][BYTE(2, 2)] ^ saes_table[3][BYTE(3, 3)];
    x[0] ^= k[0];
    k[1] ^= saes_table[0][BYTE(1, 0)] ^ saes_table[1][BYTE(2, 1)] ^ saes_table[2][BYTE(3, 2)] ^ saes_table[3][BYTE(0, 3)];
    x[1] ^= k[1];
    k[2] ^= saes_table[0][BYTE(2, 0)] ^ saes_table[1][BYTE(3, 1)] ^ saes_table[2][BYTE(0, 2)] ^ saes_table[3][BYTE(1, 3)];
    x[2] ^= k[2];
    k[3] ^= saes_table[0][BYTE(3, 0)] ^ saes_table[1][BYTE(0, 1)] ^ saes_table[2][BYTE(1, 2)] ^ saes_table[3][BYTE(2, 3)];
    #undef BYTE

    return _mm_load_si128((__m128i*)k);
}


static inline __m128i int_sqrt_v2(const uint64_t n0)
{
    __m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_cvtsi64_si128(n0 >> 12), _mm_set_epi64x(0, 1023ULL << 52)));
    x = _mm_sqrt_sd(_mm_setzero_pd(), x);
    uint64_t r = static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_castpd_si128(x)));

    const uint64_t s = r >> 20;
    r >>= 19;

    uint64_t x2 = (s - (1022ULL << 32)) * (r - s - (1022ULL << 32) + 1);
#   if (defined(_MSC_VER) || __GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ > 1)) && (defined(__x86_64__) || defined(_M_AMD64))
    _addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned long long int*)&x2), r, 0, (unsigned long long int*)&r);
#   else
    if (x2 < n0) ++r;
#   endif

    return _mm_cvtsi64_si128(r);
}

template<Variant VARIANT>
static inline void cryptonight_monero_tweak(uint64_t* mem_out, const uint8_t* l, uint64_t idx, __m128i ax0, __m128i bx0, __m128i bx1, __m128i& cx)
{
    if (VARIANT == VARIANT_2 || VARIANT == VARIANT_4)
	{
        VARIANT2_SHUFFLE(l, idx, ax0, bx0, bx1, cx, 0);
        _mm_store_si128((__m128i *)mem_out, _mm_xor_si128(bx0, cx));
    }
	else
	{
        __m128i tmp = _mm_xor_si128(bx0, cx);
        mem_out[0] = _mm_cvtsi128_si64(tmp);

        tmp = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
        uint64_t vh = _mm_cvtsi128_si64(tmp);

        uint8_t x = static_cast<uint8_t>(vh >> 24);
        static const uint16_t table = 0x7531;
        const uint8_t index = (((x >> 3) & 6) | (x & 1)) << 1;
        vh ^= ((table >> index) & 0x3) << 28;

        mem_out[1] = vh;
    }
}

constexpr const size_t   CRYPTONIGHT_MEMORY = 2 * 1024 * 1024;
constexpr const uint32_t CRYPTONIGHT_MASK   = 0x1FFFF0;
constexpr const uint32_t CRYPTONIGHT_ITER   = 0x80000;

template<bool SOFT_AES, Variant VARIANT>
inline void cryptonight_single_hash(uint8_t *__restrict__ output, const uint8_t *__restrict__ input, size_t size, cryptonight_ctx **__restrict__ ctx, uint64_t height)
{
    constexpr size_t MEM          = CRYPTONIGHT_MEMORY;
	constexpr size_t MASK         = CRYPTONIGHT_MASK;
    constexpr size_t ITERATIONS   = CRYPTONIGHT_ITER;
		
    static_assert(MASK > 0 && ITERATIONS > 0 && MEM > 0, "unsupported algorithm/variant");

    if (VARIANT == VARIANT_1 && size < 43) {
        memset(output, 0, 32);
        return;
    }

    keccak200(input, size, ctx[0]->state);

    cn_explode_scratchpad<MEM, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);

    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);

    const uint8_t* l0 = ctx[0]->memory;

    VARIANT1_INIT(0);
    VARIANT2_INIT(0);
    VARIANT2_SET_ROUNDING_MODE();
    VARIANT4_RANDOM_MATH_INIT(0);

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i bx1 = _mm_set_epi64x(h0[9] ^ h0[11], h0[8] ^ h0[10]);

    uint64_t idx0 = al0;

    for (size_t i = 0; i < ITERATIONS; i++) {
        __m128i cx;
        if (!SOFT_AES) {
            cx = _mm_load_si128((__m128i *) &l0[idx0 & MASK]);
        }

        const __m128i ax0 = _mm_set_epi64x(ah0, al0);
        if (SOFT_AES) {
            cx = soft_aesenc((uint32_t*)&l0[idx0 & MASK], ax0, (const uint32_t*)saes_table);
        }
        else {
            cx = _mm_aesenc_si128(cx, ax0);
        }

        if (VARIANT == VARIANT_1 || VARIANT == VARIANT_2 || VARIANT == VARIANT_4)
		{
            cryptonight_monero_tweak<VARIANT>((uint64_t*)&l0[idx0 & MASK], l0, idx0 & MASK, ax0, bx0, bx1, cx);
        }
		else
		{
            _mm_store_si128((__m128i *)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));
        }

        idx0 = _mm_cvtsi128_si64(cx);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*) &l0[idx0 & MASK])[0];
        ch = ((uint64_t*) &l0[idx0 & MASK])[1];

		if (VARIANT == VARIANT_4)
		{
			VARIANT4_RANDOM_MATH(0, al0, ah0, cl, bx0, bx1);

			al0 ^= r0[2] | ((uint64_t)(r0[3]) << 32);
			ah0 ^= r0[0] | ((uint64_t)(r0[1]) << 32);
		}
		else if (VARIANT == VARIANT_2)
		{
			VARIANT2_INTEGER_MATH(0, cl, cx);
		}

        lo = __umul128(idx0, cl, &hi);

		if (VARIANT == VARIANT_4)
		{
			VARIANT2_SHUFFLE(l0, idx0 & MASK, ax0, bx0, bx1, cx, 0);
		}
		else if (VARIANT == VARIANT_2)
		{
			VARIANT2_SHUFFLE2(l0, idx0 & MASK, ax0, bx0, bx1, hi, lo, 0);
		}

        al0 += hi;
        ah0 += lo;

        ((uint64_t*)&l0[idx0 & MASK])[0] = al0;

        if (VARIANT == VARIANT_1)
		{
            ((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ tweak1_2_0;
        }
		else
		{
            ((uint64_t*)&l0[idx0 & MASK])[1] = ah0;
        }

        al0 ^= cl;
        ah0 ^= ch;
        idx0 = al0;

        if (VARIANT == VARIANT_2 || VARIANT == VARIANT_4)
		{
            bx1 = bx0;
        }

        bx0 = cx;
    }

        
    cn_implode_scratchpad<MEM, SOFT_AES>((__m128i*) ctx[0]->memory, (__m128i*) ctx[0]->state);

    keccakf(h0, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}


extern "C" void cnv2_mainloop_ivybridge_asm(cryptonight_ctx *ctx);
extern "C" void cnv2_mainloop_ryzen_asm(cryptonight_ctx *ctx);
extern "C" void cnv2_mainloop_bulldozer_asm(cryptonight_ctx *ctx);
extern "C" void cnv2_double_mainloop_sandybridge_asm(cryptonight_ctx* ctx0, cryptonight_ctx* ctx1);
extern "C" void cnv2_rwz_mainloop_asm(cryptonight_ctx *ctx);
extern "C" void cnv2_rwz_double_mainloop_asm(cryptonight_ctx* ctx0, cryptonight_ctx* ctx1);

typedef void (*cn_mainloop_fun)(cryptonight_ctx *ctx);
typedef void (*cn_mainloop_double_fun)(cryptonight_ctx *ctx1, cryptonight_ctx *ctx2);
typedef void(*void_func)();

#include "cryptonightR_template.h"

extern cn_mainloop_fun        cn_half_mainloop_ivybridge_asm;
extern cn_mainloop_fun        cn_half_mainloop_ryzen_asm;
extern cn_mainloop_fun        cn_half_mainloop_bulldozer_asm;
extern cn_mainloop_double_fun cn_half_double_mainloop_sandybridge_asm;

extern cn_mainloop_fun        cn_trtl_mainloop_ivybridge_asm;
extern cn_mainloop_fun        cn_trtl_mainloop_ryzen_asm;
extern cn_mainloop_fun        cn_trtl_mainloop_bulldozer_asm;
extern cn_mainloop_double_fun cn_trtl_double_mainloop_sandybridge_asm;

extern cn_mainloop_fun        cn_zls_mainloop_ivybridge_asm;
extern cn_mainloop_fun        cn_zls_mainloop_ryzen_asm;
extern cn_mainloop_fun        cn_zls_mainloop_bulldozer_asm;
extern cn_mainloop_double_fun cn_zls_double_mainloop_sandybridge_asm;

extern cn_mainloop_fun        cn_double_mainloop_ivybridge_asm;
extern cn_mainloop_fun        cn_double_mainloop_ryzen_asm;
extern cn_mainloop_fun        cn_double_mainloop_bulldozer_asm;
extern cn_mainloop_double_fun cn_double_double_mainloop_sandybridge_asm;

static inline void add_code(uint8_t* &p, void (*p1)(), void (*p2)())
{
    const ptrdiff_t size = reinterpret_cast<const uint8_t*>(p2) - reinterpret_cast<const uint8_t*>(p1);
    if (size > 0) {
        memcpy(p, reinterpret_cast<void*>(p1), size);
        p += size;
    }
}

static inline void add_random_math(uint8_t* &p, const V4_Instruction* code, int code_size, const void_func* instructions, const void_func* instructions_mov, bool is_64_bit, Assembly ASM)
{
    uint32_t prev_rot_src = (uint32_t)(-1);

    for (int i = 0;; ++i) {
        const V4_Instruction inst = code[i];
        if (inst.opcode == RET) {
            break;
        }

        uint8_t opcode = (inst.opcode == MUL) ? inst.opcode : (inst.opcode + 2);
        uint8_t dst_index = inst.dst_index;
        uint8_t src_index = inst.src_index;

        const uint32_t a = inst.dst_index;
        const uint32_t b = inst.src_index;
        const uint8_t c = opcode | (dst_index << V4_OPCODE_BITS) | (((src_index == 8) ? dst_index : src_index) << (V4_OPCODE_BITS + V4_DST_INDEX_BITS));

        switch (inst.opcode) {
        case ROR:
        case ROL:
            if (b != prev_rot_src) {
                prev_rot_src = b;
                add_code(p, instructions_mov[c], instructions_mov[c + 1]);
            }
            break;
        }

        if (a == prev_rot_src) {
            prev_rot_src = (uint32_t)(-1);
        }

        void_func begin = instructions[c];

        if ((ASM = ASM_BULLDOZER) && (inst.opcode == MUL) && !is_64_bit) {
            // AMD Bulldozer has latency 4 for 32-bit IMUL and 6 for 64-bit IMUL
            // Always use 32-bit IMUL for AMD Bulldozer in 32-bit mode - skip prefix 0x48 and change 0x49 to 0x41
            uint8_t* prefix = reinterpret_cast<uint8_t*>(begin);

            if (*prefix == 0x49) {
                *(p++) = 0x41;
            }

            begin = reinterpret_cast<void_func>(prefix + 1);
        }

        add_code(p, begin, instructions[c + 1]);

        if (inst.opcode == ADD) {
            *(uint32_t*)(p - sizeof(uint32_t) - (is_64_bit ? 3 : 0)) = inst.C;
            if (is_64_bit) {
                prev_rot_src = (uint32_t)(-1);
            }
        }
    }
}

void v4_compile_code(const V4_Instruction* code, int code_size, void* machine_code, Assembly ASM)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_template_part1, CryptonightR_template_part2);
    add_random_math(p, code, code_size, instructions, instructions_mov, false, ASM);
    add_code(p, CryptonightR_template_part2, CryptonightR_template_part3);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_template_mainloop) - ((const uint8_t*)CryptonightR_template_part1)) - (p - p0));
    add_code(p, CryptonightR_template_part3, CryptonightR_template_end);

    Mem__flushInstructionCache(machine_code, p - p0);
}

template<Variant VARIANT>
void cn_r_compile_code(const V4_Instruction* code, int code_size, void* machine_code, Assembly ASM)
{
    v4_compile_code(code, code_size, machine_code, ASM);
}

template<Variant VARIANT, Assembly ASM>
inline void cryptonight_single_hash_asm(uint8_t *__restrict__ output, const uint8_t *__restrict__ input, size_t size, cryptonight_ctx **__restrict__ ctx, uint64_t height)
{
    constexpr size_t MEM          = CRYPTONIGHT_MEMORY;

    if (!ctx[0]->generated_code_data.match(VARIANT, height))
	{
        V4_Instruction code[256];
        const int code_size = v4_random_math_init<VARIANT>(code, height);
        cn_r_compile_code<VARIANT>(code, code_size, reinterpret_cast<void*>(ctx[0]->generated_code), ASM);
        ctx[0]->generated_code_data.variant = VARIANT;
        ctx[0]->generated_code_data.height = height;
    }

    keccak200(input, size, ctx[0]->state);
    cn_explode_scratchpad<MEM, false>(reinterpret_cast<__m128i*>(ctx[0]->state), reinterpret_cast<__m128i*>(ctx[0]->memory));

    if (VARIANT == VARIANT_2)
	{
        if (ASM == ASM_INTEL)
		{
            cnv2_mainloop_ivybridge_asm(ctx[0]);
        }
        else if (ASM == ASM_RYZEN)
		{
            cnv2_mainloop_ryzen_asm(ctx[0]);
        }
        else
		{
            cnv2_mainloop_bulldozer_asm(ctx[0]);
        }
    }
    else
	{
        ctx[0]->generated_code(ctx[0]);
    }

    cn_implode_scratchpad<MEM, false>(reinterpret_cast<__m128i*>(ctx[0]->memory), reinterpret_cast<__m128i*>(ctx[0]->state));
    keccakf(reinterpret_cast<uint64_t*>(ctx[0]->state), 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}

inline void cryptonight_hash_ctx_soft(uint8_t *__restrict__ output, const uint8_t *__restrict__ input, size_t size, cryptonight_ctx **__restrict__ ctx, const uint64_t height)
{
	constexpr Variant VARIANT = VARIANT_4;		
	cryptonight_single_hash<true, VARIANT>(output, input, size, ctx, height);
}
inline void cryptonight_hash_ctx_aes_ni(uint8_t *__restrict__ output, const uint8_t *__restrict__ input, size_t size, cryptonight_ctx **__restrict__ ctx, const uint64_t height)
{
	constexpr Variant VARIANT = VARIANT_4;		
	cryptonight_single_hash<false, VARIANT>(output, input, size, ctx, height);
}

inline void cryptonight_hash_ctx(uint8_t *__restrict__ output, const uint8_t *__restrict__ input, size_t size, cryptonight_ctx **__restrict__ ctx, const uint64_t height)
{
	if(asm_supported)
	{
		cryptonight_single_hash_asm<VARIANT_4, ASM_INTEL>(output, input, size, ctx, height);
	}
	else if (aes_ni_supported)
	{
		cryptonight_hash_ctx_aes_ni(output, input, size, ctx, height);
	}
	else
	{
		cryptonight_hash_ctx_soft(output, input, size, ctx, height);
	}
}

#include "cryptonight_test.h"

bool selfTestV4()
{
	applog(LOG_INFO, "CryptoNight SelfTestV4 runing");
	uint8_t output[64];

	struct cryptonight_ctx ctx0, ctx1;
	struct cryptonight_ctx* ctx[2] = {&ctx0, &ctx1};

	bool rc = false;
	for(unsigned short i = 0; i < sizeof(test_inputs_v4) / sizeof(test_inputs_v4[0]); ++i)
	{
		cryptonight_hash_ctx(output, test_inputs_v4[i], strlen((char*)test_inputs_v4[i]), ctx, test_heights_v4[i]);

		rc = memcmp(output, test_outputs_v4[i], sizeof(test_outputs_v4[i])) == 0;

		if(rc == false)
		{
			break;
		}
		
		fprintf(stdout, ".");
	}
	
	fprintf(stdout, " [Done] ");
	
	if(rc == true)
	{
		fprintf(stdout, "All self-test passed!\n");
	}
	else
	{
		fprintf(stderr, "Hash self-test failed. Abort!\n");
		abort();
	}
	
	return rc;
}

extern "C" {
	void cryptonight_test()
	{
		selfTestV4();
	}
		
	void cryptonight_hash(void* output, const void* input, const int height)
	{
		struct cryptonight_ctx ctx0, ctx1;	
		struct cryptonight_ctx* ctx[2] = {&ctx0, &ctx1};
		
		cryptonight_hash_ctx((uint8_t*)output, (uint8_t*)input, 76, ctx, height);
	}
	
	void cryptonight_hash_aes(void* output, const void* input, const int height)
	{
		struct cryptonight_ctx ctx0, ctx1;	
		struct cryptonight_ctx* ctx[2] = {&ctx0, &ctx1};
		
		cryptonight_hash_ctx_aes_ni((uint8_t*)output, (uint8_t*)input, 76, ctx, height);
	}
	
	int scanhash_cryptonight(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
	{	
		uint32_t _ALIGN(128) hash[HASH_SIZE / 4];
		uint32_t *pdata = work->data;
		uint32_t *ptarget = work->target;

		uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 39);
		uint32_t n = *nonceptr - 1;
		const uint32_t first_nonce = n + 1;

		struct cryptonight_ctx ctx0, ctx1;
		struct cryptonight_ctx* ctx[2] = {&ctx0, &ctx1};

		if(opt_debug)
		{
			applog(LOG_INFO, "Scanhash cryptonight nonce %d for %d height", work->target, work->height);
		}

		do
		{
			*nonceptr = ++n;
			cryptonight_hash_ctx((uint8_t*)hash, (const uint8_t*)pdata, 76, ctx, work->height);
			if (unlikely(hash[7] < ptarget[7])) {
				work_set_target_ratio(work, hash);
				*hashes_done = n - first_nonce + 1;
				return 1;
			}
			
			if(true == opt_child && (n % 0x10) == 0)
			{
				usleep((100 - 1) * 10 * 1000);
			}
		}
		while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
		
		*hashes_done = n - first_nonce + 1;
		
		return 0;
	}
}

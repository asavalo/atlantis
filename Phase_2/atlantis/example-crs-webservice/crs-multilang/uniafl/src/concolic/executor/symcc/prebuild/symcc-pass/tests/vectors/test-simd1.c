#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>

char global_buffer[256];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) return 0;

    // 1) load unaligned 256‑bit vector → `load <8 x i32>`
    __m256i v = _mm256_loadu_si256((const __m256i*)data);

    // 2) shuffle lanes → AVX2 pshufd → will show up as a `shufflevector` or call llvm.x86.avx2.pshuf.d in IR
    __m256i shuf = _mm256_shuffle_epi32(v, _MM_SHUFFLE(2,3,1,0));

    // 3) bitcast ints → floats → `bitcast <8 x i32> to <8 x float>`
    __m256 vf = _mm256_castsi256_ps(shuf);

    // 4) vector add → `fadd <8 x float>`
    __m256 vadd = _mm256_add_ps(vf, vf);

    // 5) bitcast floats → ints → `bitcast <8 x float> to <8 x i32>`
    __m256i vi = _mm256_castps_si256(vadd);

    // 6) compare greater → `icmp sgt <8 x i32>`
    __m256i cmp = _mm256_cmpgt_epi32(vi, _mm256_set1_epi32(0));

    // 7) blend with mask → lowered to `select <8 x i1>, <8 x i32>, <8 x i32>`
    __m256i sel = _mm256_blendv_epi8(v, vi, cmp);

    // 8) extract element lane 3 → `extractelement <8 x i32>`
    int lane3 = _mm256_extract_epi32(sel, 3);

    // 9) insert element back → `insertelement <8 x i32>`
    __m256i ins = _mm256_insert_epi32(v, lane3, 3);

    // 10) arithmetic constraint → `icmp eq i32, br` forces concolic exploration
    if (lane3 == 0x12345678) {
        // this write can only happen if the constraint is satisfied
        global_buffer[(uint8_t)lane3] = 1;
    }

    // prevent optimizing out
    volatile int sink = lane3 + ((int*)(&ins))[3];
    (void)sink;
    return 0;
}


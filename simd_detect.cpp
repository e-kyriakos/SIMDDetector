#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

// Platform-specific includes
#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#if defined(__aarch64__) || defined(__arm__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif
#endif

#ifdef __x86_64__
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

struct SIMDCapabilities {
  std::string architecture;
  std::string cpu_name;
  int max_width_bytes;
  std::vector<std::string> instruction_sets;
  std::map<std::string, bool> features;
};

class SIMDDetector {
public:
  static SIMDCapabilities detect() {
    SIMDCapabilities caps;

#ifdef __x86_64__
#ifdef __GNUC__
    detect_x86_capabilities_builtin(caps);
#else
    detect_x86_capabilities(caps);
#endif
#elif defined(__aarch64__) || defined(__arm__)
    detect_arm_capabilities(caps);
#else
    caps.architecture = "Unknown";
    caps.max_width_bytes = 16;
    caps.instruction_sets.push_back("Unknown");
#endif

    return caps;
  }

private:
  // CPUID wrapper functions
  static bool cpuid_available() {
#ifdef _WIN32
    int info[4];
    __cpuid(info, 0);
    return info[0] >= 1;
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("mmx");
#else
    return false;
#endif
  }

  static void cpuid(uint32_t leaf, uint32_t &eax, uint32_t &ebx, uint32_t &ecx,
                    uint32_t &edx) {
#ifdef _WIN32
    int info[4];
    __cpuidex(info, leaf, 0);
    eax = info[0];
    ebx = info[1];
    ecx = info[2];
    edx = info[3];
#elif defined(__GNUC__) || defined(__clang__)
    __get_cpuid(leaf, &eax, &ebx, &ecx, &edx);
#endif
  }

  static void cpuid_ex(uint32_t leaf, uint32_t subleaf, uint32_t &eax,
                       uint32_t &ebx, uint32_t &ecx, uint32_t &edx) {
#ifdef _WIN32
    int info[4];
    __cpuidex(info, leaf, subleaf);
    eax = info[0];
    ebx = info[1];
    ecx = info[2];
    edx = info[3];
#elif defined(__GNUC__) || defined(__clang__)
    __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
#endif
  }

  static uint64_t xgetbv(uint32_t index) {
#ifdef _WIN32
    return _xgetbv(index);
#elif defined(__GNUC__) || defined(__clang__)
    uint32_t eax, edx;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(index));
    return ((uint64_t)edx << 32) | eax;
#else
    return 0;
#endif
  }

  // Builtin-based detection (more reliable)
  static void detect_x86_capabilities_builtin(SIMDCapabilities &caps) {
    caps.architecture = "x86_64";
    caps.cpu_name = get_x86_cpu_name();
    caps.max_width_bytes = 16;

#ifdef __GNUC__
    __builtin_cpu_init();

    if (__builtin_cpu_supports("sse"))
      caps.instruction_sets.push_back("SSE");
    if (__builtin_cpu_supports("sse2"))
      caps.instruction_sets.push_back("SSE2");
    if (__builtin_cpu_supports("sse3"))
      caps.instruction_sets.push_back("SSE3");
    if (__builtin_cpu_supports("ssse3"))
      caps.instruction_sets.push_back("SSSE3");
    if (__builtin_cpu_supports("sse4.1"))
      caps.instruction_sets.push_back("SSE4.1");
    if (__builtin_cpu_supports("sse4.2"))
      caps.instruction_sets.push_back("SSE4.2");
    if (__builtin_cpu_supports("fma"))
      caps.instruction_sets.push_back("FMA");

    if (__builtin_cpu_supports("avx")) {
      caps.instruction_sets.push_back("AVX");
      caps.max_width_bytes = 32;
    }

    if (__builtin_cpu_supports("avx2")) {
      caps.instruction_sets.push_back("AVX2");
      caps.max_width_bytes = 32;
    }

    if (__builtin_cpu_supports("avx512f")) {
      caps.instruction_sets.push_back("AVX-512F");
      caps.max_width_bytes = 64;
    }

    if (__builtin_cpu_supports("avx512dq"))
      caps.instruction_sets.push_back("AVX-512DQ");
    if (__builtin_cpu_supports("avx512bw"))
      caps.instruction_sets.push_back("AVX-512BW");
    if (__builtin_cpu_supports("avx512vl"))
      caps.instruction_sets.push_back("AVX-512VL");
#else
    detect_x86_capabilities(caps);
    return;
#endif

    test_x86_operations(caps);
  }

  // Manual CPUID-based detection (fallback)
  static void detect_x86_capabilities(SIMDCapabilities &caps) {
    caps.architecture = "x86_64";
    caps.cpu_name = get_x86_cpu_name();
    caps.max_width_bytes = 16;

    uint32_t eax, ebx, ecx, edx;

    if (!cpuid_available()) {
      caps.instruction_sets.push_back("No CPUID");
      return;
    }

    // Basic features (leaf 1)
    cpuid(1, eax, ebx, ecx, edx);

    // SSE/SSE2
    if (edx & (1 << 25))
      caps.instruction_sets.push_back("SSE");
    if (edx & (1 << 26))
      caps.instruction_sets.push_back("SSE2");

    // SSE3+
    if (ecx & (1 << 0))
      caps.instruction_sets.push_back("SSE3");
    if (ecx & (1 << 9))
      caps.instruction_sets.push_back("SSSE3");
    if (ecx & (1 << 19))
      caps.instruction_sets.push_back("SSE4.1");
    if (ecx & (1 << 20))
      caps.instruction_sets.push_back("SSE4.2");
    if (ecx & (1 << 12))
      caps.instruction_sets.push_back("FMA");

    // AVX
    if (ecx & (1 << 28)) {
      if ((ecx & (1 << 27)) && (xgetbv(0) & 0x6) == 0x6) {
        caps.instruction_sets.push_back("AVX");
        caps.max_width_bytes = 32;
        caps.features["AVX_OS_Support"] = true;
      } else {
        caps.features["AVX_OS_Support"] = false;
        return;
      }
    }

    // Extended features (leaf 7, subleaf 0)
    cpuid_ex(7, 0, eax, ebx, ecx, edx);

    // AVX2
    if (ebx & (1 << 5)) {
      caps.instruction_sets.push_back("AVX2");
      if (caps.max_width_bytes < 32)
        caps.max_width_bytes = 32;
    }

    // AVX-512
    if (ebx & (1 << 16)) {
      if ((xgetbv(0) & 0xE6) == 0xE6) {
        caps.instruction_sets.push_back("AVX-512F");
        caps.max_width_bytes = 64;

        if (ebx & (1 << 17))
          caps.instruction_sets.push_back("AVX-512DQ");
        if (ebx & (1 << 21))
          caps.instruction_sets.push_back("AVX-512IFMA");
        if (ebx & (1 << 26))
          caps.instruction_sets.push_back("AVX-512PF");
        if (ebx & (1 << 27))
          caps.instruction_sets.push_back("AVX-512ER");
        if (ebx & (1 << 28))
          caps.instruction_sets.push_back("AVX-512CD");
        if (ebx & (1 << 30))
          caps.instruction_sets.push_back("AVX-512BW");
        if (ebx & (1 << 31))
          caps.instruction_sets.push_back("AVX-512VL");
      }
    }

    test_x86_operations(caps);
  }

  static void detect_arm_capabilities(SIMDCapabilities &caps) {
#ifdef __aarch64__
    caps.architecture = "AArch64";
    caps.cpu_name = "ARM64 Processor";
    caps.max_width_bytes = 16;

    caps.instruction_sets.push_back("NEON");
    caps.instruction_sets.push_back("AdvSIMD");

#ifdef __linux__
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_SVE) {
      caps.instruction_sets.push_back("SVE");
      caps.max_width_bytes = detect_sve_width();
    }
#endif

#elif defined(__arm__)
    caps.architecture = "ARM32";
    caps.cpu_name = "ARM32 Processor";
    caps.max_width_bytes = 16;

#ifdef __linux__
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_NEON) {
      caps.instruction_sets.push_back("NEON");
    }
#endif
#endif

    test_arm_operations(caps);
  }

  static void test_x86_operations(SIMDCapabilities &caps) {
#ifdef __AVX512F__
    try {
      __m512 test = _mm512_set1_ps(1.0f);
      __m512 result = _mm512_add_ps(test, test);
      (void)result; // Suppress unused variable warning
      caps.features["AVX512_functional"] = true;
    } catch (...) {
      caps.features["AVX512_functional"] = false;
    }
#endif

#ifdef __AVX2__
    try {
      __m256 test = _mm256_set1_ps(1.0f);
      __m256 result = _mm256_add_ps(test, test);
      (void)result;
      caps.features["AVX2_functional"] = true;
    } catch (...) {
      caps.features["AVX2_functional"] = false;
    }
#endif

#ifdef __AVX__
    try {
      __m256 test = _mm256_set1_ps(1.0f);
      __m256 result = _mm256_add_ps(test, test);
      (void)result;
      caps.features["AVX_functional"] = true;
    } catch (...) {
      caps.features["AVX_functional"] = false;
    }
#endif
  }

  static void test_arm_operations(SIMDCapabilities &caps) {
#ifdef __aarch64__
    try {
      float32x4_t test = vdupq_n_f32(1.0f);
      float32x4_t result = vaddq_f32(test, test);
      (void)result;
      caps.features["NEON_functional"] = true;
    } catch (...) {
      caps.features["NEON_functional"] = false;
    }
#endif
  }

  static std::string get_x86_cpu_name() {
    char brand[49] = {0};
    uint32_t *brand_ptr = reinterpret_cast<uint32_t *>(brand);

    for (int i = 0x80000002; i <= 0x80000004; ++i) {
      uint32_t eax, ebx, ecx, edx;
      cpuid(i, eax, ebx, ecx, edx);
      *brand_ptr++ = eax;
      *brand_ptr++ = ebx;
      *brand_ptr++ = ecx;
      *brand_ptr++ = edx;
    }

    std::string result(brand);
    // Trim whitespace
    size_t start = result.find_first_not_of(" \t");
    if (start != std::string::npos) {
      size_t end = result.find_last_not_of(" \t");
      return result.substr(start, end - start + 1);
    }
    return "Unknown CPU";
  }

  static int detect_sve_width() {
#ifdef __ARM_FEATURE_SVE
    return 32; // Conservative estimate
#else
    return 16;
#endif
  }
};

void print_capabilities(const SIMDCapabilities &caps) {
  std::cout << "=== Hardware SIMD Capabilities ===" << std::endl;
  std::cout << "Architecture: " << caps.architecture << std::endl;
  std::cout << "CPU: " << caps.cpu_name << std::endl;
  std::cout << std::endl;

  std::cout << "Maximum SIMD Width: " << caps.max_width_bytes << " bytes ("
            << (caps.max_width_bytes * 8) << " bits)" << std::endl;
  std::cout << std::endl;

  std::cout << "Available Instruction Sets:" << std::endl;
  for (const auto &inst : caps.instruction_sets) {
    std::cout << "  - " << inst << std::endl;
  }
  std::cout << std::endl;

  if (!caps.features.empty()) {
    std::cout << "Feature Tests:" << std::endl;
    for (const auto &[feature, supported] : caps.features) {
      std::cout << "  " << (supported ? "✓" : "✗") << " " << feature
                << std::endl;
    }
    std::cout << std::endl;
  }

  std::cout << "=== Performance Recommendations ===" << std::endl;
  if (caps.max_width_bytes >= 64) {
    std::cout << "• Use 512-bit vectors (16 floats) for optimal throughput"
              << std::endl;
    std::cout << "• Consider AVX-512 specific optimizations" << std::endl;
  } else if (caps.max_width_bytes >= 32) {
    std::cout << "• Use 256-bit vectors (8 floats) for optimal throughput"
              << std::endl;
    std::cout << "• AVX2 provides good balance of performance and compatibility"
              << std::endl;
  } else if (caps.max_width_bytes >= 16) {
    std::cout << "• Use 128-bit vectors (4 floats) for optimal throughput"
              << std::endl;
    std::cout << "• SSE/NEON provides universal compatibility" << std::endl;
  } else {
    std::cout << "• Limited SIMD support - consider scalar optimizations"
              << std::endl;
  }

  std::cout << std::endl << "FFT Optimization Recommendations:" << std::endl;
  int complex_per_vector = caps.max_width_bytes / 8;
  int floats_per_vector = caps.max_width_bytes / 4;

  std::cout << "• " << complex_per_vector << " complex numbers per vector"
            << std::endl;
  std::cout << "• " << floats_per_vector << " float32s per vector" << std::endl;

  if (complex_per_vector >= 4) {
    std::cout << "• Optimal for radix-4 or radix-8 FFT algorithms" << std::endl;
  } else if (complex_per_vector >= 2) {
    std::cout << "• Optimal for radix-2 or radix-4 FFT algorithms" << std::endl;
  }
}

// C API for Julia FFI
extern "C" {
int get_simd_width_bytes() { return SIMDDetector::detect().max_width_bytes; }

void print_simd_info() {
  auto caps = SIMDDetector::detect();
  print_capabilities(caps);
}
}

int main() {
  auto capabilities = SIMDDetector::detect();
  print_capabilities(capabilities);
  return 0;
}

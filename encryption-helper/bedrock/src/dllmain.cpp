#include "MinHook.h"
#include "libhat.hpp" // IWYU pragma: keep
#include <cstdio>

struct EVP_CIPHER_CTX;
struct ENGINE;
struct EVP_CIPHER {
  int nid;
  /*other members...*/
};

int (*ORIGINAL_EVP_EncryptInit_ex)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                                   ENGINE *impl, const unsigned char *key,
                                   const unsigned char *iv, int enc);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv, int enc) {
  if (key && type &&
      (type->nid == 901 /*aes_256_gcm*/ || type->nid == 655 /*aes_256_cfb8*/)) {
    std::printf("nid: %d\n", type->nid);
    for (auto i = 0uz; i < 32; i++) {
      std::printf("%s ", std::to_string(key[i]).c_str());
    }
    std::puts("");
  }

  return ORIGINAL_EVP_EncryptInit_ex(ctx, type, impl, key, iv, enc);
}

void init() {
  using namespace hat::literals::signature_literals;
  auto mc = hat::process::get_process_module();
  MH_Initialize();
  if (auto target =
          hat::find_pattern(
              mc.get_module_data(),
              "48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 54 41 56 41 57 B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 8B 44 24"_sig)
              .get()) {
    MH_CreateHook(target, reinterpret_cast<void *>(&EVP_EncryptInit_ex),
                  reinterpret_cast<void **>(&ORIGINAL_EVP_EncryptInit_ex));
    std::printf("hooked EVP_EncryptInit_ex() at %p\n", target);
  } else {
    std::puts("fail to look up pattern for EVP_EncryptInit_ex()");
  }
  MH_EnableHook(MH_ALL_HOOKS);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
  switch (reason) {
  case DLL_PROCESS_ATTACH:
    init();
    break;
  }
  return TRUE;
}

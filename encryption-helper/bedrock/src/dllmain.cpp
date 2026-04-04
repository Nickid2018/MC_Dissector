#include <Windows.h>
#include <blook/blook.h>
#include <cassert>
#include <string>

struct EVP_CIPHER_CTX;
struct ENGINE;
struct EVP_CIPHER {
  int nid;
  /*other members...*/
};

namespace {

constexpr int NID_AES_256_GCM = 901;
constexpr int NID_AES_256_CFB8 = 655;
constexpr char kAssertNeedle[] =
    "assertion failed: ctx->cipher->block_size == 1 || ctx->cipher->block_size "
    "== 8 || ctx->cipher->block_size == 16";

void EnsureConsole() {
  if (!GetConsoleWindow()) {
    AllocConsole();
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
  }
}

void LogKeyIfInteresting(const EVP_CIPHER *type, const unsigned char *key) {
  if (!type || !key)
    return;
  if (type->nid != NID_AES_256_GCM && type->nid != NID_AES_256_CFB8)
    return;

  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  std::string out;
  out += "nid: " + std::to_string(type->nid) + "\n";
  for (size_t i = 0; i < 32; ++i) {
    out += std::to_string(static_cast<int>(key[i]));
    out += (i + 1 == 32) ? '\n' : ' ';
  }
  WriteConsoleA(h, out.c_str(), static_cast<DWORD>(out.size()), nullptr,
                nullptr);
}

} // namespace

void init() {
  EnsureConsole();

  auto mod = blook::Process::self()->process_module();
  if (!mod) {
    assert(false && "fail to get process module");
    return;
  }

  auto rdata = (*mod)->section(".rdata");
  if (!rdata) {
    assert(false && "fail to get section .rdata");
    return;
  }

  auto ptr = (*rdata).find_one(kAssertNeedle);
  if (!ptr) {
    assert(false && "fail to find string");
    return;
  }

  auto text = (*mod)->section(".text");
  if (!text) {
    assert(false && "fail to get section .text");
    return;
  }

  auto xref = (*text).find_xref(*ptr);
  if (!xref) {
    assert(false && "fail to find xref");
    return;
  }

  if (auto func = (*xref).guess_function()) {
    auto hooked = (*func).inline_hook();
    hooked->install([hooked](EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                             ENGINE *impl, const unsigned char *key,
                             const unsigned char *iv, int enc) -> int {
      LogKeyIfInteresting(type, key);
      return hooked->call_trampoline<int>(ctx, type, impl, key, iv, enc);
    });
  } else {
    assert(false && "fail to guess function");
  }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
  switch (reason) {
  case DLL_PROCESS_ATTACH:
    init();
    break;
  default:
    break;
  }
  return TRUE;
}

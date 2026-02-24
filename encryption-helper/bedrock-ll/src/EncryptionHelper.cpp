#pragma once

#include <format>
#include <sstream>

#include "ll/api/io/LoggerRegistry.h"
#include "ll/api/memory/Hook.h"
#include "ll/api/mod/RegisterHelper.h"
#include "mc/network/EncryptedNetworkPeer.h"

#include "EncryptionHelper.h"

namespace encryption_helper {

auto logger = ll::io::LoggerRegistry::getInstance().getOrCreate("EncryptionHelper");

LL_AUTO_TYPE_INSTANCE_HOOK(
    EncryptedNetworkPeerHook,
    ll::memory::HookPriority::Normal,
    EncryptedNetworkPeer,
    &EncryptedNetworkPeer::enableEncryption,
    void,
    std::string const& symmetricKey
) {
    std::stringstream ss;
    for (const char c : symmetricKey) {
        ss << std::format("{:02x}", c);
    }
    logger->info(ss.str());
    origin(symmetricKey);
}

EncryptionHelper& EncryptionHelper::getInstance() {
    static EncryptionHelper instance;
    return instance;
}

bool EncryptionHelper::load() {
    getSelf().getLogger().debug("Loading...");
    // Code for loading the mod goes here.
    return true;
}

bool EncryptionHelper::enable() {
    getSelf().getLogger().debug("Enabling...");
    // Code for enabling the mod goes here.
    return true;
}

bool EncryptionHelper::disable() {
    getSelf().getLogger().debug("Disabling...");
    // Code for disabling the mod goes here.
    return true;
}

} // namespace encryption_helper

LL_REGISTER_MOD(encryption_helper::EncryptionHelper, encryption_helper::EncryptionHelper::getInstance());
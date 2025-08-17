English | [简体中文](./README-zh_CN.MD)

# Minecraft Protocol Dissector

[![AUR Version](https://img.shields.io/aur/version/wireshark-minecraft-dissector)](https://aur.archlinux.org/packages/wireshark-minecraft-dissector/)
![GitHub](https://img.shields.io/github/license/Nickid2018/MC_Dissector)
![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/Nickid2018/MC_Dissector/ci.yml)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/Nickid2018/MC_Dissector)
[![wakatime](https://wakatime.com/badge/user/74cf9ef2-54ee-470f-a4ae-03e46a1e3c77/project/07a6974f-bdb4-40ce-98f1-f16c123aa610.svg)](https://wakatime.com/badge/user/74cf9ef2-54ee-470f-a4ae-03e46a1e3c77/project/07a6974f-bdb4-40ce-98f1-f16c123aa610)

## How To Use?

Built files can be found in Actions, a stable version can be found in Release.

After downloading:

For Windows,
put file `mcdissector.dll` into dissector directory of Wireshark (`plugins/<Wireshark Version>/epan`) and run Wireshark.

For Linux, please make `cjson` installed,
then put file `mcdissector.so` into dissector directory of Wireshark
(`~/.local/lib/wireshark/plugins/<Wireshark Version>/epan`) and run Wireshark.

For Arch Linux, you can directly use package `wireshark-minecraft-dissector` in AUR.

## Tunable Options

`Minecraft` can be found in `Preferences/Protocols` in Wireshark, where you can adjust some options here.

* `Directory for protocol data`: The directory for protocol data, used to parse data.
* `Ignore Packets`: Prevent parsing some packets to filter unwanted information. The format is commas-separated list of `<s|c>:<packet_name>`. `s` represents packets sent to server, `c` represents packets sent to the client. The default is an empty string. We recommend to use `c:level_chunk,c:level_chunk_with_light` for this option.
* `Key Log File`：Path to the file for logging keys.
* `Secret Key`: To realize encrypted connection among keys for decrypting data. The format is in hexadecimal strings with a length of 32.
* `NBT Decoding`: To decode NBT data.
* `TCP Port(s)`: To change TCP ports used by MCJE protocol to identify protocol.

## Protocol Data

All protocol data is read from external directory, which is controlled by option `Directory for protocol data`.

You can directly use protocol data provided by [MC_Protocol_Data](https://github.com/Nickid2018/MC_Protocol_Data).
You can use the source code archives of the repository or clone the repository to the specified protocol directory.

## Encrypted Connection

If you enter Minecraft servers in a legitimated game client,
encrypted connection will be built between server and client base on `AES/CFB8/NoPadding` algorithm.
This step will execute before compression during login.
All data in the connection will be encrypted, including data length fields used to spilt data.

To get data in encrypted connection,
we need to know what the key is with the help of `encryption-helper` in the project.
By using the feature that client executed the generation of symmetric encrypted keys,
it can force the client to use a specified key instead create a random one,
or log the current key to a file for Wireshark to read.

`encryption-helper` is a Java Agent injects executive code dynamically when running Minecraft. It needs JVM parameters as follows to attach to a Minecraft client:

```shell
-javaagent:<jarfile path>[=<key>]
```

If no key is specified,
it will log the key to a file specified by environment variable `MINECRAFT_KEY_LOG_FILE` when joining a server.
Each line in the file contains a challenge and the corresponding key, separated by a space.
The challenge is the `challenge` field in the `key` packet sent from server to client during login,
which can be used as a unique identifier for the connection.
When using Wireshark,
you need to set the preference `Key Log File` to the same path as the environment variable `MINECRAFT_KEY_LOG_FILE` of the running game,
so that Wireshark can read the key immediately to track the TCP stream and parse the entire encrypted connection.

If a key is specified, it will force the encrypted connection to use this key instead of generating a random one.
The key is a hexadecimal string only contains 0-F with length of 32.
If the input format is incorrect, it will crash immediately and throw an error when starting the client.

`encryption-helper` can theoretically run on all unobfuscated and obfuscated injectable clients,
because it locates the injection point only by the following features that will not be obfuscated:
- For the case without specifying a key, the program will search for an injection point with the following features:
    * The method is a constructor.
    * The method has the descriptor `(Ljavax/crypto/SecretKey;Ljava/security/PublicKey;[B)V`.
    * This injection point usually represents `net.minecraft.network.protocol.login.ServerboundKeyPacket#<init>`.
- For the case with specifying a key, the program will search for an injection point with the following features:
    * The method is a constructor.
    * The method has the descriptor `(Ljavax/crypto/SecretKey;Ljava/security/PublicKey;[B)V`.
    * This injection point usually represents `net.minecraft.network.protocol.login.ServerboundKeyPacket#<init>`.

The vast majority of the time, these injection points are **stable**, meaning they will not be modified by mods,
so this injection can work in most cases, including vanilla clients,
clients with unknown obfuscation mappings, and mod loaders like Fabric/Forge/NeoForge.

## Parsing Errors

Parsing error exists under 2 circumstances as follows:

* Wireshark failed to capture all data. Since the Java Edition uses TCP, data is spilt by length field, and once missing any segment, data will be unparsable immediately. You can confirm this circumstance if you have discovered `TCP Previous segment not captured` near the data parsing error.
* The program has not finished adaption or process properly for this part, or has not added corresponding strings. Such errors can be reported by open issues.

All protocol data is generated by `MC_Protocol_Data`, so if you have any questions about the data, you can open an issue in the repository.

## How To Build Projects (Windows)

Building this project requires Wireshark source code with configured dependencies.

1. Clone Wireshark repository to local and configure necessary dependencies.
2. Set environment variable `PLATFORM` as `x64`, and `WIRESHARK_LIB_DIR` as directory of dependency libraries for Wireshark (automatically created at running cmake).
3. Create `build` in same directory of Wireshark source codes, and run `cmake -A x64 .. -DBUILD_wireshark=OFF` in `build`.
4. Still in `build`, run `cmake --build . --config RelWithDebInfo --target epan`.
5. Set environment variable `WIRESHARK_DIR` (directory of Wireshark source code), `WIRESHARK_BUILD_DIR` (path of directory `build`) and `WIRESHARK_LIB_FILE_DIR` (path of directory `RelWithDebInfo` generated by building the project).
6. Run `cmake -S . -G Ninja -B build` in project root directory.
7. Run `cmake --build build --target MC_Dissector` in project root directory.
8. Built file can be discovered in "build" directory.

## How To Build Projects (Linux)

It is much easier to build on Linux, read ci.yml for details. (Too lazy to write here.)

## Current Plans

- [x] Almost complete! (Crash free, at least!）
- [x] Linux support by @xtexChooser
- [x] Support encryption. (It should be OK!)
- [x] Version compatibility.
- [ ] Support bedrock edition.

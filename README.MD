English | [简体中文](./README-zh_CN.MD)

# Minecraft Protocol Dissector

![GitHub](https://img.shields.io/github/license/Nickid2018/MC_Dissector)
![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/Nickid2018/MC_Dissector/ci.yml)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/Nickid2018/MC_Dissector)
[![wakatime](https://wakatime.com/badge/user/74cf9ef2-54ee-470f-a4ae-03e46a1e3c77/project/07a6974f-bdb4-40ce-98f1-f16c123aa610.svg)](https://wakatime.com/badge/user/74cf9ef2-54ee-470f-a4ae-03e46a1e3c77/project/07a6974f-bdb4-40ce-98f1-f16c123aa610)

## How To Use?

Built files can be found in Actions, stable version can be found in Release.

For each platform there are 2 different versions with and without additional parse function (`No Function`). Additional parse function can parse entity ID and synchronize protocol data etc.

After downloading:

For Windows, put file `mcdissector.dll` into dissector directory of Wireshark (`plugins/4.0/epan`) and run Wireshark.

For Linux, put file `mcdissector.so` into dissector directory of Wireshark (`~/.local/lib/wireshark/plugins/4.0/epan`) and run Wireshark.

## Tunable Options

`MCJE` can be found in `Preferences/Protocols` in Wireshark, where you can adjust some options here.

* Ignore Packets: Prevent parsing some packets to filt unwanted information. The format is commas-separated list of `<s|c>:<packet_name>`. `s` represents packets sent to server, `c` represents packets sent to client.The default is `c:map_chunk` which stops parsing server-to-client chunk data packets, since to parse such packets will spend extra long time and produce excess data fields.
* Secret Key: To realize encrypted connection among keys for decrypting data. The format is in hexademical strings with length of 32.
* TCP Port(s): To change TCP ports used by MCJE protocol to identify protocol.

## Encrypted Connection

If you enter Minecraft servers in legitimated game client, encrypted connection will be built between server and client base on `AES/CFB8/NoPadding` algorithm.
This step will execute before compression during login. All data in the connection will be encrypted, including data length fields used to spilt data.

To listen data in encrypted connection, we need to know what the key is with the help of `encryption-helper` in the project.
By using the feature that the generation of symmetric encrypted keys was executed by client, it forced client to use a specified key, instead create a random one.

`encryption-helper` is a Java Agent injects executive code dynamically when running Minecraft. It needs JVM parameters as follow to attach to a Minecraft client:

```shell
-javaagent:<jarfile path>=<key>
```

The key is a hexademical string only contains 0-F with length of 32. If the input format is incorrect, it will crash immediately and throw an error when starting client.

Theoretically, `encryption-helper` can run in all unobfuscated and obfuscated injectable clients, since the injection points it locates only contain features could not be obfuscated as follow:

* Method return value is `javax.crypto.SecretKey`.
* Method has no parameter.
* The type of the first local variable of the method is `javax.crypto.KeyGenerator`.

Very few mods modify logics here, so it's safe for the program to modify. It should not conflict with mods.

Only a single circumstance will disable the program: Mods have modified encryption logics here and resulted in failure in call to replace keys, but that kind of protocol is out of the scope of our program's use.

## Parsing Errors

Parsing error exists under 2 circumstances as follow:

* Wireshark failed to capture all data. Since Java edition uses TCP, data is spilt by length field, and once missing any segment, data will be unparsable immediately. You can confirm this circumstance if you have discovered error `TCP Previous segment not captured` near the data parsing error.
* The program has not finished adaption or process properly for this part, or has not added corresponding strings. Such errors can be reported by open issues.

The overall protocol is dynamically built by protocol description file in `minecraft-data`. If you are convinced that error is caused by fault in protocol description, you can open an issue in `minecraft-data` repository.

## How To Build Projects (Windows)

Building this project needs support from source code of Wireshark and dependency configuration, and python is needed for code generation.

1. Clone Wireshark repository to local and configure necessary dependencies.
2. Set environment variable `PLATFORM` as `x64`, and `WIRESHARK_LIB_DIR` as directory of dependency library of Wireshark (automatically created at running cmake).
3. Create `build` in same directory of Wireshark source codes, and run `cmake -A x64 .. -DBUILD_wireshark=OFF` in "build".
4. Still in "build", run `cmake --build . --config RelWithDebInfo --target epan`.
5. Set environment variable `WIRESHARK_DIR` (directory of Wireshark source code), `WIRESHARK_BUILD_DIR` (path of directory of "build") and `WIRESHARK_LIB_FILE_DIR` (path of directory of RelWithDebInfo generated by building the project).
6. Run `cmake -S . -G Ninja -B build` in project root directory.
7. Run `cmake --build build --target MC_Dissector` in project root directory.
8. Built file can be discovered in "build" directory.

## How To Build Projects (Linux)

It is much easier to build on Linux, read ci.yml for details. (Too lazy to write here)

## Current Plans

- [x] Almost complete! (Crash free, at least!）
- [x] Linux support by @xtexChooser
- [x] Support encryption. (It should be OK!)
- [ ] Version compatibility.
- [ ] Support bedrock edition.

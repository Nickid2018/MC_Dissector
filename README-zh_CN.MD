[English](./README.MD) | 简体中文

# Minecraft 协议解析器

[![AUR Version](https://img.shields.io/aur/version/wireshark-minecraft-dissector)](https://aur.archlinux.org/packages/wireshark-minecraft-dissector/)
![GitHub](https://img.shields.io/github/license/Nickid2018/MC_Dissector)
![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/Nickid2018/MC_Dissector/ci.yml)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/Nickid2018/MC_Dissector)
[![wakatime](https://wakatime.com/badge/user/74cf9ef2-54ee-470f-a4ae-03e46a1e3c77/project/07a6974f-bdb4-40ce-98f1-f16c123aa610.svg)](https://wakatime.com/badge/user/74cf9ef2-54ee-470f-a4ae-03e46a1e3c77/project/07a6974f-bdb4-40ce-98f1-f16c123aa610)

## 使用方法

构建的文件可以在 Action 里面找到，稳定版可以在 Release 里面找到。

Windows 下载后把`mcdissector.dll`文件放入 Wireshark 的解析器目录（`plugins/<Wireshark版本>/epan`）并启动 Wireshark 即可。

Linux 需要确保安装`cjson`，下载构建文件后把`mcdissector.so`文件放入 Wireshark 的解析器目录（`~/.local/lib/wireshark/plugins/<Wireshark版本>/epan`）并启动 Wireshark 即可。

对于 Arch Linux，可以直接使用 AUR 里面的`wireshark-minecraft-dissector`包。

## 可调选项

可以在 Wireshark 的`首选项/Protocols`里面找到`Minecraft`，在这里可以调整一些选项。

* `Directory for protocol data`：放置协议数据的目录，用于解析数据。
* `MCJE`中包含下列选项：
  * `Ignore Packets`：阻止解析一些包，用于过滤不需要的信息。格式为以`<s|c>:<packet_name>`组成的以逗号分割的列表，其中`s`
    代表发向服务端的包，`c`代表发向客户端的包。默认为空。推荐设置为`c:level_chunk,c:level_chunk_with_light`。
  * `Key Log File`：用于记录密钥的文件路径。
  * `Secret Key`：用于加密连接解密数据的密钥，格式为 32 长度的 16 进制字符串。
    如果`Key Log File`不存在或者密钥记录文件内不存在与当前加密连接对应的密钥，程序将自动使用此密钥进行解密。
  * `NBT Decoding`：是否解析 NBT 数据。
  * `TCP Port(s)`：更改 MCJE 协议使用的 TCP 端口，用于识别协议。
* `MCBE`中包含下列选项 (WIP)：
  * `NBT Decoding`：是否解析 NBT 数据。
  * `Secret Key`：用于加密连接解密数据的密钥，格式为 32 长度的 16 进制字符串。

请注意，如果需要使用`MCBE`解析，则必须将 Wireshark 中内置提供的`MCPE`端口设置为非0-65535的值，否则解析程序会因为冲突而丢失首包数据，造成逻辑端检测错误。

## 协议数据

所有协议数据都从外部目录读取，此目录由选项`Directory for protocol data`控制。

可以直接使用[MC_Protocol_Data](https://github.com/Nickid2018/MC_Protocol_Data)提供的协议数据，直接使用源代码压缩包或者克隆仓库到指定协议目录即可。

## 加密连接（Java版）

如果你使用了正版进入 Minecraft 服务器，则客户端和服务端之间会使用`AES/CFB8/NoPadding`算法建立加密连接。
此步骤在登录阶段压缩前执行，整个连接内的数据都会被加密，包括拆分数据的数据长度字段。

为了能监听加密连接内的数据，我们必须知道密钥是什么。项目内的`encryption-helper`可以做到这点，
它利用对称加密的密钥由客户端执行生成这一特点，在客户端创建密钥时强制替换为指定的密钥而不是生成随机密钥，
或将当前的密钥记录在文件中以供Wireshark读取。

`encryption-helper`是一个 Java Agent，在 Minecraft 运行时动态注入执行代码。它需要用下面的 JVM 参数附加到一个 Minecraft
客户端中：

```shell
-javaagent:<文件位置>[=<密钥>]
```

如果不指定密钥，在游戏加入服务器时会自动向环境变量`MINECRAFT_KEY_LOG_FILE`指定的文件中记录密钥。
此文件的每一行都包含了一个挑战（Challenge）和对应的密钥，以空格分割。
挑战是在登录阶段由服务端发送到客户端的`key`包中的`challenge`字段，可以作为此连接的唯一标识。
使用Wireshark时，需要将首选项`Key Log File`设置为运行游戏的环境变量`MINECRAFT_KEY_LOG_FILE`相同的路径，
这样Wireshark就可以立刻读取密钥从而追踪 TCP 流解析整个加密连接。

如果指定了密钥，则会指定加密连接强制使用此密钥而不是生成随机密钥。
此密钥需要是一个 32 长度的 16 进制字符串，如果输入格式错误，在启动客户端时会立刻报错崩溃。

`encryption-helper`理论上可以运行在所有未混淆和混淆的可注入客户端中，因为它定位的注入点只包含下列不会被混淆的特征：

- 对于不指定密钥的情况，程序将搜索下列特征的注入点：
    * 方法是构造函数。
    * 方法具有下列描述符`(Ljavax/crypto/SecretKey;Ljava/security/PublicKey;[B)V`。
    * 此注入点通常代表了`net.minecraft.network.protocol.login.ServerboundKeyPacket#<init>`。
- 对于指定密钥的情况，程序将搜索下列特征的注入点：
    * 方法返回值为`javax.crypto.SecretKey`。
    * 方法没有参数。
    * 方法的第一个局部变量类型为`javax.crypto.KeyGenerator`。
    * 此注入点通常代表了`net.minecraft.util.Crypt#generateSecretKey`。

绝大多数情况下，这些注入点都是**稳定**的，即不会被模组修改，
因此此注入可以在大多数情况下（包括原版、未知混淆表的客户端、Fabric/Forge/NeoForge等模组加载器）正常工作。

## 加密连接（基岩版）

对于基岩版，所有连接均被加密，因此必须使用 DLL 注入或者模组获取客户端与服务端的对称加密密钥。

目前此仓库提供了两种方式获取密钥：
* 使用 [LeviLamina](https://github.com/LiteLDev/LeviLamina) 加载模组。
  模组文件为`encryption-helper-bedrock-ll.zip`，需要按照 LeviLamina 文档进行正确安装。
* 使用通用获取密钥 DLL 对程序进行注入，相关文件为`encryption-helper.dll`。
  本仓库未提供 DLL 注入器，需要其他注入器提供注入操作。

使用 LeviLamina 能准确获取每次连接的密钥，从程序日志中找到`EncryptionHelper`记录就可以获取到密钥。
此方法虽然高效，但因为 LeviLamina 在`1.21.124.2`后才支持客户端模组，更旧的版本无法使用，这种情况下请使用通用获取密钥 DLL 注入。

使用通用获取密钥 DLL 会产生多条密钥记录，这是因为程序 hook 的函数并不止有加密连接会使用。使用此方法需要按照下列方法获取密钥：
1. 使用 DLL 注入器将此 DLL 注入到基岩版客户端程序中。
2. 检查控制台输出。在进入服务器前的所有信息均可忽略，只需要检查进入服务器开始时的控制台输出。
3. 所有输出均按照下列格式：`[Key Candidate] [GCM/CFB8] <32长度的16进制字符串>`。
   对于协议版本不大于 431 的基岩版版本（`1.16.221`），只需要查看`CFB8`的行；反之，只查看`GCM`的行。
4. 将查找到的每一条密钥填入`Secret Key`中，直到过滤为`MCBE`的包不再提醒为`Invalid`。

目前的方式只能手动查找并比对密钥正确性，在之后的版本中可能会加入与 JE 一样的密钥日志文件方式。

## 解析错误

如果出现了解析错误，可能有下面两种情况：

* Wireshark 没有抓取到所有数据。由于 Java 版使用 TCP，数据由长度字段拆分，一旦缺少某一部分，
  数据就会立刻无法解析。如果你在数据解析错误的前后发现了`TCP Previous segment not captured`，那么就是这种情况。
* 程序还没有做好这部分的适配或相应的处理，或没有添加对应的字符串。这类错误可以在 Issues 里面提出来。

协议整体由`MC_Protocol_Data`内的协议描述文件动态构建，如果你确信是因为协议描述出现问题而导致错误，可以在`MC_Protocol_Data`
仓库里面提出 Issue。

## 构建项目（Windows）

构建此项目需要有 Wireshark 的源码并需要配置依赖。

1. 克隆 Wireshark 仓库到本地，配置好需要的依赖。
2. 指定环境变量`PLATFORM`为`x64`，指定环境变量`WIRESHARK_LIB_DIR`为 Wireshark 依赖库目录（运行 cmake 时会自动创建）。
3. 在 Wireshark 源码同级目录创建`build`，在 build 中运行`cmake -A x64 .. -DBUILD_wireshark=OFF`。
4. 仍然在 build 中，运行`cmake --build . --config RelWithDebInfo --target epan`。
5. 指定环境变量`WIRESHARK_DIR`（Wireshark 源码目录）、`WIRESHARK_BUILD_DIR`（build 目录位置）、`WIRESHARK_LIB_FILE_DIR`（构建产生的
   RelWithDebInfo 目录位置）。
6. 在项目根目录运行`cmake -S . -G Ninja -B build`。
7. 在项目根目录运行`cmake --build build --target MC_Dissector`。
8. 在 build 目录里面能看到构建出来的文件。

## 构建项目（Linux）

需要在系统包管理中安装相应库（例如，`ubuntu`下的`libwireshark-dev`，`libcjson-dev`），并确保有`cmake`构建工具即可直接使用`cmake`编译。

## 许可证

本项目绝大多数源码均使用 GPL-2.0 许可证。基岩版通用获取密钥 DLL 代码使用 GPL-3.0 许可证。

更多信息请参考 [LICENSE](./LICENSE) 及 [LICENSE.GPL-3.0](./LICENSE.GPL-3.0) 文件。

## 致谢

* 由 @xtexChooser 实现了本项目对 Linux 的构建支持。
* 由 @killcerr 实现了基岩版通用获取密钥 DLL。
* 由 @123Duo3 及 @ArchieMackenzie 提供的自述文件英文翻译。
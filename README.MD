## Minecraft 协议解析器
![GitHub](https://img.shields.io/github/license/Nickid2018/MC_Dissector)
![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/Nickid2018/MC_Dissector/ci.yml)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/Nickid2018/MC_Dissector)

### 使用方法
构建的文件可以在 Action 里面找到，稳定版可以在 Release 里面找到。

下载后把`mcdissector.dll`文件放入 Wireshark 的解析器目录（`plugins/4.0/epan`）并启动 Wireshark 即可。

### 可调选项
可以在 Wireshark 的`首选项/Protocols`里面找到`MCJE`，在这里可以调整一些选项。
* Ignore Packets：阻止解析一些包，用于过滤不需要的信息。格式为以`<s|c>:<packet_name>`组成的以逗号分割的列表，其中`s`代表发向服务端的包，`c`代表发向客户端的包。默认为`c:map_chunk`，即停止解析服务端发向客户端的区块数据包，这种类型的包会使解析器消耗很长时间，并且会产生过量的数据字段，所以默认禁用。
* TCP Port(s)：更改 MCJE 协议使用的 TCP 端口，用于识别协议。

### 构建项目（Windows）
构建此项目需要有 Wireshark 的源码并需要配置依赖，且需要 python 用于代码生成。

1. 克隆 Wireshark 仓库到本地，配置好需要的依赖。
2. 指定环境变量`PLATFORM`为`x64`，指定环境变量`WIRESHARK_BASE_DIR`为 Wireshark 依赖库目录（运行 cmake 时会自动创建）。
3. 在 Wireshark 源码同级目录创建`build`，在 build 中运行`cmake -A x64 .. -DBUILD_wireshark=OFF`。
4. 仍然在 build 中，运行`cmake --build . --config RelWithDebInfo --target epan`。
5. 指定环境变量`GLIB_DIR`（glib2 位置，默认在 Wireshark 依赖库目录里面）、`WIRESHARK_DIR`（Wireshark 源码目录）、`WIRESHARK_BUILD_DIR`（build 目录位置）、`WIRESHARK_DIR_LIB`（构建产生的 RelWithDebInfo 目录位置）、`WIRESHARK_LIB`（wireshark.lib 位置）和`WSUTIL_LIB`（wsutil.lib 位置）。
6. 在项目根目录运行`cmake -S . -G Ninja -B build`。
7. 在项目根目录运行`cmake --build build --target MC_Dissector`。
8. 在 build 目录里面能看到构建出来的文件。

### 构建项目（Linux）
在 Linux 上构建要简单的多，具体看 ci.yml 就行（懒得写）。

### 解析错误
如果出现了解析错误，可能是因为还没有做好这部分的适配或相应的处理，可以在 Issues 里面提出来。

协议整体由`minecraft-data`内的协议描述文件动态构建，如果你确信是因为协议描述出现问题而导致错误，可以在`minecraft-data`仓库里面提出 Issue。

有些错误是由于缺少对应的字符串定义，这些错误可以直接在 Issues 内提出。

### 当前计划
- [x] 写的差不多了！（至少不炸了！）
- [x] linux 支持 by @xtexChooser
- [ ] 版本兼容性。
- [ ] 支持基岩版。
- [ ] 支持加密。
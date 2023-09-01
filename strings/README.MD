这个目录是程序内部使用的字符串定义文件目录，用于定义协议描述文件内的字段的显示名称、显示格式等。如果字符串缺失或错误，在最终显示时可能会发生异常。

## 添加字符串

JSON 文件按照以下格式定义：

* `hf_defines`：定义基础字段。
* `mappings`：定义字段与协议描述文件字段的映射。
* `bitmask_collection`：定义位掩码。
* `value_mappings`：定义数据与字符串的映射。
* `component_names`：定义协议描述组件名称。
* `packet_names`：定义协议描述包名称。

### 定义基础字段

如果一个协议描述文件之中的字段类型为基础类型（如`varint`，`string`等）或为`buffer`、`mapping`、`bitfield`
内的字段、`switch`中的以上列类型作为值的项或带有上列类型作为附加参数的`option`
，则这个字段要求写入`hf_defines`。`hf_defines`内元素的定义如下：

* `name`：字段描述，用于展示这个字段的实际用途。
* `type`：字段类型。字段类型名称和协议描述文件内的字段类型名称不完全一致，下方为对照表。

|  协议描述文件内字段类型  |  字段类型名称  |
|:-------------:|:--------:|
|   `varint`    |  `u32`   |
|   `varlong`   |  `u64`   |
|  `optvarint`  |  `u32`   |
|   `buffer`    | `bytes`  |
|    `UUID`     |  `uuid`  |
| `restBuffer`  | `bytes`  |
|     `nbt`     | `bytes`  |
| `optionalNbt` | `bytes`  |
|   `string`    | `string` |
|     其他类型      |   名称相同   |

* `display`：字段显示格式，可选，可以为`DEC`、`HEX`等。如果字段类型和显示格式无法对应则编译出的插件加载时会直接报错。
* `bitamsk`：如果字段是在`bitfield`内定义的，它还必须附加位掩码的信息，以16进制数字写入，不带`0x`。
* `value_mapping`：定义字段内值与显示值的映射，可以不存在。这些值要在`value_mappings`内定义，键为字段的值，值为映射后显示的值。

协议描述字段和定义字段需要使用`mappings`绑定，其值为定义字段的名称，键为**协议字段路径**。协议字段路径的定义如下：

* 协议字段路径是按照后缀查找的，即`a/b/c`会先查找`a/b/c`，如果不存在则查找`b/c`，如果还不存在则查找`c`。
* 路径的节点名称为每一层`container`或`bitfield`定义的名称，如果对应字段没有写`name`则为`[unnamed]`。
* 如果字段的类型引用其他非基本类型，则需要在整个路径的最后再添加上一个`/<type>`，其中`<type>`为非基本类型的名称。
* 如果字段在`switch`内（父节点在`switch`内也算），则可以指定`switch`分支，只需要在整个路径后面加上`[<case>]`，其中`case`
  为分支名称。
* 对于`packet_`开头的根节点，其`packet_`需要被省略。

以`slot`举例：

```json
{
  "slot": [
    "container",
    [
      {
        "name": "present",
        "type": "bool"
      },
      {
        "anon": true,
        "type": [
          "switch",
          {
            "compareTo": "present",
            "fields": {
              "false": "void",
              "true": [
                "container",
                [
                  {
                    "name": "itemId",
                    "type": "varint"
                  },
                  {
                    "name": "itemCount",
                    "type": "i8"
                  },
                  {
                    "name": "nbtData",
                    "type": "optionalNbt"
                  }
                ]
              ]
            }
          }
        ]
      }
    ]
  ]
}
```

`slot`内部共有4个基础字段和1个组件（`container`），分别为：

* `slot/present`
* `slot/[unnamed]/itemId`（或`slot/[unnamed]/itemId[true]`）
* `slot/[unnamed]/itemCount`（或`slot/[unnamed]/itemCount[true]`）
* `slot/[unnamed]/nbtData`（或`slot/[unnamed]/nbtData[true]`）
* `slot/[unnamed]`

再以`packet_set_slot`为例：

```json
{
  "packet_set_slot": [
    "container",
    [
      {
        "name": "windowId",
        "type": "i8"
      },
      {
        "name": "stateId",
        "type": "varint"
      },
      {
        "name": "slot",
        "type": "i16"
      },
      {
        "name": "item",
        "type": "slot"
      }
    ]
  ]
}
```

`packet_set_slot`内部共有3个基础字段和1个组件（`slot`），分别为：

* `set_slot/windowId`
* `set_slot/stateId`
* `set_slot/slot`
* `set_slot/item/slot`

### 定义位掩码字段

如果一个字段的类型是`bitfield`，则它需要在`bitmask_collection`内定义，名称的格式为`([<bitsize>]<name>)+`，其中`bitsize`
为位数，`name`为名称，必须按照顺序定义。例如22位的`x`、22位的`z`和20位的`y`定义为`[22]x[22]z[20]y`
。值为一个列表，按照顺序填写上文中定义的基础字段，如果位置上没有定义基础字段则置为`null`。

以`[6]unused[1]max_present[1]min_present`举例：

```json
[
  "bitfield",
  [
    {
      "name": "unused",
      "size": 6,
      "signed": false
    },
    {
      "name": "max_present",
      "size": 1,
      "signed": false
    },
    {
      "name": "min_present",
      "size": 1,
      "signed": false
    }
  ]
]
```

对应的定义为：

```json
{
  "[6]unused[1]max_present[1]min_present": [
    null,
    "max_present_1",
    "min_present_1"
  ]
}
```

### 定义组件

如果一个字段的类型是`container`、`array`或其他非基础类型，它就属于组件，应该在`component_names`内定义。其键为协议字段路径，值为名称。
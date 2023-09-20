This directory is a string definition file directory for program internal use to define display name and display format of fields in protocol description file. If there are strings missing or containing errors, displaying exception can exist in final displaying.

## To Add Strings

JSON files should be defined basing on formats as follow:

* `hf_defines`：To define basic fields.
* `mappings`：To define mapping between fields and protocol description file fields.
* `bitmask_collection`：To define bitmasks.
* `value_mappings`：To define mapping between data and strings.
* `component_names`：To define names of protocol define components.
* `packet_names`：To define names of protocol define packets.

### To Define Basic Fields

If the fields in a protocol description file are: 1. Basic ones（for example `varint`，`string`; 2. Fields in `buffer`、`mapping`、`bitfield`; 3. Items with types mentioned upon as values in `switch`; 4. `option` with types mentioned upon as additional parameters; `hf_defines` should be wrote into the field. Definition of elements in `hf_defines` are as follow:

* `name`：Field description, to display real usage of the field.
* `type`：Field type. Field type names are not full equivalences of field types in protocol description files. Comparison table is as follow:

|  Field type in protocol description files  |  Field type names  |
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
|     Other types      |   Identical   |

* `display`：Format of field displaying, optional, can be `DEC`, `HEX` etc., If field types cannot correspond to its displaying format, crash will be reported when loading complied plugins.
* `bitmask`：If fields were defined in `bitfield`, it needs additional information of bitmasks written in hexademical numbers without `0x`.
* `value_mapping`：To define mappings between values and displaying values in the fields. These values should be defined in `value_mappings`. Keys are values of fields, values are values display after mapping.

Protocol description fields and definition fields should be bound by using `mappings`, values are names of defined fields, keys are **paths of protocol fields**. Definitions of path of protocol fields are as follow:

* Path of protocol fields is found by suffixes that `a/b/c` will find `a/b/c` first, and find `b/c` if it does not exist，and find `c` if still not exist.
* Node name of the path is the name defined by `container` or `bitfield`, if no `name` exists in corresponding fields, it should be `[unnamed]`.
* If field types are quotations of other nonfundamental types, `/<type>` should be added at the end of the whole path, in which `<type>` represents names of nonfundamental types.
* If fields are in `switch` (including circumstances with father nodes in `switch`), `switch` branch can be specified only to add `[<case>]` at the end of the whole path, in which `case` represents branch names.
* `packet_` should be omitted in root nodes begins from `packet_`.

Take `slot` as an example:

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

4 basic fields and a module (`container`) is contained in `slot`, they are:

* `slot/present`
* `slot/[unnamed]/itemId`（or `slot/[unnamed]/itemId[true]`）
* `slot/[unnamed]/itemCount`（or `slot/[unnamed]/itemCount[true]`）
* `slot/[unnamed]/nbtData`（or `slot/[unnamed]/nbtData[true]`）
* `slot/[unnamed]`

Take `packet_set_slot` as another example

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

3 basic fields and a module (`slot`) is contained in `packet_set_slot`, they are:

* `set_slot/windowId`
* `set_slot/stateId`
* `set_slot/slot`
* `set_slot/item/slot`

### To Define Bitmask Fields

If the type if a field is `bitfield`, it should be defined in `bitmask_collection` with name format `([<bitsize>]<name>)+`, in which `bitsize` represents digit, `name` represents name. The definition needs to be finished in sequence, for example, a 22-digit `x`, a 22-digit `z` and a 20-digit `y` should be defined as `[22]x[22]z[20]y`. Values are contained in a list with basic fields defined in above texts. `null` should exists at positions with no basic field defined.

Take `[6]unused[1]max_present[1]min_present` as an example:

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

Corresponding definition should be:

```json
{
  "[6]unused[1]max_present[1]min_present": [
    null,
    "max_present_1",
    "min_present_1"
  ]
}
```

### To Define Components

If the type of a field is `container`, `array` or other nonfundamental types, it is a component and should be defined in `component_names`. Key is path of protocol fields, value is its name.
//
// Created by nickid2018 on 24-7-15.
//

#include <ws_version.h>

#define VALUE_TO_STRING(x) #x
#define VALUE(x) VALUE_TO_STRING(x)
#pragma message(VALUE(WIRESHARK_VERSION_MAJOR))
#pragma message(VALUE(WIRESHARK_VERSION_MINOR))

int main() {
    return 0;
}

#pragma once
#include <string>

namespace UsermodeClient {

// Runs a line-based user-mode interaction script against devices created by the
// emulated driver (DeviceTracker registry) through the IoManager dispatch surface.
// Grammar (one op per line, '#' comments):
//   wait <sec>
//   list
//   select <index | device-name-substring>
//   open
//   close
//   ioctl <hexcode> <in_hex|-> <outlen>
//   read <len> [offset]
//   write <in_hex> [offset]
//   dump <uc-addr-hex> <len>
bool RunScript(const std::string& ScriptPath, int DelaySeconds);

}

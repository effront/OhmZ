const std = @import("std");
const builtin = @import("builtin");

const is_darwin = builtin.os.tag == .macos or builtin.os.tag == .ios or
    builtin.os.tag == .tvos or builtin.os.tag == .watchos or builtin.os.tag == .visionos;
const is_linux = builtin.os.tag == .linux;

pub const IPPROTO_RAW: u32 = 255;

pub const IP_HDRINCL: u32 = if (is_darwin) 2 else if (is_linux) 3 else 2;

pub const MSG_DONTWAIT: u32 = if (is_darwin) 0x80 else if (is_linux) 0x40 else 0x40;

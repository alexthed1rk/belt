package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:intrinsics"
import "base:runtime"
import "core:encoding/endian"

@(private = "file", rodata)
spec_h05 := [256]u32 {
	0x00001620, 0x00001280, 0x00001740, 0x00001900, 0x00000140, 0x00000100, 0x00001EA0, 0x00000760,
	0x000006C0, 0x00000DA0, 0x00000000, 0x000011C0, 0x00000B00, 0x00000940, 0x00000BA0, 0x00001C80,
	0x000010A0, 0x00000080, 0x00001F40, 0x000013A0, 0x00000360, 0x000016C0, 0x000018E0, 0x00001580,
	0x000004A0, 0x000005C0, 0x00000E40, 0x00001840, 0x00000040, 0x00001FA0, 0x000019C0, 0x000001A0,
	0x00000B60, 0x00001C60, 0x00001AC0, 0x00000240, 0x000002E0, 0x00001720, 0x00000C20, 0x00001020,
	0x00001FC0, 0x00000CE0, 0x000010C0, 0x000015A0, 0x00000E20, 0x00000D60, 0x00001120, 0x00000160,
	0x00000B80, 0x00001600, 0x00001800, 0x00001FE0, 0x00000660, 0x00001860, 0x00000AC0, 0x00001700,
	0x000006A0, 0x00001880, 0x000000A0, 0x000015C0, 0x00001B00, 0x00001C00, 0x00000FE0, 0x00001320,
	0x00001C20, 0x00000560, 0x00001B80, 0x00000340, 0x00001C40, 0x00001040, 0x00000AE0, 0x00001D80,
	0x00000E00, 0x000007E0, 0x00001980, 0x00001E00, 0x000012A0, 0x00001DC0, 0x000011A0, 0x00001E20,
	0x00001820, 0x00001560, 0x00000EC0, 0x00000700, 0x000013E0, 0x00001CC0, 0x00000F00, 0x00001940,
	0x00001EE0, 0x000018C0, 0x00001F00, 0x00000C00, 0x00001AA0, 0x00001760, 0x00001380, 0x000009E0,
	0x00001E60, 0x00000780, 0x00000CA0, 0x00000F60, 0x00000C60, 0x00000F80, 0x00000600, 0x00000D40,
	0x00001BA0, 0x000009C0, 0x000014E0, 0x00000F20, 0x000013C0, 0x00001640, 0x000007A0, 0x00000620,
	0x000007C0, 0x00001300, 0x000016A0, 0x00000DC0, 0x000004E0, 0x00001A60, 0x00001780, 0x000019E0,
	0x00000B20, 0x000003C0, 0x00000300, 0x000003E0, 0x00000980, 0x00000B40, 0x000016E0, 0x00001260,
	0x00001D20, 0x00001BC0, 0x00001CE0, 0x00000580, 0x000011E0, 0x00000180, 0x000001E0, 0x000014C0,
	0x000005A0, 0x00001B60, 0x00000920, 0x00001E80, 0x00000DE0, 0x00000E60, 0x000012C0, 0x000008E0,
	0x000000C0, 0x000000E0, 0x00000A60, 0x000002C0, 0x00001DA0, 0x00000480, 0x00000F40, 0x000006E0,
	0x00000720, 0x00001960, 0x00001460, 0x00001060, 0x00000060, 0x00001520, 0x00001160, 0x00001EC0,
	0x00001240, 0x000017A0, 0x00001360, 0x00000380, 0x00001CA0, 0x00001A20, 0x00000820, 0x00000020,
	0x00000A80, 0x000008A0, 0x00001F60, 0x00001920, 0x00000BC0, 0x000009A0, 0x000001C0, 0x00001E40,
	0x00000D00, 0x00000400, 0x00001000, 0x00001540, 0x00000440, 0x00000FA0, 0x00000C80, 0x000005E0,
	0x000004C0, 0x000010E0, 0x00001F20, 0x00000680, 0x00001200, 0x00000800, 0x00000AA0, 0x00000220,
	0x000017C0, 0x00000640, 0x000012E0, 0x00000260, 0x00000860, 0x00001F80, 0x00001340, 0x00000900,
	0x00001400, 0x00000540, 0x00001100, 0x00000BE0, 0x00000320, 0x00000960, 0x00000120, 0x00001420,
	0x00000FC0, 0x000019A0, 0x00001480, 0x00001A00, 0x000002A0, 0x00000880, 0x000015E0, 0x00001180,
	0x000014A0, 0x00001080, 0x00000A00, 0x000017E0, 0x00000CC0, 0x00001A40, 0x00001D00, 0x00001140,
	0x00001440, 0x00001AE0, 0x000008C0, 0x00000A40, 0x00000840, 0x00001500, 0x00001BE0, 0x00001660,
	0x00000D20, 0x00000E80, 0x000018A0, 0x00000A20, 0x00001D60, 0x00000460, 0x00000520, 0x00000420,
	0x00001A80, 0x00001DE0, 0x00001B20, 0x00001680, 0x00000740, 0x00000C40, 0x00000500, 0x00000EA0,
	0x00001220, 0x00000280, 0x00000200, 0x00001D40, 0x00000EE0, 0x00000D80, 0x00001B40, 0x000003A0,
}

@(private = "file", rodata)
spec_h13 := [256]u32 {
	0x00162000, 0x00128000, 0x00174000, 0x00190000, 0x00014000, 0x00010000, 0x001EA000, 0x00076000,
	0x0006C000, 0x000DA000, 0x00000000, 0x0011C000, 0x000B0000, 0x00094000, 0x000BA000, 0x001C8000,
	0x0010A000, 0x00008000, 0x001F4000, 0x0013A000, 0x00036000, 0x0016C000, 0x0018E000, 0x00158000,
	0x0004A000, 0x0005C000, 0x000E4000, 0x00184000, 0x00004000, 0x001FA000, 0x0019C000, 0x0001A000,
	0x000B6000, 0x001C6000, 0x001AC000, 0x00024000, 0x0002E000, 0x00172000, 0x000C2000, 0x00102000,
	0x001FC000, 0x000CE000, 0x0010C000, 0x0015A000, 0x000E2000, 0x000D6000, 0x00112000, 0x00016000,
	0x000B8000, 0x00160000, 0x00180000, 0x001FE000, 0x00066000, 0x00186000, 0x000AC000, 0x00170000,
	0x0006A000, 0x00188000, 0x0000A000, 0x0015C000, 0x001B0000, 0x001C0000, 0x000FE000, 0x00132000,
	0x001C2000, 0x00056000, 0x001B8000, 0x00034000, 0x001C4000, 0x00104000, 0x000AE000, 0x001D8000,
	0x000E0000, 0x0007E000, 0x00198000, 0x001E0000, 0x0012A000, 0x001DC000, 0x0011A000, 0x001E2000,
	0x00182000, 0x00156000, 0x000EC000, 0x00070000, 0x0013E000, 0x001CC000, 0x000F0000, 0x00194000,
	0x001EE000, 0x0018C000, 0x001F0000, 0x000C0000, 0x001AA000, 0x00176000, 0x00138000, 0x0009E000,
	0x001E6000, 0x00078000, 0x000CA000, 0x000F6000, 0x000C6000, 0x000F8000, 0x00060000, 0x000D4000,
	0x001BA000, 0x0009C000, 0x0014E000, 0x000F2000, 0x0013C000, 0x00164000, 0x0007A000, 0x00062000,
	0x0007C000, 0x00130000, 0x0016A000, 0x000DC000, 0x0004E000, 0x001A6000, 0x00178000, 0x0019E000,
	0x000B2000, 0x0003C000, 0x00030000, 0x0003E000, 0x00098000, 0x000B4000, 0x0016E000, 0x00126000,
	0x001D2000, 0x001BC000, 0x001CE000, 0x00058000, 0x0011E000, 0x00018000, 0x0001E000, 0x0014C000,
	0x0005A000, 0x001B6000, 0x00092000, 0x001E8000, 0x000DE000, 0x000E6000, 0x0012C000, 0x0008E000,
	0x0000C000, 0x0000E000, 0x000A6000, 0x0002C000, 0x001DA000, 0x00048000, 0x000F4000, 0x0006E000,
	0x00072000, 0x00196000, 0x00146000, 0x00106000, 0x00006000, 0x00152000, 0x00116000, 0x001EC000,
	0x00124000, 0x0017A000, 0x00136000, 0x00038000, 0x001CA000, 0x001A2000, 0x00082000, 0x00002000,
	0x000A8000, 0x0008A000, 0x001F6000, 0x00192000, 0x000BC000, 0x0009A000, 0x0001C000, 0x001E4000,
	0x000D0000, 0x00040000, 0x00100000, 0x00154000, 0x00044000, 0x000FA000, 0x000C8000, 0x0005E000,
	0x0004C000, 0x0010E000, 0x001F2000, 0x00068000, 0x00120000, 0x00080000, 0x000AA000, 0x00022000,
	0x0017C000, 0x00064000, 0x0012E000, 0x00026000, 0x00086000, 0x001F8000, 0x00134000, 0x00090000,
	0x00140000, 0x00054000, 0x00110000, 0x000BE000, 0x00032000, 0x00096000, 0x00012000, 0x00142000,
	0x000FC000, 0x0019A000, 0x00148000, 0x001A0000, 0x0002A000, 0x00088000, 0x0015E000, 0x00118000,
	0x0014A000, 0x00108000, 0x000A0000, 0x0017E000, 0x000CC000, 0x001A4000, 0x001D0000, 0x00114000,
	0x00144000, 0x001AE000, 0x0008C000, 0x000A4000, 0x00084000, 0x00150000, 0x001BE000, 0x00166000,
	0x000D2000, 0x000E8000, 0x0018A000, 0x000A2000, 0x001D6000, 0x00046000, 0x00052000, 0x00042000,
	0x001A8000, 0x001DE000, 0x001B2000, 0x00168000, 0x00074000, 0x000C4000, 0x00050000, 0x000EA000,
	0x00122000, 0x00028000, 0x00020000, 0x001D4000, 0x000EE000, 0x000D8000, 0x001B4000, 0x0003A000,
}

@(private = "file", rodata)
spec_h21 := [256]u32 {
	0x16200000, 0x12800000, 0x17400000, 0x19000000, 0x01400000, 0x01000000, 0x1EA00000, 0x07600000,
	0x06C00000, 0x0DA00000, 0x00000000, 0x11C00000, 0x0B000000, 0x09400000, 0x0BA00000, 0x1C800000,
	0x10A00000, 0x00800000, 0x1F400000, 0x13A00000, 0x03600000, 0x16C00000, 0x18E00000, 0x15800000,
	0x04A00000, 0x05C00000, 0x0E400000, 0x18400000, 0x00400000, 0x1FA00000, 0x19C00000, 0x01A00000,
	0x0B600000, 0x1C600000, 0x1AC00000, 0x02400000, 0x02E00000, 0x17200000, 0x0C200000, 0x10200000,
	0x1FC00000, 0x0CE00000, 0x10C00000, 0x15A00000, 0x0E200000, 0x0D600000, 0x11200000, 0x01600000,
	0x0B800000, 0x16000000, 0x18000000, 0x1FE00000, 0x06600000, 0x18600000, 0x0AC00000, 0x17000000,
	0x06A00000, 0x18800000, 0x00A00000, 0x15C00000, 0x1B000000, 0x1C000000, 0x0FE00000, 0x13200000,
	0x1C200000, 0x05600000, 0x1B800000, 0x03400000, 0x1C400000, 0x10400000, 0x0AE00000, 0x1D800000,
	0x0E000000, 0x07E00000, 0x19800000, 0x1E000000, 0x12A00000, 0x1DC00000, 0x11A00000, 0x1E200000,
	0x18200000, 0x15600000, 0x0EC00000, 0x07000000, 0x13E00000, 0x1CC00000, 0x0F000000, 0x19400000,
	0x1EE00000, 0x18C00000, 0x1F000000, 0x0C000000, 0x1AA00000, 0x17600000, 0x13800000, 0x09E00000,
	0x1E600000, 0x07800000, 0x0CA00000, 0x0F600000, 0x0C600000, 0x0F800000, 0x06000000, 0x0D400000,
	0x1BA00000, 0x09C00000, 0x14E00000, 0x0F200000, 0x13C00000, 0x16400000, 0x07A00000, 0x06200000,
	0x07C00000, 0x13000000, 0x16A00000, 0x0DC00000, 0x04E00000, 0x1A600000, 0x17800000, 0x19E00000,
	0x0B200000, 0x03C00000, 0x03000000, 0x03E00000, 0x09800000, 0x0B400000, 0x16E00000, 0x12600000,
	0x1D200000, 0x1BC00000, 0x1CE00000, 0x05800000, 0x11E00000, 0x01800000, 0x01E00000, 0x14C00000,
	0x05A00000, 0x1B600000, 0x09200000, 0x1E800000, 0x0DE00000, 0x0E600000, 0x12C00000, 0x08E00000,
	0x00C00000, 0x00E00000, 0x0A600000, 0x02C00000, 0x1DA00000, 0x04800000, 0x0F400000, 0x06E00000,
	0x07200000, 0x19600000, 0x14600000, 0x10600000, 0x00600000, 0x15200000, 0x11600000, 0x1EC00000,
	0x12400000, 0x17A00000, 0x13600000, 0x03800000, 0x1CA00000, 0x1A200000, 0x08200000, 0x00200000,
	0x0A800000, 0x08A00000, 0x1F600000, 0x19200000, 0x0BC00000, 0x09A00000, 0x01C00000, 0x1E400000,
	0x0D000000, 0x04000000, 0x10000000, 0x15400000, 0x04400000, 0x0FA00000, 0x0C800000, 0x05E00000,
	0x04C00000, 0x10E00000, 0x1F200000, 0x06800000, 0x12000000, 0x08000000, 0x0AA00000, 0x02200000,
	0x17C00000, 0x06400000, 0x12E00000, 0x02600000, 0x08600000, 0x1F800000, 0x13400000, 0x09000000,
	0x14000000, 0x05400000, 0x11000000, 0x0BE00000, 0x03200000, 0x09600000, 0x01200000, 0x14200000,
	0x0FC00000, 0x19A00000, 0x14800000, 0x1A000000, 0x02A00000, 0x08800000, 0x15E00000, 0x11800000,
	0x14A00000, 0x10800000, 0x0A000000, 0x17E00000, 0x0CC00000, 0x1A400000, 0x1D000000, 0x11400000,
	0x14400000, 0x1AE00000, 0x08C00000, 0x0A400000, 0x08400000, 0x15000000, 0x1BE00000, 0x16600000,
	0x0D200000, 0x0E800000, 0x18A00000, 0x0A200000, 0x1D600000, 0x04600000, 0x05200000, 0x04200000,
	0x1A800000, 0x1DE00000, 0x1B200000, 0x16800000, 0x07400000, 0x0C400000, 0x05000000, 0x0EA00000,
	0x12200000, 0x02800000, 0x02000000, 0x1D400000, 0x0EE00000, 0x0D800000, 0x1B400000, 0x03A00000,
}

@(private = "file", rodata)
spec_h29 := [256]u32 {
	0x20000016, 0x80000012, 0x40000017, 0x00000019, 0x40000001, 0x00000001, 0xA000001E, 0x60000007,
	0xC0000006, 0xA000000D, 0x00000000, 0xC0000011, 0x0000000B, 0x40000009, 0xA000000B, 0x8000001C,
	0xA0000010, 0x80000000, 0x4000001F, 0xA0000013, 0x60000003, 0xC0000016, 0xE0000018, 0x80000015,
	0xA0000004, 0xC0000005, 0x4000000E, 0x40000018, 0x40000000, 0xA000001F, 0xC0000019, 0xA0000001,
	0x6000000B, 0x6000001C, 0xC000001A, 0x40000002, 0xE0000002, 0x20000017, 0x2000000C, 0x20000010,
	0xC000001F, 0xE000000C, 0xC0000010, 0xA0000015, 0x2000000E, 0x6000000D, 0x20000011, 0x60000001,
	0x8000000B, 0x00000016, 0x00000018, 0xE000001F, 0x60000006, 0x60000018, 0xC000000A, 0x00000017,
	0xA0000006, 0x80000018, 0xA0000000, 0xC0000015, 0x0000001B, 0x0000001C, 0xE000000F, 0x20000013,
	0x2000001C, 0x60000005, 0x8000001B, 0x40000003, 0x4000001C, 0x40000010, 0xE000000A, 0x8000001D,
	0x0000000E, 0xE0000007, 0x80000019, 0x0000001E, 0xA0000012, 0xC000001D, 0xA0000011, 0x2000001E,
	0x20000018, 0x60000015, 0xC000000E, 0x00000007, 0xE0000013, 0xC000001C, 0x0000000F, 0x40000019,
	0xE000001E, 0xC0000018, 0x0000001F, 0x0000000C, 0xA000001A, 0x60000017, 0x80000013, 0xE0000009,
	0x6000001E, 0x80000007, 0xA000000C, 0x6000000F, 0x6000000C, 0x8000000F, 0x00000006, 0x4000000D,
	0xA000001B, 0xC0000009, 0xE0000014, 0x2000000F, 0xC0000013, 0x40000016, 0xA0000007, 0x20000006,
	0xC0000007, 0x00000013, 0xA0000016, 0xC000000D, 0xE0000004, 0x6000001A, 0x80000017, 0xE0000019,
	0x2000000B, 0xC0000003, 0x00000003, 0xE0000003, 0x80000009, 0x4000000B, 0xE0000016, 0x60000012,
	0x2000001D, 0xC000001B, 0xE000001C, 0x80000005, 0xE0000011, 0x80000001, 0xE0000001, 0xC0000014,
	0xA0000005, 0x6000001B, 0x20000009, 0x8000001E, 0xE000000D, 0x6000000E, 0xC0000012, 0xE0000008,
	0xC0000000, 0xE0000000, 0x6000000A, 0xC0000002, 0xA000001D, 0x80000004, 0x4000000F, 0xE0000006,
	0x20000007, 0x60000019, 0x60000014, 0x60000010, 0x60000000, 0x20000015, 0x60000011, 0xC000001E,
	0x40000012, 0xA0000017, 0x60000013, 0x80000003, 0xA000001C, 0x2000001A, 0x20000008, 0x20000000,
	0x8000000A, 0xA0000008, 0x6000001F, 0x20000019, 0xC000000B, 0xA0000009, 0xC0000001, 0x4000001E,
	0x0000000D, 0x00000004, 0x00000010, 0x40000015, 0x40000004, 0xA000000F, 0x8000000C, 0xE0000005,
	0xC0000004, 0xE0000010, 0x2000001F, 0x80000006, 0x00000012, 0x00000008, 0xA000000A, 0x20000002,
	0xC0000017, 0x40000006, 0xE0000012, 0x60000002, 0x60000008, 0x8000001F, 0x40000013, 0x00000009,
	0x00000014, 0x40000005, 0x00000011, 0xE000000B, 0x20000003, 0x60000009, 0x20000001, 0x20000014,
	0xC000000F, 0xA0000019, 0x80000014, 0x0000001A, 0xA0000002, 0x80000008, 0xE0000015, 0x80000011,
	0xA0000014, 0x80000010, 0x0000000A, 0xE0000017, 0xC000000C, 0x4000001A, 0x0000001D, 0x40000011,
	0x40000014, 0xE000001A, 0xC0000008, 0x4000000A, 0x40000008, 0x00000015, 0xE000001B, 0x60000016,
	0x2000000D, 0x8000000E, 0xA0000018, 0x2000000A, 0x6000001D, 0x60000004, 0x20000005, 0x20000004,
	0x8000001A, 0xE000001D, 0x2000001B, 0x80000016, 0x40000007, 0x4000000C, 0x00000005, 0xA000000E,
	0x20000012, 0x80000002, 0x00000002, 0x4000001D, 0xE000000E, 0x8000000D, 0x4000001B, 0xA0000003,
}

@(private = "file", rodata)
spec_b_keys := [288]u32 {
	0x00b98895, 0x00b9912a, 0x00b999bf, 0x00b9a254, 0x00b9aae9, 0x00b9b37e, 0x00b9bc13, 0x00b9c4a8,
	0x00b9cd3d, 0x00b9d5d2, 0x00b9de67, 0x00b9e6fc, 0x00b9ef91, 0x00b9f826, 0x00bfe447, 0x01794ddd,
	0x02d66ab3, 0x02f77ea2, 0x057ec483, 0x05d7fe14, 0x05db798a, 0x05dd2a6b, 0x05dd54d6, 0x05dd7f41,
	0x05e551c6, 0x0afbe064, 0x0b2b5e9a, 0x0b2d4d97, 0x0b3d3be8, 0x0b3d77d0, 0x0b47d78d, 0x0b675f6a,
	0x0b75e03d, 0x0b9dfb11, 0x0bb04e6d, 0x0bccdcee, 0x0bd5c816, 0x0bdb601f, 0x0bddb225, 0x0bdde44a,
	0x0bde587e, 0x0bedb96e, 0x0bedf2dc, 0x0bf0ddc7, 0x0bfba588, 0x0bfbcb10, 0x0bfbf098, 0x154d6117,
	0x15a655fb, 0x15c6c04d, 0x1610f9fa, 0x1617a183, 0x1617c306, 0x1617e489, 0x16ec9678, 0x16ecacf0,
	0x16ecc368, 0x16ecd9e0, 0x16ecf058, 0x16f6c2b1, 0x170aa3e0, 0x170ac7c0, 0x170aeba0, 0x1712d2f5,
	0x1720b959, 0x1720f2b2, 0x1725eb34, 0x173f34d9, 0x173f69b2, 0x17677a19, 0x17692e42, 0x17695c84,
	0x176d73ff, 0x1782d514, 0x178d4d35, 0x17a4698b, 0x17b6c86f, 0x17bd5153, 0x17ca7e95, 0x17e07a64,
	0x17e476c6, 0x17e979cd, 0x17f93f21, 0x17f97e42, 0x1848763d, 0x2a74d1d9, 0x2a75eb0f, 0x2a84be94,
	0x2a84fd28, 0x2b19c540, 0x2c4b519b, 0x2cd0c5a3, 0x2cfb6b15, 0x2d0ff37b, 0x2d1c256d, 0x2d1c4ada,
	0x2d1c7047, 0x2d565c3e, 0x2d6a7af5, 0x2d7bf4db, 0x2daa988c, 0x2daab118, 0x2daac9a4, 0x2daae230,
	0x2daafabc, 0x2db34991, 0x2dc0df4b, 0x2e1547c0, 0x2e22c617, 0x2e28ad9e, 0x2e28db3c, 0x2e346435,
	0x2e44c919, 0x2e4be9d0, 0x2e7d40d8, 0x2e837105, 0x2e8f6fa2, 0x2e926bad, 0x2e9aac2a, 0x2e9ad854,
	0x2e9fd6f3, 0x2ea9f3df, 0x2eb5c173, 0x2eb93937, 0x2eb9726e, 0x2ed95443, 0x2ed9e4c6, 0x2ee7396f,
	0x2ee772de, 0x2f09e273, 0x2f1df023, 0x2f217b50, 0x2f25de41, 0x2f40d656, 0x2f4ec2e5, 0x2f4f4db1,
	0x2f4ffed6, 0x2f67e694, 0x2f73f18d, 0x2f9ccd51, 0x2fa6be63, 0x2fa6fcc6, 0x2fbaedeb, 0x2fca51eb,
	0x2fce5ffa, 0x2fd8e270, 0x2fdb93af, 0x2fdba75e, 0x2fdbbb0d, 0x2fdbcebc, 0x2fdbe26b, 0x2fdbf61a,
	0x2ff9b805, 0x2ff9f00a, 0x2ffb6b27, 0x313fe3eb, 0x54cd76e6, 0x557bd8f5, 0x563322a0, 0x56334540,
	0x563367e0, 0x5677d6ce, 0x56dcf451, 0x56fd543b, 0x580b65c3, 0x585c7af8, 0x58a27585, 0x58c6f6bf,
	0x58d8d605, 0x58fcf898, 0x592ee41b, 0x599df46a, 0x59c952b5, 0x59cf6e08, 0x59d4da88, 0x5a1079a3,
	0x5a5365a6, 0x5a56e532, 0x5aa337fa, 0x5aa36ff4, 0x5ac5d4d5, 0x5acec220, 0x5aea63e9, 0x5af7d869,
	0x5afcaa03, 0x5afcd406, 0x5afcfe09, 0x5b024845, 0x5b0afe83, 0x5b21bac9, 0x5b21f592, 0x5b353b71,
	0x5b3576e2, 0x5b417f21, 0x5b53c193, 0x5ba1ee4b, 0x5bb259e0, 0x5bcdc5dc, 0x5c00e008, 0x5c2a08f8,
	0x5c2a11f0, 0x5c2a1ae8, 0x5c2a23e0, 0x5c2a2cd8, 0x5c2a35d0, 0x5c2a3ec8, 0x5c2a47c0, 0x5c2a50b8,
	0x5c2a59b0, 0x5c2a62a8, 0x5c2a6ba0, 0x5c2a7498, 0x5c2a7d90, 0x5c2abc8b, 0x5c2af916, 0x5c3e5153,
	0x5c53f911, 0x5c665137, 0x5cc43a66, 0x5cc474cc, 0x5cf2fc25, 0x5d167a47, 0x5d26ffff, 0x5d585a25,
	0x5d82b405, 0x5d82e80a, 0x5d98e997, 0x5da926f9, 0x5da94df2, 0x5da974eb, 0x5daee128, 0x5dd46ada,
	0x5dd7cd2d, 0x5ddafcad, 0x5ddb3792, 0x5ddb6f24, 0x5e3ccbd4, 0x5e3dfa1b, 0x5e3f727d, 0x5e44dd9d,
	0x5e48f6e3, 0x5e4eb1c7, 0x5e4ee38e, 0x5e54d8b5, 0x5e822c21, 0x5e825842, 0x5e9bced2, 0x5e9d9a85,
	0x5e9db50a, 0x5e9dcf8f, 0x5e9dea14, 0x5ea4d3a7, 0x5ebcda43, 0x5ec72b1b, 0x5ec75636, 0x5ef0d3f3,
	0x5f014ad7, 0x5f0dcec1, 0x5f0f6611, 0x5f34d65a, 0x5f677a7b, 0x5f6a726c, 0x5f6deb1a, 0x5f6fa2f9,
	0x5f6fc5f2, 0x5f6fe8eb, 0x5f73dc93, 0x5f7b4975, 0x5f8f653b, 0x5f9264d4, 0x5f92e03d, 0x5f99700f,
	0x5fa2e2d5, 0x5fa3adc8, 0x5fa3db90, 0x5fc44c01, 0x5fdcf16d, 0x5feb7c2b, 0x5febfcc7, 0x5fef3b57,
	0x5fef76ae, 0x5ff03bf3, 0x5ff077e6, 0x5ff46c17, 0x5ff85e9d, 0x60182ac3, 0x60185586, 0x61b25c85,
}

@(private = "file", rodata)
spec_b_values := [288]u32 {
	0x0126, 0x024b, 0x0370, 0x0495, 0x05ba, 0x06df, 0x0804, 0x0929,
	0x0a4e, 0x0b73, 0x0c98, 0x0dbd, 0x0ee2, 0x1007, 0x0d73, 0x0ba2,
	0x1184, 0x14ea, 0x0c45, 0x16c0, 0x15f0, 0x07a9, 0x0f51, 0x16f9,
	0x0ec6, 0x12c4, 0x1274, 0x0f23, 0x0bb2, 0x1763, 0x1119, 0x12a8,
	0x12d4, 0x181d, 0x0f61, 0x123e, 0x0e28, 0x12e1, 0x09da, 0x13b3,
	0x1162, 0x0b4a, 0x1693, 0x126f, 0x0762, 0x0ec3, 0x1624, 0x145a,
	0x120e, 0x0d83, 0x19aa, 0x070e, 0x0e1b, 0x1528, 0x04c0, 0x097f,
	0x0e3e, 0x12fd, 0x17bc, 0x0e18, 0x0796, 0x0f2b, 0x16c0, 0x118a,
	0x0c21, 0x1841, 0x16ac, 0x0b2f, 0x165d, 0x19da, 0x09cc, 0x1397,
	0x1890, 0x1206, 0x105c, 0x165f, 0x0f5c, 0x113f, 0x1ad9, 0x19f8,
	0x1934, 0x19d9, 0x0d67, 0x1acd, 0x1921, 0x126e, 0x181b, 0x0e18,
	0x1c2f, 0x0f9e, 0x1274, 0x0fc4, 0x1840, 0x1a28, 0x087b, 0x10f5,
	0x196f, 0x14e8, 0x1bdf, 0x1a7e, 0x0592, 0x0b23, 0x10b4, 0x1645,
	0x1bd6, 0x10b0, 0x159e, 0x104a, 0x0fea, 0x0a5c, 0x14b7, 0x16c1,
	0x109a, 0x1808, 0x0ebc, 0x19ae, 0x195e, 0x1878, 0x0a0a, 0x1413,
	0x13c3, 0x1a56, 0x0ee1, 0x0d02, 0x1a03, 0x1329, 0x16ea, 0x0d10,
	0x1a1f, 0x1665, 0x1983, 0x1c0e, 0x1572, 0x13a6, 0x0f3a, 0x11af,
	0x1cde, 0x175a, 0x19da, 0x119c, 0x0e36, 0x1c6b, 0x190a, 0x12aa,
	0x15de, 0x166e, 0x047d, 0x08f9, 0x0d75, 0x11f1, 0x166d, 0x1ae9,
	0x0cc5, 0x1989, 0x186c, 0x16d4, 0x1ca0, 0x156f, 0x085a, 0x10b3,
	0x190c, 0x14f0, 0x1c11, 0x1454, 0x1896, 0x1db8, 0x1c69, 0x1cb6,
	0x14cd, 0x1d2a, 0x1837, 0x1c2c, 0x1405, 0x1aa2, 0x15ea, 0x1d73,
	0x189e, 0x1882, 0x0d90, 0x1b1f, 0x148e, 0x1006, 0x1836, 0x156d,
	0x0a2f, 0x145d, 0x1e8b, 0x1184, 0x1ea9, 0x0e40, 0x1c7f, 0x0e69,
	0x1cd1, 0x1ed1, 0x0fe6, 0x1abf, 0x15cc, 0x10f2, 0x174c, 0x022e,
	0x045b, 0x0688, 0x08b5, 0x0ae2, 0x0d0f, 0x0f3c, 0x1169, 0x1396,
	0x15c3, 0x17f0, 0x1a1d, 0x1c4a, 0x1e77, 0x0eb1, 0x1d61, 0x13bc,
	0x1d61, 0x13b6, 0x0e2e, 0x1c5b, 0x1e25, 0x1db2, 0x1f16, 0x15e6,
	0x0ca4, 0x1947, 0x19a8, 0x0979, 0x12f1, 0x1c69, 0x179c, 0x19f8,
	0x12c2, 0x1e4d, 0x0d82, 0x1b03, 0x1270, 0x1db0, 0x1bd6, 0x16c3,
	0x1ce8, 0x0c1b, 0x1835, 0x1592, 0x0abc, 0x1577, 0x132c, 0x0674,
	0x0ce7, 0x135a, 0x19cd, 0x1459, 0x15f5, 0x0a7d, 0x14f9, 0x146d,
	0x1236, 0x132a, 0x18d6, 0x1504, 0x1dd0, 0x1bda, 0x1a12, 0x0884,
	0x1107, 0x198a, 0x1689, 0x11e2, 0x18a5, 0x188c, 0x176e, 0x1b48,
	0x1810, 0x0b26, 0x164b, 0x1282, 0x1b9f, 0x1e3d, 0x1e63, 0x0e74,
	0x1ce7, 0x0e9a, 0x1d33, 0x1a53, 0x170b, 0x0a6a, 0x14d4, 0x1691,
}

@(private = "file")
spec_t :: Block128_U8 {
	0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
	0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
}

@(private = "file")
spec_c :: Block128_U8 {
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

@(private = "file")
spec_h :: Block256_U8 {
	0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
	0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
	0x85, 0x04, 0xfa, 0x9d, 0x1b, 0xb6, 0xc7, 0xac,
	0x25, 0x2e, 0x72, 0xc2, 0x02, 0xfd, 0xce, 0x0d,
}

@(private = "file")
spec_r1 :: Block256_U8 {
	0xb1, 0x94, 0xba, 0xc8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

@(private = "file")
spec_r2 :: Block256_U8 {
	0x5b, 0xe3, 0xd6, 0x12, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

@(private = "file")
spec_r3 :: Block256_U8 {
	0x5c, 0xb0, 0xc0, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

@(private = "file")
spec_r4 :: Block256_U8 {
	0xe1, 0x2b, 0xdc, 0x1a, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

@(private = "file")
spec_r5 :: Block256_U8 {
	0xc1, 0xab, 0x76, 0x38, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

@(private = "file")
spec_r6 :: Block256_U8 {
	0xf3, 0x3c, 0x65, 0x7b, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

@(private = "file", rodata)
spec_k := [56]i32 {
	0, 1, 2, 3, 4, 5, 6,
	7, 0, 1, 2, 3, 4, 5,
	6, 7, 0, 1, 2, 3, 4,
	5, 6, 7, 0, 1, 2, 3,
	4, 5, 6, 7, 0, 1, 2,
	3, 4, 5, 6, 7, 0, 1,
	2, 3, 4, 5, 6, 7, 0,
	1, 2, 3, 4, 5, 6, 7,
}

@(private = "file")
spec_g05 :: proc "contextless" (x: u32) -> u32 #no_bounds_check {
	result := (
		( spec_h05[ x       & 255 ] ) ~
		( spec_h13[ x >>  8 & 255 ] ) ~
		( spec_h21[ x >> 16 & 255 ] ) ~
		( spec_h29[ x >> 24       ] )
	)
	return result
}

@(private = "file")
spec_g13 :: proc "contextless" (x: u32) -> u32 #no_bounds_check {
	result := (
		( spec_h13[ x       & 255 ] ) ~
		( spec_h21[ x >>  8 & 255 ] ) ~
		( spec_h29[ x >> 16 & 255 ] ) ~
		( spec_h05[ x >> 24       ] )
	)
	return result
}

@(private = "file")
spec_g21 :: proc "contextless" (x: u32) -> u32 #no_bounds_check {
	result := (
		( spec_h21[ x       & 255 ] ) ~
		( spec_h29[ x >>  8 & 255 ] ) ~
		( spec_h05[ x >> 16 & 255 ] ) ~
		( spec_h13[ x >> 24       ] )
	)
	return result
}

BLOCK_SIZE_32_U8   ::  4
BLOCK_SIZE_96_U8   :: 12
BLOCK_SIZE_128_U8  :: 16
BLOCK_SIZE_256_U8  :: 32
BLOCK_SIZE_128_U32 ::  4
BLOCK_SIZE_128_U64 ::  2
KEY_SIZE_128_U8    :: 16
KEY_SIZE_192_U8    :: 24
KEY_SIZE_256_U8    :: 32
KEY_SIZE_256_U32   ::  8
MAC_SIZE_64_U8     ::  8

Block128_U8  :: #type [BLOCK_SIZE_128_U8]byte
Block256_U8  :: #type [BLOCK_SIZE_256_U8]byte
Block128_U32 :: #type [BLOCK_SIZE_128_U32]u32
Block128_U64 :: #type [BLOCK_SIZE_128_U64]u64
Key128_U8    :: #type [KEY_SIZE_128_U8]byte
Key192_U8    :: #type [KEY_SIZE_192_U8]byte
Key256_U8    :: #type [KEY_SIZE_256_U8]byte
Key256_U32   :: #type [KEY_SIZE_256_U32]u32
Mac64_U8     :: #type [MAC_SIZE_64_U8]byte

Context :: struct {
	key:            Key256_U32,
	is_initialized: bool,
}

init :: proc "contextless" (ctx: ^Context, key: []byte) #no_bounds_check {
	ensure_contextless(len(key) == KEY_SIZE_256_U8, "crypto/belt: invalid KEY size")

	for i in 0..<KEY_SIZE_256_U32 {
		ctx.key[i] = endian.unchecked_get_u32le(key[4 * i: 4 * i + 4])
	}

	ctx.is_initialized = true
}

@(private = "file")
xor_slice :: proc "contextless" (dst, src: []byte) #no_bounds_check {
	assert_contextless(len(dst) == len(src), "crypto/belt: DST size != SRC size")

	for i in 0..<len(dst) {
		dst[i] ~= src[i]
	}
}

@(private = "file")
xor_block :: proc "contextless" (dst, src: []byte) #no_bounds_check {
	assert_contextless(len(dst) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DST size")
	assert_contextless(len(src) == BLOCK_SIZE_128_U8, "crypto/belt: invalid SRC size")

	for i in 0..<BLOCK_SIZE_128_U8 {
		dst[i] ~= src[i]
	}
}

@(private = "file")
neg_block :: proc "contextless" (dst, src: []byte) #no_bounds_check {
	assert_contextless(len(dst) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DST size")
	assert_contextless(len(src) == BLOCK_SIZE_128_U8, "crypto/belt: invalid SRC size")

	for i in 0..<BLOCK_SIZE_128_U8 {
		dst[i] = ~src[i]
	}
}

@(private = "file")
inc_block :: proc "contextless" (data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")

	block: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		block[i] = endian.unchecked_get_u32le(data[4 * i: 4 * i + 4])
	}

	block = transmute(Block128_U32)(transmute(u128)block + 1)
	for i in 0..<BLOCK_SIZE_128_U32 {
		endian.unchecked_put_u32le(data[4 * i: 4 * i + 4], block[i])
	}
}

@(private = "file")
u128_block :: proc "contextless" (data: []byte, value: u128) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")

	block := transmute(Block128_U32)value
	for i in 0..<BLOCK_SIZE_128_U32 {
		endian.unchecked_put_u32le(data[4 * i: 4 * i + 4], block[i])
	}
}

/* Block cipher: belt-encrypt-block */
encrypt_block :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		block[i] = endian.unchecked_get_u32le(data[4 * i: 4 * i + 4])
	}

	a :: 0; b :: 1; c :: 2; d :: 3
	for round := i32(0); round <= 7; round += 1 {
		block[b] ~= spec_g05(block[a] + ctx.key[spec_k[7 * round]])
		block[c] ~= spec_g21(block[d] + ctx.key[spec_k[7 * round + 1]])
		block[a] -= spec_g13(block[b] + ctx.key[spec_k[7 * round + 2]])

		block[c] += block[b]
		block[b] += spec_g21(block[c] + ctx.key[spec_k[7 * round + 3]]) ~ u32(round + 1)
		block[c] -= block[b]

		block[d] += spec_g13(block[c] + ctx.key[spec_k[7 * round + 4]])
		block[b] ~= spec_g21(block[a] + ctx.key[spec_k[7 * round + 5]])
		block[c] ~= spec_g05(block[d] + ctx.key[spec_k[7 * round + 6]])

		block[a] ~= block[b]; block[b] ~= block[a]; block[a] ~= block[b]
		block[c] ~= block[d]; block[d] ~= block[c]; block[c] ~= block[d]
		block[b] ~= block[c]; block[c] ~= block[b]; block[b] ~= block[c]
	}

	block[a] ~= block[b]; block[b] ~= block[a]; block[a] ~= block[b]
	block[c] ~= block[d]; block[d] ~= block[c]; block[c] ~= block[d]
	block[b] ~= block[c]; block[c] ~= block[b]; block[b] ~= block[c]

	for i in 0..<BLOCK_SIZE_128_U32 {
		endian.unchecked_put_u32le(data[4 * i: 4 * i + 4], block[i])
	}
}

/* Block cipher: belt-decrypt-block */
decrypt_block :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		block[i] = endian.unchecked_get_u32le(data[4 * i: 4 * i + 4])
	}

	a :: 0; b :: 1; c :: 2; d :: 3
	for round := i32(7); round >= 0; round -= 1 {
		block[b] ~= spec_g05(block[a] + ctx.key[spec_k[7 * round + 6]])
		block[c] ~= spec_g21(block[d] + ctx.key[spec_k[7 * round + 5]])
		block[a] -= spec_g13(block[b] + ctx.key[spec_k[7 * round + 4]])

		block[c] += block[b]
		block[b] += spec_g21(block[c] + ctx.key[spec_k[7 * round + 3]]) ~ u32(round + 1)
		block[c] -= block[b]

		block[d] += spec_g13(block[c] + ctx.key[spec_k[7 * round + 2]])
		block[b] ~= spec_g21(block[a] + ctx.key[spec_k[7 * round + 1]])
		block[c] ~= spec_g05(block[d] + ctx.key[spec_k[7 * round]])

		block[a] ~= block[b]; block[b] ~= block[a]; block[a] ~= block[b]
		block[c] ~= block[d]; block[d] ~= block[c]; block[c] ~= block[d]
		block[a] ~= block[d]; block[d] ~= block[a]; block[a] ~= block[d]
	}

	block[a] ~= block[b]; block[b] ~= block[a]; block[a] ~= block[b]
	block[c] ~= block[d]; block[d] ~= block[c]; block[c] ~= block[d]
	block[a] ~= block[d]; block[d] ~= block[a]; block[a] ~= block[d]

	for i in 0..<BLOCK_SIZE_128_U32 {
		endian.unchecked_put_u32le(data[4 * i: 4 * i + 4], block[i])
	}
}

/* Wide block cipher: belt-encrypt-wide-block */
encrypt_wide_block :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	round_u8: Block128_U8 = ---

	num_rounds := 2 * ((uint(data_size) + BLOCK_SIZE_128_U8 - 1) / BLOCK_SIZE_128_U8)
	for round := uint(1); round <= num_rounds; round += 1 {
		copy_slice(block_u8[:], data[:BLOCK_SIZE_128_U8])
		for i := BLOCK_SIZE_128_U8; i + BLOCK_SIZE_128_U8 < data_size; i += BLOCK_SIZE_128_U8 {
			xor_block(block_u8[:], data[i: i + BLOCK_SIZE_128_U8])
		}

		copy_slice(data[:data_size - BLOCK_SIZE_128_U8], data[BLOCK_SIZE_128_U8:])
		copy_slice(data[data_size - BLOCK_SIZE_128_U8:], block_u8[:])

		encrypt_block(ctx, block_u8[:])
		u128_block(round_u8[:], u128(round))

		xor_block(block_u8[:], round_u8[:])
		xor_block(data[data_size - BLOCK_SIZE_256_U8: data_size - BLOCK_SIZE_128_U8], block_u8[:])
	}
}

/* Wide block cipher: belt-decrypt-wide-block */
decrypt_wide_block :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	round_u8: Block128_U8 = ---

	num_rounds := 2 * ((uint(data_size) + BLOCK_SIZE_128_U8 - 1) / BLOCK_SIZE_128_U8)
	for round := num_rounds; round >= 1; round -= 1 {
		copy_slice(block_u8[:], data[data_size - BLOCK_SIZE_128_U8:])
		copy_slice(data[BLOCK_SIZE_128_U8:], data[:data_size - BLOCK_SIZE_128_U8])
		copy_slice(data[:BLOCK_SIZE_128_U8], block_u8[:])

		encrypt_block(ctx, block_u8[:])
		u128_block(round_u8[:], u128(round))

		xor_block(block_u8[:], round_u8[:])
		xor_block(data[data_size - BLOCK_SIZE_128_U8:], block_u8[:])

		for i := BLOCK_SIZE_128_U8; i + BLOCK_SIZE_128_U8 < data_size; i += BLOCK_SIZE_128_U8 {
			xor_block(data[:BLOCK_SIZE_128_U8], data[i: i + BLOCK_SIZE_128_U8])
		}
	}
}

/* Electronic codebook encryption: belt-encrypt-ecb */
encrypt_ecb :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		encrypt_block(ctx, stream[:BLOCK_SIZE_128_U8])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block_u8: Block128_U8 = ---

		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]
		copy_slice(block_u8[:stream_size], stream[BLOCK_SIZE_128_U8:])
		copy_slice(block_u8[stream_size:], stream[stream_size: BLOCK_SIZE_128_U8])

		encrypt_block(ctx, block_u8[:])
		copy_slice(stream[BLOCK_SIZE_128_U8:], stream[:stream_size])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])
	}
}

/* Electronic codebook encryption: belt-decrypt-ecb */
decrypt_ecb :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		decrypt_block(ctx, stream[:BLOCK_SIZE_128_U8])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block_u8: Block128_U8 = ---

		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]
		copy_slice(block_u8[:stream_size], stream[BLOCK_SIZE_128_U8:])
		copy_slice(block_u8[stream_size:], stream[stream_size: BLOCK_SIZE_128_U8])

		decrypt_block(ctx, block_u8[:])
		copy_slice(stream[BLOCK_SIZE_128_U8:], stream[:stream_size])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])
	}
}

/* Cipher block chaining encryption: belt-encrypt-cbc */
encrypt_cbc :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	copy_slice(block_u8[:], iv)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		encrypt_block(ctx, block_u8[:])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]
		xor_slice(block_u8[:stream_size], stream[BLOCK_SIZE_128_U8:])
		copy_slice(block_u8[stream_size:], stream[stream_size: BLOCK_SIZE_128_U8])

		encrypt_block(ctx, block_u8[:])
		copy_slice(stream[BLOCK_SIZE_128_U8:], stream[:stream_size])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])
	}
}

/* Cipher block chaining encryption: belt-decrypt-cbc */
decrypt_cbc :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	round_u8: Block128_U8 = ---
	copy_slice(round_u8[:], iv)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_256_U8 || stream_size == BLOCK_SIZE_128_U8 {
		copy_slice(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		decrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], round_u8[:])
		copy_slice(round_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		copy_slice(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		decrypt_block(ctx, block_u8[:])

		xor_slice(block_u8[:stream_size - BLOCK_SIZE_128_U8], stream[BLOCK_SIZE_128_U8: stream_size])
		xor_slice(stream[BLOCK_SIZE_128_U8: stream_size], block_u8[:stream_size - BLOCK_SIZE_128_U8])
		xor_slice(block_u8[:stream_size - BLOCK_SIZE_128_U8], stream[BLOCK_SIZE_128_U8: stream_size])
		xor_slice(stream[BLOCK_SIZE_128_U8: stream_size], block_u8[:stream_size - BLOCK_SIZE_128_U8])

		decrypt_block(ctx, block_u8[:])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])
		xor_block(stream[:BLOCK_SIZE_128_U8], round_u8[:])
	}
}

/* Cipher feedback encryption: belt-encrypt-cfb */
encrypt_cfb :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	copy_slice(block_u8[:], iv)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
	}
}

/* Cipher feedback encryption: belt-decrypt-cfb */
decrypt_cfb :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	copy_slice(block_u8[:], iv)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])

		xor_block(stream[:BLOCK_SIZE_128_U8], block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		xor_block(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
	}
}

/* Counter encryption: belt-encrypt-ctr */
encrypt_ctr :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	round_u8: Block128_U8 = ---

	copy_slice(round_u8[:], iv)
	encrypt_block(ctx, round_u8[:])

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		inc_block(round_u8[:])
		copy_slice(block_u8[:], round_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		inc_block(round_u8[:])
		copy_slice(block_u8[:], round_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
	}
}

/* Counter encryption: belt-decrypt-ctr */
decrypt_ctr :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8 = ---
	round_u8: Block128_U8 = ---

	copy_slice(round_u8[:], iv)
	encrypt_block(ctx, round_u8[:])

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		inc_block(round_u8[:])
		copy_slice(block_u8[:], round_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		inc_block(round_u8[:])
		copy_slice(block_u8[:], round_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
	}
}

@(private = "file")
spec_φ1 :: proc "contextless" (data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")

	block: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		block[i] = endian.unchecked_get_u32le(data[4 * i: 4 * i + 4])
	}

	a :: 0; b :: 1; c :: 2; d :: 3
	block[a] ~= block[d]; block[d] ~= block[a]; block[a] ~= block[d]
	block[a] ~= block[b]; block[b] ~= block[a]; block[a] ~= block[b]
	block[b] ~= block[c]; block[c] ~= block[b]; block[b] ~= block[c]
	block[d] ~= block[a]

	for i in 0..<BLOCK_SIZE_128_U32 {
		endian.unchecked_put_u32le(data[4 * i: 4 * i + 4], block[i])
	}
}

@(private = "file")
spec_φ2 :: proc "contextless" (data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")

	block: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		block[i] = endian.unchecked_get_u32le(data[4 * i: 4 * i + 4])
	}

	a :: 0; b :: 1; c :: 2; d :: 3
	block[a] ~= block[d]; block[d] ~= block[a]; block[a] ~= block[d]
	block[b] ~= block[d]; block[d] ~= block[b]; block[b] ~= block[d]
	block[c] ~= block[d]; block[d] ~= block[c]; block[c] ~= block[d]
	block[a] ~= block[b]

	for i in 0..<BLOCK_SIZE_128_U32 {
		endian.unchecked_put_u32le(data[4 * i: 4 * i + 4], block[i])
	}
}

/* Message authentication code derivation: belt-derive-mac */
derive_mac :: proc "contextless" (ctx: Context, mac, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(mac) == MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8
	round_u8: Block128_U8
	mac_u8: Block128_U8

	stream := data
	stream_size := data_size
	encrypt_block(ctx, round_u8[:])
	for stream_size > BLOCK_SIZE_128_U8 {
		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		encrypt_block(ctx, mac_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size == BLOCK_SIZE_128_U8 {
		spec_φ1(round_u8[:])
		xor_block(mac_u8[:], round_u8[:])
		xor_block(mac_u8[:], stream[:])
	} else {
		spec_ψ_unit :: 0x80
		copy_slice(block_u8[:stream_size], stream[:])
		block_u8[stream_size] = spec_ψ_unit

		spec_φ2(round_u8[:])
		xor_block(mac_u8[:], round_u8[:])
		xor_block(mac_u8[:], block_u8[:])
	}

	encrypt_block(ctx, mac_u8[:])
	copy_slice(mac[:], mac_u8[:MAC_SIZE_64_U8])
}

/* Authenticated encryption: belt-seal-dwp */
seal_dwp :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(aad_size != 0, "crypto/belt: invalid AAD size")

	block_u8:  Block128_U8
	rblock_u8: Block128_U8 = ---
	sblock_u8: Block128_U8 = ---
	mblock_u8: Block128_U8 = ---
	mac_u8  := spec_t

	aad_mod  := u64((8 * u128(aad_size))  & u128(max(u64) - 1))
	data_mod := u64((8 * u128(data_size)) & u128(max(u64) - 1))
	endian.unchecked_put_u64le(mblock_u8[:MAC_SIZE_64_U8], aad_mod)
	endian.unchecked_put_u64le(mblock_u8[MAC_SIZE_64_U8:], data_mod)

	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])
	copy_slice(rblock_u8[:], sblock_u8[:])
	encrypt_block(ctx, rblock_u8[:])

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])
		block_u8 = Block128_U8 {}
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		inc_block(sblock_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		inc_block(sblock_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
		block_u8 = Block128_U8 {}

		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])
	}

	xor_block(mac_u8[:], mblock_u8[:])
	mul_block(mac_u8[:], rblock_u8[:])
	encrypt_block(ctx, mac_u8[:])
	copy_slice(mac[:], mac_u8[:mac_size])
}

/* Authenticated encryption: belt-open-dwp */
open_dwp :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(aad_size != 0, "crypto/belt: invalid AAD size")

	block_u8:  Block128_U8
	rblock_u8: Block128_U8 = ---
	sblock_u8: Block128_U8 = ---
	mblock_u8: Block128_U8 = ---
	mac_u8  := spec_t

	aad_mod  := u64((8 * u128(aad_size))  & u128(max(u64) - 1))
	data_mod := u64((8 * u128(data_size)) & u128(max(u64) - 1))
	endian.unchecked_put_u64le(mblock_u8[:MAC_SIZE_64_U8], aad_mod)
	endian.unchecked_put_u64le(mblock_u8[MAC_SIZE_64_U8:], data_mod)

	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])
	copy_slice(rblock_u8[:], sblock_u8[:])
	encrypt_block(ctx, rblock_u8[:])

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])
		block_u8 = Block128_U8 {}
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		inc_block(sblock_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block_u8 = Block128_U8 {}
		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])

		inc_block(sblock_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
	}

	xor_block(mac_u8[:], mblock_u8[:])
	mul_block(mac_u8[:], rblock_u8[:])
	encrypt_block(ctx, mac_u8[:])

	if runtime.memory_compare(raw_data(mac), &mac_u8[0], mac_size) == 0 {
		return true
	} else {
		intrinsics.mem_zero(raw_data(mac), mac_size)
		intrinsics.mem_zero(raw_data(data), data_size)
		return false
	}
}

/* Authenticated encryption: belt-seal-che */
seal_che :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(aad_size != 0, "crypto/belt: invalid AAD size")

	block_u8:  Block128_U8
	rblock_u8: Block128_U8 = ---
	sblock_u8: Block128_U8 = ---
	mblock_u8: Block128_U8 = ---
	cblock_u8 := spec_c
	mac_u8    := spec_t

	aad_mod  := u64((8 * u128(aad_size))  & u128(max(u64) - 1))
	data_mod := u64((8 * u128(data_size)) & u128(max(u64) - 1))
	endian.unchecked_put_u64le(mblock_u8[:MAC_SIZE_64_U8], aad_mod)
	endian.unchecked_put_u64le(mblock_u8[MAC_SIZE_64_U8:], data_mod)

	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])
	copy_slice(rblock_u8[:], sblock_u8[:])

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])
		block_u8 = Block128_U8 {}
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		mul_block(sblock_u8[:], cblock_u8[:])
		u128_block(block_u8[:], 1)
		xor_block(sblock_u8[:], block_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		mul_block(sblock_u8[:], cblock_u8[:])
		u128_block(block_u8[:], 1)
		xor_block(sblock_u8[:], block_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
		block_u8 = Block128_U8 {}

		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])
	}

	xor_block(mac_u8[:], mblock_u8[:])
	mul_block(mac_u8[:], rblock_u8[:])
	encrypt_block(ctx, mac_u8[:])
	copy_slice(mac[:], mac_u8[:mac_size])
}

/* Authenticated encryption: belt-open-che */
open_che :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(aad_size != 0, "crypto/belt: invalid AAD size")

	block_u8:  Block128_U8
	rblock_u8: Block128_U8 = ---
	sblock_u8: Block128_U8 = ---
	mblock_u8: Block128_U8 = ---
	cblock_u8 := spec_c
	mac_u8    := spec_t

	aad_mod  := u64((8 * u128(aad_size))  & u128(max(u64) - 1))
	data_mod := u64((8 * u128(data_size)) & u128(max(u64) - 1))
	endian.unchecked_put_u64le(mblock_u8[:MAC_SIZE_64_U8], aad_mod)
	endian.unchecked_put_u64le(mblock_u8[MAC_SIZE_64_U8:], data_mod)

	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])
	copy_slice(rblock_u8[:], sblock_u8[:])

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])
		block_u8 = Block128_U8 {}
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		xor_block(mac_u8[:], stream[:BLOCK_SIZE_128_U8])
		mul_block(mac_u8[:], rblock_u8[:])

		mul_block(sblock_u8[:], cblock_u8[:])
		u128_block(block_u8[:], 1)
		xor_block(sblock_u8[:], block_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_block(block_u8[:], stream[:BLOCK_SIZE_128_U8])
		copy_slice(stream[:BLOCK_SIZE_128_U8], block_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block_u8 = Block128_U8 {}
		copy_slice(block_u8[:stream_size], stream[:])
		xor_block(mac_u8[:], block_u8[:])
		mul_block(mac_u8[:], rblock_u8[:])

		mul_block(sblock_u8[:], cblock_u8[:])
		u128_block(block_u8[:], 1)
		xor_block(sblock_u8[:], block_u8[:])
		copy_slice(block_u8[:], sblock_u8[:])
		encrypt_block(ctx, block_u8[:])
		xor_slice(block_u8[:stream_size], stream[:])
		copy_slice(stream[:], block_u8[:stream_size])
	}

	xor_block(mac_u8[:], mblock_u8[:])
	mul_block(mac_u8[:], rblock_u8[:])
	encrypt_block(ctx, mac_u8[:])

	if runtime.memory_compare(raw_data(mac), &mac_u8[0], mac_size) == 0 {
		return true
	} else {
		intrinsics.mem_zero(raw_data(mac), mac_size)
		intrinsics.mem_zero(raw_data(data), data_size)
		return false
	}
}

/* Key wrap encryption: belt-seal-kwp */
seal_kwp :: proc "contextless" (ctx: Context, cipher, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(cipher) == data_size + BLOCK_SIZE_128_U8, "crypto/belt: invalid CIPHER size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	copy_slice(cipher[:data_size], data)
	copy_slice(cipher[data_size:], iv)
	encrypt_wide_block(ctx, cipher)
}

/* Key wrap encryption: belt-open-kwp */
open_kwp :: proc "contextless" (ctx: Context, cipher, iv, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); cipher_size := len(cipher); iv_size := len(iv)

	ensure_contextless(cipher_size == data_size + BLOCK_SIZE_128_U8, "crypto/belt: invalid CIPHER size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(iv_size == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block_u8: Block128_U8
	decrypt_wide_block(ctx, cipher)
	copy_slice(block_u8[:], cipher[data_size:])

	if runtime.memory_compare(raw_data(iv), &block_u8[0], iv_size) == 0 {
		copy_slice(data, cipher[:data_size])
		return true
	} else {
		intrinsics.mem_zero(raw_data(iv), iv_size)
		intrinsics.mem_zero(raw_data(data), data_size)
		intrinsics.mem_zero(raw_data(cipher), cipher_size)
		return false
	}
}

@(private = "package")
spec_compress :: proc "contextless" (dummy, compr, data: []byte) #no_bounds_check {
	assert_contextless(len(dummy) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DUMMY size")
	assert_contextless(len(compr) == BLOCK_SIZE_256_U8, "crypto/belt: invalid COMPR size")
	assert_contextless(len(data)  == BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")

	ctx: Context = ---
	block_u8: Block128_U8 = ---
	key_u8:   Key256_U8   = ---

	block_a := data[:BLOCK_SIZE_128_U8]
	block_b := data[BLOCK_SIZE_128_U8:]
	block_c := compr[:BLOCK_SIZE_128_U8]
	block_d := compr[BLOCK_SIZE_128_U8:]

	copy_slice(block_u8[:], block_c)
	xor_block(block_u8[:], block_d)

	copy_slice(dummy, block_u8[:])
	copy_slice(key_u8[:BLOCK_SIZE_128_U8], block_a)
	copy_slice(key_u8[BLOCK_SIZE_128_U8:], block_b)

	init(&ctx, key_u8[:])
	encrypt_block(ctx, block_u8[:])
	xor_block(dummy, block_u8[:])

	copy_slice(block_u8[:], block_c)
	copy_slice(compr[:BLOCK_SIZE_128_U8], block_a)
	copy_slice(key_u8[:BLOCK_SIZE_128_U8], dummy)
	copy_slice(key_u8[BLOCK_SIZE_128_U8:], block_d)

	init(&ctx, key_u8[:])
	encrypt_block(ctx, compr[:BLOCK_SIZE_128_U8])
	xor_block(compr[:BLOCK_SIZE_128_U8], block_a)

	copy_slice(compr[BLOCK_SIZE_128_U8:], block_b)
	neg_block(key_u8[:BLOCK_SIZE_128_U8], dummy)
	copy_slice(key_u8[BLOCK_SIZE_128_U8:], block_u8[:])

	init(&ctx, key_u8[:])
	encrypt_block(ctx, compr[BLOCK_SIZE_128_U8:])
	xor_block(compr[BLOCK_SIZE_128_U8:], block_b)
}

/* Hash derivation: belt-derive-hash */
derive_hash :: proc "contextless" (hash, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(hash) == BLOCK_SIZE_256_U8, "crypto/belt: invalid HASH size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	hblock_u8 := spec_h
	tblock_u8: Block128_U8 = ---
	rblock_u8: Block256_U8
	u128_block(rblock_u8[:BLOCK_SIZE_128_U8], 8 * u128(data_size))

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_256_U8 {
		spec_compress(tblock_u8[:], hblock_u8[:], stream[:BLOCK_SIZE_256_U8])
		xor_block(rblock_u8[BLOCK_SIZE_128_U8:], tblock_u8[:])

		stream = stream[BLOCK_SIZE_256_U8:]
		stream_size -= BLOCK_SIZE_256_U8
	}

	if stream_size > 0 {
		block_u8: Block256_U8
		copy_slice(block_u8[:stream_size], stream)
		spec_compress(tblock_u8[:], hblock_u8[:], block_u8[:])
		xor_block(rblock_u8[BLOCK_SIZE_128_U8:], tblock_u8[:])
	}

	spec_compress(tblock_u8[:], hblock_u8[:], rblock_u8[:])
	copy_slice(hash, hblock_u8[:])
}

/* Block level encryption: belt-encrypt-bde */
encrypt_bde :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8 && data_size & (BLOCK_SIZE_128_U8 - 1) == 0, "crypto/belt: invalid DATA size")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	sblock_u8: Block128_U8 = ---
	cblock_u8 := spec_c

	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		mul_block(sblock_u8[:], cblock_u8[:])
		xor_block(stream[:BLOCK_SIZE_128_U8], sblock_u8[:])
		encrypt_block(ctx, stream[:BLOCK_SIZE_128_U8])
		xor_block(stream[:BLOCK_SIZE_128_U8], sblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}
}

/* Block level encryption: belt-decrypt-bde */
decrypt_bde :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8 && data_size & (BLOCK_SIZE_128_U8 - 1) == 0, "crypto/belt: invalid DATA size")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	sblock_u8: Block128_U8 = ---
	cblock_u8 := spec_c

	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		mul_block(sblock_u8[:], cblock_u8[:])
		xor_block(stream[:BLOCK_SIZE_128_U8], sblock_u8[:])
		decrypt_block(ctx, stream[:BLOCK_SIZE_128_U8])
		xor_block(stream[:BLOCK_SIZE_128_U8], sblock_u8[:])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}
}

/* Sector level encryption: belt-encrypt-sde */
encrypt_sde :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_256_U8 && data_size & (BLOCK_SIZE_128_U8 - 1) == 0, "crypto/belt: invalid DATA size")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	sblock_u8: Block128_U8 = ---
	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])

	xor_block(data[:BLOCK_SIZE_128_U8], sblock_u8[:])
	encrypt_wide_block(ctx, data)
	xor_block(data[:BLOCK_SIZE_128_U8], sblock_u8[:])
}

/* Sector level encryption: belt-decrypt-sde */
decrypt_sde :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_256_U8 && data_size & (BLOCK_SIZE_128_U8 - 1) == 0, "crypto/belt: invalid DATA size")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	sblock_u8: Block128_U8 = ---
	copy_slice(sblock_u8[:], iv)
	encrypt_block(ctx, sblock_u8[:])

	xor_block(data[:BLOCK_SIZE_128_U8], sblock_u8[:])
	decrypt_wide_block(ctx, data)
	xor_block(data[:BLOCK_SIZE_128_U8], sblock_u8[:])
}

/* Expand key {128, 192} to key {256}: belt-expand-key */
expand_key :: proc "contextless" (dst, src: []byte) #no_bounds_check {
	src_size := len(src)
	ensure_contextless(len(dst) == KEY_SIZE_256_U8, "crypto/belt: invalid DST size")

	if src_size == KEY_SIZE_128_U8 {
		copy_slice(dst[:KEY_SIZE_128_U8], src)
		copy_slice(dst[KEY_SIZE_128_U8:], src)
	} else if src_size == KEY_SIZE_192_U8 {
		copy_slice(dst[:KEY_SIZE_192_U8], src)
		copy_slice(dst[24:28], src[0:4])
		copy_slice(dst[28:32], src[12:16])
		xor_slice(dst[24:28], src[4:8])
		xor_slice(dst[24:28], src[8:12])
		xor_slice(dst[28:32], src[16:20])
		xor_slice(dst[28:32], src[20:24])
	} else if src_size == KEY_SIZE_256_U8 {
		copy_slice(dst, src)
	} else {
		ensure_contextless(false, "crypto/belt: invalid SRC size")
	}
}

/* Derive key {128, 192, 256} from key {128, 192, 256}: belt-derive-key */
derive_key :: proc "contextless" (dv, iv, dst, src: []byte) #no_bounds_check {
	dst_size := len(dst); src_size := len(src)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(len(dv) == BLOCK_SIZE_96_U8, "crypto/belt: invalid DV size")

	tblock_u8: Block128_U8 = ---
	rblock_u8: Block256_U8 = ---
	sblock_u8: Key256_U8 = ---

	if src_size == KEY_SIZE_128_U8 && dst_size == KEY_SIZE_128_U8 {
		rblock_u8 = spec_r1
	} else if src_size == KEY_SIZE_192_U8 && dst_size == KEY_SIZE_128_U8 {
		rblock_u8 = spec_r2
	} else if src_size == KEY_SIZE_192_U8 && dst_size == KEY_SIZE_192_U8 {
		rblock_u8 = spec_r3
	} else if src_size == KEY_SIZE_256_U8 && dst_size == KEY_SIZE_128_U8 {
		rblock_u8 = spec_r4
	} else if src_size == KEY_SIZE_256_U8 && dst_size == KEY_SIZE_192_U8 {
		rblock_u8 = spec_r5
	} else if src_size == KEY_SIZE_256_U8 && dst_size == KEY_SIZE_256_U8 {
		rblock_u8 = spec_r6
	} else {
		ensure_contextless(false, "crypto/belt: invalid SRC or DST size")
	}

	expand_key(sblock_u8[:], src)
	copy_slice(rblock_u8[BLOCK_SIZE_128_U8:], iv)
	copy_slice(rblock_u8[BLOCK_SIZE_32_U8: BLOCK_SIZE_128_U8], dv)
	spec_compress(tblock_u8[:], sblock_u8[:], rblock_u8[:])
	copy_slice(dst, sblock_u8[:dst_size])
}

/* Reorder the lanes of a Block128_U32 block */
@(private = "file")
swizzle_block :: proc "contextless" (x: Block128_U32, indices: ..int) -> Block128_U32 #no_bounds_check {
	result: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		result[i] = x[indices[i]]
	}
	return result
}

/* Reorder the lanes of two Block128_U32 blocks */
@(private = "file")
shuffle_block :: proc "contextless" (a, b: Block128_U32, indices: ..int) -> Block128_U32 #no_bounds_check {
	result: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		idx := indices[i]
		if idx < BLOCK_SIZE_128_U32 {
			result[i] = a[idx]
		} else {
			result[i] = b[idx - BLOCK_SIZE_128_U32]
		}
	}
	return result
}

/* Shift left lanes of a Block128_U32 block */
@(private = "file")
shl_block :: proc "contextless" (a: Block128_U32, shift: u32) -> Block128_U32 #no_bounds_check {
	result: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		if shift < 8 * size_of(u32) {
			result[i] = a[i] << shift
		} else {
			result[i] = 0
		}
	}
	return result
}

/* Shift right lanes of a Block128_U32 block */
@(private = "file")
shr_block :: proc "contextless" (a: Block128_U32, shift: u32) -> Block128_U32 #no_bounds_check {
	result: Block128_U32 = ---
	for i in 0..<BLOCK_SIZE_128_U32 {
		if shift < 8 * size_of(u32) {
			result[i] = a[i] >> shift
		} else {
			result[i] = 0
		}
	}
	return result
}

/* Software alternative to _mm_clmulepi64_si128(a, b, 0x00) */
@(private = "file")
clmul_low :: proc "contextless" (x, y: Block128_U32) -> Block128_U32 #no_bounds_check {
	result: u128
	a := (transmute(Block128_U64)x)[0]
	b := (transmute(Block128_U64)y)[0]
	for i := uint(0); i < 8 * size_of(u64); i += 1 {
		result ~= (u128(a) << i) * u128((b >> i) & 1)
	}
	return transmute(Block128_U32)result
}

/* Software alternative to _mm_clmulepi64_si128(a, b, 0x11) */
@(private = "file")
clmul_high :: proc "contextless" (x, y: Block128_U32) -> Block128_U32 #no_bounds_check {
	result: u128
	a := (transmute(Block128_U64)x)[1]
	b := (transmute(Block128_U64)y)[1]
	for i := uint(0); i < 8 * size_of(u64); i += 1 {
		result ~= (u128(a) << i) * u128((b >> i) & 1)
	}
	return transmute(Block128_U32)result
}

/* Intel Carry-Less Multiplication Instruction */
/* and its Usage for Computing the GCM Mode    */
@(private = "file")
gf128mul :: proc "contextless" (a, b: Block128_U32) -> Block128_U32 #no_bounds_check {
	temp0, temp1, temp2, temp3, temp4: Block128_U32
	temp5, temp6, temp7, temp8, temp9: Block128_U32
	mask := Block128_U32 {max(u32), 0, 0, 0}
	temp0 = clmul_low(a, b)
	temp3 = clmul_high(a, b)
	temp1 = swizzle_block(a, 2, 3, 0, 1)
	temp2 = swizzle_block(b, 2, 3, 0, 1)
	temp1 = temp1 ~ a
	temp2 = temp2 ~ b
	temp1 = clmul_low(temp1, temp2)
	temp1 = temp1 ~ temp0
	temp1 = temp1 ~ temp3
	temp2 = shuffle_block(temp1, Block128_U32{}, 4, 5, 0, 1)
	temp1 = shuffle_block(Block128_U32{}, temp1, 6, 7, 0, 1)
	temp0 = temp0 ~ temp2
	temp3 = temp3 ~ temp1
	temp4 = shr_block(temp3, 31)
	temp5 = shr_block(temp3, 30)
	temp6 = shr_block(temp3, 25)
	temp4 = temp4 ~ temp5
	temp4 = temp4 ~ temp6
	temp5 = swizzle_block(temp4, 3, 0, 1, 2)
	temp4 = mask & temp5
	temp5 = temp5 &~ mask
	temp0 = temp0 ~ temp5
	temp3 = temp3 ~ temp4
	temp7 = shl_block(temp3, 1)
	temp0 = temp0 ~ temp7
	temp8 = shl_block(temp3, 2)
	temp0 = temp0 ~ temp8
	temp9 = shl_block(temp3, 7)
	temp0 = temp0 ~ temp9
	return temp0 ~ temp3
}

@(private = "package")
mul_block :: proc "contextless" (dst, src: []byte) #no_bounds_check {
	assert_contextless(len(dst) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DST size")
	assert_contextless(len(src) == BLOCK_SIZE_128_U8, "crypto/belt: invalid SRC size")

	when ODIN_ARCH == .amd64 || ODIN_ARCH == .arm64 {
		if is_hardware_accelerated() {
			dst_block := intrinsics.unaligned_load((^Simd_Block128)(raw_data(dst)))
			src_block := intrinsics.unaligned_load((^Simd_Block128)(raw_data(src)))
			dst_block  = gf128mulhw(dst_block, src_block)
			intrinsics.unaligned_store((^Simd_Block128)(raw_data(dst)), dst_block)
		} else {
			dst_block: Block128_U32 = ---
			src_block: Block128_U32 = ---
			for i in 0..<BLOCK_SIZE_128_U32 {
				src_block[i] = endian.unchecked_get_u32le(src[4 * i: 4 * i + 4])
				dst_block[i] = endian.unchecked_get_u32le(dst[4 * i: 4 * i + 4])
			}
			dst_block = gf128mul(dst_block, src_block)
			for i in 0..<BLOCK_SIZE_128_U32 {
				endian.unchecked_put_u32le(dst[4 * i: 4 * i + 4], dst_block[i])
			}
		}
	} else {
		dst_block: Block128_U32 = ---
		src_block: Block128_U32 = ---
		for i in 0..<BLOCK_SIZE_128_U32 {
			src_block[i] = endian.unchecked_get_u32le(src[4 * i: 4 * i + 4])
			dst_block[i] = endian.unchecked_get_u32le(dst[4 * i: 4 * i + 4])
		}
		dst_block = gf128mul(dst_block, src_block)
		for i in 0..<BLOCK_SIZE_128_U32 {
			endian.unchecked_put_u32le(dst[4 * i: 4 * i + 4], dst_block[i])
		}
	}
}

@(private = "file")
binary_search :: proc "contextless" (array: []u32, key: u32) -> (int, bool) #no_bounds_check {
	array_size := len(array)
	left, right := 0, array_size
	for left < right {
		mid := int(uint(left + right) / 2)
		if array[mid] < key {
			left = mid + 1
		} else {
			right = mid
		}
	}
	return left, left < array_size && array[left] == key
}

/* compute `b = ceil(0.015625 * n * log2(m))` in constant time */
spec_find_b :: proc "contextless" (m, n: u32) -> u32 {
	assert_contextless(m >= 2 && m <= 65536, "crypto/belt: invalid M value")
	assert_contextless(n >= 1 && n <= 32768, "crypto/belt: invalid N value")

	if spec_b_key, ok := binary_search(spec_b_keys[:], m << 15 | n); ok {
		return spec_b_values[spec_b_key]
	}

	k := u32(8 * size_of(m) - intrinsics.count_leading_zeros(m))
	if u32(1) << k - u32(m) > u32(m) - (u32(1) << (k - 1)) {
		k -= 1
	}

	k0 := u128(k)
	k1 := u128(1) << k
	k2 := k1 << k
	k3 := k2 << k
	k4 := k3 << k

	m1 := u128(m)
	m2 := m1 * m1
	m3 := m2 * m1
	m4 := m3 * m1

	num := m3 * k1 * (5025408 * k0 + 12083552)
	num += m1 * k3 * (5025408 * k0 - 12083552)
	num += m4 * (314088 * k0 + 1888055)
	num += k4 * (314088 * k0 - 1888055)
	num += 11307168 * m2 * k2 * k0
	num *= u128(n)

	den := 36 * k2 * m2
	den += 16 * k1 * m3
	den += 16 * k3 * m1
	den += m4 + k4
	den *= 20101632

	return u32((num + den - 1) / den)
}

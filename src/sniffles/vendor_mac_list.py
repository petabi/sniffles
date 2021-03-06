"""
    Vendor OUI for use in Ethernet MAC addresses.
    Used when the OUI are not provided in a MAC
    definition list.
"""
VENDOR_MAC_OUI = [[oui >> 16, (oui & 0xff00) >> 8, oui & 0xff] for oui in [
    0x000001,
    0x000002,
    0x000009,
    0x00000C,
    0x00000E,
    0x00000F,
    0x000010,
    0x000011,
    0x000015,
    0x000018,
    0x00001A,
    0x00001B,
    0x00001C,
    0x00001D,
    0x00001F,
    0x000020,
    0x000021,
    0x000022,
    0x000023,
    0x000024,
    0x000029,
    0x00002A,
    0x00002C,
    0x000032,
    0x000037,
    0x00003B,
    0x00003C,
    0x00003D,
    0x00003F,
    0x000044,
    0x000046,
    0x000048,
    0x000049,
    0x00004B,
    0x00004C,
    0x00004F,
    0x000051,
    0x000052,
    0x000055,
    0x000058,
    0x00005A,
    0x00005A,
    0x00005B,
    0x00005D,
    0x00005E,
    0x00005F,
    0x000061,
    0x000062,
    0x000063,
    0x000064,
    0x000065,
    0x000066,
    0x000068,
    0x000069,
    0x00006B,
    0x00006D,
    0x00006E,
    0x00006F,
    0x000073,
    0x000075,
    0x000077,
    0x000078,
    0x000079,
    0x00007A,
    0x00007B,
    0x00007D,
    0x00007E,
    0x00007F,
    0x000080,
    0x000081,
    0x000083,
    0x000084,
    0x000086,
    0x000087,
    0x000089,
    0x00008A,
    0x00008E,
    0x000092,
    0x000093,
    0x000094,
    0x000095,
    0x000097,
    0x000098,
    0x000099,
    0x00009F,
    0x0000A0,
    0x0000A2,
    0x0000A3,
    0x0000A4,
    0x0000A5,
    0x0000A6,
    0x0000A7,
    0x0000A8,
    0x0000A9,
    0x0000AA,
    0x0000AC,
    0x0000AE,
    0x0000AF,
    0x0000B0,
    0x0000B1,
    0x0000B3,
    0x0000B4,
    0x0000B5,
    0x0000B6,
    0x0000B7,
    0x0000BB,
    0x0000BC,
    0x0000C0,
    0x0000C1,
    0x0000C5,
    0x0000C6,
    0x0000C8,
    0x0000C9,
    0x0000CA,
    0x0000CC,
    0x0000CD,
    0x0000D0,
    0x0000D1,
    0x0000D2,
    0x0000D3,
    0x0000D4,
    0x0000D7,
    0x0000D8,
    0x0000DD,
    0x0000DE,
    0x0000E1,
    0x0000E2,
    0x0000E3,
    0x0000E4,
    0x0000E6,
    0x0000E8,
    0x0000E9,
    0x0000ED,
    0x0000EE,
    0x0000EF,
    0x0000F0,
    0x0000F2,
    0x0000F3,
    0x0000F4,
    0x0000F6,
    0x0000F8,
    0x0000FB,
    0x0000FD,
    0x0000FF,
    0x000102,
    0x000143,
    0x000150,
    0x000163,
    0x000168,
    0x0001C8,
    0x0001FA,
    0x000204,
    0x000205,
    0x000216,
    0x000288,
    0x0003C6,
    0x000400,
    0x0004AC,
    0x000502,
    0x00059A,
    0x0005A8,
    0x00060D,
    0x000629,
    0x00067C,
    0x0006C1,
    0x000701,
    0x00070D,
    0x000852,
    0x000855,
    0x0008C7,
    0x001007,
    0x00100B,
    0x00100D,
    0x001011,
    0x00101F,
    0x001029,
    0x00102F,
    0x00104B,
    0x00105A,
    0x001060,
    0x001079,
    0x00107A,
    0x00107B,
    0x001083,
    0x0010A4,
    0x0010A6,
    0x0010D7,
    0x0010F6,
    0x001700,
    0x002000,
    0x002005,
    0x002008,
    0x00200C,
    0x002011,
    0x002017,
    0x002018,
    0x00201A,
    0x002025,
    0x002028,
    0x002029,
    0x00202B,
    0x002035,
    0x002036,
    0x002042,
    0x002045,
    0x002048,
    0x00204B,
    0x00204C,
    0x002056,
    0x002061,
    0x002063,
    0x002066,
    0x002067,
    0x00206B,
    0x002078,
    0x002085,
    0x00208A,
    0x00208B,
    0x00208C,
    0x002094,
    0x0020A5,
    0x0020A6,
    0x0020A7,
    0x0020AF,
    0x0020B2,
    0x0020B6,
    0x0020B9,
    0x0020C5,
    0x0020C6,
    0x0020D0,
    0x0020D2,
    0x0020D3,
    0x0020D8,
    0x0020DA,
    0x0020DC,
    0x0020E0,
    0x0020E5,
    0x0020EE,
    0x0020F6,
    0x0020F8,
    0x0020FC,
    0x004001,
    0x004005,
    0x004009,
    0x00400B,
    0x00400C,
    0x00400D,
    0x004010,
    0x004011,
    0x004013,
    0x004014,
    0x004015,
    0x004017,
    0x00401C,
    0x00401F,
    0x004020,
    0x004023,
    0x004025,
    0x004026,
    0x004027,
    0x004028,
    0x00402A,
    0x00402B,
    0x00402F,
    0x004030,
    0x004032,
    0x004033,
    0x004036,
    0x004039,
    0x00403C,
    0x004041,
    0x004043,
    0x004048,
    0x00404C,
    0x00404D,
    0x00404F,
    0x004050,
    0x004052,
    0x004053,
    0x004054,
    0x004057,
    0x004059,
    0x00405B,
    0x00405D,
    0x004066,
    0x004067,
    0x004068,
    0x004069,
    0x00406A,
    0x00406E,
    0x00406F,
    0x004072,
    0x004074,
    0x004076,
    0x004078,
    0x00407F,
    0x004082,
    0x004085,
    0x004086,
    0x004087,
    0x004088,
    0x00408A,
    0x00408C,
    0x00408E,
    0x00408F,
    0x004090,
    0x004091,
    0x004092,
    0x004094,
    0x004095,
    0x004096,
    0x00409A,
    0x00409C,
    0x00409D,
    0x00409E,
    0x00409F,
    0x0040A4,
    0x0040A6,
    0x0040AA,
    0x0040AD,
    0x0040AE,
    0x0040AF,
    0x0040B4,
    0x0040B5,
    0x0040B6,
    0x0040B9,
    0x0040BD,
    0x0040C1,
    0x0040C2,
    0x0040C3,
    0x0040C5,
    0x0040C6,
    0x0040C7,
    0x0040C8,
    0x0040CC,
    0x0040CF,
    0x0040D0,
    0x0040D2,
    0x0040D4,
    0x0040D7,
    0x0040D8,
    0x0040DC,
    0x0040DF,
    0x0040E1,
    0x0040E2,
    0x0040E3,
    0x0040E5,
    0x0040E7,
    0x0040E9,
    0x0040EA,
    0x0040ED,
    0x0040F0,
    0x0040F1,
    0x0040F4,
    0x0040F5,
    0x0040F6,
    0x0040F9,
    0x0040FA,
    0x0040FB,
    0x0040FD,
    0x0040FF,
    0x004854,
    0x004F49,
    0x004F4B,
    0x005004,
    0x00500F,
    0x00504D,
    0x00504E,
    0x005050,
    0x005069,
    0x0050BD,
    0x0050E2,
    0x005500,
    0x006008,
    0x006009,
    0x006025,
    0x00602F,
    0x006030,
    0x00603E,
    0x006047,
    0x00604E,
    0x006052,
    0x00605C,
    0x006067,
    0x006070,
    0x006083,
    0x00608C,
    0x006094,
    0x006097,
    0x0060B0,
    0x0060F5,
    0x008000,
    0x008001,
    0x008004,
    0x008005,
    0x008006,
    0x008007,
    0x008009,
    0x00800D,
    0x00800F,
    0x008010,
    0x008012,
    0x008013,
    0x008015,
    0x008016,
    0x008017,
    0x008019,
    0x00801A,
    0x00801B,
    0x00801C,
    0x008021,
    0x008023,
    0x008024,
    0x008026,
    0x008029,
    0x00802A,
    0x00802C,
    0x00802D,
    0x00802E,
    0x008033,
    0x008034,
    0x008035,
    0x008037,
    0x008038,
    0x00803B,
    0x00803D,
    0x00803E,
    0x00803F,
    0x008042,
    0x008043,
    0x008045,
    0x008046,
    0x008048,
    0x008049,
    0x00804C,
    0x00804D,
    0x008051,
    0x008052,
    0x008057,
    0x00805A,
    0x00805B,
    0x00805C,
    0x00805F,
    0x008060,
    0x008062,
    0x008063,
    0x008064,
    0x008067,
    0x008069,
    0x00806A,
    0x00806B,
    0x00806C,
    0x00806D,
    0x00806E,
    0x00806F,
    0x008071,
    0x008072,
    0x008074,
    0x008079,
    0x00807B,
    0x00807C,
    0x00807D,
    0x008082,
    0x008086,
    0x008087,
    0x00808A,
    0x00808B,
    0x00808C,
    0x00808D,
    0x00808E,
    0x008090,
    0x008092,
    0x008093,
    0x008094,
    0x008096,
    0x008098,
    0x00809A,
    0x00809B,
    0x00809D,
    0x00809F,
    0x0080A1,
    0x0080A3,
    0x0080A6,
    0x0080A7,
    0x0080AD,
    0x0080AE,
    0x0080AF,
    0x0080B1,
    0x0080B2,
    0x0080B6,
    0x0080BA,
    0x0080C0,
    0x0080C2,
    0x0080C6,
    0x0080C7,
    0x0080C8,
    0x0080C9,
    0x0080CE,
    0x0080D0,
    0x0080D3,
    0x0080D4,
    0x0080D6,
    0x0080D7,
    0x0080D8,
    0x0080DA,
    0x0080E0,
    0x0080E3,
    0x0080E7,
    0x0080EA,
    0x0080F0,
    0x0080F1,
    0x0080F3,
    0x0080F4,
    0x0080F5,
    0x0080F7,
    0x0080FB,
    0x0080FE,
    0x009004,
    0x009027,
    0x0090B1,
    0x00902B,
    0x009086,
    0x009092,
    0x0090AB,
    0x0090B1,
    0x0090F2,
    0x00A000,
    0x00A00C,
    0x00A024,
    0x00A040,
    0x00A04B,
    0x00A073,
    0x00A083,
    0x00A092,
    0x00A0AE,
    0x00A0C8,
    0x00A0C9,
    0x00A0CC,
    0x00A0D1,
    0x00A0D2,
    0x00AA00,
    0x00B0D0,
    0x00C000,
    0x00C001,
    0x00C002,
    0x00C003,
    0x00C004,
    0x00C005,
    0x00C006,
    0x00C007,
    0x00C008,
    0x00C009,
    0x00C00A,
    0x00C00B,
    0x00C00C,
    0x00C00D,
    0x00C00E,
    0x00C00F,
    0x00C011,
    0x00C012,
    0x00C013,
    0x00C014,
    0x00C015,
    0x00C016,
    0x00C017,
    0x00C018,
    0x00C01A,
    0x00C01B,
    0x00C01C,
    0x00C01D,
    0x00C01F,
    0x00C020,
    0x00C021,
    0x00C023,
    0x00C024,
    0x00C025,
    0x00C027,
    0x00C028,
    0x00C029,
    0x00C02A,
    0x00C02B,
    0x00C02C,
    0x00C02D,
    0x00C02E,
    0x00C02F,
    0x00C030,
    0x00C031,
    0x00C032,
    0x00C033,
    0x00C034,
    0x00C035,
    0x00C036,
    0x00C039,
    0x00C03B,
    0x00C03C,
    0x00C03D,
    0x00C03E,
    0x00C03F,
    0x00C040,
    0x00C041,
    0x00C042,
    0x00C043,
    0x00C044,
    0x00C045,
    0x00C046,
    0x00C047,
    0x00C048,
    0x00C049,
    0x00C04D,
    0x00C04E,
    0x00C04F,
    0x00C050,
    0x00C051,
    0x00C055,
    0x00C056,
    0x00C057,
    0x00C058,
    0x00C059,
    0x00C05B,
    0x00C05C,
    0x00C05D,
    0x00C05E,
    0x00C060,
    0x00C061,
    0x00C063,
    0x00C064,
    0x00C065,
    0x00C066,
    0x00C067,
    0x00C068,
    0x00C069,
    0x00C06A,
    0x00C06B,
    0x00C06C,
    0x00C06D,
    0x00C06F,
    0x00C070,
    0x00C071,
    0x00C072,
    0x00C073,
    0x00C074,
    0x00C075,
    0x00C076,
    0x00C077,
    0x00C078,
    0x00C079,
    0x00C07A,
    0x00C07B,
    0x00C07D,
    0x00C07F,
    0x00C080,
    0x00C081,
    0x00C082,
    0x00C084,
    0x00C085,
    0x00C086,
    0x00C087,
    0x00C089,
    0x00C08A,
    0x00C08B,
    0x00C08C,
    0x00C08D,
    0x00C08E,
    0x00C08F,
    0x00C090,
    0x00C091,
    0x00C092,
    0x00C093,
    0x00C095,
    0x00C096,
    0x00C097,
    0x00C098,
    0x00C09B,
    0x00C09C,
    0x00C09D,
    0x00C09F,
    0x00C0A0,
    0x00C0A1,
    0x00C0A2,
    0x00C0A3,
    0x00C0A4,
    0x00C0A7,
    0x00C0A8,
    0x00C0A9,
    0x00C0AA,
    0x00C0AB,
    0x00C0AC,
    0x00C0AD,
    0x00C0AE,
    0x00C0B0,
    0x00C0B2,
    0x00C0B3,
    0x00C0B4,
    0x00C0B5,
    0x00C0B6,
    0x00C0B7,
    0x00C0B8,
    0x00C0B9,
    0x00C0BA,
    0x00C0BB,
    0x00C0BD,
    0x00C0BE,
    0x00C0BF,
    0x00C0C0,
    0x00C0C1,
    0x00C0C2,
    0x00C0C3,
    0x00C0C4,
    0x00C0C5,
    0x00C0C6,
    0x00C0C8,
    0x00C0C9,
    0x00C0CA,
    0x00C0CB,
    0x00C0CD,
    0x00C0D0,
    0x00C0D1,
    0x00C0D2,
    0x00C0D4,
    0x00C0D5,
    0x00C0D6,
    0x00C0D9,
    0x00C0DB,
    0x00C0DC,
    0x00C0DE,
    0x00C0DF,
    0x00C0E1,
    0x00C0E2,
    0x00C0E3,
    0x00C0E4,
    0x00C0E5,
    0x00C0E6,
    0x00C0E7,
    0x00C0E8,
    0x00C0E9,
    0x00C0EA,
    0x00C0EC,
    0x00C0ED,
    0x00C0EE,
    0x00C0EF,
    0x00C0F0,
    0x00C0F1,
    0x00C0F2,
    0x00C0F3,
    0x00C0F4,
    0x00C0F5,
    0x00C0F6,
    0x00C0F7,
    0x00C0F8,
    0x00C0FA,
    0x00C0FB,
    0x00C0FC,
    0x00C0FD,
    0x00C0FF,
    0x00DD00,
    0x00DD01,
    0x00DD08,
    0x00E011,
    0x00E014,
    0x00E016,
    0x00E018,
    0x00E01E,
    0x00E029,
    0x00E02C,
    0x00E034,
    0x00E039,
    0x00E04F,
    0x00E07D,
    0x00E081,
    0x00E083,
    0x00E08F,
    0x00E098,
    0x00E0A3,
    0x00E0B0,
    0x00E0B8,
    0x00E0C5,
    0x00E0ED,
    0x00E0F7,
    0x00E0F9,
    0x00E0FE,
    0x020406,
    0x020701,
    0x020701,
    0x026060,
    0x026086,
    0x02608C,
    0x02A0C9,
    0x02AA3C,
    0x02CF1F,
    0x02E03B,
    0x02E6D3,
    0x048845,
    0x080001,
    0x080002,
    0x080003,
    0x080005,
    0x080006,
    0x080007,
    0x080008,
    0x080009,
    0x08000A,
    0x08000B,
    0x08000D,
    0x08000E,
    0x08000F,
    0x080010,
    0x080011,
    0x080014,
    0x080017,
    0x08001A,
    0x08001B,
    0x08001E,
    0x08001F,
    0x080020,
    0x080022,
    0x080023,
    0x080025,
    0x080026,
    0x080027,
    0x080028,
    0x08002B,
    0x08002E,
    0x08002F,
    0x080030,
    0x080032,
    0x080036,
    0x080037,
    0x080038,
    0x080039,
    0x08003B,
    0x08003D,
    0x08003E,
    0x080041,
    0x080044,
    0x080045,
    0x080046,
    0x080047,
    0x080048,
    0x080049,
    0x08004C,
    0x08004E,
    0x080051,
    0x080056,
    0x080057,
    0x080058,
    0x08005A,
    0x080066,
    0x080067,
    0x080068,
    0x080069,
    0x08006A,
    0x08006E,
    0x080070,
    0x080074,
    0x080075,
    0x080077,
    0x080079,
    0x08007C,
    0x080080,
    0x080081,
    0x080083,
    0x080086,
    0x080087,
    0x080088,
    0x080089,
    0x08008B,
    0x08008D,
    0x08008E,
    0x08008F,
    0x080090,
    0x09006A,
    0x10005A,
    0x100090,
    0x1000D4,
    0x1000E0,
    0x2E2E2E,
    0x3C0000,
    0x400003,
    0x444553,
    0x444649,
    0x475443,
    0x484453,
    0x484C00,
    0x4854E8,
    0x4C424C,
    0x525400,
    0x52544C,
    0x5254AB,
    0x565857,
    0x800010,
    0x80AD00,
    0xAA0000,
    0xAA0001,
    0xAA0002,
    0xAA0003,
    0xAA0004,
    0xC00000,
    0xEC1000,
    0xE20C0F,
]]

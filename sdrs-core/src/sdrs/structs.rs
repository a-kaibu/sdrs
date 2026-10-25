use std::fmt;

use crate::utils::read_ascii_string;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct SdrsFlags(pub u32);

impl SdrsFlags {
    pub const USE_COMMAND_LINE_SHORT_PATH: Self = Self(0x0000_0001);
    pub const USE_DEFAULT_DISPLAY_SETTING: Self = Self(0x0000_0002);
    pub const AUTO_VERIFY: Self = Self(0x0000_0004);
    pub const USE_EXECUTABLE_FILE_NAME_ARGUMENT: Self = Self(0x0000_0008);
    pub const ALLOW_MULTI_PROCESS: Self = Self(0x0000_0010);
    pub const UC_SCID_CHARGE_DIALOG: Self = Self(0x0000_0020);
    pub const EXECUTABLE_FILE_NOT_PACK: Self = Self(0x0000_0040);
    pub const SHOW_SOFT_DC_DIALOG: Self = Self(0x0000_0080);
    pub const USE_TEMP_PATH: Self = Self(0x0000_0100);
    pub const USE_LOCK_FILE: Self = Self(0x0000_0200);
    pub const UC_DIALOG_VERSION3: Self = Self(0x0000_0400);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl fmt::Display for SdrsFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const FLAGS: [(u32, &str); 11] = [
            (0x0000_0001, "UseCommandLineShortPath"),
            (0x0000_0002, "UseDefaultDisplaySetting"),
            (0x0000_0004, "AutoVerify"),
            (0x0000_0008, "UseExecutableFileNameArgument"),
            (0x0000_0010, "AllowMultiProcess"),
            (0x0000_0020, "UCScidChargeDialog"),
            (0x0000_0040, "ExecutableFileNotPack"),
            (0x0000_0080, "ShowSoftDCDialog"),
            (0x0000_0100, "UseTempPath"),
            (0x0000_0200, "UseLockFile"),
            (0x0000_0400, "UCDialogVersion3"),
        ];

        let mut residue = self.0;
        let mut known = Vec::new();
        for (flag, name) in FLAGS {
            if residue & flag == flag {
                known.push(name);
                residue ^= flag;
            }
        }

        if known.is_empty() {
            write!(f, "{}", self.0)
        } else if residue != 0 {
            write!(f, "{}, {residue}", known.join(", "))
        } else {
            write!(f, "{}", known.join(", "))
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct SdrsHeader {
    pub version: u32,
    pub hash: u32,
    pub key: u32,
    pub reserve1: u32,
}

impl SdrsHeader {
    pub fn read(data: &[u8]) -> Option<Self> {
        if data.len() < 0x10 {
            return None;
        }
        let get = |offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };
        Some(Self {
            version: get(0),
            hash: get(4),
            key: get(8),
            reserve1: get(12),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct SdrsConfig {
    pub mode: SdrsFlags,
}

impl SdrsConfig {
    pub fn read(data: &[u8]) -> Option<Self> {
        if data.len() < 0x40 {
            return None;
        }
        Some(Self {
            mode: SdrsFlags(u32::from_le_bytes([
                data[0x3C], data[0x3D], data[0x3E], data[0x3F],
            ])),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum SdrsPatchMode {
    #[default]
    None,
    ExecutableOnly,
    File,
    Memory,
}

impl fmt::Display for SdrsPatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::None => "None",
            Self::ExecutableOnly => "ExecutableOnly",
            Self::File => "File",
            Self::Memory => "Memory",
        };
        write!(f, "{text}")
    }
}

#[derive(Clone, Default, Debug)]
pub struct SdrsPatch {
    pub file_name: String,
    pub position: u32,
    pub length: u32,
    pub signature1: u32,
    pub signature2: u32,
    pub reserve1: u32,
    pub mode: SdrsPatchMode,
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

pub fn read_patch_v1(data: &[u8]) -> Option<SdrsPatch> {
    if data.len() < 0x10 {
        return None;
    }
    Some(SdrsPatch {
        file_name: String::new(),
        position: read_u32(data, 0)?,
        length: 0,
        signature1: read_u32(data, 4)?,
        signature2: read_u32(data, 8)?,
        reserve1: 0,
        mode: SdrsPatchMode::None,
    })
}

pub fn read_patch_v2(data: &[u8]) -> Option<SdrsPatch> {
    if data.len() < 0x114 {
        return None;
    }
    Some(SdrsPatch {
        file_name: read_ascii_string(&data[..0x100], Some(0x80)),
        position: read_u32(data, 0x100)?,
        signature1: read_u32(data, 0x104)?,
        length: read_u32(data, 0x108)?,
        signature2: read_u32(data, 0x10C)?,
        reserve1: read_u32(data, 0x110)?,
        mode: SdrsPatchMode::None,
    })
}

pub fn read_patch_v3(data: &[u8]) -> Option<SdrsPatch> {
    if data.len() < 0x94 {
        return None;
    }
    Some(SdrsPatch {
        file_name: read_ascii_string(&data[..0x80], None),
        position: read_u32(data, 0x80)?,
        signature1: read_u32(data, 0x84)?,
        length: read_u32(data, 0x88)?,
        signature2: read_u32(data, 0x8C)?,
        reserve1: read_u32(data, 0x90)?,
        mode: SdrsPatchMode::None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_read() {
        let mut data = vec![0u8; 0x10];
        data[0..4].copy_from_slice(&0x3257_6453u32.to_le_bytes());
        data[4..8].copy_from_slice(&0xBEEFu32.to_le_bytes());
        data[8..12].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let header = SdrsHeader::read(&data).unwrap();
        assert_eq!(header.version, 0x3257_6453);
        assert_eq!(header.hash, 0xBEEF);
        assert_eq!(header.key, 0x1234_5678);
        assert!(SdrsHeader::read(&[0u8; 4]).is_none());
        assert!(SdrsHeader::read(&[0u8; 15]).is_none());
    }

    #[test]
    fn config_mode_offset() {
        let mut data = vec![0u8; 0x40];
        data[0x3C..0x40].copy_from_slice(&0x0000_0140u32.to_le_bytes());
        let config = SdrsConfig::read(&data).unwrap();
        assert_eq!(config.mode, SdrsFlags(0x140));
        assert!(config.mode.contains(SdrsFlags::USE_TEMP_PATH));
        assert!(config.mode.contains(SdrsFlags::EXECUTABLE_FILE_NOT_PACK));
        assert!(!config.mode.contains(SdrsFlags::SHOW_SOFT_DC_DIALOG));
    }

    #[test]
    fn patch_v2_layout() {
        let mut data = vec![0u8; 0x114];
        let mut name = vec![0u8; 0x100];
        name[..5].copy_from_slice(b"a.exe");
        name[5] = 0;
        data[..0x100].copy_from_slice(&name);
        data[0x100..0x104].copy_from_slice(&0x10u32.to_le_bytes());
        data[0x104..0x108].copy_from_slice(&0x20u32.to_le_bytes());
        data[0x108..0x10C].copy_from_slice(&0x30u32.to_le_bytes());
        data[0x10C..0x110].copy_from_slice(&0x40u32.to_le_bytes());
        data[0x110..0x114].copy_from_slice(&0x50u32.to_le_bytes());
        let patch = read_patch_v2(&data).unwrap();
        assert_eq!(patch.file_name, "a.exe");
        assert_eq!(patch.position, 0x10);
        assert_eq!(patch.signature1, 0x20);
        assert_eq!(patch.length, 0x30);
        assert_eq!(patch.signature2, 0x40);
        assert_eq!(patch.reserve1, 0x50);
        assert_eq!(patch.mode, SdrsPatchMode::None);
    }

    #[test]
    fn patch_v3_layout() {
        let mut data = vec![0u8; 0x94];
        data[0..8].copy_from_slice(b"b.dat\0\0\0");
        data[0x80..0x84].copy_from_slice(&0x11u32.to_le_bytes());
        data[0x84..0x88].copy_from_slice(&0x22u32.to_le_bytes());
        data[0x88..0x8C].copy_from_slice(&0x33u32.to_le_bytes());
        let patch = read_patch_v3(&data).unwrap();
        assert_eq!(patch.file_name, "b.dat");
        assert_eq!(patch.position, 0x11);
        assert_eq!(patch.signature1, 0x22);
        assert_eq!(patch.length, 0x33);
        assert_eq!(patch.signature2, 0);
        assert_eq!(patch.reserve1, 0);
    }

    #[test]
    fn patch_v3_limit_requires_nul() {
        let mut data = vec![0xFF; 0x94];
        assert_eq!(read_patch_v3(&data).unwrap().file_name, "");
        data[0] = b'a';
        assert_eq!(read_patch_v3(&data).unwrap().file_name, "");
        data[1] = 0;
        assert_eq!(read_patch_v3(&data).unwrap().file_name, "a");
    }

    #[test]
    fn flags_display() {
        assert_eq!(SdrsFlags(0).to_string(), "0");
        assert_eq!(SdrsFlags(0x100).to_string(), "UseTempPath");
        assert_eq!(
            SdrsFlags(0x1C0).to_string(),
            "ExecutableFileNotPack, ShowSoftDCDialog, UseTempPath"
        );
        assert_eq!(SdrsFlags(0x4000).to_string(), "16384");
        assert_eq!(
            SdrsFlags(0x4001).to_string(),
            "UseCommandLineShortPath, 16384"
        );
    }
}

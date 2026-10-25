use std::fmt;

use crate::sdrs::crypto::decrypt_v1;
use crate::sdrs::hash::crc32;
use crate::sdrs::structs::{
    read_patch_v1, read_patch_v2, read_patch_v3, SdrsConfig, SdrsFlags, SdrsHeader, SdrsPatch,
    SdrsPatchMode,
};
use crate::utils::read_ascii_string;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SdrsLevel {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
}

impl fmt::Display for SdrsLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::V1 => "V1",
            Self::V2 => "V2",
            Self::V3 => "V3",
            Self::V4 => "V4",
            Self::V5 => "V5",
            Self::V6 => "V6",
            Self::V7 => "V7",
        };
        write!(f, "{text}")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StubError {
    Invalid,
    UnknownVersion,
    HashInvalid,
}

impl StubError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid => "Stubデータが無効です",
            Self::UnknownVersion => "Stubバージョンが不明です",
            Self::HashInvalid => "Stubデータの検証に失敗しました",
        }
    }
}

impl fmt::Display for StubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for StubError {}

pub const HEADER_VERSION_V1: u32 = 0x0057_6453;
pub const HEADER_VERSION_V2: u32 = 0x3257_6453;
pub const HEADER_VERSION_V3: u32 = 0x3357_6453;
pub const HEADER_VERSION_V4: u32 = 0x3457_6453;
pub const HEADER_VERSION_V5: u32 = 0x3557_6453;
pub const HEADER_VERSION_V6: u32 = 0x3657_6453;
pub const HEADER_VERSION_V7: u32 = 0x3757_6453;

const ARG_SIZE_V1: u32 = 0x140;
const ARG_SIZE_V2: u32 = 0x1180;
const ARG_SIZE_V3: u32 = 0x1280;
const ARG_SIZE_V4: u32 = 0x9540;

const ARG_ALIGN_V1: u32 = 0x1000;
const ARG_ALIGN_V2: u32 = 0x2000;
const ARG_ALIGN_V3: u32 = 0x2000;
const ARG_ALIGN_V4: u32 = 0x1_0000;

const SECTION_NAMES_SIZE: u32 = 0x100;

const ENTRY_COUNT_V1: usize = 16;
const ENTRY_SIZE_V1: usize = 0x10;
const ENTRY_COUNT_V2: usize = 16;
const ENTRY_SIZE_V2: usize = 0x114;
const ENTRY_COUNT_V4: usize = 256;
const ENTRY_SIZE_V4: usize = 0x94;

#[derive(Debug)]
pub struct SdrsStub {
    level: SdrsLevel,
    size: u32,
    align_size: u32,
    header: SdrsHeader,
    config: SdrsConfig,
    patches: Vec<SdrsPatch>,
    executable_file_name: String,
}

impl SdrsStub {
    fn new(version: u32) -> Option<Self> {
        let (level, size, align_size) = match version {
            HEADER_VERSION_V1 => (SdrsLevel::V1, ARG_SIZE_V1, ARG_ALIGN_V1),
            HEADER_VERSION_V2 => (SdrsLevel::V2, ARG_SIZE_V2, ARG_ALIGN_V2),
            HEADER_VERSION_V3 => (SdrsLevel::V3, ARG_SIZE_V3, ARG_ALIGN_V3),
            HEADER_VERSION_V4 => (SdrsLevel::V4, ARG_SIZE_V4, ARG_ALIGN_V4),
            HEADER_VERSION_V5 => (SdrsLevel::V5, ARG_SIZE_V4, ARG_ALIGN_V4),
            HEADER_VERSION_V6 => (SdrsLevel::V6, ARG_SIZE_V4, ARG_ALIGN_V4),
            HEADER_VERSION_V7 => (SdrsLevel::V7, ARG_SIZE_V4, ARG_ALIGN_V4),
            _ => return None,
        };

        Some(Self {
            level,
            size,
            align_size,
            header: SdrsHeader::default(),
            config: SdrsConfig::default(),
            patches: Vec::new(),
            executable_file_name: String::new(),
        })
    }

    pub fn level(&self) -> SdrsLevel {
        self.level
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn align_size(&self) -> u32 {
        self.align_size
    }

    pub fn header(&self) -> SdrsHeader {
        self.header
    }

    pub fn config(&self) -> SdrsConfig {
        self.config
    }

    pub fn patches(&self) -> &[SdrsPatch] {
        &self.patches
    }

    #[must_use]
    pub fn executable_file_name(&self) -> &str {
        let mode = self.config.mode;
        if (mode.contains(SdrsFlags::USE_EXECUTABLE_FILE_NAME_ARGUMENT)
            || mode.contains(SdrsFlags::EXECUTABLE_FILE_NOT_PACK))
            && !self.executable_file_name.is_empty()
        {
            &self.executable_file_name
        } else {
            "main.bin"
        }
    }

    #[must_use]
    pub fn decrypt_resource(
        &self,
        data: &mut [u8],
        key: u32,
        signature1: u32,
        signature2: u32,
        packed_mode: bool,
    ) -> bool {
        if data.len() < 4 {
            return false;
        }

        let mut sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        //非パック(解読)モード / パック(暗号化)モード
        let replacement = if packed_mode {
            if sig != signature1 {
                return false;
            }
            signature2
        } else {
            if sig != signature2 {
                return false;
            }
            signature1
        };
        sig = replacement;

        data[..4].copy_from_slice(&sig.to_le_bytes());

        if data.len() > 4 {
            decrypt_v1(&mut data[4..], key);
        }
        true
    }

    pub fn set_arguments(&mut self, header: SdrsHeader, args: &mut [u8]) -> Result<(), StubError> {
        self.header = header;

        decrypt_v1(args, header.key);

        if crc32(args) != header.hash {
            return Err(StubError::HashInvalid);
        }

        self.config = SdrsConfig::read(args).ok_or(StubError::Invalid)?;

        let cfg_size = 0x40usize;
        self.parse_patch_arguments(args.get(cfg_size..).ok_or(StubError::Invalid)?)?;

        self.refresh_patch_mode();
        Ok(())
    }

    fn parse_patch_arguments(&mut self, args: &[u8]) -> Result<(), StubError> {
        match self.level {
            SdrsLevel::V1 => {
                if args.len() < ENTRY_COUNT_V1 * ENTRY_SIZE_V1 {
                    return Err(StubError::Invalid);
                }
                for i in 0..ENTRY_COUNT_V1 {
                    let patch =
                        read_patch_v1(&args[i * ENTRY_SIZE_V1..]).ok_or(StubError::Invalid)?;
                    self.patches.push(patch);
                }
            }
            SdrsLevel::V2 => {
                if args.len() < ENTRY_COUNT_V2 * ENTRY_SIZE_V2 {
                    return Err(StubError::Invalid);
                }
                for i in 0..ENTRY_COUNT_V2 {
                    let patch =
                        read_patch_v2(&args[i * ENTRY_SIZE_V2..]).ok_or(StubError::Invalid)?;
                    self.patches.push(patch);
                }
            }
            SdrsLevel::V3 => {
                if args.len() < SECTION_NAMES_SIZE as usize + ENTRY_COUNT_V2 * ENTRY_SIZE_V2 {
                    return Err(StubError::Invalid);
                }

                let name_offset = args.len() - SECTION_NAMES_SIZE as usize;
                self.executable_file_name = read_ascii_string(&args[name_offset..], None);

                let patch_args = &args[..name_offset];
                for i in 0..ENTRY_COUNT_V2 {
                    let patch = read_patch_v2(&patch_args[i * ENTRY_SIZE_V2..])
                        .ok_or(StubError::Invalid)?;
                    self.patches.push(patch);
                }
            }
            SdrsLevel::V4 | SdrsLevel::V5 | SdrsLevel::V6 | SdrsLevel::V7 => {
                if args.len() < SECTION_NAMES_SIZE as usize + ENTRY_COUNT_V4 * ENTRY_SIZE_V4 {
                    return Err(StubError::Invalid);
                }

                for i in 0..ENTRY_COUNT_V4 {
                    let patch =
                        read_patch_v3(&args[i * ENTRY_SIZE_V4..]).ok_or(StubError::Invalid)?;
                    self.patches.push(patch);
                }

                let name_offset = args.len() - SECTION_NAMES_SIZE as usize;
                self.executable_file_name = read_ascii_string(&args[name_offset..], None);
            }
        }
        Ok(())
    }

    pub fn refresh_patch_mode(&mut self) {
        let use_temp_path = self.config.mode.contains(SdrsFlags::USE_TEMP_PATH);

        for patch in &mut self.patches {
            if use_temp_path {
                patch.mode = if patch.position != 0 || !patch.file_name.is_empty() {
                    SdrsPatchMode::ExecutableOnly
                } else {
                    SdrsPatchMode::None
                };
            } else {
                patch.mode = if patch.position != 0 || !patch.file_name.is_empty() {
                    if !patch.file_name.is_empty() {
                        SdrsPatchMode::File
                    } else {
                        SdrsPatchMode::Memory
                    }
                } else {
                    SdrsPatchMode::None
                };
            }
        }
    }
}

pub fn create_factory(data: &[u8]) -> Result<SdrsStub, StubError> {
    let header = SdrsHeader::read(data).ok_or(StubError::Invalid)?;

    let mut stub = SdrsStub::new(header.version).ok_or(StubError::UnknownVersion)?;

    let args_len = stub.size as usize;
    let args_src = data.get(0x10..0x10 + args_len).ok_or(StubError::Invalid)?;
    let mut args = args_src.to_vec();

    stub.set_arguments(header, &mut args)?;

    Ok(stub)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_args(mode: u32, key: u32, patches: &[(String, u32, u32, u32, u32)]) -> Vec<u8> {
        let mut args = vec![0u8; ARG_SIZE_V2 as usize];
        args[0x3C..0x40].copy_from_slice(&mode.to_le_bytes());
        for (i, (name, position, length, signature1, signature2)) in patches.iter().enumerate() {
            let base = 0x40 + i * ENTRY_SIZE_V2;
            args[base..base + name.len()].copy_from_slice(name.as_bytes());
            args[base + 0x100..base + 0x104].copy_from_slice(&position.to_le_bytes());
            args[base + 0x104..base + 0x108].copy_from_slice(&signature1.to_le_bytes());
            args[base + 0x108..base + 0x10C].copy_from_slice(&length.to_le_bytes());
            args[base + 0x10C..base + 0x110].copy_from_slice(&signature2.to_le_bytes());
        }

        let hash = crc32(&args);
        let mut data = Vec::new();
        data.extend_from_slice(&HEADER_VERSION_V2.to_le_bytes());
        data.extend_from_slice(&hash.to_le_bytes());
        data.extend_from_slice(&key.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let args = {
            let mut args = args;
            decrypt_v1(&mut args, key);
            args
        };

        data.extend_from_slice(&args);
        data
    }

    #[test]
    fn create_v2_factory_and_patch_modes() {
        const KEY: u32 = 0x1234_5678;
        const SIG1: u32 = 0x89AB_CDEF;
        const SIG2: u32 = 0x1122_3344;

        let data = v2_args(
            0,
            KEY,
            &[
                ("data.bin".to_string(), 0x100, 0x20, SIG1, SIG2),
                (String::new(), 0x10, 0, 0, 0),
            ],
        );

        let stub = create_factory(&data).expect("create_factory");
        assert_eq!(stub.level(), SdrsLevel::V2);
        assert_eq!(stub.size(), ARG_SIZE_V2);
        assert_eq!(stub.align_size(), ARG_ALIGN_V2);
        assert_eq!(stub.header().key, KEY);
        assert_eq!(stub.patches().len(), 16);
        assert_eq!(stub.patches()[0].mode, SdrsPatchMode::File);
        assert_eq!(stub.patches()[0].file_name, "data.bin");
        assert_eq!(stub.patches()[0].position, 0x100);
        assert_eq!(stub.patches()[0].length, 0x20);
        assert_eq!(stub.patches()[1].mode, SdrsPatchMode::Memory);
        assert_eq!(stub.patches()[2].mode, SdrsPatchMode::None);
    }

    #[test]
    fn executable_file_name_fallback() {
        let data = v2_args(SdrsFlags::USE_EXECUTABLE_FILE_NAME_ARGUMENT.0, 0, &[]);
        let stub = create_factory(&data).expect("create_factory");
        assert_eq!(stub.executable_file_name(), "main.bin");
    }

    #[test]
    fn temp_path_forces_executable_only() {
        let data = v2_args(
            SdrsFlags::USE_TEMP_PATH.0,
            0,
            &[
                ("data.bin".to_string(), 0x100, 0x20, 1, 2),
                (String::new(), 0, 0, 0, 0),
            ],
        );
        let stub = create_factory(&data).expect("create_factory");
        assert_eq!(stub.patches()[0].mode, SdrsPatchMode::ExecutableOnly);
        assert_eq!(stub.patches()[1].mode, SdrsPatchMode::None);
    }

    #[test]
    fn unknown_version_rejected() {
        let mut data = vec![0u8; 0x10];
        data[0..4].copy_from_slice(&0x9999_9999u32.to_le_bytes());
        data[4..8].copy_from_slice(&crc32(&[0u8; 8]).to_le_bytes());
        assert!(matches!(
            create_factory(&data),
            Err(StubError::UnknownVersion)
        ));
    }

    #[test]
    fn hash_mismatch_rejected() {
        let mut data = v2_args(0, 0, &[]);
        let key_offset = 8;
        data[key_offset..key_offset + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(matches!(create_factory(&data), Err(StubError::HashInvalid)));
    }

    #[test]
    fn truncated_stream_rejected() {
        let mut data = vec![0u8; 0x10];
        data[0..4].copy_from_slice(&HEADER_VERSION_V2.to_le_bytes());
        data[4..8].copy_from_slice(&crc32(&[0u8; 4]).to_le_bytes());
        assert!(matches!(create_factory(&data), Err(StubError::Invalid)));
    }

    #[test]
    fn decrypt_resource_signatures() {
        let stub = SdrsStub::new(HEADER_VERSION_V2).unwrap();

        let mut data = 0x89AB_CDEFu32.to_le_bytes().to_vec();
        data.extend_from_slice(b"payload");
        assert!(stub.decrypt_resource(&mut data, 0, 0x89AB_CDEF, 0x1122_3344, true));
        assert_eq!(&data[..4], &0x1122_3344u32.to_le_bytes());

        let mut data = 0x89AB_CDEFu32.to_le_bytes().to_vec();
        data.extend_from_slice(b"payload");
        assert!(!stub.decrypt_resource(&mut data, 0, 0, 0x1122_3344, true));

        let mut data = 0x89AB_CDEFu32.to_le_bytes().to_vec();
        data.extend_from_slice(b"payload");
        assert!(!stub.decrypt_resource(&mut data, 0, 0x89AB_CDEF, 0x1122_3344, false));

        let mut data = vec![0u8; 3];
        assert!(!stub.decrypt_resource(&mut data, 0, 0, 0, false));

        let mut data = 0x89AB_CDEFu32.to_le_bytes().to_vec();
        assert!(stub.decrypt_resource(&mut data, 0, 0x89AB_CDEF, 0x1122_3344, true));
        assert_eq!(&data[..4], &0x1122_3344u32.to_le_bytes());
    }

    #[test]
    fn decrypt_resource_roundtrip() {
        let stub = SdrsStub::new(HEADER_VERSION_V2).unwrap();
        let key = 0x1234_5678u32;

        let plain = {
            let mut v = 0xAABB_CCDDu32.to_le_bytes().to_vec();
            v.extend_from_slice(b"secret data body");
            v
        };

        let mut encrypted = {
            let mut v = 0xDEAD_BEEFu32.to_le_bytes().to_vec();
            v.extend_from_slice(&plain[4..]);
            decrypt_v1(&mut v[4..], key);
            v
        };

        assert!(stub.decrypt_resource(&mut encrypted, key, 0xAABB_CCDD, 0xDEAD_BEEF, false));
        assert_eq!(encrypted, plain);
    }
}

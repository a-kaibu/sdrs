use std::fmt;

pub const DOS_HEADER_SIZE: usize = 0x40;
pub const FILE_HEADER_SIZE: usize = 0x14;
pub const SECTION_HEADER_SIZE: usize = 0x28;
pub const OPTIONAL_HEADER_SIZE: usize = 0xE0;

const PE_SIGNATURE: u32 = 0x0000_4550;
const MZ_SIGNATURE: u16 = 0x5A4D;
const MACHINE_IA32: u16 = 0x014C;
const MACHINE_AMD64: u16 = 0x8664;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bits {
    X32,
    X64,
}

#[derive(Clone, Copy, Debug)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

impl ImageDosHeader {
    pub fn is_valid(&self) -> bool {
        self.e_magic == MZ_SIGNATURE
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_data_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl ImageFileHeader {
    pub fn is_32bit(&self) -> bool {
        self.machine == MACHINE_IA32
    }

    pub fn is_64bit(&self) -> bool {
        self.machine == MACHINE_AMD64
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub load_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: [ImageDataDirectory; 16],
}

#[derive(Clone, Debug)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub load_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: [ImageDataDirectory; 16],
}

#[derive(Clone, Copy, Debug)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_of_raw_data: u32,
    pub pointer_of_relocations: u32,
    pub pointer_of_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl ImageSectionHeader {
    pub fn section_name(&self) -> String {
        self.name
            .iter()
            .map(|&b| if b < 0x80 { b as char } else { '?' })
            .collect::<String>()
            .trim_end_matches('\0')
            .to_string()
    }
}

#[derive(Clone, Debug)]
pub enum OptionalHeader {
    X32(ImageOptionalHeader32),
    X64(ImageOptionalHeader64),
}

#[derive(Clone, Debug)]
pub struct PEFile {
    pub bits: Bits,
    pub dos_header: ImageDosHeader,
    pub file_header: ImageFileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<ImageSectionHeader>,
}

impl fmt::Display for PEFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.bits {
            Bits::X32 => write!(f, "PE32"),
            Bits::X64 => write!(f, "PE64"),
        }
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&data[offset..offset + 2]);
    Some(u16::from_le_bytes(buf))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[offset..offset + 4]);
    Some(u32::from_le_bytes(buf))
}

impl ImageDosHeader {
    fn read(data: &[u8]) -> Option<Self> {
        if data.len() <= DOS_HEADER_SIZE {
            return None;
        }
        Some(Self {
            e_magic: read_u16(data, 0)?,
            e_lfanew: read_u32(data, 0x3C)?,
        })
    }
}

impl ImageFileHeader {
    fn read(data: &[u8], offset: usize) -> Option<Self> {
        if offset + FILE_HEADER_SIZE > data.len() {
            return None;
        }
        Some(Self {
            machine: read_u16(data, offset)?,
            number_of_sections: read_u16(data, offset + 2)?,
            time_data_stamp: read_u32(data, offset + 4)?,
            pointer_to_symbol_table: read_u32(data, offset + 8)?,
            number_of_symbols: read_u32(data, offset + 12)?,
            size_of_optional_header: read_u16(data, offset + 16)?,
            characteristics: read_u16(data, offset + 18)?,
        })
    }
}

fn read_directory(data: &[u8], offset: usize) -> Option<ImageDataDirectory> {
    Some(ImageDataDirectory {
        virtual_address: read_u32(data, offset)?,
        size: read_u32(data, offset + 4)?,
    })
}

impl ImageOptionalHeader32 {
    fn read(data: &[u8]) -> Option<Self> {
        let mut magic_pos = 96usize;
        let mut dirs = [ImageDataDirectory::default(); 16];
        for dir in &mut dirs {
            *dir = read_directory(data, magic_pos)?;
            magic_pos += 8;
        }
        Some(Self {
            magic: read_u16(data, 0)?,
            major_linker_version: *data.get(2)?,
            minor_linker_version: *data.get(3)?,
            size_of_code: read_u32(data, 4)?,
            size_of_initialized_data: read_u32(data, 8)?,
            size_of_uninitialized_data: read_u32(data, 12)?,
            address_of_entry_point: read_u32(data, 16)?,
            base_of_code: read_u32(data, 20)?,
            base_of_data: read_u32(data, 24)?,
            image_base: read_u32(data, 28)?,
            section_alignment: read_u32(data, 32)?,
            file_alignment: read_u32(data, 36)?,
            major_operating_system_version: read_u16(data, 40)?,
            minor_operating_system_version: read_u16(data, 42)?,
            major_image_version: read_u16(data, 44)?,
            minor_image_version: read_u16(data, 46)?,
            major_subsystem_version: read_u16(data, 48)?,
            minor_subsystem_version: read_u16(data, 50)?,
            win32_version_value: read_u32(data, 52)?,
            size_of_image: read_u32(data, 56)?,
            size_of_headers: read_u32(data, 60)?,
            check_sum: read_u32(data, 64)?,
            subsystem: read_u16(data, 68)?,
            dll_characteristics: read_u16(data, 70)?,
            size_of_stack_reserve: read_u32(data, 72)?,
            size_of_stack_commit: read_u32(data, 76)?,
            size_of_heap_reserve: read_u32(data, 80)?,
            size_of_heap_commit: read_u32(data, 84)?,
            load_flags: read_u32(data, 88)?,
            number_of_rva_and_sizes: read_u32(data, 92)?,
            data_directories: dirs,
        })
    }
}

impl ImageOptionalHeader64 {
    fn read(data: &[u8]) -> Option<Self> {
        let mut magic_pos = 112usize;
        let mut dirs = [ImageDataDirectory::default(); 16];
        for dir in &mut dirs {
            *dir = read_directory(data, magic_pos)?;
            magic_pos += 8;
        }
        Some(Self {
            magic: read_u16(data, 0)?,
            major_linker_version: *data.get(2)?,
            minor_linker_version: *data.get(3)?,
            size_of_code: read_u32(data, 4)?,
            size_of_initialized_data: read_u32(data, 8)?,
            size_of_uninitialized_data: read_u32(data, 12)?,
            address_of_entry_point: read_u32(data, 16)?,
            base_of_code: read_u32(data, 20)?,
            image_base: u64::from_le_bytes([
                *data.get(24)?,
                *data.get(25)?,
                *data.get(26)?,
                *data.get(27)?,
                *data.get(28)?,
                *data.get(29)?,
                *data.get(30)?,
                *data.get(31)?,
            ]),
            section_alignment: read_u32(data, 32)?,
            file_alignment: read_u32(data, 36)?,
            major_operating_system_version: read_u16(data, 40)?,
            minor_operating_system_version: read_u16(data, 42)?,
            major_image_version: read_u16(data, 44)?,
            minor_image_version: read_u16(data, 46)?,
            major_subsystem_version: read_u16(data, 48)?,
            minor_subsystem_version: read_u16(data, 50)?,
            win32_version_value: read_u32(data, 52)?,
            size_of_image: read_u32(data, 56)?,
            size_of_headers: read_u32(data, 60)?,
            check_sum: read_u32(data, 64)?,
            subsystem: read_u16(data, 68)?,
            dll_characteristics: read_u16(data, 70)?,
            size_of_stack_reserve: u64::from_le_bytes([
                *data.get(72)?,
                *data.get(73)?,
                *data.get(74)?,
                *data.get(75)?,
                *data.get(76)?,
                *data.get(77)?,
                *data.get(78)?,
                *data.get(79)?,
            ]),
            size_of_stack_commit: u64::from_le_bytes([
                *data.get(80)?,
                *data.get(81)?,
                *data.get(82)?,
                *data.get(83)?,
                *data.get(84)?,
                *data.get(85)?,
                *data.get(86)?,
                *data.get(87)?,
            ]),
            size_of_heap_reserve: u64::from_le_bytes([
                *data.get(88)?,
                *data.get(89)?,
                *data.get(90)?,
                *data.get(91)?,
                *data.get(92)?,
                *data.get(93)?,
                *data.get(94)?,
                *data.get(95)?,
            ]),
            size_of_heap_commit: u64::from_le_bytes([
                *data.get(96)?,
                *data.get(97)?,
                *data.get(98)?,
                *data.get(99)?,
                *data.get(100)?,
                *data.get(101)?,
                *data.get(102)?,
                *data.get(103)?,
            ]),
            load_flags: read_u32(data, 104)?,
            number_of_rva_and_sizes: read_u32(data, 108)?,
            data_directories: dirs,
        })
    }
}

impl ImageSectionHeader {
    fn read(data: &[u8], offset: usize) -> Option<Self> {
        if offset + SECTION_HEADER_SIZE > data.len() {
            return None;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[offset..offset + 8]);
        Some(Self {
            name,
            virtual_size: read_u32(data, offset + 8)?,
            virtual_address: read_u32(data, offset + 12)?,
            size_of_raw_data: read_u32(data, offset + 16)?,
            pointer_of_raw_data: read_u32(data, offset + 20)?,
            pointer_of_relocations: read_u32(data, offset + 24)?,
            pointer_of_linenumbers: read_u32(data, offset + 28)?,
            number_of_relocations: read_u16(data, offset + 32)?,
            number_of_linenumbers: read_u16(data, offset + 34)?,
            characteristics: read_u32(data, offset + 36)?,
        })
    }
}

impl PEFile {
    pub fn load(bits: Bits, data: &[u8]) -> Option<PEFile> {
        let dos_header = ImageDosHeader::read(data)?;

        if !dos_header.is_valid() {
            return None;
        }

        let pe_offset = dos_header.e_lfanew as usize;
        if data.len() <= pe_offset + FILE_HEADER_SIZE + 4 {
            return None;
        }

        if read_u32(data, pe_offset)? != PE_SIGNATURE {
            return None;
        }

        let file_header = ImageFileHeader::read(data, pe_offset + 4)?;

        let machine_match = match bits {
            Bits::X32 => file_header.is_32bit(),
            Bits::X64 => file_header.is_64bit(),
        };
        if !machine_match {
            return None;
        }

        let option_offset = pe_offset + 4 + FILE_HEADER_SIZE;
        let option_size = OPTIONAL_HEADER_SIZE.min(file_header.size_of_optional_header as usize);
        if option_offset + option_size > data.len() {
            return None;
        }

        let mut option_data = [0u8; OPTIONAL_HEADER_SIZE];
        option_data[..option_size]
            .copy_from_slice(&data[option_offset..option_offset + option_size]);

        let optional_header = match bits {
            Bits::X32 => OptionalHeader::X32(ImageOptionalHeader32::read(&option_data)?),
            Bits::X64 => OptionalHeader::X64(ImageOptionalHeader64::read(&option_data)?),
        };

        let section_offset = option_offset + file_header.size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(file_header.number_of_sections as usize);
        for i in 0..file_header.number_of_sections as usize {
            sections.push(ImageSectionHeader::read(
                data,
                section_offset + SECTION_HEADER_SIZE * i,
            )?);
        }

        Some(PEFile {
            bits,
            dos_header,
            file_header,
            optional_header,
            sections,
        })
    }

    pub fn display(&self) -> &'static str {
        match self.bits {
            Bits::X32 => "PE32",
            Bits::X64 => "PE64",
        }
    }

    pub fn overlay_data_file_offset(&self) -> u32 {
        match self.sections.last() {
            Some(section) => section
                .pointer_of_raw_data
                .wrapping_add(section.size_of_raw_data),
            None => 0,
        }
    }

    #[must_use]
    pub fn rva_to_foa(&self, rva: u32) -> u32 {
        if self.sections.is_empty() {
            return 0;
        }

        let first = &self.sections[0];
        if rva < first.virtual_address && rva < first.pointer_of_raw_data {
            return rva;
        }

        for section in &self.sections {
            if rva >= section.virtual_address
                && rva
                    < section
                        .virtual_address
                        .wrapping_add(section.size_of_raw_data)
            {
                return rva - section.virtual_address + section.pointer_of_raw_data;
            }
        }

        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_with_sections(sections: &[ImageSectionHeader]) -> Vec<u8> {
        let mut data = vec![0u8; DOS_HEADER_SIZE];
        data[0..2].copy_from_slice(&MZ_SIGNATURE.to_le_bytes());
        data[0x3C..0x40].copy_from_slice(&(DOS_HEADER_SIZE as u32).to_le_bytes());

        data.extend_from_slice(&PE_SIGNATURE.to_le_bytes());
        data.extend_from_slice(&MACHINE_IA32.to_le_bytes());
        data.extend_from_slice(&(sections.len() as u16).to_le_bytes());
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&OPTIONAL_HEADER_SIZE_U16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        data.extend_from_slice(&[0u8; OPTIONAL_HEADER_SIZE]);

        for section in sections {
            data.extend_from_slice(&section.name);
            data.extend_from_slice(&section.virtual_size.to_le_bytes());
            data.extend_from_slice(&section.virtual_address.to_le_bytes());
            data.extend_from_slice(&section.size_of_raw_data.to_le_bytes());
            data.extend_from_slice(&section.pointer_of_raw_data.to_le_bytes());
            data.extend_from_slice(&[0u8; 12]);
            data.extend_from_slice(&section.characteristics.to_le_bytes());
        }
        data
    }

    const OPTIONAL_HEADER_SIZE_U16: u16 = 0xE0;

    #[test]
    fn load_pe32() {
        let data = pe_with_sections(&[]);
        let pe = PEFile::load(Bits::X32, &data).expect("load");
        assert_eq!(pe.display(), "PE32");
        assert!(pe.dos_header.is_valid());
        assert_eq!(pe.file_header.number_of_sections, 0);
    }

    #[test]
    fn load_rejects_bad_magic() {
        let mut data = pe_with_sections(&[]);
        data[0] = 0x00;
        assert!(PEFile::load(Bits::X32, &data).is_none());
    }

    #[test]
    fn load_rejects_truncated() {
        let data = pe_with_sections(&[]);
        assert!(PEFile::load(Bits::X64, &data).is_none());
        assert!(PEFile::load(Bits::X32, &data[..0x20]).is_none());
        let mut bad_sign = pe_with_sections(&[]);
        bad_sign[DOS_HEADER_SIZE] = 0x00;
        assert!(PEFile::load(Bits::X32, &bad_sign).is_none());
    }

    #[test]
    fn overlay_offset() {
        let section = ImageSectionHeader {
            name: *b".text\0\0\0",
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x260,
            pointer_of_raw_data: 0x200,
            pointer_of_relocations: 0,
            pointer_of_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x6000_0020,
        };
        let data = pe_with_sections(&[section]);
        let pe = PEFile::load(Bits::X32, &data).expect("load");
        assert_eq!(pe.overlay_data_file_offset(), 0x200 + 0x260);
        assert_eq!(pe.sections[0].section_name(), ".text");
    }

    #[test]
    fn rva_to_foa_regions() {
        let section = ImageSectionHeader {
            name: *b".rdata\0\0",
            virtual_size: 0x800,
            virtual_address: 0x1000,
            size_of_raw_data: 0x800,
            pointer_of_raw_data: 0x400,
            pointer_of_relocations: 0,
            pointer_of_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x4000_0040,
        };
        let data = pe_with_sections(&[section]);
        let pe = PEFile::load(Bits::X32, &data).expect("load");

        assert_eq!(pe.rva_to_foa(0x1004), 0x404);
        assert_eq!(pe.rva_to_foa(0x80), 0x80);
        assert_eq!(pe.rva_to_foa(0x1000), 0x400);
        assert_eq!(pe.rva_to_foa(0x1800), 0x0);
        assert_eq!(pe.rva_to_foa(0xFFF), 0x0);
    }
}

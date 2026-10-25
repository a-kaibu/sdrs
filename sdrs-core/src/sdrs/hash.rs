use std::sync::LazyLock;

static CRC_TABLE: LazyLock<[u32; 256]> = LazyLock::new(|| {
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut v = i << 24;
        for _ in 0..8 {
            if v & 0x8000_0000 == 0 {
                v <<= 1;
            } else {
                v = (v << 1) ^ 0x04C1_1DB7;
            }
        }
        table[i as usize] = v;
    }
    table
});

#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let table = &*CRC_TABLE;
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = table[(((crc >> 24) ^ u32::from(byte)) & 0xFF) as usize] ^ (crc << 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bzip2_check_value() {
        assert_eq!(crc32(b"123456789"), 0xFC89_1918);
    }

    #[test]
    fn empty_input() {
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn sample_data() {
        assert_eq!(crc32(b"sdrsTestData"), 0x977C_79A5);
    }
}

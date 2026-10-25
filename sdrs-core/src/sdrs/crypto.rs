pub struct RandomV1 {
    data: Vec<u32>,
    position: usize,
}

impl RandomV1 {
    pub fn new(seed: u32) -> Self {
        let mut random = Self {
            data: vec![0; 521],
            position: 0,
        };
        random.initialize(seed);
        random.position = 520;
        random
    }

    fn initialize(&mut self, mut seed: u32) {
        let data = &mut self.data;

        for slot in data.iter_mut().take(17) {
            let mut v: u32 = 0;
            for _ in 0..32 {
                seed = seed.wrapping_mul(0x5D58_8B65).wrapping_add(1);
                v >>= 1;
                v |= seed & 0x8000_0000;
            }
            *slot = v;
        }

        data[16] = data[15] ^ (data[0] >> 9) ^ (data[16] << 23);

        for i in 0..504 {
            let v0 = data[i];
            let v1 = data[i + 1];
            let v2 = data[i + 16];
            data[i + 17] = v2 ^ (v1 >> 9) ^ (v0 << 23);
        }

        self.transform();
        self.transform();
        self.transform();
    }

    fn transform(&mut self) {
        let data = &mut self.data;

        for i in 0..32 {
            data[i] ^= data[i + 489];
        }

        for i in 0..489 {
            data[i + 32] ^= data[i];
        }
    }

    pub fn move_next(&mut self) -> u32 {
        let mut pos = self.position + 1;
        if pos >= 521 {
            self.transform();
            pos = 0;
        }
        self.position = pos;
        self.data[pos]
    }
}

pub fn decrypt_v1(bytes: &mut [u8], key: u32) {
    let mut random = RandomV1::new(key);
    for byte in bytes.iter_mut() {
        *byte ^= random.move_next() as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next_n(random: &mut RandomV1, n: usize) -> Vec<u32> {
        (0..n).map(|_| random.move_next()).collect()
    }

    #[test]
    fn key_zero_reference() {
        let mut random = RandomV1::new(0);
        assert_eq!(
            next_n(&mut random, 8),
            vec![
                0x273A_199B,
                0x475E_3D06,
                0x7209_0046,
                0x3F09_1D65,
                0x247F_7C89,
                0xB33D_48B6,
                0x5BD3_0FDF,
                0x1BC6_6F6D,
            ]
        );
    }

    #[test]
    fn key_reference_0x12345678() {
        let mut random = RandomV1::new(0x1234_5678);
        assert_eq!(
            next_n(&mut random, 4),
            vec![0x0432_E2C2, 0xDBCE_2D4B, 0x9B6B_F0B9, 0x2B92_A50A]
        );
    }

    #[test]
    fn key_reference_0xffffffff() {
        let mut random = RandomV1::new(0xFFFF_FFFF);
        assert_eq!(
            next_n(&mut random, 4),
            vec![0x31E9_F5C7, 0x813D_D2D6, 0x56D7_4495, 0x16A8_8E65]
        );
    }

    #[test]
    fn decrypt_reference_0() {
        let mut data: Vec<u8> = (0..32).collect();
        decrypt_v1(&mut data, 0);
        assert_eq!(
            data,
            [
                0x9b, 0x07, 0x44, 0x66, 0x8d, 0xb3, 0xd9, 0x6a, 0x1c, 0xb6, 0x30, 0x73, 0x36, 0x5c,
                0x94, 0xc4, 0xd7, 0xc8, 0x4b, 0xc4, 0x7d, 0xd8, 0x5c, 0x6a, 0x3c, 0x81, 0xa8, 0xbf,
                0x03, 0xbd, 0x5e, 0xf9,
            ]
        );
    }

    #[test]
    fn decrypt_reference_0x12345678() {
        let mut data: Vec<u8> = (0..32).collect();
        decrypt_v1(&mut data, 0x1234_5678);
        assert_eq!(
            data,
            [
                0xc2, 0x4a, 0xbb, 0x09, 0x56, 0x51, 0xa2, 0xb1, 0x6a, 0xf4, 0x7f, 0x4b, 0x41, 0xf4,
                0x16, 0xaf, 0xc1, 0xd6, 0x2d, 0x7e, 0x50, 0x96, 0x6f, 0x50, 0xdc, 0xd6, 0x57, 0x75,
                0x45, 0x0f, 0xd4, 0x07,
            ]
        );
    }

    #[test]
    fn decrypt_reference_0xffffffff() {
        let mut data: Vec<u8> = (0..32).collect();
        decrypt_v1(&mut data, 0xFFFF_FFFF);
        assert_eq!(
            data,
            [
                0xc7, 0xd7, 0x97, 0x66, 0xa1, 0x6b, 0x19, 0x15, 0x2a, 0xf4, 0x9d, 0x58, 0x81, 0x17,
                0x59, 0xfa, 0x1f, 0xf7, 0x56, 0x10, 0x67, 0x09, 0x80, 0xd7, 0x93, 0x24, 0x0b, 0x99,
                0xf0, 0x54, 0x31, 0x7c,
            ]
        );
    }

    #[test]
    fn decrypt_is_involution() {
        let plain: Vec<u8> = (0..64).collect();
        let mut data = plain.clone();
        decrypt_v1(&mut data, 0xDEAD_BEEF);
        assert_ne!(data, plain);
        decrypt_v1(&mut data, 0xDEAD_BEEF);
        assert_eq!(data, plain);
    }
}

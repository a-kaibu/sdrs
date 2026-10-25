use encoding_rs::SHIFT_JIS;

#[must_use]
pub fn read_ascii_string(bytes: &[u8], limit: Option<usize>) -> String {
    let mut length = bytes.len();
    if let Some(limit) = limit {
        length = length.min(limit);
    }

    if length == 0 || bytes[0] == 0 {
        return String::new();
    }

    let mut index = 1;
    while index < length && bytes[index] != 0 {
        index += 1;
    }

    if index == length && bytes[index - 1] != 0 {
        return String::new();
    }

    let (decoded, _, _) = SHIFT_JIS.decode(&bytes[..index]);
    decoded.replace('\u{FFFD}', "?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_nul_terminated() {
        assert_eq!(read_ascii_string(b"game.exe\0garbage", None), "game.exe");
        assert_eq!(read_ascii_string(b"game.exe\0", None), "game.exe");
        assert_eq!(read_ascii_string(b"game.exe\0garbage", Some(5)), "");
    }

    #[test]
    fn empty_cases() {
        assert_eq!(read_ascii_string(b"", None), "");
        assert_eq!(read_ascii_string(b"\0game.exe", None), "");
        assert_eq!(read_ascii_string(b"game.exe", None), "");
        assert_eq!(read_ascii_string(b"g\0ame.exe", None), "g");
    }

    #[test]
    fn limit_includes_nul() {
        assert_eq!(read_ascii_string(b"game.exe\0garbage", Some(9)), "game.exe");
        assert_eq!(read_ascii_string(b"game.exe\0garbage", Some(8)), "");
    }

    #[test]
    fn shift_jis_decode() {
        assert_eq!(
            read_ascii_string(
                &[0x83, 0x51, 0x81, 0x5b, 0x83, 0x80, 0x2e, 0x65, 0x78, 0x65, 0x00],
                None
            ),
            "ゲーム.exe"
        );
        assert_eq!(
            read_ascii_string(
                &[0x83, 0x65, 0x83, 0x58, 0x83, 0x67, 0x2e, 0x64, 0x61, 0x74, 0x00],
                None
            ),
            "テスト.dat"
        );
        assert_eq!(
            read_ascii_string(&[0xb1, 0xb2, 0xb3, 0x2e, 0x65, 0x78, 0x65, 0x00], None),
            "ｱｲｳ.exe"
        );
    }

    #[test]
    fn shift_jis_limit_truncation() {
        assert_eq!(
            read_ascii_string(
                &[0x83, 0x51, 0x81, 0x5b, 0x83, 0x80, 0x2e, 0x65, 0x78, 0x65, 0x00],
                Some(2)
            ),
            ""
        );
        assert_eq!(
            read_ascii_string(
                &[0x83, 0x51, 0x81, 0x5b, 0x83, 0x80, 0x2e, 0x65, 0x78, 0x65, 0x00],
                Some(11)
            ),
            "ゲーム.exe"
        );
    }
}

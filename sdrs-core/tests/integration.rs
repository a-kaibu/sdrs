use std::fs;
use std::path::{Path, PathBuf};

use sdrs_core::pe::{Bits, PEFile};
use sdrs_core::sdrs::crypto::decrypt_v1;
use sdrs_core::sdrs::hash::crc32;
use sdrs_core::sdrs::program::SdrsProgram;
use sdrs_core::sdrs::structs::SdrsPatchMode;
use sdrs_core::sdrs::stub::{HEADER_VERSION_V2, HEADER_VERSION_V4};

const DOS_HEADER_SIZE: usize = 0x40;
const OPTIONAL_HEADER_SIZE: usize = 0xE0;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sdrs-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn dos_header(e_lfanew: u32) -> Vec<u8> {
    let mut data = vec![0u8; DOS_HEADER_SIZE];
    data[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    data[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    data
}

fn file_header(machine: u16, sections: u16) -> [u8; 0x14] {
    let mut data = [0u8; 0x14];
    data[0..2].copy_from_slice(&machine.to_le_bytes());
    data[2..4].copy_from_slice(&sections.to_le_bytes());
    data[16..18].copy_from_slice(&(OPTIONAL_HEADER_SIZE as u16).to_le_bytes());
    data
}

fn section_header(
    name: &[u8; 8],
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_of_raw_data: u32,
) -> [u8; 0x28] {
    let mut data = [0u8; 0x28];
    data[..8].copy_from_slice(name);
    data[8..12].copy_from_slice(&size_of_raw_data.to_le_bytes());
    data[12..16].copy_from_slice(&virtual_address.to_le_bytes());
    data[16..20].copy_from_slice(&size_of_raw_data.to_le_bytes());
    data[20..24].copy_from_slice(&pointer_of_raw_data.to_le_bytes());
    data[36..40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    data
}

fn build_pe(machine: u16, sections: &[[u8; 0x28]]) -> Vec<u8> {
    let mut data = dos_header(DOS_HEADER_SIZE as u32);
    data.extend_from_slice(&0x0000_4550u32.to_le_bytes());
    data.extend_from_slice(&file_header(machine, sections.len() as u16));
    data.extend_from_slice(&[0u8; OPTIONAL_HEADER_SIZE]);
    for section in sections {
        data.extend_from_slice(section);
    }
    data
}

fn game_shell_pe() -> Vec<u8> {
    build_pe(
        0x014C,
        &[section_header(b".bride\0\0", 0x1000, 0x800, 0x400)],
    )
}

fn game_min_pe() -> Vec<u8> {
    build_pe(0x014C, &[])
}

const SHELL_SECTION_RAW_START: usize = 0x400;
const SHELL_SECTION_RAW_SIZE: usize = 0x800;
const SHELL_OVERLAY: usize = SHELL_SECTION_RAW_START + SHELL_SECTION_RAW_SIZE;

fn encrypt_region(mut plain: Vec<u8>, key: u32, signature1: u32, signature2: u32) -> Vec<u8> {
    assert_eq!(plain[0..4], signature1.to_le_bytes());
    plain[0..4].copy_from_slice(&signature2.to_le_bytes());
    decrypt_v1(&mut plain[4..], key);
    plain
}

struct ShellFile {
    bytes: Vec<u8>,
    overlay_offset: usize,
    exe_offset: usize,
}

fn shell_file(
    version: u32,
    arg_size: usize,
    align_size: u32,
    key: u32,
    mode: u32,
    args_fill: impl FnOnce(&mut [u8]),
    exe_bytes: Option<&[u8]>,
) -> ShellFile {
    let mut args = vec![0u8; arg_size];
    args[0x3C..0x40].copy_from_slice(&mode.to_le_bytes());
    args_fill(&mut args);

    let hash = crc32(&args);
    decrypt_v1(&mut args, key);

    let mut bytes = game_shell_pe();

    let overlay_offset = {
        let pe = PEFile::load(Bits::X32, &bytes).expect("shell pe");
        pe.overlay_data_file_offset() as usize
    };

    while bytes.len() < overlay_offset {
        bytes.push(0);
    }

    bytes.extend_from_slice(&{
        let mut header = vec![0u8; 0x10];
        header[0..4].copy_from_slice(&version.to_le_bytes());
        header[4..8].copy_from_slice(&hash.to_le_bytes());
        header[8..12].copy_from_slice(&key.to_le_bytes());
        header
    });
    bytes.extend_from_slice(&args);

    let exe_offset = if let Some(exe_bytes) = exe_bytes {
        let exe_offset = overlay_offset + align_size as usize;
        while bytes.len() < exe_offset {
            bytes.push(0);
        }
        bytes.extend_from_slice(exe_bytes);
        exe_offset
    } else {
        overlay_offset + args.len()
    };

    ShellFile {
        bytes,
        overlay_offset,
        exe_offset,
    }
}

fn write_and_load(dir: &Path, file_name: &str, bytes: &[u8]) -> (SdrsProgram, PathBuf) {
    let shell_path = dir.join(file_name);
    fs::write(&shell_path, bytes).expect("write shell");
    let mut program = SdrsProgram::default();
    program.load(&shell_path).expect("load");
    (program, shell_path)
}

#[test]
fn v2_pack_mode_full_flow() {
    let dir = temp_dir("v2-pack");
    let key = 0x1234_5678u32;
    const MEM_POS: u32 = 0x1004;
    const MEM_SIG1: u32 = 0x89AB_CDEF;
    const MEM_SIG2: u32 = 0x1122_3344;
    const BIN_POS: u32 = 0x100;
    const BIN_LEN: u32 = 0x100;
    const BIN_SIG1: u32 = 0x5555_AAAA;
    const BIN_SIG2: u32 = 0x6666_BBBB;

    //ゲームExe: RVA 0x1000 → FOA 0x400
    let mut game_exe = game_shell_pe();
    while game_exe.len() < 0xC00 {
        game_exe.push(0);
    }

    //メモリパッチ領域 FOA 0x404..0x424 (XOR key = patch.position)
    let mem_plain = {
        let mut v = vec![0xA5u8; 0x20];
        v[0..4].copy_from_slice(&MEM_SIG1.to_le_bytes());
        v
    };
    let mem_encrypted = encrypt_region(mem_plain.clone(), MEM_POS, MEM_SIG1, MEM_SIG2);
    game_exe[SHELL_SECTION_RAW_START + 4..SHELL_SECTION_RAW_START + 4 + mem_encrypted.len()]
        .copy_from_slice(&mem_encrypted);
    let game_size = game_exe.len();

    //patchエントリ i: base = 0x40 + i*0x114 / name: [base..+0x100) position: base+0x100 sig1: +0x104 length: +0x108 sig2: +0x10C
    let shell = shell_file(
        HEADER_VERSION_V2,
        0x1180,
        0x2000,
        key,
        0,
        |args| {
            args[0x140..0x144].copy_from_slice(&MEM_POS.to_le_bytes());
            args[0x144..0x148].copy_from_slice(&MEM_SIG1.to_le_bytes());
            args[0x148..0x14C].copy_from_slice(&0x20u32.to_le_bytes());
            args[0x14C..0x150].copy_from_slice(&MEM_SIG2.to_le_bytes());

            args[0x154..0x15C].copy_from_slice(b"data.bin");
            args[0x254..0x258].copy_from_slice(&BIN_POS.to_le_bytes());
            args[0x258..0x25C].copy_from_slice(&BIN_SIG1.to_le_bytes());
            args[0x25C..0x260].copy_from_slice(&BIN_LEN.to_le_bytes());
            args[0x260..0x264].copy_from_slice(&BIN_SIG2.to_le_bytes());
        },
        Some(&game_exe),
    );
    assert_eq!(shell.overlay_offset, SHELL_OVERLAY);
    assert_eq!(shell.exe_offset, SHELL_OVERLAY + 0x2000);

    //data.bin: patch位置0x100に暗号済みブロック(key = patch.position)
    let mut data_bin = vec![0u8; 0x400];
    let bin_plain = {
        let mut v = vec![0x5Au8; BIN_LEN as usize];
        v[0..4].copy_from_slice(&BIN_SIG1.to_le_bytes());
        v
    };
    let bin_encrypted = encrypt_region(bin_plain.clone(), BIN_POS, BIN_SIG1, BIN_SIG2);
    data_bin[BIN_POS as usize..(BIN_POS + BIN_LEN) as usize].copy_from_slice(&bin_encrypted);
    fs::write(dir.join("data.bin"), &data_bin).expect("write data.bin");

    let (mut program, shell_path) = write_and_load(&dir, "shell.exe", &shell.bytes);

    assert_eq!(program.size() as usize, SHELL_OVERLAY);
    assert_eq!(program.executable_version(), "PE32");
    assert_eq!(program.executable_size(), game_size);

    {
        let stub = program.stub().expect("stub");
        assert_eq!(stub.level().to_string(), "V2");
        assert_eq!(stub.size(), 0x1180);
        assert_eq!(stub.align_size(), 0x2000);
        assert_eq!(stub.executable_file_name(), "main.bin");
        assert_eq!(stub.patches().len(), 16);
        assert_eq!(stub.patches()[0].mode, SdrsPatchMode::Memory);
        assert_eq!(stub.patches()[1].mode, SdrsPatchMode::File);
        assert_eq!(stub.patches()[2].mode, SdrsPatchMode::None);
    }

    program.extract().expect("extract");

    let out_dir = dir.join("sdrs_extract");
    let exe_out = fs::read(out_dir.join(shell_path.file_name().unwrap())).expect("read exe");
    let exe_expected = {
        let mut v = game_exe.clone();
        v[SHELL_SECTION_RAW_START + 4..SHELL_SECTION_RAW_START + 0x24].copy_from_slice(&mem_plain);
        v
    };
    assert_eq!(exe_out, exe_expected, "exe memory patch restored");

    let bin_out = fs::read(out_dir.join("data.bin")).expect("read data.bin");
    let bin_expected = {
        let mut v = data_bin.clone();
        v[BIN_POS as usize..(BIN_POS + BIN_LEN) as usize].copy_from_slice(&bin_plain);
        v
    };
    assert_eq!(bin_out, bin_expected, "data.bin block decrypted");
    assert!(
        dir.join("data.bin").is_file(),
        "original data.bin untouched"
    );
}

#[test]
fn v2_arg_hash_mismatch_rejected() {
    let dir = temp_dir("v2-bad-hash");
    let mut shell = shell_file(
        HEADER_VERSION_V2,
        0x1180,
        0x2000,
        0x11,
        0,
        |_| {},
        Some(&game_min_pe()),
    );
    //header hash破壊 → StubHashInvalid
    let hash_offset = shell.overlay_offset + 4;
    shell.bytes[hash_offset..hash_offset + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

    let shell_path = dir.join("shell.exe");
    fs::write(&shell_path, &shell.bytes).expect("write");

    let mut program = SdrsProgram::default();
    let err = program.load(&shell_path).expect_err("must fail");
    assert_eq!(err.to_string(), "Stubデータの検証に失敗しました");
    assert!(program.stub().is_none());
}

#[test]
fn unknown_version_rejected() {
    let dir = temp_dir("unknown-version");
    let mut bytes = game_shell_pe();
    while bytes.len() < SHELL_OVERLAY {
        bytes.push(0);
    }
    bytes.extend_from_slice(&{
        let mut header = vec![0u8; 0x10];
        header[0..4].copy_from_slice(&0x9999_9999u32.to_le_bytes());
        header
    });

    let shell_path = dir.join("shell.exe");
    fs::write(&shell_path, &bytes).expect("write");

    let mut program = SdrsProgram::default();
    let err = program.load(&shell_path).expect_err("must fail");
    assert_eq!(err.to_string(), "Stubバージョンが不明です");
}

#[test]
fn v4_not_pack_mode_full_flow() {
    let dir = temp_dir("v4-notpack");
    const NAME_SIZE: usize = 0x100;
    const ARG_SIZE: usize = 0x9540;
    const ARG_ALIGN: u32 = 0x1_0000;
    const EXE_POS: u32 = 0x10;
    const EXE_SIG1: u32 = 0xCAFE_0001;
    const EXE_SIG2: u32 = 0xCAFE_0002;
    const BIN_SIG1: u32 = 0xCAFE_0003;
    const BIN_SIG2: u32 = 0xCAFE_0004;
    const MEM_POS: u32 = 0x1004;
    const MEM_SIG1: u32 = 0xCAFE_0005;
    const MEM_SIG2: u32 = 0xCAFE_0006;
    let key = 0x1357_9BDFu32;

    //ゲームExe(外部ファイル)
    let mut game_exe = game_shell_pe();
    while game_exe.len() < 0xC00 {
        game_exe.push(0);
    }

    let exe_plain = {
        let mut v = vec![0x77u8; 0x20];
        v[0..4].copy_from_slice(&EXE_SIG1.to_le_bytes());
        v
    };
    let exe_encrypted = encrypt_region(exe_plain.clone(), EXE_POS, EXE_SIG1, EXE_SIG2);
    game_exe[EXE_POS as usize..(EXE_POS + 0x20) as usize].copy_from_slice(&exe_encrypted);

    let mem_plain = {
        let mut v = vec![0x33u8; 8];
        v[0..4].copy_from_slice(&MEM_SIG1.to_le_bytes());
        v
    };
    game_exe[0x404..0x40C].copy_from_slice(&encrypt_region(
        mem_plain.clone(),
        MEM_POS,
        MEM_SIG1,
        MEM_SIG2,
    ));

    //data.bin
    let mut data_bin = vec![0u8; 0x300];
    let bin_plain = {
        let mut v = vec![0x5Cu8; 0x80];
        v[0..4].copy_from_slice(&BIN_SIG1.to_le_bytes());
        v
    };
    data_bin[..0x80].copy_from_slice(&encrypt_region(bin_plain.clone(), 0, BIN_SIG1, BIN_SIG2));

    //V4 patchエントリ i: base = 0x40 + i*0x94 / name: [base..+0x80) position: base+0x80 sig1: +0x84 length: +0x88 sig2: +0x8C
    //Exe名: args末尾0x100 (0x9440)
    let shell = shell_file(
        HEADER_VERSION_V4,
        ARG_SIZE,
        ARG_ALIGN,
        key,
        0x0000_0048,
        |args| {
            //patch0: game.exe
            args[0x40..0x48].copy_from_slice(b"game.exe");
            args[0xC0..0xC4].copy_from_slice(&EXE_POS.to_le_bytes());
            args[0xC4..0xC8].copy_from_slice(&EXE_SIG1.to_le_bytes());
            args[0xC8..0xCC].copy_from_slice(&0x20u32.to_le_bytes());
            args[0xCC..0xD0].copy_from_slice(&EXE_SIG2.to_le_bytes());
            //patch1: data.bin
            args[0xD4..0xDC].copy_from_slice(b"data.bin");
            args[0x158..0x15C].copy_from_slice(&BIN_SIG1.to_le_bytes());
            args[0x15C..0x160].copy_from_slice(&0x80u32.to_le_bytes());
            args[0x160..0x164].copy_from_slice(&BIN_SIG2.to_le_bytes());
            //patch2: メモリ
            args[0x1E8..0x1EC].copy_from_slice(&MEM_POS.to_le_bytes());
            args[0x1EC..0x1F0].copy_from_slice(&MEM_SIG1.to_le_bytes());
            args[0x1F0..0x1F4].copy_from_slice(&8u32.to_le_bytes());
            args[0x1F4..0x1F8].copy_from_slice(&MEM_SIG2.to_le_bytes());
            //Exe名
            let name_offset = ARG_SIZE - NAME_SIZE;
            args[name_offset..name_offset + 9].copy_from_slice(b"game.exe\0");
        },
        None,
    );

    fs::write(dir.join("game.exe"), &game_exe).expect("write game.exe");
    fs::write(dir.join("data.bin"), &data_bin).expect("write data.bin");

    let shell_path = dir.join("packer.exe");
    fs::write(&shell_path, &shell.bytes).expect("write packer.exe");

    let mut program = SdrsProgram::default();
    program.load(&shell_path).expect("load");

    {
        let stub = program.stub().expect("stub");
        assert_eq!(stub.level().to_string(), "V4");
        assert_eq!(stub.size(), 0x9540);
        assert_eq!(stub.align_size(), ARG_ALIGN);
        assert_eq!(stub.executable_file_name(), "game.exe");
        assert_eq!(program.executable_version(), "PE32");
        assert_eq!(program.executable_size(), game_exe.len());
        assert_eq!(stub.patches().len(), 256);
        assert_eq!(stub.patches()[0].mode, SdrsPatchMode::File);
        assert_eq!(stub.patches()[1].mode, SdrsPatchMode::File);
        assert_eq!(stub.patches()[2].mode, SdrsPatchMode::Memory);
        assert_eq!(stub.patches()[255].mode, SdrsPatchMode::None);
    }

    program.extract().expect("extract");

    let out_dir = dir.join("sdrs_extract");
    //同名FileパッチはExeスライス復号のみ → 復号済みゲームExeはpacker.exeとして出力
    let exe_out = fs::read(out_dir.join("packer.exe")).expect("read");
    let exe_expected = {
        let mut v = game_exe.clone();
        v[EXE_POS as usize..(EXE_POS + 0x20) as usize].copy_from_slice(&exe_plain);
        v[0x404..0x40C].copy_from_slice(&mem_plain);
        v
    };
    assert_eq!(exe_out, exe_expected, "game.exe decrypted");

    let bin_out = fs::read(out_dir.join("data.bin")).expect("read");
    let bin_expected = {
        let mut v = data_bin.clone();
        v[..0x80].copy_from_slice(&bin_plain);
        v
    };
    assert_eq!(bin_out, bin_expected, "data.bin decrypted");
}

#[test]
fn v4_exe_name_is_shift_jis() {
    let dir = temp_dir("v4-sjis-name");
    const NAME_SIZE: usize = 0x100;
    const ARG_SIZE: usize = 0x9540;
    let mode = 0x0000_0048u32;
    let key = 1u32;

    let game_exe = game_min_pe();
    fs::write(dir.join("ゲーム.exe"), &game_exe).expect("write");

    let shell = shell_file(
        HEADER_VERSION_V4,
        ARG_SIZE,
        0x1_0000,
        key,
        mode,
        |args| {
            let name_offset = ARG_SIZE - NAME_SIZE;
            let sjis_name: &[u8] = &[
                0x83, 0x51, 0x81, 0x5b, 0x83, 0x80, 0x2e, 0x65, 0x78, 0x65, 0x00,
            ];
            args[name_offset..name_offset + sjis_name.len()].copy_from_slice(sjis_name);
        },
        None,
    );

    let (mut program, _) = write_and_load(&dir, "packer.exe", &shell.bytes);
    let stub = program.stub().expect("stub");
    assert_eq!(stub.executable_file_name(), "ゲーム.exe");
    program.extract().expect("extract");
    assert!(dir.join("sdrs_extract").join("packer.exe").is_file());
}

#[test]
fn failed_patch_marks_error() {
    let dir = temp_dir("v2-fail");
    let key = 7u32;
    let game_exe = game_min_pe();

    //patch0: data.bin signature不一致(mode 0 → File)
    let shell = shell_file(
        HEADER_VERSION_V2,
        0x1180,
        0x2000,
        key,
        0,
        |args| {
            args[0x40..0x48].copy_from_slice(b"data.bin");
            args[0x144..0x148].copy_from_slice(&0x1u32.to_le_bytes());
            args[0x148..0x14C].copy_from_slice(&0x10u32.to_le_bytes());
            args[0x14C..0x150].copy_from_slice(&0x2u32.to_le_bytes());
        },
        Some(&game_exe),
    );

    fs::write(dir.join("data.bin"), vec![0u8; 0x100]).expect("write");

    let (mut program, _) = write_and_load(&dir, "shell.exe", &shell.bytes);
    let err = program.extract().expect_err("must fail");
    assert!(err.to_string().contains("復号に失敗"), "{err}");
    assert!(
        dir.join("sdrs_extract").join("shell.exe").is_file(),
        "exe still written"
    );
}

#[test]
fn load_error_messages() {
    let dir = temp_dir("load-errors");

    let mut program = SdrsProgram::default();
    assert!(program.load(dir.join("missing.exe")).is_err());

    fs::write(dir.join("empty.exe"), b"not a pe").expect("write");
    let mut program = SdrsProgram::default();
    let err = program.load(dir.join("empty.exe")).expect_err("must fail");
    assert_eq!(err.to_string(), "主プログラムは32bitのみ対応しています");
}

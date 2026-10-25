use std::path::PathBuf;
use std::process::ExitCode;

use sdrs_core::sdrs::program::SdrsProgram;

const USAGE: &str = "使い方: sdrs [オプション] <主プログラム.exe>

オプション:
  -i, --info  情報のみ表示して抽出は行わない
  -h, --help  このヘルプを表示する";

fn print_info(program: &SdrsProgram) {
    let stub = program.stub().expect("stub must be loaded");

    println!("シェル情報:");
    println!("  バージョン: {}", stub.level());
    println!("  シェルサイズ: 0x{:08X}", program.size());
    println!("  設定データサイズ: 0x{:08X}", stub.size());
    println!("  設定総サイズ: 0x{:08X}", stub.align_size());
    println!("  モード: {}", stub.config().mode);

    println!();
    println!("主プログラム情報:");
    println!("  抽出ファイル名: {}", program.extracted_file_name());
    println!("  バージョン: {}", program.executable_version());
    println!("  サイズ: 0x{:08X}", program.executable_size());

    let patches = stub.patches();
    if !patches.is_empty() {
        println!();
        println!("暗号化区画: ({})", patches.len());
        println!(
            "  {:<4} {:<10} {:<10} {:<10} {:<10} {:<10} モード",
            "#", "オフセット", "長さ", "シグ1", "シグ2", "予約1"
        );
        for (i, patch) in patches.iter().enumerate() {
            println!(
                "  {:<4} {:<10} {:<10} {:<10} {:<10} {:<10} {}",
                i,
                format!("{:08X}", patch.position),
                format!("{:08X}", patch.length),
                format!("{:08X}", patch.signature1),
                format!("{:08X}", patch.signature2),
                format!("{:08X}", patch.reserve1),
                patch.mode
            );
        }
    }
}

fn main() -> ExitCode {
    let mut info_only = false;
    let mut path: Option<PathBuf> = None;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-i" | "--info" => info_only = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => path = Some(PathBuf::from(arg)),
        }
    }

    let Some(path) = path else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    let mut program = SdrsProgram::default();

    println!("ファイル: {}", path.display());
    if let Err(err) = program.load(&path) {
        eprintln!("エラー: {err}");
        return ExitCode::FAILURE;
    }

    print_info(&program);

    if info_only {
        return ExitCode::SUCCESS;
    }

    println!();
    match program.extract() {
        Ok(backup_dir) => {
            println!("抽出に成功しました");
            println!(
                "配置先: {}",
                path.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join(program.extracted_file_name())
                    .display()
            );
            println!("元ファイルの退避先: {}", backup_dir.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("エラー: {err}");
            ExitCode::FAILURE
        }
    }
}

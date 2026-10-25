use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Error, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pe::{Bits, PEFile};
use crate::sdrs::structs::{SdrsFlags, SdrsPatch, SdrsPatchMode};
use crate::sdrs::stub::{create_factory, SdrsStub, StubError};

#[derive(Debug)]
pub enum LoadError {
    Io(Error),
    FileNotExists,
    Not32Bit,
    Stub(StubError),
    ExeNotExists,
    ExeInvalidFormat,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "ファイルの読み込みに失敗しました: {err}"),
            Self::FileNotExists => write!(f, "主プログラムファイルが見つかりません"),
            Self::Not32Bit => write!(f, "主プログラムは32bitのみ対応しています"),
            Self::Stub(err) => write!(f, "{err}"),
            Self::ExeNotExists => write!(f, "ゲームEXEファイルが見つかりません"),
            Self::ExeInvalidFormat => {
                write!(f, "ゲーム主プログラムは有効なEXEファイルではありません")
            }
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Stub(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum ExtractError {
    Io(Error),
    NotInitialized,
    FailedPatches(Vec<bool>),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "ファイルの入出力に失敗しました: {err}"),
            Self::NotInitialized => write!(f, "シェルが初期化されていません"),
            Self::FailedPatches(patch_errors) => {
                let mut text = String::new();
                for (i, &failed) in patch_errors.iter().enumerate() {
                    if i != 0 && i % 16 == 0 {
                        text.push_str("\r\n");
                    }
                    if failed {
                        text.push_str(&format!("{i}, "));
                    }
                }
                write!(f, "以下の区画の復号に失敗しました: {text}")
            }
        }
    }
}

impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Default, Debug)]
pub struct SdrsProgram {
    stub: Option<SdrsStub>,
    executable_file_bytes: Vec<u8>,
    executable_pe: Option<PEFile>,
    current_directory: PathBuf,
    file_name: String,
    size: u32,
}

impl SdrsProgram {
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<(), LoadError> {
        self.clear();

        let path = path.as_ref();
        if !path.is_file() {
            return Err(LoadError::FileNotExists);
        }

        self.current_directory = path.parent().map(Path::to_path_buf).unwrap_or_default();
        self.file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        //主プログラムを読み込む
        let shell_bytes = std::fs::read(path).map_err(LoadError::Io)?;

        //シェルは現状32bitのみ
        let shell_pe = PEFile::load(Bits::X32, &shell_bytes).ok_or(LoadError::Not32Bit)?;

        //設定データはオーバーレイ(附加データ区画)に格納されている
        let program_size = shell_pe.overlay_data_file_offset();
        self.size = program_size;

        let stub = create_factory(
            shell_bytes
                .get(program_size as usize..)
                .ok_or(LoadError::Stub(StubError::Invalid))?,
        )
        .map_err(LoadError::Stub)?;

        //非パック形式: 実行ファイルを別ファイルから読み込む
        let exe_bytes: Vec<u8> = if stub
            .config()
            .mode
            .contains(SdrsFlags::EXECUTABLE_FILE_NOT_PACK)
        {
            let exe_path = self.current_directory.join(stub.executable_file_name());
            if !exe_path.is_file() {
                return Err(LoadError::ExeNotExists);
            }
            std::fs::read(&exe_path).map_err(LoadError::Io)?
        } else {
            //パック形式: シェル引数領域の後方に格納されている
            let start = program_size.wrapping_add(stub.align_size()) as usize;
            shell_bytes
                .get(start..)
                .ok_or(LoadError::Stub(StubError::Invalid))?
                .to_vec()
        };

        //主プログラムを解析する
        let executable_pe = PEFile::load(Bits::X32, &exe_bytes)
            .or_else(|| PEFile::load(Bits::X64, &exe_bytes))
            .ok_or(LoadError::ExeInvalidFormat)?;

        self.stub = Some(stub);
        self.executable_file_bytes = exe_bytes;
        self.executable_pe = Some(executable_pe);
        Ok(())
    }

    pub fn stub(&self) -> Option<&SdrsStub> {
        self.stub.as_ref()
    }

    pub fn executable_version(&self) -> &str {
        match &self.executable_pe {
            Some(pe) => pe.display(),
            None => "",
        }
    }

    pub fn executable_size(&self) -> usize {
        self.executable_file_bytes.len()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn extracted_file_name(&self) -> &str {
        self.stub
            .as_ref()
            .and_then(SdrsStub::configured_executable_file_name)
            .unwrap_or(&self.file_name)
    }

    pub fn extract(&mut self) -> Result<PathBuf, ExtractError> {
        let Some(stub) = self.stub.as_ref() else {
            return Err(ExtractError::NotInitialized);
        };
        let Some(exe_pe) = self.executable_pe.as_ref() else {
            return Err(ExtractError::NotInitialized);
        };

        let game_dir = self.current_directory.clone();
        let backup_dir = create_backup_dir(&game_dir).map_err(ExtractError::Io)?;
        let staging = StagingDirectory(backup_dir.join(".staging"));
        let out_dir = &staging.0;
        std::fs::create_dir(out_dir).map_err(ExtractError::Io)?;
        let exe_name = relative_file_name(self.extracted_file_name()).map_err(ExtractError::Io)?;
        let mut outputs: Vec<PathBuf> = Vec::new();

        //実行ファイルのコピーを作成する
        let mut exe_bytes = self.executable_file_bytes.clone();

        //失敗したパッチの記録
        let mut patch_errors = vec![false; stub.patches().len()];

        //復号処理
        for (i, patch) in stub.patches().iter().enumerate() {
            match patch.mode {
                SdrsPatchMode::ExecutableOnly => {
                    patch_errors[i] = !decrypt_exe_region(&mut exe_bytes, patch, stub);
                }
                SdrsPatchMode::File => {
                    //実行ファイルは別途処理する
                    if same_file_name(
                        Path::new(&patch.file_name),
                        Path::new(stub.executable_file_name()),
                    ) {
                        patch_errors[i] = !decrypt_exe_region(&mut exe_bytes, patch, stub);
                    } else {
                        let name =
                            relative_file_name(&patch.file_name).map_err(ExtractError::Io)?;
                        if same_file_name(&name, &exe_name)
                            || same_file_name(&name, Path::new(&self.file_name))
                        {
                            return Err(ExtractError::Io(Error::other(
                                "データファイル名が実行ファイル名と競合しています",
                            )));
                        }
                        patch_errors[i] = !extract_file_patch(&game_dir, out_dir, patch, stub)
                            .map_err(ExtractError::Io)?;
                        if !outputs.iter().any(|path| same_file_name(path, &name)) {
                            outputs.push(name);
                        }
                    }
                }
                SdrsPatchMode::Memory => {
                    let foa = exe_pe.rva_to_foa(patch.position);
                    patch_errors[i] = !decrypt_exe_region_at(&mut exe_bytes, foa, patch, stub);
                }
                SdrsPatchMode::None => {}
            }
        }

        //復号がすべて成功するまで元のファイルには触れない。
        if patch_errors.iter().any(|&failed| failed) {
            return Err(ExtractError::FailedPatches(patch_errors));
        }

        //ゲームが元のEXE名を指定して自己検証する場合があるため、設定名を保持する。
        let exe_dest_path = out_dir.join(&exe_name);
        if let Some(parent) = exe_dest_path.parent() {
            std::fs::create_dir_all(parent).map_err(ExtractError::Io)?;
        }
        std::fs::write(exe_dest_path, &exe_bytes).map_err(ExtractError::Io)?;
        outputs.push(exe_name);

        install_outputs(&game_dir, &backup_dir, out_dir, &self.file_name, &outputs)
            .map_err(ExtractError::Io)?;
        Ok(backup_dir)
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

//このフォルダには未配置の新規ファイルだけを格納する。バックアップは削除しない。
struct StagingDirectory(PathBuf);

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_dir(self.0.parent().expect("staging parent"));
    }
}

fn relative_file_name(name: &str) -> Result<PathBuf, Error> {
    let path = Path::new(name);
    if name.is_empty()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        || name.contains(':')
    {
        return Err(Error::other(format!("無効な出力ファイル名です: {name}")));
    }
    Ok(path.to_path_buf())
}

fn same_file_name(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

fn create_backup_dir(game_dir: &Path) -> Result<PathBuf, Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(Error::other)?
        .as_nanos();
    for suffix in 0..100 {
        let path = game_dir.join(format!("sdrs_backup_{timestamp}_{suffix}"));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(Error::other("バックアップフォルダを作成できません"))
}

fn install_outputs(
    game_dir: &Path,
    backup_dir: &Path,
    staging_dir: &Path,
    shell_name: &str,
    outputs: &[PathBuf],
) -> Result<(), Error> {
    let mut originals = vec![PathBuf::from(shell_name)];
    for name in outputs {
        let dest = game_dir.join(name);
        if dest.exists() && !originals.iter().any(|path| same_file_name(path, name)) {
            originals.push(name.clone());
        }
    }
    let mut backed_up = Vec::new();
    let mut installed = Vec::new();
    let result = (|| {
        for name in &originals {
            let source = game_dir.join(name);
            if !source.is_file() {
                return Err(Error::other(format!(
                    "退避対象が通常ファイルではありません: {}",
                    source.display()
                )));
            }
            let dest = backup_dir.join(name);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(source, dest)?;
            backed_up.push(name.clone());
        }
        for name in outputs {
            let dest = game_dir.join(name);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(staging_dir.join(name), dest)?;
            installed.push(name.clone());
        }
        Ok(())
    })();
    if let Err(err) = result {
        let mut failures = Vec::new();
        for name in installed.iter().rev() {
            if let Err(restore_err) = std::fs::rename(game_dir.join(name), staging_dir.join(name)) {
                failures.push(restore_err.to_string());
            }
        }
        for name in backed_up.iter().rev() {
            if let Err(restore_err) = std::fs::rename(backup_dir.join(name), game_dir.join(name)) {
                failures.push(restore_err.to_string());
            }
        }
        if !failures.is_empty() {
            return Err(Error::other(format!(
                "{err}; 復元に失敗しました。バックアップ: {} ({})",
                backup_dir.display(),
                failures.join("; ")
            )));
        }
        return Err(err);
    }
    Ok(())
}

fn decrypt_exe_region(exe_bytes: &mut [u8], patch: &SdrsPatch, stub: &SdrsStub) -> bool {
    decrypt_exe_region_at(exe_bytes, patch.position, patch, stub)
}

fn decrypt_exe_region_at(
    exe_bytes: &mut [u8],
    start: u32,
    patch: &SdrsPatch,
    stub: &SdrsStub,
) -> bool {
    let Some(region) = exe_bytes.get_mut(start as usize..(start + patch.length) as usize) else {
        return false;
    };
    //keyはパッチ位置
    stub.decrypt_resource(
        region,
        patch.position,
        patch.signature1,
        patch.signature2,
        false,
    )
}

fn extract_file_patch(
    game_dir: &Path,
    out_dir: &Path,
    patch: &SdrsPatch,
    stub: &SdrsStub,
) -> Result<bool, Error> {
    let src_path = game_dir.join(&patch.file_name);
    let dest_path = out_dir.join(&patch.file_name);

    if !src_path.is_file() {
        return Ok(false);
    }

    if let Some(dir) = dest_path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    //同じファイルの複数区画を復号するとき、先に復号した区画を保持する。
    if !dest_path.exists() {
        std::fs::copy(&src_path, &dest_path)?;
    }
    let mut src_file = File::open(&dest_path)?;

    //データ区画を読み込む
    let mut block = read_block(&mut src_file, patch.position, patch.length)?;

    //データ区画を復号する
    let decrypted = stub.decrypt_resource(
        &mut block,
        patch.position,
        patch.signature1,
        patch.signature2,
        false,
    );

    //データ区画を書き戻す
    let mut dest_file = OpenOptions::new().write(true).open(&dest_path)?;
    dest_file.seek(SeekFrom::Start(u64::from(patch.position)))?;
    dest_file.write_all(&block)?;

    Ok(decrypted)
}

fn read_block(file: &mut File, position: u32, length: u32) -> Result<Vec<u8>, Error> {
    let mut block = vec![0u8; length as usize];
    file.seek(SeekFrom::Start(u64::from(position)))?;

    let mut filled = 0usize;
    while filled < block.len() {
        match file.read(&mut block[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn installation_failure_restores_originals_and_removes_partial_installation() {
        let game_dir = std::env::temp_dir().join(format!(
            "sdrs-install-rollback-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&game_dir).unwrap();
        fs::write(game_dir.join("shell.exe"), b"original shell").unwrap();
        fs::write(game_dir.join("data.bin"), b"encrypted data").unwrap();
        let backup_dir = create_backup_dir(&game_dir).unwrap();
        let staging = StagingDirectory(backup_dir.join(".staging"));
        fs::create_dir(&staging.0).unwrap();
        fs::write(staging.0.join("data.bin"), b"decrypted data").unwrap();
        //二つ目の配置に失敗する状態を作り、一つ目の配置も元へ戻ることを確認する。
        let result = install_outputs(
            &game_dir,
            &backup_dir,
            &staging.0,
            "shell.exe",
            &[PathBuf::from("data.bin"), PathBuf::from("game.exe")],
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(game_dir.join("shell.exe")).unwrap(),
            b"original shell"
        );
        assert_eq!(
            fs::read(game_dir.join("data.bin")).unwrap(),
            b"encrypted data"
        );
        assert!(!game_dir.join("game.exe").exists());
        assert_eq!(
            fs::read(staging.0.join("data.bin")).unwrap(),
            b"decrypted data"
        );
        drop(staging);
        fs::remove_dir_all(game_dir).unwrap();
    }
}

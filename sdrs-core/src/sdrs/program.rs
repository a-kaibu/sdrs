use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Error, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

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

        //ソフトバッテリーのシェルは現状32bitのみ
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

    pub fn extract(&mut self) -> Result<(), ExtractError> {
        let Some(stub) = self.stub.as_ref() else {
            return Err(ExtractError::NotInitialized);
        };
        let Some(exe_pe) = self.executable_pe.as_ref() else {
            return Err(ExtractError::NotInitialized);
        };

        let game_dir = self.current_directory.clone();
        let out_dir = game_dir.join("sdrs_extract");

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
                    if patch.file_name == stub.executable_file_name() {
                        patch_errors[i] = !decrypt_exe_region(&mut exe_bytes, patch, stub);
                    } else {
                        patch_errors[i] = !extract_file_patch(&game_dir, &out_dir, patch, stub)
                            .map_err(ExtractError::Io)?;
                    }
                }
                SdrsPatchMode::Memory => {
                    let foa = exe_pe.rva_to_foa(patch.position);
                    patch_errors[i] = !decrypt_exe_region_at(&mut exe_bytes, foa, patch, stub);
                }
                SdrsPatchMode::None => {}
            }
        }

        //実行ファイルを書き戻す
        let exe_dest_path = out_dir.join(&self.file_name);
        std::fs::create_dir_all(out_dir).map_err(ExtractError::Io)?;
        std::fs::write(exe_dest_path, &exe_bytes).map_err(ExtractError::Io)?;

        //失敗したパッチを確認する
        if patch_errors.iter().any(|&failed| failed) {
            Err(ExtractError::FailedPatches(patch_errors))
        } else {
            Ok(())
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
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

    let mut src_file = File::open(&src_path)?;

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

    //ファイルをコピーする
    let src_bytes = std::fs::read(&src_path)?;
    std::fs::write(&dest_path, &src_bytes)?;

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

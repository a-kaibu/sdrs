# sdrs

SDRS の情報表示・抽出ツール。CLI (`sdrs`) と GUI (`sdrs-gui`) を提供します。

## ダウンロード

[GitHub Releases](https://github.com/a-kaibu/sdrs/releases/latest) から OS に合うアーカイブをダウンロードして展開してください。各アーカイブには CLI と GUI の両方が含まれます。

| OS | アーキテクチャ | ファイル末尾 |
| --- | --- | --- |
| Windows | x86_64 | `x86_64-pc-windows-msvc.zip` |
| Linux | x86_64 | `x86_64-unknown-linux-gnu.tar.gz` |
| macOS | Apple Silicon | `aarch64-apple-darwin.tar.gz` |

Linux 版は Ubuntu 24.04 でビルドします。GUI の実行にはデスクトップ環境と OpenGL が必要です。macOS / Windows 版はコード署名していません。macOS の GUI は展開した `sdrs-gui` をターミナルから起動できます。

`SHA256SUMS` でダウンロードしたアーカイブの SHA-256 を確認できます。

## 使い方

```sh
# 情報のみ表示
sdrs --info 主プログラム.exe

# 抽出
sdrs 主プログラム.exe

# GUI
sdrs-gui
```

抽出した EXE と復号したデータファイルは、入力ファイルと同じゲームフォルダへ配置します。元の EXE と置換対象のファイルは、自動作成する `sdrs_backup_<番号>_<番号>` フォルダへ移動します。退避先は処理後に表示されます。復号に失敗した場合は元ファイルを変更せず、配置中に失敗した場合は元へ戻します。

EXE 名がシェル設定に指定されている場合は、その名前で配置します。指定がない場合は入力ファイル名を使います。ゲームによっては元の EXE 名でファイルを検証するため、配置後に名前を変更すると起動しない場合があります。

元に戻す場合はゲームを終了し、バックアップ内のファイルを元の場所へ戻してください。入力と配置後の EXE 名が異なる場合、新しく配置した EXE も取り除いてください。

## ビルドとテスト

Rust 1.95.0 を使用します。

```sh
cargo test --workspace --locked
cargo build --workspace --bins --release --locked
```

Linux のビルドに必要なシステムパッケージは [Actions の設定](.github/workflows/release.yml) を参照してください。

## リリース

リリースバージョンは Git タグを唯一の基準とします。変更をコミットし、`v` 付きのバージョンタグを push してください。Cargo のバージョンを手動で更新する必要はありません。

```sh
git tag v1.0.0
git push origin main v1.0.0
```

GitHub Actions はタグから workspace の Cargo バージョンと `Cargo.lock` を自動設定し、Windows・Linux・Apple Silicon Mac でテスト・ビルドします。すべて成功した後でアーカイブと `SHA256SUMS` を GitHub Release に公開します。`v1.1.0-rc.1` のようなタグはプレリリースになります。タグのない main への push と PR では開発用バージョン `0.0.0-dev` で同じビルドを検証します。

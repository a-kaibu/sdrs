# sdrs

SDRS の情報表示・抽出ツール。CLI (`sdrs`) と GUI (`sdrs-gui`) を提供します。

## ダウンロード

[GitHub Releases](https://github.com/a-kaibu/sdrs/releases/latest) から OS に合うアーカイブをダウンロードして展開してください。各アーカイブには CLI と GUI の両方が含まれます。

| OS | アーキテクチャ | ファイル末尾 |
| --- | --- | --- |
| Windows | x86_64 | `x86_64-pc-windows-msvc.zip` |
| Linux | x86_64 | `x86_64-unknown-linux-gnu.tar.gz` |
| macOS | Intel | `x86_64-apple-darwin.tar.gz` |
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

## ビルドとテスト

Rust 1.95.0 を使用します。

```sh
cargo test --workspace --locked
cargo build --workspace --bins --release --locked
```

Linux のビルドに必要なシステムパッケージは [Actions の設定](.github/workflows/release.yml) を参照してください。

## リリース

すべての workspace パッケージの `Cargo.toml` のバージョンと `Cargo.lock` を更新してコミットし、対応する `v` 付きタグを push します。

```sh
git tag v0.1.0
git push origin main v0.1.0
```

GitHub Actions が各 OS でテスト・ビルドし、すべて成功した後でアーカイブと `SHA256SUMS` を GitHub Release に公開します。タグと Cargo のバージョンが一致しない場合は失敗します。`v0.2.0-rc.1` のようなタグはプレリリースになります。main への push と PR でも同じビルドを検証します。

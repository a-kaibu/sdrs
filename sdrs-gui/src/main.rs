use std::path::PathBuf;

use eframe::egui;
use egui_extras::TableBuilder;
use sdrs_core::sdrs::program::SdrsProgram;
use sdrs_core::sdrs::structs::{SdrsPatch, SdrsPatchMode};

const WINDOW_TITLE: &str = "sdrs";
const HEX_WIDTH: f32 = 110.0;

#[derive(Clone, Copy, PartialEq)]
enum Popup {
    Info,
    Error,
}

struct PatchRow {
    offset: String,
    length: String,
    sig1: String,
    sig2: String,
    reserve1: String,
    mode: SdrsPatchMode,
}

impl PatchRow {
    fn new(patch: &SdrsPatch) -> Self {
        Self {
            offset: format!("{:08X}", patch.position),
            length: format!("{:08X}", patch.length),
            sig1: format!("{:08X}", patch.signature1),
            sig2: format!("{:08X}", patch.signature2),
            reserve1: format!("{:08X}", patch.reserve1),
            mode: patch.mode,
        }
    }

    fn mode_text(&self) -> &str {
        match self.mode {
            SdrsPatchMode::ExecutableOnly => "実行",
            SdrsPatchMode::File => "ファイル",
            SdrsPatchMode::Memory => "メモリ",
            SdrsPatchMode::None => "なし",
        }
    }

    fn color(&self) -> egui::Color32 {
        match self.mode {
            SdrsPatchMode::ExecutableOnly => egui::Color32::from_rgb(189, 255, 198),
            SdrsPatchMode::File => egui::Color32::from_rgb(255, 180, 176),
            SdrsPatchMode::Memory => egui::Color32::from_rgb(186, 217, 255),
            SdrsPatchMode::None => egui::Color32::from_rgb(239, 239, 239),
        }
    }
}

struct ShellInfo {
    path: String,
    shell_version: String,
    shell_size: String,
    config_size: String,
    align_size: String,
    config_mode: String,
    exe_version: String,
    exe_size: String,
    patches: Vec<PatchRow>,
}

impl ShellInfo {
    fn from_program(path: &PathBuf, program: &SdrsProgram) -> Option<Self> {
        let stub = program.stub()?;
        let config = stub.config();
        Some(Self {
            path: path.display().to_string(),
            shell_version: format!("{}", stub.level()),
            shell_size: format!("{:08X}", program.size()),
            config_size: format!("{:08X}", stub.size()),
            align_size: format!("{:08X}", stub.align_size()),
            config_mode: format!("{}", config.mode),
            exe_version: program.executable_version().into(),
            exe_size: format!("{:08X}", program.executable_size()),
            patches: stub.patches().iter().map(PatchRow::new).collect(),
        })
    }
}

#[derive(Default)]
struct SdrsApp {
    program: SdrsProgram,
    info: Option<ShellInfo>,
    popup: Option<(Popup, String)>,
}

impl SdrsApp {
    fn load_file(&mut self, path: PathBuf) {
        self.info = None;
        match self.program.load(&path) {
            Ok(()) => self.info = ShellInfo::from_program(&path, &self.program),
            Err(err) => self.popup = Some((Popup::Error, err.to_string())),
        }
    }

    fn extract(&mut self) {
        match self.program.extract() {
            Ok(()) => self.popup = Some((Popup::Info, "抽出に成功しました".into())),
            Err(err) => self.popup = Some((Popup::Error, err.to_string())),
        }
    }
}

fn info_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(label);
    ui.monospace(value);
    ui.end_row();
}

impl eframe::App for SdrsApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        //ドラッグ & ドロップ
        let dropped = ui.input(|input| {
            input
                .raw
                .dropped_files
                .first()
                .map(|file| file.path().to_path_buf())
        });
        if let Some(path) = dropped {
            self.load_file(path);
        }

        egui::CentralPanel::default().show(ui, |ui| {
            //ファイル選択
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("選択…").clicked() {
                        let file = rfd::FileDialog::new()
                            .set_title("主プログラムを選択")
                            .add_filter("実行可能ファイル (*.exe)", &["exe"])
                            .add_filter("すべてのファイル", &["*"])
                            .pick_file();
                        if let Some(file) = file {
                            self.load_file(file);
                        }
                    }
                    ui.label(
                        egui::RichText::new(
                            self.info
                                .as_ref()
                                .map(|info| info.path.as_str())
                                .unwrap_or("ファイル未選択 (ドラッグ & ドロップ対応)"),
                        )
                        .weak(),
                    );
                });
            });
            ui.add_space(6.0);

            let Some(info) = &self.info else {
                ui.with_layout(
                    egui::Layout::top_down_justified(egui::Align::Center),
                    |ui| {
                        ui.add_space(60.0);
                        ui.heading(WINDOW_TITLE);
                        ui.add_space(12.0);
                        ui.weak("ファイル選択またはドラッグ & ドロップしてください");
                    },
                );
                return;
            };

            //シェル情報
            ui.strong("シェル情報");
            ui.add_space(4.0);
            egui::Grid::new("shell-info-grid")
                .num_columns(2)
                .show(ui, |ui| {
                    info_row(ui, "バージョン", &info.shell_version);
                    info_row(ui, "シェルサイズ", &info.shell_size);
                    info_row(ui, "設定データサイズ", &info.config_size);
                    info_row(ui, "設定総サイズ", &info.align_size);
                    info_row(ui, "モード", &info.config_mode);
                });

            //主プログラム情報
            ui.add_space(12.0);
            ui.strong("主プログラム情報");
            ui.add_space(4.0);
            egui::Grid::new("exe-info-grid")
                .num_columns(2)
                .show(ui, |ui| {
                    info_row(ui, "バージョン", &info.exe_version);
                    info_row(ui, "サイズ", &info.exe_size);
                });

            //暗号化区画リスト
            if !info.patches.is_empty() {
                ui.add_space(12.0);
                ui.strong(format!("暗号化区画 ({})", info.patches.len()));
                ui.add_space(4.0);
                ui.push_id("patch-table", |ui| {
                    TableBuilder::new(ui)
                        .striped(false)
                        .vscroll(true)
                        .auto_shrink(false)
                        .cell_layout(egui::Layout::centered_and_justified(
                            egui::Direction::LeftToRight,
                        ))
                        .column(egui_extras::Column::exact(50.0))
                        .column(egui_extras::Column::exact(HEX_WIDTH))
                        .column(egui_extras::Column::exact(HEX_WIDTH))
                        .column(egui_extras::Column::exact(HEX_WIDTH))
                        .column(egui_extras::Column::exact(HEX_WIDTH))
                        .column(egui_extras::Column::exact(HEX_WIDTH))
                        .column(egui_extras::Column::remainder())
                        .header(24.0, |mut header| {
                            for name in [
                                "#",
                                "オフセット",
                                "長さ",
                                "シグ1",
                                "シグ2",
                                "予約1",
                                "モード",
                            ] {
                                header.col(|ui| {
                                    ui.strong(name);
                                });
                            }
                        })
                        .body(|mut body| {
                            for (index, row) in info.patches.iter().enumerate() {
                                body.row(22.0, |mut cells| {
                                    let color = row.color();
                                    let paint_row = |ui: &mut egui::Ui| {
                                        ui.painter().rect_filled(
                                            ui.available_rect_before_wrap(),
                                            0.0,
                                            color,
                                        );
                                    };
                                    let monospace_text = |ui: &mut egui::Ui, text: String| {
                                        ui.monospace(text);
                                    };
                                    cells.col(|ui| {
                                        paint_row(ui);
                                        monospace_text(ui, format!("{index}"));
                                    });
                                    cells.col(|ui| {
                                        paint_row(ui);
                                        monospace_text(ui, row.offset.clone());
                                    });
                                    cells.col(|ui| {
                                        paint_row(ui);
                                        monospace_text(ui, row.length.clone());
                                    });
                                    cells.col(|ui| {
                                        paint_row(ui);
                                        monospace_text(ui, row.sig1.clone());
                                    });
                                    cells.col(|ui| {
                                        paint_row(ui);
                                        monospace_text(ui, row.sig2.clone());
                                    });
                                    cells.col(|ui| {
                                        paint_row(ui);
                                        monospace_text(ui, row.reserve1.clone());
                                    });
                                    cells.col(|ui| {
                                        paint_row(ui);
                                        ui.label(row.mode_text());
                                    });
                                });
                            }
                        });
                });
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Max), |ui| {
                ui.add_space(4.0);
                ui.style_mut().spacing.button_padding = egui::vec2(24.0, 10.0);
                if ui
                    .add_enabled(self.info.is_some(), egui::Button::new("抽出"))
                    .clicked()
                {
                    self.extract();
                }
            });
        });

        //メッセージポップアップ
        if let Some((kind, message)) = self.popup.clone() {
            let header = match kind {
                Popup::Info => "情報",
                Popup::Error => "エラー",
            };
            let response = egui::Modal::new(egui::Id::unique("sdrs-popup")).show(&ctx, |ui| {
                ui.set_width(380.0);
                ui.strong(header);
                ui.add_space(6.0);
                ui.label(message);
                ui.add_space(12.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    if ui.button("OK").clicked() {
                        self.popup = None;
                    }
                });
            });
            if response.should_close() {
                self.popup = None;
            }
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder {
            title: Some(WINDOW_TITLE.into()),
            inner_size: Some(egui::vec2(820.0, 640.0)),
            min_inner_size: Some(egui::vec2(760.0, 560.0)),
            ..Default::default()
        },
        ..Default::default()
    };

    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(|_cc| Ok(Box::new(SdrsApp::default()))),
    )
}

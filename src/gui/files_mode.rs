use std::{path::PathBuf, ffi::OsStr};

use eframe::{epaint::FontId, egui};

use super::{Application, FilesHandlerMessage, btn};

#[derive(Debug, Default)]
enum FileModeState {
    #[default]
    WaitingForFile,
    FileIsChosen(PathBuf),
    ComputingKey,
    Encryption { progress: f32 },
    Decryption { progress: f32 },
    FinishAndWaitingForFile,
    ProcessingFailure
}

impl FileModeState {
    fn encryption() -> Self {
        Self::Encryption { progress: 0. }
    }
    fn decryption() -> Self {
        Self::Decryption { progress: 0. }
    }
}

#[derive(Debug)]
pub(super) struct FilesModeData {
    state: FileModeState,
    status: String
}

impl FilesModeData {
    pub fn on_drop_file(&mut self, path: impl Into<PathBuf>) {
        match &self.state {
            FileModeState::WaitingForFile 
            | FileModeState::FileIsChosen(_)
            | FileModeState::FinishAndWaitingForFile
            | FileModeState::ProcessingFailure => {
                let file_path: PathBuf = path.into();
                let file_name: &str = file_path.file_name()
                    .and_then(|file_name: &OsStr| file_name.to_str())
                    .unwrap_or("<unable_to_read>");
                let new_status = format!("Выбран файл\n{}", file_name);
                self.set_status(&new_status);
                self.state = FileModeState::FileIsChosen(file_path);
            },
            _ => {}
        }
    }
    pub fn when_computing_key(&mut self) {
        match &self.state {
            FileModeState::FileIsChosen(_) => {},
            _ => {
                // Maybe here should be panic, but now I'm not sure
            }
        }
        self.set_status("Вычисление ключа...");
        self.state = FileModeState::ComputingKey;
    }
    pub fn on_start_encryption(&mut self) {
        match &self.state {
            FileModeState::ComputingKey => {},
            _ => {}
        }
        self.set_status("Шифрование...");
        self.state = FileModeState::encryption();
    }
    pub fn on_start_decryption(&mut self) {
        match &self.state {
            FileModeState::ComputingKey => {},
            _ => {}
        }
        self.set_status("Расшифровка...");
        self.state = FileModeState::decryption();
    }
    pub fn on_progress(&mut self, progress: f32) {
        match &self.state {
            FileModeState::Encryption { progress: _ } => {
                self.state = FileModeState::Encryption { progress }
            },
            FileModeState::Decryption { progress: _ } => {
                self.state = FileModeState::Decryption { progress }
            },
            _ => {}
        }
    }
    pub fn on_finish(&mut self) {
        match &self.state {
            FileModeState::Encryption { .. }
            | FileModeState::Decryption { .. } => {},
            _ => {}
        }
        self.set_status("Готово.\nПеретащите сюда следующий файл");
        self.state = FileModeState::FinishAndWaitingForFile;
    }
    pub fn on_processing_failure(&mut self) {
        match &self.state {
            FileModeState::Encryption { .. } => {
                self.set_status("Ошибка шифрования");
            },
            FileModeState::Decryption { .. } => {
                self.set_status("Ошибка расшифровки");
            },
            _ => {
                dbg!(&self.state);
            }
        }
        self.state = FileModeState::ProcessingFailure;
    }
    fn set_status(&mut self, status: &str) {
        self.status.clear();
        self.status.push_str(status);
    }
    pub fn chosen_file(&self) -> Option<&PathBuf> {
        if let FileModeState::FileIsChosen(file_path) = &self.state {
            Some(file_path)
        } else {
            None
        }
    }
    pub fn progress(&self) -> Option<f32> {
        match self.state {
            FileModeState::Encryption { progress } 
            | FileModeState::Decryption { progress } => Some(progress),
            _ => None
        }
    }
    pub fn status(&self) -> &str {
        &self.status
    }
}

impl Default for FilesModeData {
    fn default() -> Self {
        let mut new = Self {
            state: Default::default(), 
            status: String::with_capacity(100)
        };
        new.status.push_str("Перетащите сюда файл");
        new
    }
}

pub(super) trait FilesMode {
    fn render_files_mode(&mut self, ui: &mut egui::Ui);
}

impl FilesMode for Application {
    fn render_files_mode(&mut self, ui: &mut egui::Ui) {
        let height: f32 = ui.available_height();
        ui.vertical_centered(|ui| {
            ui.set_height(height);

            let label_text: &str = self.files_mode.status();
            let label = egui::Label::new(egui::RichText::new(label_text)
                                            .font(FontId::proportional(50.)));

            if let Some(dropped_file) = ui.input().raw.dropped_files.iter().next() {
                if let Some(path) = &dropped_file.path {
                    println!("Dropped file path: {}", path.to_str().unwrap());
                    self.files_mode.on_drop_file(path);
                }
            }

            match self.files_mode_rx.try_recv() {
                Ok(FilesHandlerMessage::ComputingKey) => {
                    self.files_mode.when_computing_key();
                },
                Ok(FilesHandlerMessage::StartEncryption) => {
                    self.files_mode.on_start_encryption();
                },
                Ok(FilesHandlerMessage::StartDecryption) => {
                    self.files_mode.on_start_decryption();
                },
                Ok(FilesHandlerMessage::Progress(progress)) => {
                    self.files_mode.on_progress(progress);
                    println!("PROGRESS: {}", progress);
                },
                Ok(FilesHandlerMessage::Finish) => {
                    self.files_mode.on_finish();
                    self.sending_is_locked = false;
                    self.is_loading = false;
                    println!("Finished!");
                },
                Ok(FilesHandlerMessage::EncryptionFailure) => {
                    self.files_mode.on_processing_failure();
                    println!("ENCRYPTION FAILURE");
                    self.sending_is_locked = false;
                    self.is_loading = false;
                },
                Ok(FilesHandlerMessage::DecryptionFailure) => {
                    self.files_mode.on_processing_failure();
                    println!("DECRYPTION FAILURE");
                    self.sending_is_locked = false;
                    self.is_loading = false;
                },
                Err(_) => {},
            }

            let general_pane_width: f32 = ui.available_width();
            let general_pane_height_percents: f32 = 0.92;
            let general_pane_height: f32 = ui.available_height() * general_pane_height_percents;
            ui.add_sized((general_pane_width, general_pane_height), label);
            if let Some(progress) = self.files_mode.progress() {
                let progress_bar = egui::ProgressBar::new(progress)
                    .animate(true)
                    .show_percentage();
                ui.add(progress_bar);
            }

            let width: f32 = ui.available_width() - 10.;

            ui.vertical_centered(|ui| {
                ui.horizontal_top(|ui| {
                    ui.set_width(width);
                    let file_not_choosen: bool = self.files_mode.chosen_file().is_none();
                    let enable_encryption_buttons: bool = !(self.sending_is_locked || file_not_choosen);
                    // ui.separator();
                    ui.add_enabled_ui(enable_encryption_buttons, |ui| {
                        if btn("Зашифровать", ui).clicked() {
                            self.on_encrypt_file_btn_clicked();
                        }
                    });

                    ui.add_enabled_ui(enable_encryption_buttons, |ui| {
                        if btn("Расшифровать", ui).clicked() {
                            self.on_decrypt_btn_file_clicked();
                        }
                    });

                    let enable_to_text_mode_btn: bool = !self.is_loading;
                    ui.add_enabled_ui(enable_to_text_mode_btn, |ui| {
                        if btn("В режим текста", ui).clicked() {
                            self.to_text_mode();
                        }
                    });

                    if !enable_encryption_buttons {
                        ui.add_space(10.);
                    }
                });
            });
        });
    }
}
    

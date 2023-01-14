use eframe::{egui::{Ui, self}, epaint::FontId};

use super::{Application, FONT_SIZE, btn, TextHandlerMessage};

pub(super) trait TextMode {
    fn render_text_mode(&mut self, ui: &mut Ui);
}

impl TextMode for Application {
    fn render_text_mode(&mut self, ui: &mut Ui) {
        match self.text_mode_rx.try_recv() {
            Ok(TextHandlerMessage::Loading) => self.is_loading = true,
            Ok(TextHandlerMessage::Result(result)) => {
                self.sending_is_locked = false;
                self.is_loading = false;
                self.result_text = result;
            },
            Err(_) => {},
        }
        let height: f32 = ui.available_height();
        ui.vertical_centered(|ui| {
            ui.set_height(height);

            ui.horizontal_top(|ui| {
                let width: f32 = ui.available_width() / 2. - 5.;
                let height: f32 = height * 0.88;
                ui.set_height(height);

                ui.vertical(|ui| {
                    ui.push_id(1, |ui| {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            let left_text_edit = egui::TextEdit::multiline(&mut self.input_text)
                                .font(FontId::proportional(FONT_SIZE));

                            ui.set_width(width);
                            ui.add_sized([width, height], left_text_edit);
                            for dropped_file in ui.input().raw.dropped_files.iter() {
                                if let Some(path) = &dropped_file.path {
                                    println!("Dropped file path: {}", path.to_str().unwrap());
                                }
                            }
                        });
                    });

                    ui.add(egui::TextEdit::singleline(&mut self.password)
                           .password(true)
                           .font(FontId::proportional(FONT_SIZE)))
                });

                if self.is_loading {
                    ui.horizontal_centered(|ui| {
                        const SPINNER_SIZE: f32 = 100.;
                        ui.set_width(width);
                        ui.add_space((width - SPINNER_SIZE) / 2.);
                        ui.add(egui::Spinner::new()
                               .size(SPINNER_SIZE));
                    });
                } else {
                    ui.push_id(2, |ui| {
                        egui::ScrollArea::vertical()
                            .show(ui, |ui| {
                                let right_text_edit = egui::TextEdit::multiline(&mut self.result_text)
                                    .font(FontId::monospace(FONT_SIZE))
                                    .hint_text("Результат")
                                    .frame(false);
                                ui.set_width(width);
                                ui.add_sized([width, height], right_text_edit);
                            });
                    });
                }
            });

            ui.add_space(10.);

            let width: f32 = ui.available_width() - 10.;

            ui.vertical_centered(|ui| {
                ui.horizontal_top(|ui| {
                    ui.set_width(width);
                    if self.sending_is_locked {
                        ui.set_enabled(false);
                    }
                    // ui.separator();
                    if btn("Зашифровать", ui).clicked() {
                        self.on_encrypt_text_btn_clicked();
                    }
                    if btn("Расшифровать", ui).clicked() {
                        self.on_decrypt_text_btn_clicked();
                    }
                    if btn("В режим файлов", ui).clicked() {
                        self.to_files_mode();
                    }
                    // ui.separator();
                });
            });
        });
    }
}

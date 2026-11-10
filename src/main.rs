#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod charts;
#[cfg(windows)]
mod diagnostics;
#[cfg(windows)]
mod network;
#[cfg(windows)]
mod ui;

fn main() {
    #[cfg(windows)]
    ui::run();
    #[cfg(not(windows))]
    eprintln!("此程序需要 Windows 10 或 11。");
}

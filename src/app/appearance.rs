use crate::{MainWindow, NoticeBackdrop};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use slint::{
    ComponentHandle,
    winit_030::{
        EventResult, WinitWindowAccessor,
        winit::{event::WindowEvent, window::Theme as WindowTheme},
    },
};
#[cfg(windows)]
use slint::{
    platform::WindowEvent as SlintWindowEvent,
    winit_030::winit::keyboard::{Key, KeyCode, ModifiersState, PhysicalKey},
};
use std::{
    cell::Cell,
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

/// Invalidate the entire client surface when the native backing may have been discarded.
/// request_redraw alone only schedules partial rendering of changed items.
pub fn refresh(ui: &MainWindow) {
    ui.set_surface_fresh(!ui.get_surface_fresh());
    ui.window().request_redraw();
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[repr(i32)]
#[serde(rename_all = "lowercase")]
enum SidebarBackdrop {
    Mica = 1,
    #[default]
    Acrylic = 2,
    #[serde(other)]
    Off = 0,
}

impl SidebarBackdrop {
    fn from_ui(value: i32) -> Self {
        match value {
            1 => Self::Mica,
            2 => Self::Acrylic,
            _ => Self::Off,
        }
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(default)]
struct Preferences {
    dark_theme: bool,
    sidebar_backdrop: SidebarBackdrop,
    sidebar_transparency: i32,
    sidebar_blur: i32,
    notice_transparency: i32,
    notice_blur: i32,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            dark_theme: true,
            sidebar_backdrop: SidebarBackdrop::default(),
            sidebar_transparency: 30,
            sidebar_blur: 32,
            notice_transparency: 48,
            notice_blur: 9,
        }
    }
}

impl Preferences {
    fn bounded(mut self) -> Self {
        self.sidebar_transparency = self.sidebar_transparency.clamp(0, 100);
        self.sidebar_blur = self.sidebar_blur.clamp(0, 32);
        self.notice_transparency = self.notice_transparency.clamp(0, 100);
        self.notice_blur = self.notice_blur.clamp(0, 24);
        self
    }

    fn current(ui: &MainWindow) -> Self {
        Self {
            dark_theme: ui.get_dark_theme(),
            sidebar_backdrop: SidebarBackdrop::from_ui(ui.get_sidebar_backdrop()),
            sidebar_transparency: ui.get_sidebar_transparency(),
            sidebar_blur: ui.get_sidebar_blur(),
            notice_transparency: ui.get_notice_transparency(),
            notice_blur: ui.get_notice_blur(),
        }
        .bounded()
    }

    fn apply(self, ui: &MainWindow) {
        ui.set_dark_theme(self.dark_theme);
        ui.set_sidebar_backdrop(self.sidebar_backdrop as i32);
        ui.set_sidebar_transparency(self.sidebar_transparency);
        ui.set_sidebar_blur(self.sidebar_blur);
        ui.set_notice_transparency(self.notice_transparency);
        ui.set_notice_blur(self.notice_blur);
    }

    fn load(path: &Path) -> Result<Self> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let mut contents = Vec::new();
        file.take(4097).read_to_end(&mut contents)?;
        ensure!(
            contents.len() <= 4096,
            "Appearance preferences exceed 4 KiB"
        );
        let preferences: Self =
            serde_json::from_slice(&contents).context("Could not read appearance preferences")?;
        Ok(preferences.bounded())
    }

    fn save(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(
            path.parent()
                .context("Missing appearance preferences directory")?,
        )?;
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        let mut file = File::create(&temporary)?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.sync_all()?;
        drop(file);
        true_proxy::platform::replace_file(&temporary, path)
            .context("Could not save appearance preferences")
    }
}

pub(super) fn apply_native_theme(ui: &MainWindow) {
    let theme = if ui.get_dark_theme() {
        WindowTheme::Dark
    } else {
        WindowTheme::Light
    };
    ui.window().with_winit_window(|window| {
        window.set_theme(Some(theme));
        ui.set_caption_maximized(window.is_maximized());
    });
    #[cfg(not(windows))]
    ui.set_sidebar_backdrop_active(false);
    #[cfg(windows)]
    {
        let Ok(hwnd) = native_handle(ui) else {
            ui.set_sidebar_backdrop_active(false);
            return;
        };
        let active = true_proxy::platform::windows::presentation::apply_sidebar_backdrop(
            hwnd,
            ui.get_sidebar_backdrop(),
            ui.get_dark_theme(),
            ui.get_sidebar_blur(),
        );
        ui.set_sidebar_backdrop_active(active);
        if active {
            return;
        }
        use windows_sys::Win32::Graphics::Dwm::{
            DWMWA_CAPTION_COLOR, DWMWA_COLOR_DEFAULT, DwmSetWindowAttribute,
        };
        let color = if ui.get_dark_theme() {
            let caption = ui.get_caption_color();
            u32::from_le_bytes([caption.red(), caption.green(), caption.blue(), 0])
        } else {
            DWMWA_COLOR_DEFAULT
        };
        // SAFETY: hwnd belongs to this window, and the attribute expects a COLORREF.
        // Older Windows versions keep their system caption color.
        unsafe {
            DwmSetWindowAttribute(
                hwnd,
                DWMWA_CAPTION_COLOR as u32,
                std::ptr::from_ref(&color).cast(),
                std::mem::size_of_val(&color) as u32,
            );
        }
    }
}

fn wire_preferences(ui: &MainWindow, path: Option<PathBuf>) {
    if let Some(path) = path.as_deref() {
        match Preferences::load(path) {
            Ok(preferences) => preferences.apply(ui),
            Err(error) => super::report(ui, Err(error)),
        }
    }
    let saved = Cell::new(Preferences::current(ui));
    let commit = Rc::new(move |ui: &MainWindow, preferences: Preferences| {
        let previous = saved.get();
        if preferences != previous
            && let Some(path) = &path
            && let Err(error) = preferences.save(path)
        {
            previous.apply(ui);
            super::report(ui, Err(error));
            return;
        }
        saved.set(preferences);
        preferences.apply(ui);
        if previous.dark_theme != preferences.dark_theme
            || previous.sidebar_backdrop != preferences.sidebar_backdrop
        {
            apply_native_theme(ui);
            refresh(ui);
        }
    });
    let save_notice = commit.clone();
    let weak = ui.as_weak();
    ui.on_save_notice_appearance(move || {
        if let Some(ui) = weak.upgrade() {
            save_notice(&ui, Preferences::current(&ui));
        }
    });
    let save_sidebar = commit.clone();
    let weak = ui.as_weak();
    ui.on_save_sidebar_appearance(move || {
        if let Some(ui) = weak.upgrade() {
            save_sidebar(&ui, Preferences::current(&ui));
        }
    });
    let weak = ui.as_weak();
    ui.on_update_sidebar_material(move || {
        if let Some(ui) = weak.upgrade() {
            apply_native_theme(&ui);
            refresh(&ui);
        }
    });
    let weak = ui.as_weak();
    ui.on_choose_theme(move |dark_theme| {
        let Some(ui) = weak.upgrade() else { return };
        if ui.get_dark_theme() == dark_theme {
            return;
        }
        let preferences = Preferences {
            dark_theme,
            ..Preferences::current(&ui)
        };
        commit(&ui, preferences);
    });
}

#[cfg(windows)]
fn refresh_motion_preference(ui: &MainWindow) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SPI_GETCLIENTAREAANIMATION, SystemParametersInfoW,
    };
    let mut enabled = 1i32;
    // SAFETY: this read-only query expects a writable BOOL.
    let result = unsafe {
        SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&raw mut enabled).cast(), 0)
    };
    if result != 0 {
        ui.set_reduce_motion(enabled == 0);
    }
}

pub fn wire(ui: &MainWindow, preferences_path: Option<PathBuf>) {
    wire_preferences(ui, preferences_path);
    #[cfg(windows)]
    let mut transparency_allowed = {
        use true_proxy::platform::windows::presentation::{
            caption_action, sidebar_backdrop_allowed,
        };
        refresh_motion_preference(ui);
        let weak = ui.as_weak();
        ui.on_caption_action(move |action| {
            if let Some(ui) = weak.upgrade()
                && let Ok(hwnd) = native_handle(&ui)
            {
                caption_action(hwnd, action);
            }
        });
        sidebar_backdrop_allowed()
    };
    let weak = ui.as_weak();
    #[cfg(windows)]
    let mut modifiers = ModifiersState::empty();
    #[cfg(windows)]
    let mut themed_window = None;
    let backdrop_refresh = slint::Timer::default();
    ui.window().on_winit_window_event(move |_window, event| {
        // On initial startup show() can precede winit's first realized HWND.
        // Reapply once for each new window, after its native event is dispatched.
        #[cfg(windows)]
        if (themed_window.is_none()
            || matches!(
                event,
                WindowEvent::Focused(true) | WindowEvent::Occluded(false)
            ))
            && let Some(ui) = weak.upgrade()
            && let Some(id) = ui.window().with_winit_window(|window| window.id())
            && themed_window != Some(id)
        {
            themed_window = Some(id);
            let weak = ui.as_weak();
            slint::Timer::single_shot(std::time::Duration::ZERO, move || {
                if let Some(ui) = weak.upgrade()
                    && ui.window().is_visible()
                {
                    apply_native_theme(&ui);
                    refresh(&ui);
                }
            });
        }
        // Refresh a floating card once the underlying page finishes scrolling or editing.
        if matches!(
            event,
            WindowEvent::MouseWheel { .. }
                | WindowEvent::MouseInput {
                    state: slint::winit_030::winit::event::ElementState::Released,
                    ..
                }
                | WindowEvent::KeyboardInput { .. }
                | WindowEvent::Touch(_)
        ) && let Some(ui) = weak.upgrade()
            && ui.get_floating_notices_visible()
        {
            let weak = ui.as_weak();
            backdrop_refresh.start(
                slint::TimerMode::SingleShot,
                std::time::Duration::from_millis(150),
                move || {
                    if let Some(ui) = weak.upgrade()
                        && ui.window().is_visible()
                        && ui.get_floating_notices_visible()
                    {
                        ui.global::<NoticeBackdrop>().invoke_invalidate();
                    }
                },
            );
        }
        if let WindowEvent::ThemeChanged(theme) = event
            && let Some(ui) = weak.upgrade()
            && (*theme == WindowTheme::Dark) != ui.get_dark_theme()
        {
            apply_native_theme(&ui);
        }
        #[cfg(windows)]
        match event {
            WindowEvent::ModifiersChanged(current) => modifiers = current.state(),
            WindowEvent::KeyboardInput {
                event,
                is_synthetic: false,
                ..
            } if event.state.is_pressed() => {
                if let Some(shortcut) =
                    editing_shortcut(modifiers, event.physical_key, &event.logical_key)
                {
                    let text = shortcut.into();
                    _window.dispatch_event(if event.repeat {
                        SlintWindowEvent::KeyPressRepeated { text }
                    } else {
                        SlintWindowEvent::KeyPressed { text }
                    });
                    return EventResult::PreventDefault;
                }
            }
            _ => {}
        }
        if matches!(
            event,
            WindowEvent::Focused(true)
                | WindowEvent::Occluded(false)
                | WindowEvent::Resized(_)
                | WindowEvent::ScaleFactorChanged { .. }
        ) && let Some(ui) = weak.upgrade()
        {
            #[cfg(windows)]
            if matches!(event, WindowEvent::Focused(true)) {
                refresh_motion_preference(&ui);
                let allowed =
                    true_proxy::platform::windows::presentation::sidebar_backdrop_allowed();
                if allowed != transparency_allowed {
                    transparency_allowed = allowed;
                    if ui.get_sidebar_backdrop() != SidebarBackdrop::Off as i32 {
                        apply_native_theme(&ui);
                    }
                }
            }
            if matches!(event, WindowEvent::Resized(_)) {
                ui.window()
                    .with_winit_window(|window| ui.set_caption_maximized(window.is_maximized()));
            }
            if matches!(event, WindowEvent::Resized(size) if size.width == 0 || size.height == 0) {
                ui.invoke_suspend_connection_observation();
            } else {
                refresh(&ui);
                ui.global::<NoticeBackdrop>().invoke_invalidate();
                ui.invoke_sync_connection_observation();
            }
        }
        EventResult::Propagate
    });
}

/// Slint's standard editing shortcuts match Latin key text. On another layout,
/// send the corresponding Latin letter for these physical Ctrl combinations.
#[cfg(windows)]
fn editing_shortcut(
    modifiers: ModifiersState,
    physical: PhysicalKey,
    logical: &Key,
) -> Option<&'static str> {
    if modifiers != ModifiersState::CONTROL {
        return None;
    }
    let Key::Character(text) = logical else {
        return None;
    };
    let shortcut = match physical {
        PhysicalKey::Code(KeyCode::KeyA) => "a",
        PhysicalKey::Code(KeyCode::KeyC) => "c",
        PhysicalKey::Code(KeyCode::KeyV) => "v",
        PhysicalKey::Code(KeyCode::KeyX) => "x",
        PhysicalKey::Code(KeyCode::KeyZ) => "z",
        PhysicalKey::Code(KeyCode::KeyY) => "y",
        _ => return None,
    };
    (!text.is_ascii() || (text.as_str() != shortcut && text.eq_ignore_ascii_case(shortcut)))
        .then_some(shortcut)
}

#[cfg(windows)]
pub(super) fn native_handle(
    ui: &impl ComponentHandle,
) -> anyhow::Result<windows_sys::Win32::Foundation::HWND> {
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    ui.window()
        .with_winit_window(|window| {
            if let Ok(handle) = window.window_handle()
                && let RawWindowHandle::Win32(handle) = handle.as_raw()
            {
                Some(handle.hwnd.get() as _)
            } else {
                None
            }
        })
        .flatten()
        .ok_or_else(|| anyhow::anyhow!("Diagnostic window has not been created"))
}
/// Smoke-only: exercise the actual presented client surface, not take_snapshot,
/// which renders a fresh image and cannot detect a lost native backing buffer.
#[cfg(windows)]
pub fn mark_surface(
    ui: &MainWindow,
) -> anyhow::Result<true_proxy::platform::windows::presentation::SurfaceProbe> {
    true_proxy::platform::windows::presentation::mark_owned_surface(
        native_handle(ui)?,
        ui.window().scale_factor(),
    )
}
#[cfg(windows)]
pub fn verify_surface(
    ui: &MainWindow,
    probe: &true_proxy::platform::windows::presentation::SurfaceProbe,
) -> anyhow::Result<()> {
    true_proxy::platform::windows::presentation::verify_owned_surface(native_handle(ui)?, probe)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::platform::{Key as SlintKey, PointerEventButton};

    #[test]
    fn general_settings_actions_accept_first_click_in_wide_and_stacked_layouts() {
        i_slint_backend_testing::init_no_event_loop();
        for (width, height) in [(1240., 780.), (960., 640.)] {
            let ui = MainWindow::new().unwrap();
            ui.window().set_size(slint::LogicalSize::new(width, height));
            ui.set_page(4);
            ui.set_autostart_enabled(false);
            ui.set_updates_automatic(false);

            let checks = Rc::new(Cell::new(0));
            let called = checks.clone();
            ui.on_check_updates(move || called.set(called.get() + 1));
            let startup = Rc::new(Cell::new(None));
            let called = startup.clone();
            ui.on_set_autostart(move |enabled| called.set(Some(enabled)));
            let automatic = Rc::new(Cell::new(None));
            let called = automatic.clone();
            ui.on_set_updates_automatic(move |enabled| called.set(Some(enabled)));
            ui.show().unwrap();

            let scroll = ElementHandle::find_by_element_id(&ui, "MainWindow::settings-scroll")
                .next()
                .unwrap();
            let click = |label: &str| {
                let find = || ElementHandle::find_by_accessible_label(&ui, label).next();
                // The accessibility tree only exposes controls in the viewport.
                let control = find()
                    .or_else(|| {
                        scroll.scroll(0., -scroll.size().height);
                        i_slint_backend_testing::mock_elapsed_time(
                            std::time::Duration::from_millis(250),
                        );
                        find()
                    })
                    .unwrap_or_else(|| panic!("General settings control missing: {label}"));
                let below = control.absolute_position().y + control.size().height
                    - scroll.absolute_position().y
                    - scroll.size().height;
                if below > 0. {
                    scroll.scroll(0., -below - 16.);
                    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(
                        250,
                    ));
                }
                control.mock_single_click(PointerEventButton::Left);
            };
            click("Check for Updates");
            assert_eq!(checks.get(), 1);
            click("Check for updates automatically");
            assert_eq!(automatic.get(), Some(true));
            assert!(ui.get_updates_automatic());
            click("Start when I sign in to Windows");
            assert_eq!(startup.get(), Some(true));
            assert!(ui.get_autostart_enabled());
            ui.hide().unwrap();
        }
    }

    #[test]
    fn theme_and_surface_effects_migrate_and_survive_a_new_window() {
        i_slint_backend_testing::init_no_event_loop();
        let directory =
            std::env::temp_dir().join(format!("true-proxy-appearance-{}", super::super::id()));
        let path = directory.join("appearance.json");
        fs::create_dir_all(&directory).unwrap();
        fs::write(&path, br#"{"dark_theme":true}"#).unwrap();
        let window = || {
            let ui = MainWindow::new().unwrap();
            ui.window().set_size(slint::LogicalSize::new(1240., 780.));
            wire_preferences(&ui, Some(path.clone()));
            ui.set_page(4);
            ui.show().unwrap();
            ui
        };
        let click = |ui: &MainWindow, label| {
            ElementHandle::find_by_accessible_label(ui, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                .unwrap()
                .mock_single_click(PointerEventButton::Left);
        };

        let ui = window();
        assert!(ui.get_dark_theme());
        assert_eq!(
            (
                ui.get_sidebar_backdrop(),
                ui.get_sidebar_transparency(),
                ui.get_sidebar_blur()
            ),
            (2, 30, 32),
        );
        assert_eq!(
            (ui.get_notice_transparency(), ui.get_notice_blur()),
            (48, 9)
        );
        let slider = |ui: &MainWindow, label| {
            ElementHandle::find_by_accessible_label(ui, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Slider))
                .unwrap()
        };
        let press_key = |ui: &MainWindow, key: SlintKey| {
            ui.window()
                .dispatch_event(SlintWindowEvent::KeyPressed { text: key.into() });
            ui.window()
                .dispatch_event(SlintWindowEvent::KeyReleased { text: key.into() });
        };
        let button = PointerEventButton::Left;
        click(&ui, "Off");
        assert_eq!(
            slider(&ui, "Sidebar transparency").accessible_enabled(),
            Some(false)
        );
        assert_eq!(
            Preferences::load(&path).unwrap().sidebar_backdrop,
            SidebarBackdrop::Off
        );
        click(&ui, "Acrylic");
        assert_eq!(ui.get_sidebar_backdrop(), 2);
        assert!(!ui.get_sidebar_backdrop_active()); // No native window on the testing backend.
        slider(&ui, "Sidebar transparency").mock_single_click(button);
        press_key(&ui, SlintKey::End);
        slider(&ui, "Sidebar frost level").mock_single_click(button);
        let transitions = Rc::new(Cell::new(0));
        let calls = transitions.clone();
        ui.on_update_sidebar_material(move || calls.set(calls.get() + 1));
        for (key, count) in [
            (SlintKey::Home, 1),
            (SlintKey::RightArrow, 2),
            (SlintKey::RightArrow, 2),
        ] {
            press_key(&ui, key);
            i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(1));
            assert_eq!(transitions.get(), count);
            assert_eq!(
                Preferences::load(&path).unwrap().sidebar_blur,
                ui.get_sidebar_blur()
            );
        }
        press_key(&ui, SlintKey::End);
        let saved = Preferences::load(&path).unwrap();
        assert_eq!(
            (
                saved.sidebar_backdrop,
                saved.sidebar_transparency,
                saved.sidebar_blur
            ),
            (SidebarBackdrop::Acrylic, 100, 32)
        );
        click(&ui, "Notification surface effects");
        let transparency = slider(&ui, "Notification transparency");
        let origin = transparency.absolute_position();
        let size = transparency.size();
        let position =
            slint::LogicalPosition::new(origin.x + size.width * 0.75, origin.y + size.height / 2.);
        ui.window()
            .dispatch_event(SlintWindowEvent::PointerMoved { position });
        ui.window()
            .dispatch_event(SlintWindowEvent::PointerPressed { position, button });
        let chosen = ui.get_notice_transparency();
        assert!((70..=80).contains(&chosen));
        assert_eq!(Preferences::load(&path).unwrap().notice_transparency, 48);
        ui.window()
            .dispatch_event(SlintWindowEvent::PointerReleased { position, button });
        assert_eq!(
            Preferences::load(&path).unwrap().notice_transparency,
            chosen
        );
        slider(&ui, "Notification background blur").mock_single_click(button);
        press_key(&ui, SlintKey::End);
        assert_eq!(Preferences::load(&path).unwrap().notice_blur, 24);
        click(&ui, "Light theme");
        assert!(!ui.get_dark_theme() && !Preferences::load(&path).unwrap().dark_theme);
        ui.hide().unwrap();

        let ui = window();
        assert!(!ui.get_dark_theme());
        assert_eq!(
            (
                ui.get_sidebar_backdrop(),
                ui.get_sidebar_transparency(),
                ui.get_sidebar_blur()
            ),
            (2, 100, 32),
        );
        assert!(slider(&ui, "Sidebar transparency").accessible_enabled() != Some(false));
        assert_eq!(
            (ui.get_notice_transparency(), ui.get_notice_blur()),
            (chosen, 24)
        );
        click(&ui, "Notification surface effects");
        slider(&ui, "Notification background blur").mock_single_click(button);
        press_key(&ui, SlintKey::Home);
        let saved = Preferences::load(&path).unwrap();
        assert!(!saved.dark_theme);
        assert_eq!((saved.notice_transparency, saved.notice_blur), (chosen, 0));
        click(&ui, "Dark theme");
        assert!(ui.get_dark_theme() && Preferences::load(&path).unwrap().dark_theme);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn sidebar_modes_serialize_by_name_and_legacy_notice_values_are_preserved() {
        let old = serde_json::from_str::<Preferences>(
            r#"{"dark_theme":false,"notice_transparency":81,"notice_blur":17}"#,
        )
        .unwrap();
        let json = serde_json::to_value(old).unwrap();
        assert_eq!(json["sidebar_backdrop"], "acrylic");
        assert_eq!((old.sidebar_transparency, old.sidebar_blur), (30, 32));
        assert_eq!((old.notice_transparency, old.notice_blur), (81, 17));
        let partial =
            serde_json::from_str::<Preferences>(r#"{"sidebar_backdrop":"mica","sidebar_blur":0}"#)
                .unwrap();
        assert_eq!(partial.sidebar_backdrop, SidebarBackdrop::Mica);
        assert_eq!(
            (partial.sidebar_transparency, partial.sidebar_blur),
            (30, 0)
        );
        let edited = serde_json::from_str::<Preferences>(
            r#"{"dark_theme":false,"sidebar_backdrop":"future-mode","sidebar_transparency":-5,"sidebar_blur":40,"notice_transparency":81,"notice_blur":17}"#,
        ).unwrap().bounded();
        assert_eq!(edited.sidebar_backdrop, SidebarBackdrop::Off);
        assert_eq!((edited.sidebar_transparency, edited.sidebar_blur), (0, 32));
        assert_eq!((edited.notice_transparency, edited.notice_blur), (81, 17));
        assert!(!edited.dark_theme);
    }

    #[test]
    fn russian_editing_shortcuts_use_the_native_input_and_test_clipboard() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1240., 780.));
        ui.set_dialog(1);
        ui.set_form_name("Прокси".into());
        ui.set_form_host("".into());
        ui.show().unwrap();
        let click = |label: &str| {
            ElementHandle::find_by_accessible_label(&ui, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::TextInput))
                .unwrap()
                .mock_single_click(PointerEventButton::Left);
        };
        click("Proxy Name");
        let window = ui.window();
        window.dispatch_event(SlintWindowEvent::KeyPressed {
            text: SlintKey::Control.into(),
        });
        let press = |code, letter: &str| {
            let text = editing_shortcut(
                ModifiersState::CONTROL,
                PhysicalKey::Code(code),
                &Key::Character(letter.into()),
            )
            .unwrap()
            .into();
            window.dispatch_event(SlintWindowEvent::KeyPressed { text });
        };
        press(KeyCode::KeyA, "ф");
        press(KeyCode::KeyC, "с");
        click("Host Address");
        press(KeyCode::KeyV, "м");
        assert_eq!(ui.get_form_host().as_str(), "Прокси");
        click("Proxy Name");
        press(KeyCode::KeyA, "ф");
        press(KeyCode::KeyX, "ч");
        assert!(ui.get_form_name().is_empty());
        press(KeyCode::KeyV, "м");
        assert_eq!(ui.get_form_name().as_str(), "Прокси");
        press(KeyCode::KeyZ, "я");
        assert!(ui.get_form_name().is_empty());
        press(KeyCode::KeyY, "н");
        assert_eq!(ui.get_form_name().as_str(), "Прокси");
        window.dispatch_event(SlintWindowEvent::KeyReleased {
            text: SlintKey::Control.into(),
        });
    }

    #[test]
    fn ordinary_typing_and_other_modifiers_keep_native_keyboard_events() {
        let v = PhysicalKey::Code(KeyCode::KeyV);
        let russian = Key::Character("м".into());
        for modifiers in [
            ModifiersState::empty(),
            ModifiersState::CONTROL | ModifiersState::ALT,
            ModifiersState::CONTROL | ModifiersState::SHIFT,
            ModifiersState::CONTROL | ModifiersState::SUPER,
        ] {
            assert_eq!(editing_shortcut(modifiers, v, &russian), None);
        }
        for letter in ["v", "j"] {
            assert_eq!(
                editing_shortcut(ModifiersState::CONTROL, v, &Key::Character(letter.into())),
                None
            );
        }
        assert_eq!(
            editing_shortcut(ModifiersState::CONTROL, v, &Key::Character("V".into())),
            Some("v")
        );
    }
}

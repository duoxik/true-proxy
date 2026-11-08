use crate::MainWindow;
use slint::{
    ComponentHandle,
    winit_030::{EventResult, WinitWindowAccessor, winit::event::WindowEvent},
};
#[cfg(windows)]
use slint::{
    platform::WindowEvent as SlintWindowEvent,
    winit_030::winit::keyboard::{Key, KeyCode, ModifiersState, PhysicalKey},
};

/// Invalidate the full opaque surface only when it may have been discarded.
/// request_redraw alone only schedules partial rendering of changed items.
pub fn refresh(ui: &MainWindow) {
    ui.set_surface_fresh(!ui.get_surface_fresh());
    ui.window().request_redraw();
}
pub fn wire(ui: &MainWindow) {
    let weak = ui.as_weak();
    #[cfg(windows)]
    let mut modifiers = ModifiersState::empty();
    ui.window().on_winit_window_event(move |_window, event| {
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
            if matches!(event, WindowEvent::Resized(size) if size.width == 0 || size.height == 0) {
                ui.invoke_suspend_connection_observation();
            } else {
                refresh(&ui);
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

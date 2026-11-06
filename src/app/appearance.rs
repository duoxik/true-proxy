use crate::MainWindow;
use slint::{
    ComponentHandle,
    winit_030::{EventResult, WinitWindowAccessor, winit::event::WindowEvent},
};

/// Invalidate the full opaque surface only when it may have been discarded.
/// request_redraw alone only schedules partial rendering of changed items.
pub fn refresh(ui: &MainWindow) {
    ui.set_surface_fresh(!ui.get_surface_fresh());
    ui.window().request_redraw();
}
pub fn wire(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.window().on_winit_window_event(move |_, event| {
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

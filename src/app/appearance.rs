use crate::{ConnectionsWindow, MainWindow};
use slint::{
    ComponentHandle,
    winit_030::{EventResult, WinitWindowAccessor, winit::event::WindowEvent},
};
use std::{cell::Cell, rc::Rc, time::Duration};

/// Invalidate the full opaque surface only when it may have been discarded.
/// request_redraw alone only schedules partial rendering of changed items.
pub fn refresh(ui: &MainWindow) {
    ui.set_surface_fresh(!ui.get_surface_fresh());
    ui.window().request_redraw();
}
pub fn wire(ui: &MainWindow, connections: &ConnectionsWindow, preview: bool) {
    let weak = ui.as_weak();
    #[cfg(windows)]
    let connections = connections.as_weak();
    #[cfg(not(windows))]
    let _ = connections;
    let focused = Rc::new(Cell::new(false));
    let blur_timer = Rc::new(slint::Timer::default());
    ui.window().on_winit_window_event(move |_, event| {
        if let WindowEvent::Focused(value) = event {
            focused.set(*value);
            if *value {
                blur_timer.stop();
            } else if !preview {
                let weak = weak.clone();
                #[cfg(windows)]
                let connections = connections.clone();
                let focused = focused.clone();
                let weak_timer = Rc::downgrade(&blur_timer);
                blur_timer.start(
                    slint::TimerMode::Repeated,
                    Duration::from_millis(100),
                    move || {
                        let stop = || {
                            if let Some(timer) = weak_timer.upgrade() {
                                timer.stop();
                            }
                        };
                        let Some(ui) = weak.upgrade() else {
                            stop();
                            return;
                        };
                        if !ui.window().is_visible() || focused.get() {
                            stop();
                            return;
                        }
                        #[cfg(windows)]
                        let own = {
                            let separate_window = connections
                                .upgrade()
                                .and_then(|window| native_handle(&window).ok());
                            true_proxy::platform::windows::panel::foreground_is_own_process_except(
                                separate_window,
                            )
                        };
                        #[cfg(not(windows))]
                        let own = false;
                        if !own {
                            ui.invoke_hide_window();
                            stop();
                        }
                    },
                );
            }
        }
        if matches!(
            event,
            WindowEvent::Focused(true)
                | WindowEvent::Occluded(false)
                | WindowEvent::Resized(_)
                | WindowEvent::ScaleFactorChanged { .. }
        ) && let Some(ui) = weak.upgrade()
            && !matches!(event, WindowEvent::Resized(size) if size.width == 0 || size.height == 0)
        {
            refresh(&ui);
        }
        EventResult::Propagate
    });
}

pub fn wire_connections(ui: &ConnectionsWindow) {
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
                ui.invoke_suspend_connections();
            } else {
                ui.invoke_resume_observation();
                ui.set_surface_fresh(!ui.get_surface_fresh());
                ui.window().request_redraw();
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
        .ok_or_else(|| anyhow::anyhow!("Окно проверки не создано"))
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

use super::{MainWindow, XrayModule, XrayRestartPhase, finish_restart};
use i_slint_backend_testing::{
    AccessibleLiveness, AccessibleRole, ElementHandle, mock_elapsed_time,
};
use slint::{
    ComponentHandle, LogicalSize,
    platform::{Key, PointerEventButton, WindowEvent},
};
use std::time::Duration;

const HIDE: &str = "Hide in notifications";
const RESTART: &str =
    "Restart Xray to apply changes. Xray pauses briefly and its proxy connections close.";
const LIST_RESTART: &str = "Restart · Restart Xray to apply changes";

fn find(ui: &MainWindow, label: &str) -> Option<ElementHandle> {
    ElementHandle::find_by_accessible_label(ui, label).find(|element| {
        label != "Notifications" || element.accessible_role() == Some(AccessibleRole::Button)
    })
}

fn control(ui: &MainWindow, label: &str) -> ElementHandle {
    find(ui, label).unwrap_or_else(|| panic!("Missing {label}"))
}

fn click(ui: &MainWindow, label: &str) {
    control(ui, label).mock_single_click(PointerEventButton::Left);
}

fn key(ui: &MainWindow, key: Key) {
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: key.into() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text: key.into() });
}

fn tick(ms: u64) {
    mock_elapsed_time(Duration::ZERO);
    mock_elapsed_time(Duration::from_millis(ms));
}

fn window() -> MainWindow {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().unwrap();
    ui.window().set_size(LogicalSize::new(1240., 780.));
    ui.set_page(6);
    let xray = ui.global::<XrayModule>();
    xray.set_installed(true);
    xray.set_running(true);
    xray.set_section(1);
    ui.show().unwrap();
    ui
}

#[test]
fn only_new_pending_runtime_changes_advance_the_pulse() {
    use super::{Activity, Arc, Bypass, Controller, SharedGeoCatalog};

    let directory = std::env::temp_dir().join(format!("true-proxy-notice-{}", super::super::id()));
    let mut controller = Controller::load(
        directory.clone(),
        Arc::new(Bypass::default()),
        Arc::new(Activity::default()),
        SharedGeoCatalog::default(),
    )
    .unwrap();
    let original = controller.settings.clone();
    let mut changed = original.clone();
    changed.dns = vec!["192.0.2.1".into()];
    controller.save_settings(changed.clone(), false).unwrap();
    assert!(!controller.pending);
    assert_eq!(controller.pending_revision, 0);

    controller.applied = Some(changed.clone());
    changed.dns.push("192.0.2.2".into());
    controller.save_settings(changed.clone(), false).unwrap();
    assert!(controller.pending);
    assert_eq!(controller.pending_revision, 1);
    changed.log_recording = !changed.log_recording;
    controller.save_settings(changed.clone(), false).unwrap();
    assert_eq!(controller.pending_revision, 1);
    changed.dns.pop();
    controller.save_settings(changed, false).unwrap();
    assert!(!controller.pending);
    assert_eq!(controller.pending_revision, 1);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn notice_preserves_layout_focus_and_scope() {
    let ui = window();
    let xray = ui.global::<XrayModule>();
    xray.set_profiles(super::model(
        (0..20)
            .map(|i| crate::XrayProfileRow {
                id: format!("sample-{i}").into(),
                name: format!("Sample {i}").into(),
                ..Default::default()
            })
            .collect(),
    ));
    let scroll = || {
        ElementHandle::find_by_element_id(&ui, "XrayView::settings-scroll")
            .next()
            .unwrap()
    };
    let content = || {
        ElementHandle::find_by_element_id(&ui, "XrayView::section-content")
            .next()
            .unwrap()
    };
    let before = (
        scroll().absolute_position(),
        scroll().size(),
        content().size(),
    );
    // Showing the notice leaves the text field's focus where the user put it.
    click(&ui, "VLESS, HTTPS, or v2RayTun link");
    xray.set_pending(true);
    tick(250);
    assert_eq!(scroll().absolute_position(), before.0);
    assert_eq!(scroll().size(), before.1);
    assert_eq!(content().size().height, before.2.height + 72.);
    assert_eq!(
        control(&ui, RESTART).accessible_live_region(),
        Some(AccessibleLiveness::Polite)
    );
    key(&ui, Key::Escape);
    assert!(!xray.get_restart_collapsed());

    click(&ui, HIDE);
    tick(250);
    assert!(xray.get_restart_collapsed());
    assert!(find(&ui, RESTART).is_none());
    assert_eq!(content().size(), before.2);
    key(&ui, Key::Return);
    tick(250);
    let title = ElementHandle::find_by_element_id(&ui, "NoticeListRow::notice-title")
        .next()
        .unwrap();
    let action = control(&ui, LIST_RESTART);
    assert!(title.size().width >= 260.);
    assert!(action.absolute_position().y >= title.absolute_position().y + title.size().height);
    assert!((action.absolute_position().x - title.absolute_position().x).abs() <= 1.);
    assert!(find(&ui, RESTART).is_none());
    key(&ui, Key::Escape);
    tick(250);
    assert!(find(&ui, LIST_RESTART).is_none());

    // Opening focuses the panel. Tab reaches its close button and Enter returns to the bell.
    key(&ui, Key::Return);
    tick(0);
    assert!(find(&ui, LIST_RESTART).is_some());
    key(&ui, Key::Tab);
    key(&ui, Key::Return);
    tick(0);
    assert!(find(&ui, LIST_RESTART).is_none());

    for section in 0..7 {
        xray.set_section(section);
        assert!(xray.get_restart_collapsed());
    }
    ui.set_page(2);
    tick(250);
    assert!(find(&ui, RESTART).is_none());
    assert_eq!(
        control(&ui, "Notifications")
            .accessible_description()
            .unwrap(),
        "Hidden notifications available"
    );
    assert!(
        control(&ui, "X-RAY")
            .accessible_description()
            .is_none_or(|description| description.is_empty())
    );
    click(&ui, "Notifications");
    tick(250);
    assert!(find(&ui, LIST_RESTART).is_some());
    assert!(find(&ui, RESTART).is_none());
    click(&ui, "Close notifications");
    ui.set_page(6);
    tick(250);
    xray.set_pending_revision(1);
    tick(250);
    assert!(xray.get_restart_collapsed());
    xray.set_section(1);
    xray.set_pending(false);
    tick(250);
    assert_eq!(
        control(&ui, "Notifications")
            .accessible_description()
            .unwrap(),
        "No hidden notifications"
    );
    assert_eq!(content().size(), before.2);
    xray.set_pending(true);
    tick(250);
    assert!(find(&ui, RESTART).is_some());
    xray.set_installed(false);
    tick(250);
    assert!(find(&ui, RESTART).is_none());
    assert!(find(&ui, "X-RAY").is_none());
}

#[test]
fn notice_shows_restart_outcomes_and_scopes_other_notices() {
    let ui = window();
    ui.set_dark_theme(false);
    ui.set_reduce_motion(true);
    let xray = ui.global::<XrayModule>();
    let weak = ui.as_weak();
    xray.on_restart(move || {
        if let Some(ui) = weak.upgrade() {
            ui.global::<XrayModule>()
                .set_restart_phase(XrayRestartPhase::Restarting);
        }
    });
    xray.set_pending(true);
    tick(250);
    let notice_position = control(&ui, RESTART).absolute_position();
    click(&ui, "Restart");
    tick(250);
    assert!(find(&ui, "Restarting Xray…").is_some());
    assert_eq!(control(&ui, "Restart").accessible_enabled(), Some(false));
    assert_eq!(
        control(&ui, "Restarting Xray…").absolute_position(),
        notice_position
    );

    xray.set_running(false);
    xray.set_pending(false);
    finish_restart(&ui, "Sample startup failure".into());
    tick(250);
    assert!(find(&ui, "Xray restart failed. Sample startup failure").is_some());
    assert_eq!(control(&ui, "Retry").accessible_enabled(), Some(true));
    click(&ui, "View logs");
    assert_eq!(xray.get_section(), 6);
    click(&ui, HIDE);
    tick(250);
    ui.set_page(2);
    click(&ui, "Notifications");
    tick(250);
    click(&ui, "View logs · Xray restart failed");
    assert_eq!(ui.get_page(), 6);
    assert_eq!(xray.get_section(), 6);
    assert!(xray.get_restart_collapsed());
    click(&ui, "Notifications");
    tick(250);
    click(&ui, "Retry · Xray restart failed");
    assert_eq!(xray.get_restart_phase(), XrayRestartPhase::Restarting);
    assert!(find(&ui, "Retry").is_none());
    finish_restart(&ui, String::new());
    tick(500);
    assert!(find(&ui, "Restarted").is_some());
    tick(750);
    assert!(find(&ui, "Restarted").is_none());
    click(&ui, "Close notifications");
    tick(0);
    assert_eq!(
        control(&ui, "Notifications").accessible_expanded(),
        Some(false)
    );
    assert_eq!(
        control(&ui, "Notifications")
            .accessible_description()
            .unwrap(),
        "No hidden notifications"
    );

    ui.set_routing_pending(true);
    ui.set_update_available(true);
    ui.set_update_version("99.0".into());
    ui.set_notice("Sample general notification".into());
    tick(250);
    assert!(find(&ui, "Sample general notification").is_none());
    assert!(find(&ui, "True Proxy 99.0 is available").is_none());
    ui.set_page(2);
    tick(250);
    assert!(find(&ui, "Sample general notification").is_some());
    assert!(find(&ui, "True Proxy 99.0 is available").is_some());
    assert!(find(&ui, "Restart").is_some());
    // The app messages share the same list and keep their own actions.
    for _ in 0..3 {
        click(&ui, HIDE);
        tick(250);
    }
    assert_eq!(ui.get_notice(), "Sample general notification");
    ui.set_page(6);
    click(&ui, "Notifications");
    tick(250);
    assert!(find(&ui, "Restart · Restart routing to apply changes").is_some());
    assert!(find(&ui, "Install and Restart · True Proxy 99.0 is available").is_some());
    assert!(find(&ui, "Clear all").is_none());
    click(&ui, "Dismiss · True Proxy");
    assert!(ui.get_notice().is_empty());
    assert!(find(&ui, "Clear all").is_none());
    click(&ui, "Close notifications");
    ui.set_page(4);
    tick(250);
    assert!(find(&ui, "Restart").is_none());
    assert!(find(&ui, "Install and Restart").is_none());
}

#[test]
fn clear_all_removes_a_dismissible_message_and_leaves_the_empty_center_open() {
    let ui = window();
    ui.set_page(2);
    ui.set_notice("Sample general notification".into());
    tick(250);
    click(&ui, HIDE);
    tick(250);
    click(&ui, "Notifications");

    assert!(find(&ui, "Dismiss · True Proxy").is_some());
    click(&ui, "Clear all");
    tick(250);
    assert!(ui.get_notice().is_empty());
    assert!(find(&ui, "No hidden notifications").is_some());
    assert!(find(&ui, "Clear all").is_none());
    assert!(find(&ui, "Close notifications").is_some());
}

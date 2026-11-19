use crate::{MainWindow, XrayModule, XrayPortDraft};
use anyhow::{Context, Result};
use slint::{ComponentHandle, Model, SharedString};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, time::Duration};
use true_proxy::xray::profile::Settings;

pub(in crate::app) struct PortEdit {
    pub(in crate::app) owner: String,
    pub(in crate::app) profile: bool,
    pub(in crate::app) value: String,
}

impl PortEdit {
    fn number(value: &str) -> Result<u16> {
        let port = value
            .parse::<u16>()
            .ok()
            .filter(|port| *port >= 1024 && value.bytes().all(|byte| byte.is_ascii_digit()));
        port.context("Enter a port between 1024 and 65535.")
    }

    pub(in crate::app) fn apply(&self, settings: &mut Settings) -> Result<Option<u16>> {
        if self.profile {
            let custom = if self.value.is_empty() {
                None
            } else {
                Some(Self::number(&self.value)?)
            };
            let profile = settings
                .profiles
                .iter()
                .find(|p| p.id == self.owner)
                .context("Profile not found")?;
            if profile.custom_port == custom {
                return Ok(None);
            }
            let port =
                custom.unwrap_or_else(|| settings.default_port(profile.subscription.as_deref()));
            settings.set_custom_port(&self.owner, custom)?;
            Ok(Some(port))
        } else {
            let port = Self::number(&self.value)?;
            let container = (!self.owner.is_empty()).then_some(self.owner.as_str());
            if settings.default_port(container) == port {
                return Ok(None);
            }
            settings.set_default_port(container, port)?;
            Ok(Some(port))
        }
    }
}

type PortFieldKey = (SharedString, bool);

enum PortDraftState {
    Editing,
    Ready,
    Saving,
    Invalid,
}

struct PortDraft {
    value: SharedString,
    error: SharedString,
    state: PortDraftState,
    revision: i32,
}

#[derive(Default)]
struct PortEditor {
    active: Option<PortFieldKey>,
    drafts: BTreeMap<PortFieldKey, PortDraft>,
    in_flight: Option<i32>,
}

impl PortEditor {
    fn save_pending(&self) -> bool {
        self.in_flight.is_some()
            || self
                .drafts
                .values()
                .any(|draft| matches!(draft.state, PortDraftState::Editing | PortDraftState::Ready))
    }

    fn prepare(&mut self, key: &PortFieldKey, allow_inherit: bool) {
        let Some(draft) = self.drafts.get_mut(key) else {
            return;
        };
        if !matches!(
            draft.state,
            PortDraftState::Editing | PortDraftState::Invalid
        ) {
            return;
        }
        let result = if allow_inherit && key.1 && draft.value.is_empty() {
            Ok(())
        } else {
            PortEdit::number(&draft.value).map(|_| ())
        };
        match result {
            Ok(_) => {
                draft.state = PortDraftState::Ready;
                draft.error = SharedString::default();
            }
            Err(error) => {
                draft.state = PortDraftState::Invalid;
                draft.error = error.to_string().into();
            }
        }
    }
}

fn update_port_drafts(xray: &XrayModule<'_>, editor: &RefCell<PortEditor>) {
    let save_pending = editor.borrow().save_pending();
    xray.set_port_save_pending(save_pending);
    let revision = xray.get_port_draft_revision().wrapping_add(1);
    xray.set_port_draft_revision(revision);
}

pub(in crate::app) fn wire_port_editor(
    ui: &MainWindow,
    submit: impl Fn(&MainWindow, PortEdit, i32) -> bool + 'static,
) {
    let xray = ui.global::<XrayModule>();
    let state = Rc::new(RefCell::new(PortEditor::default()));
    let timer = Rc::new(slint::Timer::default());
    let drafts = state.clone();
    xray.on_port_draft(move |owner, profile, _| {
        drafts
            .borrow()
            .drafts
            .get(&(owner, profile))
            .map_or_else(XrayPortDraft::default, |draft| XrayPortDraft {
                present: true,
                value: draft.value.clone(),
                error: draft.error.clone(),
            })
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    let edit_timer = timer.clone();
    xray.on_edit_port(move |owner, profile, value| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let key = (owner, profile);
        let revision = xray.get_port_draft_revision().wrapping_add(1);
        {
            let mut editor = drafts.borrow_mut();
            if let Some(previous) = editor.active.replace(key.clone())
                && previous != key
            {
                editor.prepare(&previous, true);
            }
            editor.drafts.insert(
                key.clone(),
                PortDraft {
                    value,
                    error: SharedString::default(),
                    state: PortDraftState::Editing,
                    revision,
                },
            );
        }
        xray.set_port_save_pending(true);
        xray.set_port_draft_revision(revision);
        let drafts = drafts.clone();
        let weak = weak.clone();
        edit_timer.start(
            slint::TimerMode::SingleShot,
            Duration::from_millis(550),
            move || {
                let Some(ui) = weak.upgrade() else { return };
                let xray = ui.global::<XrayModule>();
                drafts.borrow_mut().prepare(&key, false);
                update_port_drafts(&xray, &drafts);
                xray.invoke_process_port_edits();
            },
        );
        xray.invoke_process_port_edits();
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_commit_port(move |owner, profile| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let key = (owner, profile);
        {
            let mut editor = drafts.borrow_mut();
            if editor.active.as_ref() == Some(&key) {
                timer.stop();
                editor.active = None;
            }
            editor.prepare(&key, true);
        }
        update_port_drafts(&xray, &drafts);
        xray.invoke_process_port_edits();
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_flush_port_edit(move || {
        let active = drafts.borrow().active.clone();
        if let Some(((owner, profile), ui)) = active.zip(weak.upgrade()) {
            ui.global::<XrayModule>().invoke_commit_port(owner, profile);
        }
    });
    let weak = ui.as_weak();
    xray.on_reset_profile_port(move |owner, _| {
        if let Some(ui) = weak.upgrade() {
            let xray = ui.global::<XrayModule>();
            xray.invoke_edit_port(owner.clone(), true, SharedString::default());
            xray.invoke_commit_port(owner, true);
        }
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_process_port_edits(move || {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        if xray.get_busy() {
            return;
        }
        loop {
            let pending = {
                let mut editor = drafts.borrow_mut();
                if editor.in_flight.is_some() {
                    return;
                }
                let pending = editor
                    .drafts
                    .iter_mut()
                    .filter(|(_, draft)| matches!(draft.state, PortDraftState::Ready))
                    .min_by_key(|(_, draft)| draft.revision)
                    .map(|((owner, profile), draft)| {
                        draft.state = PortDraftState::Saving;
                        (owner.clone(), *profile, draft.value.clone(), draft.revision)
                    });
                editor.in_flight = pending.as_ref().map(|(_, _, _, revision)| *revision);
                pending
            };
            let Some((owner, profile, value, revision)) = pending else {
                return;
            };
            if !submit(
                &ui,
                PortEdit {
                    owner: owner.to_string(),
                    profile,
                    value: value.to_string(),
                },
                revision,
            ) {
                xray.invoke_finish_port_edit(
                    owner,
                    profile,
                    revision,
                    "Could not save the port. Try again.".into(),
                );
            }
        }
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_finish_port_edit(move |owner, profile, revision, error| {
        let Some(ui) = weak.upgrade() else { return };
        {
            let mut editor = drafts.borrow_mut();
            if editor.in_flight != Some(revision) {
                return;
            }
            editor.in_flight = None;
            let key = (owner, profile);
            if let Some(draft) = editor
                .drafts
                .get_mut(&key)
                .filter(|draft| draft.revision == revision)
            {
                if error.is_empty() {
                    editor.drafts.remove(&key);
                } else {
                    draft.state = PortDraftState::Invalid;
                    draft.error = error;
                }
            }
        }
        update_port_drafts(&ui.global::<XrayModule>(), &drafts);
    });
    let weak = ui.as_weak();
    xray.on_port_owners_changed(move || {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let mut editor = state.borrow_mut();
        let count = editor.drafts.len();
        let manual = xray.get_profiles();
        let groups = xray.get_subscriptions();
        editor.drafts.retain(|(owner, profile), _| {
            if *profile {
                manual.iter().any(|row| row.id == *owner)
                    || groups
                        .iter()
                        .any(|group| group.profiles.iter().any(|row| row.id == *owner))
            } else {
                owner.is_empty() || groups.iter().any(|group| group.id == *owner)
            }
        });
        let changed = editor.drafts.len() != count;
        drop(editor);
        if changed {
            update_port_drafts(&xray, &state);
        }
    });
}

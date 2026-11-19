use crate::{MainWindow, XrayModule, XrayPortDraft};
use anyhow::{Context, Result, ensure};
use slint::{ComponentHandle, Model, SharedString};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use true_proxy::xray::{profile::Settings, runtime};

pub(in crate::app) struct PortEdit {
    pub(in crate::app) id: String,
    pub(in crate::app) number: bool,
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

    pub(in crate::app) fn apply(&self, settings: &mut Settings, owned: &[u16]) -> Result<()> {
        if self.number {
            settings.set_port_number(&self.id, Self::number(&self.value)?, owned)
        } else {
            settings.rename_port(&self.id, &self.value)
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

    fn prepare(&mut self, key: &PortFieldKey) {
        if let Some(draft) = self.drafts.get_mut(key)
            && matches!(
                draft.state,
                PortDraftState::Editing | PortDraftState::Invalid
            )
            && draft.error.is_empty()
        {
            draft.state = PortDraftState::Ready;
        }
    }
}

fn validate_draft(xray: &XrayModule<'_>, id: &str, number: bool, value: &str) -> Result<()> {
    let ports = xray.get_ports();
    if number {
        let parsed = PortEdit::number(value)?;
        ensure!(
            !ports
                .iter()
                .any(|p| p.id != id && p.number.parse::<u16>() == Ok(parsed)),
            "Another port already uses this number."
        );
        if !xray
            .get_listening_numbers()
            .iter()
            .any(|owned| owned == i32::from(parsed))
        {
            runtime::check_listener_port(parsed)?;
        }
    } else {
        let name = value.trim();
        ensure!(!name.is_empty(), "Enter a port name.");
        ensure!(
            !ports
                .iter()
                .any(|p| p.id != id && p.name.to_lowercase() == name.to_lowercase()),
            "Another port already uses this name."
        );
    }
    Ok(())
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
    let drafts = state.clone();
    xray.on_port_draft(move |id, number, _| {
        drafts
            .borrow()
            .drafts
            .get(&(id, number))
            .map_or_else(XrayPortDraft::default, |draft| XrayPortDraft {
                present: true,
                value: draft.value.clone(),
                error: draft.error.clone(),
            })
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_edit_port(move |id, number, value| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let error = validate_draft(&xray, &id, number, &value)
            .err()
            .map_or_else(SharedString::default, |e| e.to_string().into());
        let key = (id, number);
        let revision = xray.get_port_draft_revision().wrapping_add(1);
        {
            let mut editor = drafts.borrow_mut();
            if let Some(previous) = editor.active.replace(key.clone())
                && previous != key
            {
                editor.prepare(&previous);
            }
            editor.drafts.insert(
                key.clone(),
                PortDraft {
                    value,
                    state: if error.is_empty() {
                        PortDraftState::Editing
                    } else {
                        PortDraftState::Invalid
                    },
                    error,
                    revision,
                },
            );
        }
        update_port_drafts(&xray, &drafts);
        xray.invoke_process_port_edits();
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_commit_port(move |id, number| {
        let Some(ui) = weak.upgrade() else { return };
        let xray = ui.global::<XrayModule>();
        let key = (id, number);
        {
            let mut editor = drafts.borrow_mut();
            if editor.active.as_ref() == Some(&key) {
                editor.active = None;
            }
            // A conflicting listener may have closed since the last keystroke.
            if let Some(draft) = editor.drafts.get_mut(&key)
                && matches!(draft.state, PortDraftState::Invalid)
            {
                draft.error = validate_draft(&xray, &key.0, key.1, &draft.value)
                    .err()
                    .map_or_else(SharedString::default, |e| e.to_string().into());
            }
            editor.prepare(&key);
        }
        update_port_drafts(&xray, &drafts);
        xray.invoke_process_port_edits();
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_flush_port_edit(move || {
        let active = drafts.borrow().active.clone();
        if let Some(((id, number), ui)) = active.zip(weak.upgrade()) {
            ui.global::<XrayModule>().invoke_commit_port(id, number);
        }
    });
    let weak = ui.as_weak();
    let drafts = state.clone();
    xray.on_cancel_port_edit(move |id, number| {
        let Some(ui) = weak.upgrade() else { return };
        let key = (id, number);
        let mut editor = drafts.borrow_mut();
        if editor.active.as_ref() == Some(&key) {
            editor.active = None;
        }
        editor.drafts.remove(&key);
        drop(editor);
        update_port_drafts(&ui.global::<XrayModule>(), &drafts);
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
                    .map(|((id, number), draft)| {
                        draft.state = PortDraftState::Saving;
                        (id.clone(), *number, draft.value.clone(), draft.revision)
                    });
                editor.in_flight = pending.as_ref().map(|(_, _, _, revision)| *revision);
                pending
            };
            let Some((id, number, value, revision)) = pending else {
                return;
            };
            if !submit(
                &ui,
                PortEdit {
                    id: id.to_string(),
                    number,
                    value: value.to_string(),
                },
                revision,
            ) {
                xray.invoke_finish_port_edit(
                    id,
                    number,
                    revision,
                    "Could not save the port. Try again.".into(),
                );
            }
        }
    });
    let drafts = state.clone();
    let weak = ui.as_weak();
    xray.on_finish_port_edit(move |id, number, revision, error| {
        let Some(ui) = weak.upgrade() else { return };
        {
            let mut editor = drafts.borrow_mut();
            if editor.in_flight != Some(revision) {
                return;
            }
            editor.in_flight = None;
            let key = (id, number);
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
        let ports = xray.get_ports();
        editor
            .drafts
            .retain(|(owner, _), _| ports.iter().any(|row| row.id == *owner));
        if editor
            .active
            .as_ref()
            .is_some_and(|key| !editor.drafts.contains_key(key))
        {
            editor.active = None;
        }
        let changed = editor.drafts.len() != count;
        drop(editor);
        if changed {
            update_port_drafts(&xray, &state);
        }
    });
}

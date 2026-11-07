use crate::{ConnectionMonitor, MainWindow};
use slint::{ComponentHandle, Image, Rgba8Pixel, SharedPixelBuffer};
use std::{
    cell::{OnceCell, RefCell},
    collections::{HashMap, VecDeque},
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    thread,
};
use true_proxy::platform::{PROCESS_ICON_SIZE, process_icon};

const CACHE_LIMIT: usize = 512;
const QUEUE_LIMIT: usize = 32;

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    pid: u32,
    name: String,
}

struct Worker {
    requests: SyncSender<Key>,
    results: Receiver<(Key, Option<Vec<u8>>)>,
}

impl Worker {
    fn start() -> Option<Self> {
        let (requests, pending) = sync_channel::<Key>(QUEUE_LIMIT);
        let (completed, results) = sync_channel(QUEUE_LIMIT);
        thread::Builder::new()
            .name("process-icons".into())
            .spawn(move || {
                while let Ok(key) = pending.recv() {
                    let pixels = process_icon(key.pid, &key.name);
                    if completed.send((key, pixels)).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Self { requests, results })
    }
}

#[derive(Default)]
struct Loader {
    worker: OnceCell<Option<Worker>>,
    cached: HashMap<Key, Image>,
    order: VecDeque<Key>,
}

impl Loader {
    fn get(&mut self, name: &str, pid: u32) -> Image {
        if pid == 0 {
            return Image::default();
        }
        let Some(worker) = self.worker.get_or_init(Worker::start) else {
            return Image::default();
        };
        // The monitor's existing refresh drains the queue. No UI work is
        // scheduled by the loader while the window or page is hidden.
        for (key, pixels) in worker.results.try_iter() {
            if let (Some(icon), Some(pixels)) = (self.cached.get_mut(&key), pixels) {
                let buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
                    &pixels,
                    PROCESS_ICON_SIZE,
                    PROCESS_ICON_SIZE,
                );
                *icon = Image::from_rgba8(buffer);
            }
        }
        let key = Key {
            pid,
            name: name.to_owned(),
        };
        if let Some(icon) = self.cached.get(&key) {
            return icon.clone();
        }
        if worker.requests.try_send(key.clone()).is_ok() {
            if self.cached.len() == CACHE_LIMIT
                && let Some(oldest) = self.order.pop_front()
            {
                self.cached.remove(&oldest);
            }
            // Cache pending and missing icons too, so they are requested once.
            self.order.push_back(key.clone());
            self.cached.insert(key, Image::default());
        }
        Image::default()
    }
}

pub(super) fn wire(ui: &MainWindow) {
    let loader = RefCell::new(Loader::default());
    ui.global::<ConnectionMonitor>()
        .on_process_icon(move |name, pid| loader.borrow_mut().get(&name, pid as u32));
}

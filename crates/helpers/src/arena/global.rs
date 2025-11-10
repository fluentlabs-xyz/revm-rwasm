use crate::arena::Arena;
use spin::{Mutex, MutexGuard};
use std::vec::Vec;

pub struct GlobalArenaRegistry {
    pub vec_u8: Arena<usize, Vec<u8>>,
}

pub static GLOBAL_ARENA_REGISTRY: spin::Once<Mutex<GlobalArenaRegistry>> = spin::Once::new();

pub fn global_arena_registry_lock<'a>() -> MutexGuard<'a, GlobalArenaRegistry> {
    let arena = GLOBAL_ARENA_REGISTRY.call_once(|| {
        Mutex::new(GlobalArenaRegistry {
            vec_u8: Default::default(),
        })
    });
    arena.lock()
}

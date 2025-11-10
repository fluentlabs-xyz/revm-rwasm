#[macro_export]
macro_rules! define_global_arena {
    ($scope: ident, $idx_typ: ty, $item_typ: ty) => {
        pub mod $scope {
            pub type IdxType = $idx_typ;
            pub type ItemType = $item_typ;
            pub type ArenaType = $crate::arena::Arena<IdxType, ItemType>;
            pub static GLOBAL: $crate::spin::Once<$crate::spin::Mutex<ArenaType>> =
                $crate::spin::Once::new();

            pub fn lock<'a>() -> $crate::spin::MutexGuard<'a, ArenaType> {
                let arena = GLOBAL.call_once(|| $crate::spin::Mutex::new(ArenaType::default()));
                arena.lock()
            }
            // pub fn get_or_create_mut<'a, F: FnOnce() -> $typ>(
            //     idx: $idx,
            //     create_strategy: F,
            // ) -> &'a mut $typ {
            //     let mut arena = lock();
            //     if let Some(item) = arena.get_mut(idx) {
            //         item
            //     } else {
            //         let idx_fact = arena.alloc(create_strategy());
            //         assert_eq!(idx, idx_fact);
            //         arena.get_mut(idx_fact).unwrap()
            //     }
            // }
            pub fn with_item_mut<'a, F: FnOnce() -> ItemType, R, H: FnOnce(&mut ItemType) -> R>(
                idx: usize,
                create_strategy: F,
                h: H,
            ) -> R {
                let mut arena = lock();
                if let Some(item) = arena.get_mut(idx) {
                    h(item)
                } else {
                    let idx_fact = arena.alloc(create_strategy());
                    h(arena.get_mut(idx_fact).unwrap())
                }
            }
        }
    };
}

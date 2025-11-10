#[macro_export]
macro_rules! define_global_reusable_pool {
    ($scope: ident, $item_typ: ty, $keep:expr, $create_strategy: expr, $reset_strategy: expr $(,)?) => {
        pub mod $scope {
            pub type ItemType = $item_typ;
            pub type PoolType = $crate::reusable_pool::ReusablePool<
                ItemType,
                fn() -> $item_typ,
                fn(&mut $item_typ),
            >;
            pub static GLOBAL: $crate::spin::Once<$crate::spin::Mutex<PoolType>> =
                $crate::spin::Once::new();
            pub fn lock<'a>() -> $crate::spin::MutexGuard<'a, PoolType> {
                let pool = GLOBAL.call_once(|| {
                    $crate::spin::Mutex::new(PoolType::new(
                        $crate::reusable_pool::ReusablePoolConfig::new(
                            $keep,
                            $create_strategy,
                            $reset_strategy,
                        ),
                    ))
                });
                pool.lock()
            }
            pub fn pop() -> ItemType {
                let mut pool = lock();
                pool.reuse_or_new()
            }
            pub fn recycle(item: ItemType) {
                let mut pool = lock();
                pool.recycle(item)
            }
        }
    };
}

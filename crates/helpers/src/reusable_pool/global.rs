use crate::define_global_reusable_pool;
use alloy_primitives::Bytes;
use core::ops::{Deref, DerefMut};
use std::vec::Vec;

pub const VEC_U8_REUSABLE_POOL_CAPACITY: usize = 1024 * 512;

define_global_reusable_pool!(
    vec_u8_reusable_pool,
    std::vec::Vec<u8>,
    128,
    || {
        std::vec::Vec::<u8>::with_capacity(
            crate::reusable_pool::global::VEC_U8_REUSABLE_POOL_CAPACITY,
        )
    },
    |item: &mut std::vec::Vec<u8>| -> bool {
        let item_capacity = item.capacity();
        if item_capacity >= crate::reusable_pool::global::VEC_U8_REUSABLE_POOL_CAPACITY {
            item.clear();
            return true;
        } else {
            // what should we do if item has some cap? extend capacity? or just leak
        }
        false
    },
);

#[derive(Default, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VecU8(Vec<u8>);

impl AsRef<[u8]> for VecU8 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Clone for VecU8 {
    fn clone(&self) -> Self {
        Self::try_from_slice_unwrap(self)
    }
}

impl<const N: usize> From<[u8; N]> for VecU8 {
    fn from(value: [u8; N]) -> Self {
        VecU8::try_from_slice_unwrap(value)
    }
}

impl<const N: usize> From<&[u8; N]> for VecU8 {
    fn from(value: &[u8; N]) -> Self {
        VecU8::try_from_slice_unwrap(value)
    }
}

impl From<&[u8]> for VecU8 {
    fn from(value: &[u8]) -> Self {
        VecU8::try_from_slice_unwrap(value)
    }
}

impl AsMut<Vec<u8>> for VecU8 {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        self.0.as_mut()
    }
}

impl Deref for VecU8 {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl DerefMut for VecU8 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl Drop for VecU8 {
    fn drop(&mut self) {
        vec_u8_reusable_pool::take_recycle(&mut self.0);
    }
}

impl VecU8 {
    pub fn default_for_reuse() -> Self {
        Self(vec_u8_reusable_pool::reuse_or_new())
    }
    pub fn try_with_capacity(cap: usize) -> Result<Self, ()> {
        let result = Self::default_for_reuse();
        if cap > result.capacity() {
            return Err(());
        }
        Ok(result)
    }
    pub fn try_with_capacity_unwrap(cap: usize) -> Self {
        Self::try_with_capacity(cap).unwrap()
    }
    pub fn try_from_slice<D: AsRef<[u8]>>(src: D) -> Result<Self, ()> {
        let mut dst = Self::default_for_reuse();
        vec_u8_try_extend_in_place_from(src, &mut dst.0)?;
        Ok(dst)
    }
    pub fn try_from_slice_unwrap<D: AsRef<[u8]>>(src: D) -> Self {
        Self::try_from_slice(src).unwrap()
    }

    pub fn is_reusable(&self) -> bool {
        self.capacity() >= VEC_U8_REUSABLE_POOL_CAPACITY
    }

    pub fn bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn try_extend_from<D: AsRef<[u8]>>(&mut self, src: D) -> Result<(), ()> {
        vec_u8_try_extend_in_place_from(src, self)?;
        Ok(())
    }

    pub fn try_extend_in_place_from<D: AsRef<[u8]>>(&mut self, src: D) -> Result<(), ()> {
        vec_u8_try_extend_in_place_from(src, self)
    }
}

pub fn vec_u8_try_extend_from<D: AsRef<[u8]>>(
    src: D,
    mut dst: std::vec::Vec<u8>,
) -> Result<std::vec::Vec<u8>, ()> {
    let data = src.as_ref();
    if data.len() > dst.capacity() {
        return Err(());
    }
    dst.extend_from_slice(data);
    Ok(dst)
}

pub fn vec_u8_try_extend_in_place_from<D: AsRef<[u8]>>(
    src: D,
    dst: &mut std::vec::Vec<u8>,
) -> Result<(), ()> {
    let data = src.as_ref();
    if data.len() > dst.capacity() {
        return Err(());
    }
    dst.extend_from_slice(data);
    Ok(())
}

pub fn vec_u8_try_reuse_and_copy_from<D: AsRef<[u8]>>(src: D) -> Result<std::vec::Vec<u8>, ()> {
    let buffer = vec_u8_reusable_pool::reuse_or_new();
    vec_u8_try_extend_from(src, buffer)
}

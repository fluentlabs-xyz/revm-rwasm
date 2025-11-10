use crate::arena::ArenaIndex;

impl ArenaIndex for usize {
    fn into_usize(self) -> usize {
        self
    }

    fn from_usize(value: usize) -> Self {
        value
    }
}

impl ArenaIndex for u32 {
    fn into_usize(self) -> usize {
        self as usize
    }

    fn from_usize(value: usize) -> Self {
        value as u32
    }
}

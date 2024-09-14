#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CacheErr {
    MissingKey,
    ValueExpired,
    CacheFull,
}


impl std::fmt::Debug for CacheErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheErr::MissingKey => {
                write!(f, "Key not found in cache")
            }
            CacheErr::ValueExpired => {
                write!(f, "Value expired in cache")
            }
            CacheErr::CacheFull => {
                write!(f, "Cache is full")
            }
        }
    }
}

pub type CacheResult<T> = Result<T, CacheErr>;


use der::Sequence;

#[derive(Sequence)]
struct KrbSafe {
    i: i32,
}

#[derive(Sequence)]
struct KrbSafeBody {
    i: i32,
}
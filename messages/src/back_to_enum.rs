/// This macro is used to make it easier to convert from an integer to an enum.
/// Usage:
/// ```rust
/// use crate::messages::back_to_enum;
/// back_to_enum! {
///     enum MyEnum {
///         A = 1,
///         B,
///         C,
///     }
/// }
/// let a = MyEnum::try_from(1).unwrap();
///
/// ```
#[macro_export]
macro_rules! back_to_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl std::convert::TryFrom<i32> for $name {
            type Error = ();

            fn try_from(v: i32) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == $name::$vname as i32 => Ok($name::$vname),)*
                    _ => Err(()),
                }
            }
        }
    }
}

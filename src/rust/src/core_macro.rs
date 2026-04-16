/// Macro to define a zero-copy message core block struct.
/// Generates: struct definition, SIZE/MESSAGE_TYPE/SCHEMA_ID consts,
/// from_bytes, try_from_bytes, as_bytes.
///
/// Used by generated messages module and can be used for hand-written structs.
#[macro_export]
macro_rules! define_core {
    (
        $(#[$meta:meta])*
        $name:ident, schema=$schema:expr, msg_type=$mtype:expr, size=$size:expr,
        { $( $(#[$fmeta:meta])* $vis:vis $field:ident : $ftype:ty ),* $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        #[repr(C)]
        pub struct $name {
            $( $(#[$fmeta])* $vis $field : $ftype ),*
        }

        impl $name {
            pub const SIZE: usize = $size;
            pub const MESSAGE_TYPE: u16 = $mtype;
            pub const SCHEMA_ID: u16 = $schema;

            #[inline(always)]
            pub fn from_bytes(buf: &[u8]) -> &Self {
                debug_assert!(buf.len() >= Self::SIZE);
                unsafe { &*(buf.as_ptr() as *const Self) }
            }

            #[inline(always)]
            pub fn try_from_bytes(buf: &[u8]) -> Option<&Self> {
                if buf.len() >= Self::SIZE {
                    Some(unsafe { &*(buf.as_ptr() as *const Self) })
                } else {
                    None
                }
            }

            #[inline(always)]
            pub fn as_bytes(&self) -> &[u8] {
                unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
            }
        }
    };
}

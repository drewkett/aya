use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_ARRAY},
    helpers::bpf_map_lookup_elem,
    maps::PinningType,
};

/// A fixed-size array.
///
/// The size of the array is defined using the `bpf_map_def::max_entries` field
/// which is set via `Array::with_max_entries`. All the entries are
/// zero-initialized when the map is created.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19.
///
/// # Examples
/// ```no_run
/// use aya_bpf::macros::map;
///
/// #[map]
/// static mut ARRAY: Array<u64> = Array::with_max_entries(1, 0);
///
/// #[uprobe]
/// fn sample_uprobe(ctx: ProbeContext) {
///     if let Some(value) = unsafe { ARRAY.get(0) } {
///         // Do something with value
///     }
/// }
/// ```
#[repr(transparent)]
pub struct Array<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T: Sync> Sync for Array<T> {}

impl<T> Array<T> {
    /// Define an Array with elements of type `T` with size `max_entries`.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Array<T> {
        Array {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Array<T> {
        Array {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _t: PhantomData,
        }
    }

    /// Returns the value stored at the given index.
    ///
    /// The BPF verifier requires that the option is handled correctly. You
    /// cannot call `unwrap()` on the `Option`, for example.
    pub fn get(&self, index: u32) -> Option<&T> {
        unsafe {
            let value = bpf_map_lookup_elem(
                self.def.get() as *mut _,
                &index as *const _ as *const c_void,
            );
            // FIXME: alignment
            NonNull::new(value as *mut T).map(|p| p.as_ref())
        }
    }
}

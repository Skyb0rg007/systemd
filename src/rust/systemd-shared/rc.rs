// SPDX-License-Identifier: LGPL-2.1-or-later

//! Single-threaded reference counting: [`Rc`] and [`Weak`], like `alloc::rc` but returning an error when memory
//! runs out, like [`Box`](crate::alloc::Box) does.
//!
//! This is the `n_ref` field plus `DEFINE_TRIVIAL_REF_UNREF_FUNC()` of C objects: an [`Rc`] is a reference,
//! dropping the last one drops the value. [`Weak`] is a back-pointer that does not keep the value alive, for
//! the cases where C keeps a borrowed pointer to an owner, e.g. an object to its manager. Neither is `Send` or
//! `Sync`: the counters are not atomic, like the C ones.
//!
//! Like std's, every [`Rc`] and [`Weak`] carries its own [`Allocator`]: [`Malloc`] unless another one is handed
//! to [`Rc::new_in()`] or [`Rc::new_cyclic_in()`], e.g. [`Erasing`](crate::alloc::Erasing) for a shared key.
//! Making another reference clones it, so [`Clone`], [`Rc::downgrade()`] and [`Weak::upgrade()`] need an
//! [`AllocatorClone`].

use core::alloc::Layout;
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{self, ManuallyDrop};
use core::ops::Deref;
use core::ptr::{self, NonNull};

use crate::alloc::{AllocError, Allocator, AllocatorClone, Malloc};

/// The allocation behind an [`Rc`]: both counters and the value. `weak` counts the [`Weak`]s, plus one for all
/// [`Rc`]s together, so that the allocation outlives the value while a [`Weak`] still points at it.
#[repr(C)]
struct RcBox<T> {
    strong: Cell<usize>,
    weak: Cell<usize>,
    value: ManuallyDrop<T>,
}

/// A reference-counted pointer to a `T` on the heap, `alloc::rc::Rc` without the paths that abort when memory
/// runs out.
pub struct Rc<T, A: Allocator = Malloc> {
    ptr: NonNull<RcBox<T>>,
    alloc: A,
    _owns: PhantomData<RcBox<T>>,
}

/// A pointer to the value of an [`Rc`] that does not keep it alive. [`Weak::upgrade()`] returns `None` once the
/// last [`Rc`] is gone.
pub struct Weak<T, A: Allocator = Malloc> {
    ptr: NonNull<RcBox<T>>,
    alloc: A,
}

fn increment(c: &Cell<usize>) {
    // Overflow checks are on, so this panics rather than wraps.
    c.set(c.get() + 1);
}

/// Allocates an [`RcBox`] with `strong` strong references and the weak one they share, leaving the value to the
/// caller.
fn allocate_rc_box<T, A: Allocator>(strong: usize, alloc: &A) -> Result<NonNull<RcBox<T>>, AllocError> {
    // Never zero-sized, the counters are in it.
    let ptr = alloc.allocate(Layout::new::<RcBox<T>>())?.cast::<RcBox<T>>();
    // SAFETY: the block is valid for writes of an RcBox<T> and aligned for it. Only raw pointers go near the
    // value, which is not initialized yet.
    unsafe {
        let raw = ptr.as_ptr();
        ptr::addr_of_mut!((*raw).strong).write(Cell::new(strong));
        ptr::addr_of_mut!((*raw).weak).write(Cell::new(1));
    }
    Ok(ptr)
}

/// The strong counter of the allocation `ptr` points to. Like [`weak_counter()`], this does not go through a
/// reference to the [`RcBox`]: what a [`Weak`] points to may hold an uninitialized or a dropped value.
///
/// # Safety
///
/// The allocation must stay alive for `'a`.
unsafe fn strong_counter<'a, T>(ptr: NonNull<RcBox<T>>) -> &'a Cell<usize> {
    // SAFETY: the allocation is alive, as the caller guarantees, and the counter is initialized from the start.
    unsafe { &*ptr::addr_of!((*ptr.as_ptr()).strong) }
}

/// The weak counter of the allocation `ptr` points to, see [`strong_counter()`].
///
/// # Safety
///
/// The allocation must stay alive for `'a`.
unsafe fn weak_counter<'a, T>(ptr: NonNull<RcBox<T>>) -> &'a Cell<usize> {
    // SAFETY: as in strong_counter().
    unsafe { &*ptr::addr_of!((*ptr.as_ptr()).weak) }
}

/// Gives up a weak reference, freeing the allocation if it was the last.
///
/// # Safety
///
/// The caller must own a weak reference to `ptr`, which `alloc` or an allocator equivalent to it allocated.
unsafe fn release_weak<T, A: Allocator>(ptr: NonNull<RcBox<T>>, alloc: &A) {
    // SAFETY: the allocation lives as long as there is a weak reference, it is not used after it is freed.
    let weak = unsafe { weak_counter(ptr) };
    let n = weak.get() - 1;
    weak.set(n);
    if n == 0 {
        // SAFETY: the last weak reference is gone, hence so is every strong one and the value with them. The
        // block came from an equivalent allocator for this layout, and the value is not dropped again.
        unsafe { alloc.deallocate(ptr.cast(), Layout::new::<RcBox<T>>()) };
    }
}

impl<T> Rc<T> {
    /// Moves `value` to the heap, with one reference, allocating with [`Malloc`].
    pub fn new(value: T) -> Result<Rc<T>, AllocError> {
        Rc::new_in(value, Malloc)
    }

    /// Like [`Rc::new()`], for a value that points back at itself: `f` gets a [`Weak`] to the value it
    /// returns, which [`Weak::upgrade()`]s to `None` until `f` has returned.
    pub fn new_cyclic(f: impl FnOnce(&Weak<T>) -> T) -> Result<Rc<T>, AllocError> {
        Rc::new_cyclic_in(f, Malloc)
    }

    /// Gives up the reference without dropping it, for handing it to C as userdata. [`Rc::from_raw()`] takes it
    /// back.
    pub fn into_raw(this: Rc<T>) -> *const T {
        Rc::into_raw_with_allocator(this).0
    }

    /// Takes back a reference that [`Rc::into_raw()`] gave up.
    ///
    /// # Safety
    ///
    /// `p` must come from [`Rc::into_raw()`], and each such reference may only be taken back once.
    pub unsafe fn from_raw(p: *const T) -> Rc<T> {
        // SAFETY: as the caller guarantees, and Malloc frees what any Malloc allocated.
        unsafe { Rc::from_raw_in(p, Malloc) }
    }

    /// A new reference to the value `p` points to, which stays with its current owners. For the userdata of C
    /// callbacks that borrows an [`Rc`] somebody else holds.
    ///
    /// # Safety
    ///
    /// `p` must be [`Rc::as_ptr()`] of an [`Rc`] that is still alive.
    pub unsafe fn clone_from_raw(p: *const T) -> Rc<T> {
        // SAFETY: as the caller guarantees, a reference is alive, so we only add one and take it.
        let this = ManuallyDrop::new(unsafe { Rc::from_raw(p) });
        Rc::clone(&this)
    }
}

impl<T, A: Allocator> Rc<T, A> {
    /// Moves `value` to the heap, with one reference, allocating with `alloc`.
    pub fn new_in(value: T, alloc: A) -> Result<Rc<T, A>, AllocError> {
        let ptr = allocate_rc_box::<T, A>(/* strong= */ 1, &alloc)?;
        // SAFETY: the block is ours alone and its value field is uninitialized, so it is written, not assigned.
        unsafe { ptr::addr_of_mut!((*ptr.as_ptr()).value).write(ManuallyDrop::new(value)) };
        Ok(Rc {
            ptr,
            alloc,
            _owns: PhantomData,
        })
    }

    /// Like [`Rc::new_in()`], for a value that points back at itself: `f` gets a [`Weak`] to the value it
    /// returns, which [`Weak::upgrade()`]s to `None` until `f` has returned.
    pub fn new_cyclic_in(f: impl FnOnce(&Weak<T, A>) -> T, alloc: A) -> Result<Rc<T, A>, AllocError> {
        let ptr = allocate_rc_box::<T, A>(/* strong= */ 0, &alloc)?;
        // The implicit weak reference of the strong ones, handed to f while there are none yet.
        let weak = ManuallyDrop::new(Weak { ptr, alloc });
        let value = f(&weak);
        // SAFETY: the allocation is alive, and nothing could read the value yet: upgrade() refuses while strong
        // is 0. Only raw pointers go near the uninitialized value. The weak reference becomes the Rc's, which
        // takes its allocator along: it is moved out once and weak is not dropped.
        let alloc = unsafe {
            let raw = ptr.as_ptr();
            ptr::addr_of_mut!((*raw).value).write(ManuallyDrop::new(value));
            strong_counter(ptr).set(1);
            ptr::read(&weak.alloc)
        };
        Ok(Rc {
            ptr,
            alloc,
            _owns: PhantomData,
        })
    }

    fn inner(&self) -> &RcBox<T> {
        // SAFETY: the allocation lives as long as there is a reference.
        unsafe { self.ptr.as_ref() }
    }

    /// The allocator the value was allocated with.
    pub fn allocator(this: &Rc<T, A>) -> &A {
        &this.alloc
    }

    /// A [`Weak`] pointer to the value, with a clone of the allocator.
    pub fn downgrade(this: &Rc<T, A>) -> Weak<T, A>
    where
        A: AllocatorClone,
    {
        increment(&this.inner().weak);
        Weak {
            ptr: this.ptr,
            alloc: this.alloc.clone(),
        }
    }

    /// Whether two references point to the same value.
    pub fn ptr_eq(a: &Rc<T, A>, b: &Rc<T, A>) -> bool {
        a.ptr == b.ptr
    }

    /// The number of [`Rc`]s pointing to the value.
    pub fn strong_count(this: &Rc<T, A>) -> usize {
        this.inner().strong.get()
    }

    /// A pointer to the value, valid for as long as there is an [`Rc`].
    pub fn as_ptr(this: &Rc<T, A>) -> *const T {
        let inner = this.ptr.as_ptr();
        // SAFETY: the allocation is alive, only the address of the value is computed.
        unsafe { ptr::addr_of!((*inner).value).cast::<T>() }
    }

    /// Like [`Rc::into_raw()`], returning the allocator too. [`Rc::from_raw_in()`] takes both back.
    pub fn into_raw_with_allocator(this: Rc<T, A>) -> (*const T, A) {
        let this = ManuallyDrop::new(this);
        // SAFETY: the allocator is moved out once, this is not dropped.
        let alloc = unsafe { ptr::read(&this.alloc) };
        (Rc::as_ptr(&this), alloc)
    }

    /// Takes back a reference that [`Rc::into_raw_with_allocator()`] gave up.
    ///
    /// # Safety
    ///
    /// `p` must come from [`Rc::into_raw_with_allocator()`] or [`Rc::into_raw()`], each such reference may only
    /// be taken back once, and `alloc` must be equivalent to the allocator of the value, e.g. the one returned
    /// with `p`.
    pub unsafe fn from_raw_in(p: *const T, alloc: A) -> Rc<T, A> {
        let offset = mem::offset_of!(RcBox<T>, value);
        // SAFETY: p points to the value field of a live RcBox<T>, as the caller guarantees.
        let ptr =
            unsafe { NonNull::new_unchecked(p.cast::<u8>().sub(offset).cast::<RcBox<T>>().cast_mut()) };
        Rc {
            ptr,
            alloc,
            _owns: PhantomData,
        }
    }
}

impl<T, A: AllocatorClone> Clone for Rc<T, A> {
    fn clone(&self) -> Rc<T, A> {
        increment(&self.inner().strong);
        Rc {
            ptr: self.ptr,
            alloc: self.alloc.clone(),
            _owns: PhantomData,
        }
    }
}

impl<T, A: Allocator> Deref for Rc<T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner().value
    }
}

impl<T, A: Allocator> Drop for Rc<T, A> {
    fn drop(&mut self) {
        let inner = self.inner();
        let strong = inner.strong.get() - 1;
        inner.strong.set(strong);
        if strong > 0 {
            return;
        }
        // SAFETY: that was the last reference, the value is dropped once. A Weak may still look at the counters,
        // which stay valid until the implicit weak reference is released, here, with the allocator of this
        // reference, which is equivalent to that of the value.
        unsafe {
            ManuallyDrop::drop(&mut (*self.ptr.as_ptr()).value);
            release_weak(self.ptr, &self.alloc);
        }
    }
}

impl<T: fmt::Debug, A: Allocator> fmt::Debug for Rc<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T, A: Allocator> Weak<T, A> {
    /// The allocator the value was allocated with.
    pub fn allocator(&self) -> &A {
        &self.alloc
    }

    /// An [`Rc`] to the value, with a clone of the allocator, `None` if the value was dropped already.
    pub fn upgrade(&self) -> Option<Rc<T, A>>
    where
        A: AllocatorClone,
    {
        // SAFETY: the allocation lives as long as there is a Weak.
        let strong = unsafe { strong_counter(self.ptr) };
        if strong.get() == 0 {
            return None;
        }
        increment(strong);
        Some(Rc {
            ptr: self.ptr,
            alloc: self.alloc.clone(),
            _owns: PhantomData,
        })
    }
}

impl<T, A: AllocatorClone> Clone for Weak<T, A> {
    fn clone(&self) -> Weak<T, A> {
        // SAFETY: the allocation lives as long as there is a Weak.
        increment(unsafe { weak_counter(self.ptr) });
        Weak {
            ptr: self.ptr,
            alloc: self.alloc.clone(),
        }
    }
}

impl<T, A: Allocator> Drop for Weak<T, A> {
    fn drop(&mut self) {
        // SAFETY: this reference is given up once, and its allocator is the value's or a clone of it.
        unsafe { release_weak(self.ptr, &self.alloc) };
    }
}

impl<T, A: Allocator> fmt::Debug for Weak<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(Weak)")
    }
}

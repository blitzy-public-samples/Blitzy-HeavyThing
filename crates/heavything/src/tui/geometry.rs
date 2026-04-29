// crates/heavything/src/tui/geometry.rs — HeavyThing TUI geometry primitives.
//
// Rust translation of tui_geometry.inc (484 lines of FASM assembly). Defines
// `Point`, `Rect`, and the `align_offset` helper used by every TUI widget and
// the rendering engine for widget bounds, layout computation, and cursor
// positioning.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! Geometry primitives: [`Point`], [`Rect`], and the [`align_offset`] helper.
//!
//! `Point` is a Cartesian (x, y) pair of `i32` coordinates, matching FASM
//! `point_size = 8` (two `dd` fields). `Rect` is represented as
//! (ax, ay, bx, by) where (ax, ay) is the top-left and (bx, by) is the
//! *exclusive* bottom-right (consistent with FASM's half-open convention
//! for widget bounds).
//!
//! All helpers are pure functions; this module has no side effects, performs
//! no I/O, and requires no external dependencies beyond Rust's core library.

// (no imports required — uses only core types)

/// Cartesian coordinate, `i32` fields. 8 bytes, matching FASM `point_size`.
///
/// Used for widget absolute positions, cursor positions, scroll offsets,
/// and mouse-click coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Point {
    /// Column (horizontal, rightward positive).
    pub x: i32,
    /// Row (vertical, downward positive).
    pub y: i32,
}

impl Point {
    /// Construct a new point.
    #[must_use]
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }

    /// Zero point (0, 0).
    pub const ZERO: Self = Self { x: 0, y: 0 };

    /// Translate this point by (dx, dy), returning a new point.
    #[must_use]
    pub const fn translated(self, dx: i32, dy: i32) -> Self {
        Self {
            x: self.x + dx,
            y: self.y + dy,
        }
    }

    /// Return `true` if both coordinates are non-negative.
    #[must_use]
    pub const fn is_non_negative(self) -> bool {
        self.x >= 0 && self.y >= 0
    }
}

/// Axis-aligned rectangle with half-open convention.
///
/// `ax, ay` is inclusive top-left; `bx, by` is exclusive bottom-right.
/// A rect is *empty* when `ax >= bx` or `ay >= by`.
///
/// Matches FASM `rect_size = 16` layout: four `i32` fields at offsets
/// 0 (ax), 4 (ay), 8 (bx), 12 (by) — the same layout used by `tui_object.bounds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Rect {
    /// Inclusive left edge.
    pub ax: i32,
    /// Inclusive top edge.
    pub ay: i32,
    /// Exclusive right edge.
    pub bx: i32,
    /// Exclusive bottom edge.
    pub by: i32,
}

impl Rect {
    /// Construct a rect from two points (top-left inclusive, bottom-right exclusive).
    #[must_use]
    pub const fn new(ax: i32, ay: i32, bx: i32, by: i32) -> Self {
        Self { ax, ay, bx, by }
    }

    /// Construct from origin + size. `width` or `height` may be 0.
    #[must_use]
    pub const fn from_origin_size(origin: Point, width: i32, height: i32) -> Self {
        Self {
            ax: origin.x,
            ay: origin.y,
            bx: origin.x + width,
            by: origin.y + height,
        }
    }

    /// The empty rect (0,0)-(0,0).
    pub const EMPTY: Self = Self {
        ax: 0,
        ay: 0,
        bx: 0,
        by: 0,
    };

    /// Width (non-negative; clamps negatives to 0).
    #[must_use]
    pub const fn width(self) -> i32 {
        let w = self.bx - self.ax;
        if w < 0 {
            0
        } else {
            w
        }
    }

    /// Height (non-negative; clamps negatives to 0).
    #[must_use]
    pub const fn height(self) -> i32 {
        let h = self.by - self.ay;
        if h < 0 {
            0
        } else {
            h
        }
    }

    /// Area in cells.
    #[must_use]
    pub const fn area(self) -> i32 {
        self.width() * self.height()
    }

    /// True if empty (zero width or height, or inverted).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.ax >= self.bx || self.ay >= self.by
    }

    /// Top-left corner.
    #[must_use]
    pub const fn top_left(self) -> Point {
        Point {
            x: self.ax,
            y: self.ay,
        }
    }

    /// Bottom-right corner (exclusive).
    #[must_use]
    pub const fn bottom_right(self) -> Point {
        Point {
            x: self.bx,
            y: self.by,
        }
    }

    /// True if `point` is contained (inclusive left/top, exclusive right/bottom).
    #[must_use]
    pub const fn contains(self, point: Point) -> bool {
        point.x >= self.ax && point.y >= self.ay && point.x < self.bx && point.y < self.by
    }

    /// True if `other` is fully contained in `self`.
    #[must_use]
    pub const fn contains_rect(self, other: Rect) -> bool {
        other.ax >= self.ax && other.ay >= self.ay && other.bx <= self.bx && other.by <= self.by
    }

    /// Intersection of two rects. Returns `Rect::EMPTY` if disjoint or edge-touching.
    #[must_use]
    pub fn intersect(self, other: Rect) -> Rect {
        let ax = self.ax.max(other.ax);
        let ay = self.ay.max(other.ay);
        let bx = self.bx.min(other.bx);
        let by = self.by.min(other.by);
        if ax >= bx || ay >= by {
            Rect::EMPTY
        } else {
            Rect { ax, ay, bx, by }
        }
    }

    /// Smallest rect containing both rects. Returns the non-empty rect when one is empty.
    #[must_use]
    pub fn union(self, other: Rect) -> Rect {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        Rect {
            ax: self.ax.min(other.ax),
            ay: self.ay.min(other.ay),
            bx: self.bx.max(other.bx),
            by: self.by.max(other.by),
        }
    }

    /// Translate the rect by (dx, dy).
    #[must_use]
    pub const fn translated(self, dx: i32, dy: i32) -> Rect {
        Rect {
            ax: self.ax + dx,
            ay: self.ay + dy,
            bx: self.bx + dx,
            by: self.by + dy,
        }
    }

    /// Shrink the rect inward by `padding` on each side; clamps to empty if over-shrunk.
    #[must_use]
    pub fn shrink(self, padding: i32) -> Rect {
        let r = Rect {
            ax: self.ax + padding,
            ay: self.ay + padding,
            bx: self.bx - padding,
            by: self.by - padding,
        };
        if r.is_empty() {
            Rect::EMPTY
        } else {
            r
        }
    }
}

/// Compute an aligned offset inside a container.
///
/// `mode` values:
/// - 0 = start (left/top)
/// - 1 = center (middle)
/// - 2 = end (right/bottom)
/// - 3 = fill (returns 0; caller stretches child)
///
/// Any other mode value is treated as start (0).
///
/// Returns 0 when `container <= child` (no slack available) or when
/// `mode == 3` (fill).
///
/// Callers in `tui::object` that hold a `HorizAlign` or `VertAlign` enum
/// value convert it via `as u32` (those enums are `#[repr(u32)]`) before
/// passing it here. This keeps `geometry.rs` free of enum dependencies and
/// avoids a circular module coupling with `tui::object`.
#[must_use]
pub const fn align_offset(container: i32, child: i32, mode: u32) -> i32 {
    let slack = container - child;
    if slack <= 0 {
        return 0;
    }
    match mode {
        1 => slack / 2,
        2 => slack,
        _ => 0, // 0 (start), 3 (fill), or any unknown mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_size_is_eight_bytes() {
        // Matches FASM point_size = 8
        assert_eq!(std::mem::size_of::<Point>(), 8);
    }

    #[test]
    fn rect_size_is_sixteen_bytes() {
        // Matches FASM rect_size = 16
        assert_eq!(std::mem::size_of::<Rect>(), 16);
    }

    #[test]
    fn point_new_and_default() {
        let p = Point::new(3, 4);
        assert_eq!(p.x, 3);
        assert_eq!(p.y, 4);
        let z: Point = Default::default();
        assert_eq!(z, Point::ZERO);
    }

    #[test]
    fn point_translated() {
        let p = Point::new(1, 2).translated(10, 20);
        assert_eq!(p, Point::new(11, 22));
    }

    #[test]
    fn point_is_non_negative() {
        assert!(Point::new(0, 0).is_non_negative());
        assert!(Point::new(1, 2).is_non_negative());
        assert!(!Point::new(-1, 0).is_non_negative());
        assert!(!Point::new(0, -1).is_non_negative());
    }

    #[test]
    fn rect_new_width_height_area() {
        let r = Rect::new(0, 0, 10, 5);
        assert_eq!(r.width(), 10);
        assert_eq!(r.height(), 5);
        assert_eq!(r.area(), 50);
    }

    #[test]
    fn rect_from_origin_size() {
        let r = Rect::from_origin_size(Point::new(3, 4), 10, 5);
        assert_eq!(r, Rect::new(3, 4, 13, 9));
    }

    #[test]
    fn rect_is_empty() {
        assert!(Rect::EMPTY.is_empty());
        assert!(Rect::new(5, 5, 5, 10).is_empty()); // zero width
        assert!(Rect::new(5, 5, 10, 5).is_empty()); // zero height
        assert!(Rect::new(10, 5, 5, 10).is_empty()); // inverted
        assert!(!Rect::new(0, 0, 1, 1).is_empty());
    }

    #[test]
    fn rect_contains_point() {
        let r = Rect::new(0, 0, 10, 5);
        assert!(r.contains(Point::new(0, 0)));
        assert!(r.contains(Point::new(9, 4)));
        assert!(!r.contains(Point::new(10, 4))); // exclusive right
        assert!(!r.contains(Point::new(9, 5))); // exclusive bottom
        assert!(!r.contains(Point::new(-1, 0)));
    }

    #[test]
    fn rect_contains_rect() {
        let outer = Rect::new(0, 0, 10, 10);
        let inner = Rect::new(2, 2, 8, 8);
        assert!(outer.contains_rect(inner));
        assert!(!inner.contains_rect(outer));
        assert!(outer.contains_rect(outer)); // self
    }

    #[test]
    fn rect_intersect_overlapping() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 15, 15);
        assert_eq!(a.intersect(b), Rect::new(5, 5, 10, 10));
    }

    #[test]
    fn rect_intersect_disjoint_is_empty() {
        let a = Rect::new(0, 0, 5, 5);
        let b = Rect::new(10, 10, 15, 15);
        assert!(a.intersect(b).is_empty());
    }

    #[test]
    fn rect_intersect_edge_touching_is_empty() {
        let a = Rect::new(0, 0, 5, 5);
        let b = Rect::new(5, 0, 10, 5); // shares edge x=5 only
        assert!(a.intersect(b).is_empty()); // half-open convention
    }

    #[test]
    fn rect_union_with_empty() {
        let r = Rect::new(0, 0, 10, 10);
        assert_eq!(Rect::EMPTY.union(r), r);
        assert_eq!(r.union(Rect::EMPTY), r);
    }

    #[test]
    fn rect_union_overlapping() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 15, 15);
        assert_eq!(a.union(b), Rect::new(0, 0, 15, 15));
    }

    #[test]
    fn rect_translated() {
        let r = Rect::new(1, 2, 5, 6).translated(10, 20);
        assert_eq!(r, Rect::new(11, 22, 15, 26));
    }

    #[test]
    fn rect_shrink() {
        let r = Rect::new(0, 0, 10, 10).shrink(2);
        assert_eq!(r, Rect::new(2, 2, 8, 8));
        // Over-shrink clamps to empty:
        let r2 = Rect::new(0, 0, 4, 4).shrink(3);
        assert!(r2.is_empty());
    }

    #[test]
    fn rect_top_left_and_bottom_right() {
        let r = Rect::new(3, 4, 10, 15);
        assert_eq!(r.top_left(), Point::new(3, 4));
        assert_eq!(r.bottom_right(), Point::new(10, 15));
    }

    #[test]
    fn align_offset_start() {
        assert_eq!(align_offset(100, 20, 0), 0);
    }

    #[test]
    fn align_offset_center() {
        assert_eq!(align_offset(100, 20, 1), 40);
    }

    #[test]
    fn align_offset_end() {
        assert_eq!(align_offset(100, 20, 2), 80);
    }

    #[test]
    fn align_offset_fill_returns_zero() {
        assert_eq!(align_offset(100, 20, 3), 0);
    }

    #[test]
    fn align_offset_overflow_returns_zero() {
        assert_eq!(align_offset(10, 20, 1), 0);
    }
}

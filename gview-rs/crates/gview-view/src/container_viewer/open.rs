//! `ContainerViewer` open / extract flow (spec `02_VIEWER_CONTAINER`
//! §5, §12).
//!
//! C++ anchors: `Instance::OnTreeViewItemPressed`
//! (`ContainerViewer/Instance.cpp:126-142`), `OpenItemInterface`
//! (`GView.hpp:1339-1341`), `GView::App::OpenBuffer`
//! (`GViewApp.cpp:150-160`); reference plugins `ZIPFile::OnOpenItem`
//! (`Types/ZIP/src/ZIPFile.cpp`) and `MachOFile::OnOpenItem`.
//!
//! The C++ flow (§5.1): a pressed item is opened **only when it has no
//! children**; the viewer rebuilds `currentPath` for it and calls
//! `openItemInterface->OnOpenItem(currentPath, item)`; the plugin
//! decompresses that single entry (§5.2 extract-on-demand) and calls
//! `App::OpenBuffer(buffer, name, path, OpenMethod::BestMatch)`, which
//! creates a new memory-buffer object and identifies its type. Here
//! the plugin returns an [`OpenRequest`] instead of reaching into the
//! application, and the shell performs the `OpenBuffer` step.
//!
//! Security invariants (§12), enforced here so every container plugin
//! shares them:
//!
//! 1. [`sanitize_entry_path`] / [`extract_path`] — path
//!    canonicalisation and zip-slip prevention: absolute names, drive
//!    letters, `..` components and NUL bytes are rejected, `\` is a
//!    separator, `.` / empty components are dropped, and the result
//!    always stays inside the base directory;
//! 2. [`DecompressionGuard`] — decompression-bomb protection: a hard
//!    cap on one entry's output and a maximum `uncompressed /
//!    compressed` ratio, checked before extraction on the declared
//!    sizes and again on the produced byte count;
//! 3. [`entry_cap`] — bounded `PopulateItem` iteration per directory;
//! 4. [`EntryKind::Symlink`] entries are reported so the shell can flag
//!    or block them.

use std::path::{Path, PathBuf};

use super::tree::{ContainerTree, TreeItemId, TreeNode};

/// §12.4 default cap on entries enumerated for one directory.
pub const MAX_ENTRIES_PER_DIRECTORY: u32 = 1_000_000;
/// §12.2 default hard cap on one extracted entry (256 MiB).
pub const DEFAULT_MAX_OUTPUT_SIZE: u64 = 256 * 1024 * 1024;
/// §12.2 default maximum `uncompressed / compressed` ratio (1000:1).
pub const DEFAULT_MAX_COMPRESSION_RATIO: u64 = 1000;
/// `OpenMethod` the C++ plugins open extracted entries with.
pub const OPEN_METHOD: &str = "BestMatch";

/// What the plugin knows about a leaf it is asked to open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EntryKind {
    /// Unknown / not classified.
    #[default]
    Unknown,
    /// A regular file.
    File,
    /// A directory (never opened: leaf-only rule).
    Directory,
    /// A symbolic link (§12.5: flagged).
    Symlink,
}

/// The `App::OpenBuffer(buffer, name, path, BestMatch)` call a plugin
/// asks the shell to perform (C++ `OnOpenItem` body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    /// `name` — the new object's display name.
    pub name: String,
    /// `path` — the new object's path (typically
    /// `<container>.drop/<entry>`), already sanitised.
    pub path: PathBuf,
    /// The decompressed entry.
    pub bytes: Vec<u8>,
    /// `creationProcess` (e.g. `"extraction and decompression"`).
    pub creation_process: String,
    /// Kind of the entry that produced the request.
    pub kind: EntryKind,
}

/// Item open callback implemented by container type plugins (C++
/// `OpenItemInterface`, `GView.hpp:1339-1341`).
pub trait OpenItemInterface {
    /// C++ `OnOpenItem(path, item)`: `path` is the viewer's
    /// `currentPath` for the pressed leaf, `item` its node. Returns the
    /// buffer to open, or `None` when nothing is opened (the C++ shows
    /// a message box and returns).
    fn on_open_item(&mut self, path: &str, item: TreeItemId, node: &TreeNode) -> Option<OpenRequest>;
}

/// C++ `Instance::OnTreeViewItemPressed` (`Instance.cpp:126-142`):
/// leaf-only, path rebuilt for the item, then `OnOpenItem`.
pub fn on_tree_view_item_pressed(
    tree: &mut ContainerTree,
    id: TreeItemId,
    opener: &mut dyn OpenItemInterface,
) -> Option<OpenRequest> {
    if !tree.children(id).is_empty() {
        return None;
    }
    tree.update_path_for_item(id);
    let path = tree.current_path.clone();
    let node = tree.node(id)?.clone();
    opener.on_open_item(&path, id, &node)
}

/// Why a path or an extraction was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtractError {
    /// An entry name that is empty, absolute, drive-relative, contains
    /// `..` or a NUL byte (§12.1 / §12.3).
    UnsafePath(String),
    /// Declared or produced size above the output cap (§12.2).
    OutputLimitExceeded {
        /// Bytes declared or produced.
        size: u64,
        /// Configured cap.
        limit: u64,
    },
    /// Declared sizes above the compression-ratio cap (§12.2).
    SuspiciousRatio {
        /// Compressed size.
        compressed: u64,
        /// Declared uncompressed size.
        uncompressed: u64,
        /// Configured cap.
        limit: u64,
    },
    /// More entries than [`MAX_ENTRIES_PER_DIRECTORY`] / the configured
    /// cap were enumerated for one directory (§12.4).
    TooManyEntries {
        /// Configured cap.
        limit: u32,
    },
}

impl core::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsafePath(name) => write!(f, "unsafe archive path: {name:?}"),
            Self::OutputLimitExceeded { size, limit } => write!(f, "entry of {size} bytes exceeds the {limit} byte cap"),
            Self::SuspiciousRatio {
                compressed,
                uncompressed,
                limit,
            } => write!(f, "compression ratio {uncompressed}:{compressed} exceeds {limit}:1"),
            Self::TooManyEntries { limit } => write!(f, "more than {limit} entries in one directory"),
        }
    }
}

impl std::error::Error for ExtractError {}

/// §12.1 / §12.3 zip-slip guard: an entry name as a **relative** path.
///
/// The result cannot escape its base — no absolute names, no drive
/// letters, no `..` components, no NUL bytes; `\` counts as a
/// separator and `.` / empty components are dropped.
///
/// # Errors
///
/// [`ExtractError::UnsafePath`] with the offending name; also for a
/// name that reduces to nothing (`"./"`).
pub fn sanitize_entry_path(name: &str) -> Result<PathBuf, ExtractError> {
    let unsafe_path = || ExtractError::UnsafePath(name.to_owned());
    if name.is_empty() || name.contains('\0') {
        return Err(unsafe_path());
    }
    let normalized = name.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(unsafe_path());
    }
    // `C:` / `C:/…` drive-relative or drive-absolute names.
    if normalized.as_bytes().get(1) == Some(&b':') {
        return Err(unsafe_path());
    }
    let mut out = PathBuf::new();
    let mut depth = 0_usize;
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(unsafe_path()),
            other => {
                out.push(other);
                depth = depth.saturating_add(1);
            }
        }
    }
    if depth == 0 {
        return Err(unsafe_path());
    }
    Ok(out)
}

/// `base/<sanitised name>`: the extraction target of one entry.
///
/// # Errors
///
/// As [`sanitize_entry_path`].
pub fn extract_path(base: &Path, name: &str) -> Result<PathBuf, ExtractError> {
    Ok(base.join(sanitize_entry_path(name)?))
}

/// The C++ `<archive path>.drop/<entry>` convention (`ZIPFile.cpp`
/// `OnOpenItem`): the container's path with `.drop` appended is the
/// base directory.
///
/// # Errors
///
/// As [`sanitize_entry_path`].
pub fn drop_path(container: &Path, name: &str) -> Result<PathBuf, ExtractError> {
    let mut base = container.as_os_str().to_owned();
    base.push(".drop");
    extract_path(Path::new(&base), name)
}

/// §12.2 decompression-bomb guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecompressionGuard {
    /// Hard cap on one entry's extracted size.
    pub max_output_size: u64,
    /// Maximum `uncompressed / compressed` ratio accepted.
    pub max_compression_ratio: u64,
}

impl Default for DecompressionGuard {
    fn default() -> Self {
        Self {
            max_output_size: DEFAULT_MAX_OUTPUT_SIZE,
            max_compression_ratio: DEFAULT_MAX_COMPRESSION_RATIO,
        }
    }
}

impl DecompressionGuard {
    /// Checks the sizes an archive **declares** before anything is
    /// inflated: the output cap first, then the ratio (a zero
    /// compressed size with a non-zero declared size counts as an
    /// infinite ratio).
    ///
    /// # Errors
    ///
    /// [`ExtractError::OutputLimitExceeded`] or
    /// [`ExtractError::SuspiciousRatio`].
    pub const fn check_declared(&self, compressed: u64, uncompressed: u64) -> Result<(), ExtractError> {
        if uncompressed > self.max_output_size {
            return Err(ExtractError::OutputLimitExceeded {
                size: uncompressed,
                limit: self.max_output_size,
            });
        }
        let ratio_exceeded = match uncompressed.checked_div(compressed) {
            Some(ratio) => ratio > self.max_compression_ratio,
            None => uncompressed != 0,
        };
        if ratio_exceeded {
            return Err(ExtractError::SuspiciousRatio {
                compressed,
                uncompressed,
                limit: self.max_compression_ratio,
            });
        }
        Ok(())
    }

    /// Checks the byte count a decoder **produced** against the output
    /// cap (a stream that lies about its declared size is still bounded).
    ///
    /// # Errors
    ///
    /// [`ExtractError::OutputLimitExceeded`].
    pub const fn check_produced(&self, produced: u64) -> Result<(), ExtractError> {
        if produced > self.max_output_size {
            return Err(ExtractError::OutputLimitExceeded {
                size: produced,
                limit: self.max_output_size,
            });
        }
        Ok(())
    }

    /// Bytes a decoder may still write after `produced` bytes.
    #[must_use]
    pub const fn remaining(&self, produced: u64) -> u64 {
        self.max_output_size.saturating_sub(produced)
    }
}

/// A `std::io::Write` sink that stops accepting bytes past the guard's
/// output cap, for decoders that stream into a buffer.
#[derive(Debug)]
pub struct BoundedSink {
    guard: DecompressionGuard,
    /// Bytes collected so far.
    pub bytes: Vec<u8>,
}

impl BoundedSink {
    /// An empty sink bounded by `guard`.
    #[must_use]
    pub const fn new(guard: DecompressionGuard) -> Self {
        Self {
            guard,
            bytes: Vec::new(),
        }
    }

    /// The collected bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for BoundedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let produced = self.bytes.len() as u64;
        let allowed = self.guard.remaining(produced);
        if (buf.len() as u64) > allowed {
            return Err(std::io::Error::other(
                ExtractError::OutputLimitExceeded {
                    size: produced.saturating_add(buf.len() as u64),
                    limit: self.guard.max_output_size,
                }
                .to_string(),
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// §12.4: a progress callback for
/// [`ContainerTree::populate_item`] that cancels the enumeration once
/// `limit` entries were added (the C++ has no cap).
pub fn entry_cap(limit: u32) -> impl FnMut(u32) -> bool {
    move |count| count > limit
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::container_viewer::tree::EnumerateInterface;
    use std::io::Write;

    /// A two-level mock VFS: `dir/` with `dir/inner.txt`, plus
    /// `top.txt`, `../evil`, and a symlink `link`.
    struct MockVfs {
        cursor: usize,
        current: Vec<(&'static str, bool)>,
        opened: Vec<(String, TreeItemId)>,
    }

    impl MockVfs {
        fn new() -> Self {
            Self {
                cursor: 0,
                current: Vec::new(),
                opened: Vec::new(),
            }
        }
    }

    impl EnumerateInterface for MockVfs {
        fn begin_iteration(&mut self, path: &str, _parent: TreeItemId) -> bool {
            self.cursor = 0;
            self.current = match path {
                "" => vec![("dir", true), ("top.txt", false), ("../evil", false), ("link", false)],
                "dir" => vec![("inner.txt", false)],
                _ => Vec::new(),
            };
            !self.current.is_empty()
        }

        fn populate_item(&mut self, child: &mut TreeNode) -> bool {
            if let Some((name, is_dir)) = self.current.get(self.cursor) {
                child.set_text(0, name);
                child.expandable = *is_dir;
                child.priority = *is_dir;
                child.data = self.cursor as u64;
            }
            self.cursor += 1;
            self.cursor < self.current.len()
        }
    }

    impl OpenItemInterface for MockVfs {
        fn on_open_item(&mut self, path: &str, item: TreeItemId, node: &TreeNode) -> Option<OpenRequest> {
            self.opened.push((path.to_owned(), item));
            let kind = if node.name() == "link" {
                EntryKind::Symlink
            } else {
                EntryKind::File
            };
            let target = drop_path(Path::new("box.zip"), path).ok()?;
            Some(OpenRequest {
                name: path.to_owned(),
                path: target,
                bytes: format!("contents of {path}").into_bytes(),
                creation_process: String::from("extraction and decompression"),
                kind,
            })
        }
    }

    fn populated() -> (ContainerTree, MockVfs) {
        let mut tree = ContainerTree::new('/');
        let mut vfs = MockVfs::new();
        let root = tree.root();
        assert!(tree.populate_item(root, &mut vfs, &mut |_| false));
        (tree, vfs)
    }

    #[test]
    fn pressing_a_leaf_opens_it_with_its_full_path() {
        let (mut tree, mut vfs) = populated();
        let root = tree.root();
        let top = tree.children(root)[1];
        let request = on_tree_view_item_pressed(&mut tree, top, &mut vfs).expect("opened");
        assert_eq!(request.name, "top.txt");
        assert_eq!(request.path, Path::new("box.zip.drop").join("top.txt"));
        assert_eq!(request.bytes, b"contents of top.txt");
        assert_eq!(request.kind, EntryKind::File);
        assert_eq!(request.creation_process, "extraction and decompression");
        assert_eq!(vfs.opened, [(String::from("top.txt"), top)]);
        // A nested leaf gets the joined path.
        let dir = tree.children(root)[0];
        tree.unfold(dir);
        assert!(tree.on_item_toggle(dir, false, &mut vfs, &mut |_| false));
        let inner = tree.children(dir)[0];
        let request = on_tree_view_item_pressed(&mut tree, inner, &mut vfs).expect("opened");
        assert_eq!(request.name, "dir/inner.txt");
        assert_eq!(request.path, Path::new("box.zip.drop").join("dir").join("inner.txt"));
        assert_eq!(tree.current_path, "dir/inner.txt");
    }

    #[test]
    fn only_leaves_are_opened() {
        let (mut tree, mut vfs) = populated();
        let root = tree.root();
        let dir = tree.children(root)[0];
        tree.unfold(dir);
        assert!(tree.on_item_toggle(dir, false, &mut vfs, &mut |_| false));
        assert!(!tree.children(dir).is_empty());
        assert!(on_tree_view_item_pressed(&mut tree, dir, &mut vfs).is_none());
        assert!(on_tree_view_item_pressed(&mut tree, root, &mut vfs).is_none());
        assert!(vfs.opened.is_empty(), "OnOpenItem is not called for folders");
        // An unknown id opens nothing.
        assert!(on_tree_view_item_pressed(&mut tree, 999, &mut vfs).is_none());
    }

    #[test]
    fn zip_slip_entries_are_rejected_and_symlinks_flagged() {
        let (mut tree, mut vfs) = populated();
        let root = tree.root();
        let evil = tree.children(root)[2];
        assert_eq!(tree.node(evil).map(TreeNode::name), Some("../evil"));
        assert!(on_tree_view_item_pressed(&mut tree, evil, &mut vfs).is_none(), "`../` path rejected");
        assert_eq!(vfs.opened.last().map(|(p, _)| p.as_str()), Some("../evil"));
        let link = tree.children(root)[3];
        let request = on_tree_view_item_pressed(&mut tree, link, &mut vfs).expect("opened");
        assert_eq!(request.kind, EntryKind::Symlink);
    }

    #[test]
    fn sanitize_entry_path_rules() {
        assert_eq!(sanitize_entry_path("a/b.txt").expect("ok"), Path::new("a").join("b.txt"));
        assert_eq!(sanitize_entry_path("./a//./b").expect("ok"), Path::new("a").join("b"));
        assert_eq!(sanitize_entry_path("a\\b").expect("ok"), Path::new("a").join("b"));
        for bad in ["", "../x", "a/../../etc/passwd", "/abs", "\\abs", "C:/win", "c:x", "a\0b", ".", "./", "a/.."] {
            assert!(matches!(sanitize_entry_path(bad), Err(ExtractError::UnsafePath(ref n)) if n == bad), "{bad:?}");
        }
        assert_eq!(extract_path(Path::new("out"), "x/y").expect("ok"), Path::new("out").join("x").join("y"));
        assert!(extract_path(Path::new("out"), "../y").is_err());
        assert_eq!(drop_path(Path::new("dir/a.zip"), "f.bin").expect("ok"), Path::new("dir/a.zip.drop").join("f.bin"));
        assert_eq!(
            ExtractError::UnsafePath(String::from("../x")).to_string(),
            "unsafe archive path: \"../x\""
        );
    }

    #[test]
    fn decompression_guard_caps_output_and_ratio() {
        let guard = DecompressionGuard {
            max_output_size: 1000,
            max_compression_ratio: 10,
        };
        assert_eq!(guard.check_declared(100, 1000), Ok(()));
        assert_eq!(guard.check_declared(100, 999), Ok(()));
        assert_eq!(
            guard.check_declared(100, 1001),
            Err(ExtractError::OutputLimitExceeded { size: 1001, limit: 1000 })
        );
        assert_eq!(
            guard.check_declared(1, 11),
            Err(ExtractError::SuspiciousRatio {
                compressed: 1,
                uncompressed: 11,
                limit: 10
            })
        );
        assert_eq!(guard.check_declared(1, 10), Ok(()));
        assert_eq!(guard.check_declared(0, 0), Ok(()));
        assert!(matches!(guard.check_declared(0, 5), Err(ExtractError::SuspiciousRatio { .. })));
        assert_eq!(guard.check_produced(1000), Ok(()));
        assert!(guard.check_produced(1001).is_err());
        assert_eq!(guard.remaining(990), 10);
        assert_eq!(guard.remaining(5000), 0);
        let defaults = DecompressionGuard::default();
        assert_eq!(defaults.max_output_size, 256 * 1024 * 1024);
        assert_eq!(defaults.max_compression_ratio, 1000);
        assert!(defaults.check_declared(1, 1000).is_ok());
        assert!(defaults.check_declared(1, 1001).is_err());
        assert_eq!(
            ExtractError::SuspiciousRatio {
                compressed: 1,
                uncompressed: 2000,
                limit: 1000
            }
            .to_string(),
            "compression ratio 2000:1 exceeds 1000:1"
        );
    }

    #[test]
    fn bounded_sink_refuses_bytes_past_the_cap() {
        let guard = DecompressionGuard {
            max_output_size: 8,
            max_compression_ratio: 1000,
        };
        let mut sink = BoundedSink::new(guard);
        assert_eq!(sink.write(b"1234").expect("ok"), 4);
        assert_eq!(sink.write(b"5678").expect("ok"), 4);
        let err = sink.write(b"9").expect_err("over the cap");
        assert!(err.to_string().contains("exceeds the 8 byte cap"));
        assert!(sink.flush().is_ok());
        assert_eq!(sink.into_bytes(), b"12345678");
    }

    #[test]
    fn entry_cap_cancels_population_past_the_limit() {
        let mut cancel = entry_cap(2);
        assert!(!cancel(1));
        assert!(!cancel(2));
        assert!(cancel(3));
        let mut tree = ContainerTree::new('/');
        let mut vfs = MockVfs::new();
        let root = tree.root();
        assert!(!tree.populate_item(root, &mut vfs, &mut entry_cap(2)), "cancelled");
        assert_eq!(tree.children(root).len(), 3, "the third add triggers the cancel");
        assert_eq!(MAX_ENTRIES_PER_DIRECTORY, 1_000_000);
        assert_eq!(OPEN_METHOD, "BestMatch");
        assert_eq!(EntryKind::default(), EntryKind::Unknown);
    }
}

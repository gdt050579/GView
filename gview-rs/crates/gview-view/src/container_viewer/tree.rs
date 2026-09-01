//! `ContainerViewer` lazy VFS tree
//! (spec `02_VIEWER_CONTAINER` §3.1–§3.3).
//!
//! C++ anchors: `Instance::PopulateItem`
//! (`ContainerViewer/Instance.cpp:97-112`), `BuildPath` /
//! `UpdatePathForItem` (`Instance.cpp:78-96`), `OnTreeViewItemToggle`
//! (`Instance.cpp:113-125`), root creation (`Instance.cpp:68-76`);
//! `EnumerateInterface` (`GView.hpp:1335-1337`); reference plugin
//! `ZIPFile::BeginIteration` / `PopulateItem`
//! (`Types/ZIP/src/ZIPFile.cpp:31-129`).
//!
//! Enumeration protocol (from the C++ loop
//! `while (enumInterface->PopulateItem(item.AddChild("")))`):
//! `begin_iteration` returns `false` when the path has no children
//! (no child is added); otherwise each `populate_item` call **fills**
//! the freshly added child and returns whether more entries follow —
//! the last child is filled too, with `false` returned after it.
//!
//! Children are fetched only when a node is unfolded (§3.1 lazy
//! loading), and — per the §3.2 contract the task matrix pins down —
//! `populate_item` is **idempotent**: a node that already has
//! children is not enumerated again, so re-expanding cannot
//! duplicate entries (the C++ code relies on the `TreeView` control
//! discarding children on fold instead of guarding here).

/// Handle to a node inside [`ContainerTree`] (C++ `TreeViewItem`).
pub type TreeItemId = u32;

/// One tree node (the model behind a C++ `TreeViewItem`).
// The bools mirror independent C++ TreeViewItem flags (SetExpandable,
// SetPriority, IsFolded, populated-guard); keeping them 1:1 preserves
// the parity mapping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub struct TreeNode {
    /// Column texts (C++ `SetText(col, ...)`; index 0 is the name
    /// used by `BuildPath`).
    pub texts: Vec<String>,
    /// C++ `SetExpandable` — folders.
    pub expandable: bool,
    /// C++ `SetPriority` — folders sort before files.
    pub priority: bool,
    /// C++ `SetData` — plugin entry handle (e.g. ZIP entry index).
    pub data: u64,
    /// C++ `IsFolded` — collapsed state (new nodes start folded).
    pub folded: bool,
    /// The §3.2 idempotence guard: set after a successful
    /// enumeration.
    populated: bool,
    parent: Option<TreeItemId>,
    children: Vec<TreeItemId>,
}

impl TreeNode {
    /// Column 0 text (the node's name).
    #[must_use]
    pub fn name(&self) -> &str {
        self.texts.first().map_or("", String::as_str)
    }

    /// Sets the text of one column, growing the column list as
    /// needed (C++ `SetText(col, text)`).
    pub fn set_text(&mut self, col: usize, text: &str) {
        if self.texts.len() <= col {
            self.texts.resize(col.saturating_add(1), String::new());
        }
        if let Some(slot) = self.texts.get_mut(col) {
            text.clone_into(slot);
        }
    }
}

/// Child enumeration callback implemented by type plugins
/// (C++ `EnumerateInterface`, `GView.hpp:1335-1337`).
pub trait EnumerateInterface {
    /// Starts iterating the children of `path`; `false` = nothing to
    /// enumerate (C++ `BeginIteration`).
    fn begin_iteration(&mut self, path: &str, parent: TreeItemId) -> bool;
    /// Fills the freshly created child node and returns `true` while
    /// more entries follow (C++ `PopulateItem` — the last child is
    /// filled and `false` returned after it).
    fn populate_item(&mut self, child: &mut TreeNode) -> bool;
}

/// The lazy VFS tree model (C++ `Instance` tree state).
pub struct ContainerTree {
    nodes: Vec<TreeNode>,
    root: TreeItemId,
    /// C++ `settings->pathSeparator`.
    pub path_separator: char,
    /// C++ `currentPath`, rebuilt by [`Self::update_path_for_item`].
    pub current_path: String,
    /// C++ `tempCountRecursiveItems` — progress counter across one
    /// toggle (recursive populates share it).
    items_populated: u32,
}

impl ContainerTree {
    /// Builds the tree with its root item (C++ `Instance` ctor,
    /// `Instance.cpp:68-76`: the root's name is the path separator
    /// itself and it starts unfolded).
    #[must_use]
    pub fn new(path_separator: char) -> Self {
        let root_node = TreeNode {
            texts: vec![path_separator.to_string()],
            expandable: true,
            folded: false,
            ..TreeNode::default()
        };
        Self {
            nodes: vec![root_node],
            root: 0,
            path_separator,
            current_path: String::new(),
            items_populated: 0,
        }
    }

    /// The root item id.
    #[must_use]
    pub const fn root(&self) -> TreeItemId {
        self.root
    }

    /// Immutable node access.
    #[must_use]
    pub fn node(&self, id: TreeItemId) -> Option<&TreeNode> {
        self.nodes.get(id as usize)
    }

    /// Mutable node access.
    pub fn node_mut(&mut self, id: TreeItemId) -> Option<&mut TreeNode> {
        self.nodes.get_mut(id as usize)
    }

    /// Child ids of `id` in insertion order.
    #[must_use]
    pub fn children(&self, id: TreeItemId) -> &[TreeItemId] {
        self.node(id).map_or(&[], |n| n.children.as_slice())
    }

    /// C++ `item.AddChild("")`: appends an empty child node.
    pub fn add_child(&mut self, parent: TreeItemId) -> TreeItemId {
        let id = self.nodes.len() as TreeItemId;
        self.nodes.push(TreeNode {
            folded: true,
            parent: Some(parent),
            ..TreeNode::default()
        });
        if let Some(parent_node) = self.nodes.get_mut(parent as usize) {
            parent_node.children.push(id);
        }
        id
    }

    /// C++ `BuildPath` (`Instance.cpp:78-91`): walks the parent chain
    /// down from the root, joining node names with the separator; the
    /// root itself contributes nothing.
    fn build_path(&mut self, id: TreeItemId) {
        if id == self.root {
            return;
        }
        // Collect the chain iteratively (the C++ recursion), bounded
        // by the node count against malformed parent links.
        let mut chain = Vec::new();
        let mut current = Some(id);
        let mut guard = self.nodes.len();
        while let Some(node_id) = current {
            if node_id == self.root || guard == 0 {
                break;
            }
            guard = guard.saturating_sub(1);
            let Some(node) = self.node(node_id) else {
                break;
            };
            chain.push(node_id);
            current = node.parent;
        }
        for node_id in chain.into_iter().rev() {
            if !self.current_path.is_empty() {
                self.current_path.push(self.path_separator);
            }
            let name = self.node(node_id).map_or("", TreeNode::name).to_owned();
            self.current_path.push_str(&name);
        }
    }

    /// C++ `UpdatePathForItem` (`Instance.cpp:92-96`).
    pub fn update_path_for_item(&mut self, id: TreeItemId) {
        self.current_path.clear();
        self.build_path(id);
    }

    /// C++ `Instance::PopulateItem` (`Instance.cpp:97-112`) with the
    /// §3.2 idempotence guard: a node that already has children (or
    /// was already enumerated) returns immediately, so lazy expansion
    /// never duplicates entries.
    ///
    /// `progress` is called with the running item count after each
    /// child (C++ `ProgressStatus::Update`); returning `true` cancels
    /// (C++ returns `false` to abort the fold toggle).
    pub fn populate_item(
        &mut self,
        id: TreeItemId,
        enumerator: &mut dyn EnumerateInterface,
        progress: &mut dyn FnMut(u32) -> bool,
    ) -> bool {
        let Some(node) = self.node(id) else {
            return true;
        };
        if node.populated || !node.children.is_empty() {
            return true; // §3.2: already fetched — idempotent
        }
        self.update_path_for_item(id);
        let path = self.current_path.clone();
        if enumerator.begin_iteration(&path, id) {
            loop {
                let child = self.add_child(id);
                let Some(child_node) = self.nodes.get_mut(child as usize) else {
                    break;
                };
                let more = enumerator.populate_item(child_node);
                self.items_populated = self.items_populated.saturating_add(1);
                if progress(self.items_populated) {
                    return false; // cancelled
                }
                if !more {
                    break;
                }
            }
        }
        if let Some(node) = self.nodes.get_mut(id as usize) {
            node.populated = true;
        }
        true
    }

    /// C++ `OnTreeViewItemToggle` (`Instance.cpp:113-125`): the
    /// outermost toggle resets the progress counter; an unfolded item
    /// populates lazily.
    pub fn on_item_toggle(
        &mut self,
        id: TreeItemId,
        recursive_call: bool,
        enumerator: &mut dyn EnumerateInterface,
        progress: &mut dyn FnMut(u32) -> bool,
    ) -> bool {
        if !recursive_call {
            self.items_populated = 0;
        }
        let folded = self.node(id).is_none_or(|n| n.folded);
        if !folded {
            return self.populate_item(id, enumerator, progress);
        }
        true
    }

    /// Unfolds a node (C++ `Unfold` / toggle result).
    pub fn unfold(&mut self, id: TreeItemId) {
        if let Some(node) = self.nodes.get_mut(id as usize) {
            node.folded = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// `(name, is-directory, data-handle)` — one VFS entry.
    type MockEntry = (String, bool, u64);
    type MockEntryRef<'a> = (&'a str, &'a [(&'a str, bool, u64)]);

    /// Mock plugin over a path → entries map.
    struct MockVfs {
        entries: BTreeMap<String, Vec<MockEntry>>,
        cursor: usize,
        current: Vec<MockEntry>,
        begin_calls: u32,
    }

    impl MockVfs {
        fn new(entries: &[MockEntryRef]) -> Self {
            let map = entries
                .iter()
                .map(|(path, items)| {
                    (
                        (*path).to_owned(),
                        items
                            .iter()
                            .map(|(n, d, h)| ((*n).to_owned(), *d, *h))
                            .collect(),
                    )
                })
                .collect();
            Self {
                entries: map,
                cursor: 0,
                current: Vec::new(),
                begin_calls: 0,
            }
        }
    }

    impl EnumerateInterface for MockVfs {
        fn begin_iteration(&mut self, path: &str, _parent: TreeItemId) -> bool {
            self.begin_calls = self.begin_calls.saturating_add(1);
            self.cursor = 0;
            self.current = self.entries.get(path).cloned().unwrap_or_default();
            !self.current.is_empty()
        }

        fn populate_item(&mut self, child: &mut TreeNode) -> bool {
            if let Some((name, is_dir, handle)) = self.current.get(self.cursor) {
                child.set_text(0, name);
                child.expandable = *is_dir;
                child.priority = *is_dir;
                child.data = *handle;
            }
            self.cursor = self.cursor.saturating_add(1);
            self.cursor < self.current.len()
        }
    }

    fn no_cancel(_: u32) -> bool {
        false
    }

    #[test]
    fn lazy_expand_fetches_only_on_toggle() {
        let mut vfs = MockVfs::new(&[("", &[("dir", true, 1), ("file.txt", false, 2)])]);
        let mut tree = ContainerTree::new('/');
        // Nothing enumerated at construction.
        assert_eq!(vfs.begin_calls, 0);
        assert!(tree.children(tree.root()).is_empty());
        // Unfolding the root populates it.
        let root = tree.root();
        assert!(tree.on_item_toggle(root, false, &mut vfs, &mut no_cancel));
        assert_eq!(vfs.begin_calls, 1);
        let children = tree.children(root).to_vec();
        assert_eq!(children.len(), 2);
        // The last child is filled too (protocol: false AFTER fill).
        assert_eq!(tree.node(children[0]).unwrap().name(), "dir");
        assert!(tree.node(children[0]).unwrap().expandable);
        assert_eq!(tree.node(children[1]).unwrap().name(), "file.txt");
        assert!(!tree.node(children[1]).unwrap().expandable);
        assert_eq!(tree.node(children[1]).unwrap().data, 2);
    }

    #[test]
    fn populate_item_is_idempotent() {
        let mut vfs = MockVfs::new(&[("", &[("a", false, 1), ("b", false, 2)])]);
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        assert!(tree.populate_item(root, &mut vfs, &mut no_cancel));
        assert_eq!(tree.children(root).len(), 2);
        // Re-populating (re-expand) does not duplicate children.
        assert!(tree.populate_item(root, &mut vfs, &mut no_cancel));
        assert!(tree.populate_item(root, &mut vfs, &mut no_cancel));
        assert_eq!(tree.children(root).len(), 2);
        assert_eq!(vfs.begin_calls, 1);
    }

    #[test]
    fn empty_folder_marks_populated_without_children() {
        let mut vfs = MockVfs::new(&[]);
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        assert!(tree.populate_item(root, &mut vfs, &mut no_cancel));
        assert!(tree.children(root).is_empty());
        // Guard also holds for the empty result: no re-enumeration.
        assert!(tree.populate_item(root, &mut vfs, &mut no_cancel));
        assert_eq!(vfs.begin_calls, 1);
    }

    #[test]
    fn build_path_joins_names_and_skips_root() {
        let mut vfs = MockVfs::new(&[
            ("", &[("dir", true, 1)]),
            ("dir", &[("sub", true, 2)]),
            ("dir/sub", &[("leaf.bin", false, 3)]),
        ]);
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        tree.populate_item(root, &mut vfs, &mut no_cancel);
        let dir = tree.children(root)[0];
        // Root path is empty (BuildPath skips the root item).
        tree.update_path_for_item(root);
        assert_eq!(tree.current_path, "");
        tree.update_path_for_item(dir);
        assert_eq!(tree.current_path, "dir");
        // Nested expansion enumerates with the built path.
        tree.populate_item(dir, &mut vfs, &mut no_cancel);
        let sub = tree.children(dir)[0];
        tree.update_path_for_item(sub);
        assert_eq!(tree.current_path, "dir/sub");
        tree.populate_item(sub, &mut vfs, &mut no_cancel);
        let leaf = tree.children(sub)[0];
        tree.update_path_for_item(leaf);
        assert_eq!(tree.current_path, "dir/sub/leaf.bin");
    }

    #[test]
    fn separator_char_is_configurable() {
        let mut vfs = MockVfs::new(&[("", &[("d", true, 1)]), ("d", &[("f", false, 2)])]);
        let mut tree = ContainerTree::new('\\');
        assert_eq!(tree.node(tree.root()).unwrap().name(), "\\");
        let root = tree.root();
        tree.populate_item(root, &mut vfs, &mut no_cancel);
        let d = tree.children(root)[0];
        tree.populate_item(d, &mut vfs, &mut no_cancel);
        let f = tree.children(d)[0];
        tree.update_path_for_item(f);
        assert_eq!(tree.current_path, "d\\f");
    }

    #[test]
    fn progress_cancel_aborts_population() {
        let mut vfs = MockVfs::new(&[(
            "",
            &[("a", false, 1), ("b", false, 2), ("c", false, 3)],
        )]);
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        // Cancel after the second item (C++ ProgressStatus::Update
        // returning true).
        let mut cancel_after_two = |count: u32| count >= 2;
        assert!(!tree.populate_item(root, &mut vfs, &mut cancel_after_two));
        assert_eq!(tree.children(root).len(), 2);
    }

    #[test]
    fn toggle_resets_progress_counter_and_respects_fold() {
        let mut vfs = MockVfs::new(&[("", &[("a", false, 1)])]);
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        // A folded node does not populate.
        let child = tree.add_child(root);
        tree.node_mut(child).unwrap().set_text(0, "a");
        assert!(tree.on_item_toggle(child, false, &mut vfs, &mut no_cancel));
        assert_eq!(vfs.begin_calls, 0);
        // Unfolded → populates ("a" has no entries → stays empty).
        tree.unfold(child);
        assert!(tree.on_item_toggle(child, false, &mut vfs, &mut no_cancel));
        assert_eq!(vfs.begin_calls, 1);
    }
}

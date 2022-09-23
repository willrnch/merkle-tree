use sha2::{Sha256, Digest};

const LEAF_PREFIX: &[u8] = &[0];
const INTERMEDIATE_PREFIX: &[u8] = &[1];

/// Return true if value is an odd number.
#[inline]
fn is_odd(value: usize) -> bool {
    value & 1 == 1
}

/// Returns the number of leaf on a full balanced tree that
/// has at least `size` leafs.
fn get_full_balanced_tree_leaf_count(size: usize) -> usize {
    if size == 0 {
        return 0;
    }
    let mut rt = 1;
    while rt < size {
        rt <<= 1;
    }
    return rt;
}

/// Returns the sha256 hash of a leaf.
fn hash_leaf(values: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_PREFIX);
    for value in values {
        hasher.update(value);
    }
    let hash = hasher.finalize();
    let hash: [u8; 32] = hash.as_slice().try_into().expect("Wrong length");
    return hash;
}

/// Returns the sha256 hash of a node.
fn hash_node(partners: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INTERMEDIATE_PREFIX);
    hasher.update(partners[0]);
    if partners.len() == 1 {
        hasher.update(partners[0]);
    } else {
        hasher.update(partners[1]);
    }
    let hash = hasher.finalize();
    let hash: [u8; 32] = hash.as_slice().try_into().expect("Wrong length");
    return hash;
}

#[derive(Debug)]
pub struct MerkleTree<T>
where
    T: Eq + std::fmt::Debug
{
    arity: usize,
    items: Vec<T>,
}

impl<T: Eq + std::fmt::Debug> MerkleTree<T> {
    // Creates a new tree of the given arity with the given items
    pub fn new(arity: usize, items: Vec<T>) -> Self {
        let tree = MerkleTree{
            arity,
            items,
        };
        tree
    }

    // Inserts items in the tree.
    pub fn insert(&mut self, items: &mut Vec<T>) {
        self.items.append(items);
    }

    /// Returns the index of the first leaf that contains the input.
    pub fn find_index(&self, input: &Vec<T>) -> Option<usize> {
        self.items
            .chunks(self.arity)
            .position(|chunk| chunk == input)
    }
}

impl MerkleTree<Vec<u8>> {
    /// Returns a tuple of the merkle openning of the leaf at the given
    /// index or `None` if the index is out of bounds.
    pub fn get_opening(&self, index: usize) -> Option<([u8; 32], [u8; 32])> {
        // As the tree itself is never really constructed, we must consider
        // the case when the number of leafs we can build out of the items,
        // is lower than the merkle tree total number of leafs
        let len = self.items.len();

        let leaf_count = ((len as f64) / (self.arity as f64)).ceil() as usize;

        let total_leaf_count = get_full_balanced_tree_leaf_count(leaf_count);
        if index >= total_leaf_count {
            // Index out of bounds
            return None;
        }

        let left;
        let right;
        if index < leaf_count {
            if is_odd(index) {
                // Sibling is the previous node.
                left = index - 1;
                right = index;
            } else {
                // Sibling will be the next item if any or the current node.
                left = index;
                right = if index + 1 < leaf_count { index + 1 } else { left };
            }
        } else {
            // Index is in the range of the leafs that are copies of the last nodes
            let last = leaf_count - 1;

            if is_odd(last) {
                left = last - 1;
                right = last;
            } else {
                left = last;
                right = left;
            }
        }

        let start = left * self.arity;
        let end = std::cmp::min(start + self.arity, len);
        let left = &self.items[start..end];

        let start = right * self.arity;
        let end = std::cmp::min(start + self.arity, len);
        let right = &self.items[start..end];

        Some((hash_leaf(left), hash_leaf(right)))
    }

    /// Returns the merkle tree root hash.
    pub fn get_root(&self) -> [u8; 32] {
        if self.items.len() == 0 {
            return Sha256::digest(&[0]).as_slice().try_into().expect("Wrong length");
        }

        let mut nodes = Vec::from_iter(
            self.items.chunks(self.arity).map(hash_leaf)
        );

        while nodes.len() > 1 {
            nodes = Vec::from_iter(nodes.chunks(2).map(hash_node));
        }

        nodes[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::ToBase58;

    #[test]
    fn test_tree_from_empty() {
        let tree = MerkleTree::new(1, vec![]);
        assert_eq!(
            "8RBsoeyoRwajj86MZfZE6gMDJQVYGYcdSfx1zxqxNHbr",
            tree.get_root().to_base58()
        );
    }

    #[test]
    fn test_tree_from_one() {
        let tree = MerkleTree::new(1, vec![
            b"test".to_vec(),
        ]);
        assert_eq!(
            "FoUqud5m4u15CaUJeigj6ouZJ4r3c1RAMYYiRqquQsCq",
            tree.get_root().to_base58()
        );
    }

    #[test]
    fn test_get_root() {
        let tree = MerkleTree::new(3, vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),

            b"d".to_vec(),
            b"e".to_vec(),
            b"f".to_vec(),

            b"g".to_vec(),
            b"h".to_vec(),
        ]);

        let root = tree.get_root();
        assert_eq!(root.to_base58(), "81ib5BVoYvhojLBr7psbwBRbuHGZ7KYBdHEP2zAgBGnW");
    }

    #[test]
    fn test_find_index() {
        let tree = MerkleTree::new(3, vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),

            b"d".to_vec(),
            b"e".to_vec(),
            b"f".to_vec(),

            b"g".to_vec(),
            b"h".to_vec(),
        ]);

        let index = tree.find_index(&vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
        ]);

        assert_eq!(index, Some(0));
    }

    #[test]
    fn test_get_opening_out_of_bounds() {
        let values = vec![
            b"a".to_vec(),
            b"b".to_vec(),
        ];
        let tree = MerkleTree::new(1, values.clone());

        let opening = tree.get_opening(2);
        assert_eq!(opening, None);
    }

    #[test]
    fn test_get_opening_simple() {
        let values = vec![
            b"a".to_vec(),
            b"b".to_vec(),
        ];
        let tree = MerkleTree::new(1, values.clone());

        let expected = (
            hash_leaf(&[values[0].clone()]),
            hash_leaf(&[values[1].clone()])
        );

        let opening = tree.get_opening(0);
        assert_eq!(expected, opening.unwrap());

        let opening = tree.get_opening(1);
        assert_eq!(expected, opening.unwrap());
    }

    #[test]
    fn test_get_opening_uneven() {
        let values = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
        ];

        let tree = MerkleTree::new(1, values.clone());

        let expected = (
            hash_leaf(&[values[0].clone()]),
            hash_leaf(&[values[1].clone()])
        );

        let opening = tree.get_opening(0);
        assert_eq!(expected, opening.unwrap());

        let opening = tree.get_opening(1);
        assert_eq!(expected, opening.unwrap());

        let expected = (
            hash_leaf(&[values[2].clone()]),
            hash_leaf(&[values[2].clone()])
        );

        let opening = tree.get_opening(2);
        assert_eq!(expected, opening.unwrap());
    }

    #[test]
    fn test_get_opening_ghost_branch() {
        let values = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"d".to_vec(),
            b"e".to_vec(),
            b"f".to_vec(),
        ];

        let tree = MerkleTree::new(1, values.clone());

        let expected = (
            hash_leaf(&[values[4].clone()]),
            hash_leaf(&[values[5].clone()])
        );

        let opening = tree.get_opening(6);
        assert!(expected == opening.unwrap());

        let opening = tree.get_opening(7);
        assert!(expected == opening.unwrap());

        let opening = tree.get_opening(8);
        assert_eq!(None, opening);
    }

    #[test]
    fn test_get_opening_simple_arity_3() {
        let values = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),

            b"d".to_vec(),
            b"e".to_vec(),
            b"f".to_vec(),
        ];
        let tree = MerkleTree::new(3, values.clone());

        let expected = (
            hash_leaf(&[
                values[0].clone(),
                values[1].clone(),
                values[2].clone(),
            ]),
            hash_leaf(&[
                values[3].clone(),
                values[4].clone(),
                values[5].clone(),
            ])
        );

        let opening = tree.get_opening(0);
        assert_eq!(expected, opening.unwrap());

        let opening = tree.get_opening(1);
        assert_eq!(expected, opening.unwrap());
    }

    #[test]
    fn test_get_opening_uneven_arity_3() {
        let values = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),

            b"d".to_vec(),
            b"e".to_vec(),
            b"f".to_vec(),

            b"g".to_vec(),
            b"h".to_vec(),
        ];

        let tree = MerkleTree::new(3, values.clone());

        let expected = (
            hash_leaf(&[
                values[0].clone(),
                values[1].clone(),
                values[2].clone(),
            ]),
            hash_leaf(&[
                values[3].clone(),
                values[4].clone(),
                values[5].clone(),
            ])
        );

        let opening = tree.get_opening(0);
        assert_eq!(expected, opening.unwrap());

        let opening = tree.get_opening(1);
        assert_eq!(expected, opening.unwrap());

        let expected = (
            hash_leaf(&[
                values[6].clone(),
                values[7].clone(),
            ]),
            hash_leaf(&[
                values[6].clone(),
                values[7].clone(),
            ])
        );

        let opening = tree.get_opening(2);
        assert!(expected == opening.unwrap());
    }

    #[test]
    fn test_get_opening_ghost_branch_arity_3() {
        let values = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),

            b"d".to_vec(),
            b"e".to_vec(),
            b"f".to_vec(),

            b"g".to_vec(),
            b"h".to_vec(),
            b"i".to_vec(),

            b"j".to_vec(),
            b"k".to_vec(),
            b"l".to_vec(),

            b"m".to_vec(),
            b"n".to_vec(),
            b"o".to_vec(),

            b"p".to_vec(),
            b"q".to_vec(),
        ];

        let tree = MerkleTree::new(3, values.clone());

        let expected = (
            hash_leaf(&[
                values[12].clone(),
                values[13].clone(),
                values[14].clone(),
            ]),
            hash_leaf(&[
                values[15].clone(),
                values[16].clone(),
            ])
        );

        let opening = tree.get_opening(6);
        assert!(expected == opening.unwrap());

        let opening = tree.get_opening(7);
        assert!(expected == opening.unwrap());

        let opening = tree.get_opening(8);
        assert!(None == opening);
    }

    #[test]
    fn test_soalana() {
        let tree = MerkleTree::new(1, vec![
            b"my".to_vec(),
            b"very".to_vec(),
            b"eager".to_vec(),
            b"mother".to_vec(),
            b"just".to_vec(),
            b"served".to_vec(),
            b"us".to_vec(),
            b"nine".to_vec(),
            b"pizzas".to_vec(),
            b"make".to_vec(),
            b"prime".to_vec(),
        ]);

        let root = tree.get_root();
        assert!(root.to_base58() == "D7qTTC9Mj1Pynmuvo1TLqP7ZXQfd6vh1kF6mRwa9qNfD");
    }
}
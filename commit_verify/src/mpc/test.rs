#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::TryCommitVerify;

    fn gen_proto_id(index: usize) -> ProtocolId {
        let hash = sha256::Hash::hash(format!("protocol#{}", index).as_bytes());
        ProtocolId::from(hash.into_inner())
    }

    fn gen_msg(index: usize) -> Message { Message::hash(format!("message#{}", index).as_bytes()) }

    fn gen_source() -> MultiSource {
        MultiSource {
            min_depth: 3,
            messages: bmap! {
                gen_proto_id(0) => gen_msg(0),
                gen_proto_id(1) => gen_msg(1),
                gen_proto_id(2) => gen_msg(2)
            },
        }
    }

    #[test]
    fn test_lnpbp4_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LNPBP4);
        let tag_hash = sha256::Hash::hash(b"LNPBP4");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_entropy_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ENTROPY);
        let tag_hash = sha256::Hash::hash(b"LNPBP4:entropy");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_leaf_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LEAF);
        let tag_hash = sha256::Hash::hash(b"LNPBP4:leaf");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_node_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_NODE);
        let tag_hash = sha256::Hash::hash(b"LNPBP4:node");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_tree() {
        let src = gen_source();

        let tree = MerkleTree::try_commit(&src).unwrap();
        assert_eq!(tree.depth, 3);
        assert_eq!(tree.width(), 8);

        assert_ne!(tree.commit_conceal()[..], tree.consensus_commit()[..]);
        assert_eq!(CommitmentHash::hash(tree.commit_conceal()), tree.consensus_commit());

        let tree2 = MerkleTree::try_commit(&src).unwrap();
        assert_eq!(tree2.depth, 3);

        // Each time we must generate different randomness
        assert_ne!(tree.entropy, tree2.entropy);
        assert_ne!(tree, tree2);
        assert_ne!(tree.consensus_commit(), tree2.consensus_commit());
    }

    #[test]
    fn test_block() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let block = MerkleBlock::from(&tree);
        assert_eq!(tree.depth, block.depth);
        assert_eq!(tree.width(), block.width());
        assert_eq!(Some(tree.entropy), block.entropy);

        assert_eq!(tree.consensus_commit(), block.consensus_commit());

        let mut iter = src.messages.iter();
        let first = iter.next().unwrap();
        let second = iter.next().unwrap();
        let third = iter.next().unwrap();

        assert_eq!(block.cross_section[0], TreeNode::CommitmentLeaf {
            protocol_id: *third.0,
            message: *third.1,
        });
        assert_eq!(block.cross_section[3], TreeNode::CommitmentLeaf {
            protocol_id: *first.0,
            message: *first.1,
        });
        assert_eq!(block.cross_section[6], TreeNode::CommitmentLeaf {
            protocol_id: *second.0,
            message: *second.1,
        });

        assert_eq!(protocol_id_pos(*first.0, 8), 3);
        assert_eq!(protocol_id_pos(*second.0, 8), 6);
        assert_eq!(protocol_id_pos(*third.0, 8), 0);

        for pos in [1usize, 2, 4, 5, 7] {
            assert_eq!(block.cross_section[pos], TreeNode::ConcealedNode {
                depth: 3,
                hash: MerkleNode::with_entropy(tree.entropy, pos as u16)
            });
        }
    }

    #[test]
    fn test_block_conceal() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let orig_block = MerkleBlock::from(&tree);

        let mut iter = src.messages.iter();
        let first = iter.next().unwrap();

        let mut block = orig_block.clone();
        assert_eq!(block.conceal_except([*first.0]).unwrap(), 6);

        assert_eq!(block.entropy, None);

        assert_eq!(block.cross_section[0].depth().unwrap(), 2);
        assert_eq!(block.cross_section[1].depth().unwrap(), 3);
        assert_eq!(block.cross_section[3].depth().unwrap(), 1);
        assert_eq!(block.cross_section[2], TreeNode::CommitmentLeaf {
            protocol_id: *first.0,
            message: *first.1
        });

        assert_eq!(block.consensus_commit(), orig_block.consensus_commit());
    }

    #[test]
    fn test_proof() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let orig_block = MerkleBlock::from(&tree);

        for ((proto, msg), pos) in src.messages.into_iter().zip([3, 6, 0]) {
            let mut block = orig_block.clone();
            block.conceal_except([proto]).unwrap();

            let proof1 = block.to_merkle_proof(proto).unwrap();
            let proof2 = orig_block.to_merkle_proof(proto).unwrap();

            assert_eq!(proof1, proof2);

            assert_eq!(proof1.pos, pos);
            if pos == 3 {
                assert_eq!(proof1.path, vec![
                    block.cross_section[3].merkle_node_with(1),
                    block.cross_section[0].merkle_node_with(2),
                    block.cross_section[1].merkle_node_with(3)
                ]);
            }

            assert_eq!(proof1.convolve(proto, msg).unwrap(), tree.consensus_commit());
        }
    }

    #[test]
    fn test_proof_roundtrip() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let orig_block = MerkleBlock::from(&tree);

        for (proto, msg) in src.messages {
            let mut block = orig_block.clone();
            block.conceal_except([proto]).unwrap();
            assert_eq!(block.consensus_commit(), tree.consensus_commit());

            let proof = block.to_merkle_proof(proto).unwrap();
            let new_block = MerkleBlock::with(&proof, proto, msg).unwrap();
            assert_eq!(block, new_block);
            assert_eq!(block.consensus_commit(), new_block.consensus_commit());
        }
    }

    #[test]
    fn test_merge_reveal() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let mut orig_block = MerkleBlock::from(&tree);

        let mut iter = src.messages.iter();
        let first = iter.next().unwrap();

        let mut block = orig_block.clone();
        block.conceal_except([*first.0]).unwrap();

        let proof1 = block.to_merkle_proof(*first.0).unwrap();

        let mut new_block = MerkleBlock::with(&proof1, *first.0, *first.1).unwrap();
        assert_eq!(block, new_block);

        let second = iter.next().unwrap();
        let third = iter.next().unwrap();

        let proof2 = orig_block.to_merkle_proof(*second.0).unwrap();
        let proof3 = orig_block.to_merkle_proof(*third.0).unwrap();

        new_block
            .merge_reveal_path(&proof2, *second.0, *second.1)
            .unwrap();
        new_block
            .merge_reveal_path(&proof3, *third.0, *third.1)
            .unwrap();

        orig_block
            .conceal_except(src.messages.into_keys().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(orig_block, new_block);
    }

    #[test]
    fn test_merge_blocks() {
        let mut block1 = MerkleBlock {
            depth: 3,
            cross_section: vec![
                TreeNode::ConcealedNode {
                    depth: 3,
                    hash: MerkleNode::from_str(
                        "03e43c730e76e654a40fdc0b62940bb7382ed95d4e8124ba687b4ec470cd1f01",
                    )
                    .unwrap(),
                },
                TreeNode::CommitmentLeaf {
                    protocol_id: ProtocolId::from_str(
                        "391cfae9f7b23562826b3260831e92698c7ec43c49e7afeed8e83a1bd75bbce9",
                    )
                    .unwrap(),
                    message: Message::from_str(
                        "72c7278c8337a0480aa343dae2e6e6e1aee6c7b3df7d88f150a21c82f2b373ac",
                    )
                    .unwrap(),
                },
                TreeNode::ConcealedNode {
                    depth: 2,
                    hash: MerkleNode::from_str(
                        "d42b5b6f1d6cc564fea2258e5147f4dd07735fac5aafa4a8394feb75ed8e366d",
                    )
                    .unwrap(),
                },
                TreeNode::ConcealedNode {
                    depth: 1,
                    hash: MerkleNode::from_str(
                        "5009030a186d268e698e184cf9e32607951ab81c6e3b42ecaf6ccf73a5ca0f2e",
                    )
                    .unwrap(),
                },
            ],
            entropy: None,
        };

        let block2 = MerkleBlock {
            depth: 3,
            cross_section: vec![
                TreeNode::CommitmentLeaf {
                    protocol_id: ProtocolId::from_str(
                        "f0f2fc11fa38f3fd6132f46d8044612fc73e26b769025edabbe1290af9851897",
                    )
                    .unwrap(),
                    message: Message::from_str(
                        "c0abbb938d4da7ce3a25e704b5b41dbacc762afe45a536e7d0a962fb1b34413e",
                    )
                    .unwrap(),
                },
                TreeNode::ConcealedNode {
                    depth: 3,
                    hash: MerkleNode::from_str(
                        "8fff224a68c261d62ab33d802182ff09d6332e9079fce71936ea414ed45ee782",
                    )
                    .unwrap(),
                },
                TreeNode::ConcealedNode {
                    depth: 2,
                    hash: MerkleNode::from_str(
                        "d42b5b6f1d6cc564fea2258e5147f4dd07735fac5aafa4a8394feb75ed8e366d",
                    )
                    .unwrap(),
                },
                TreeNode::ConcealedNode {
                    depth: 1,
                    hash: MerkleNode::from_str(
                        "5009030a186d268e698e184cf9e32607951ab81c6e3b42ecaf6ccf73a5ca0f2e",
                    )
                    .unwrap(),
                },
            ],
            entropy: None,
        };

        let expected = MerkleBlock {
            depth: 3,
            cross_section: vec![
                TreeNode::CommitmentLeaf {
                    protocol_id: ProtocolId::from_str(
                        "f0f2fc11fa38f3fd6132f46d8044612fc73e26b769025edabbe1290af9851897",
                    )
                    .unwrap(),
                    message: Message::from_str(
                        "c0abbb938d4da7ce3a25e704b5b41dbacc762afe45a536e7d0a962fb1b34413e",
                    )
                    .unwrap(),
                },
                TreeNode::CommitmentLeaf {
                    protocol_id: ProtocolId::from_str(
                        "391cfae9f7b23562826b3260831e92698c7ec43c49e7afeed8e83a1bd75bbce9",
                    )
                    .unwrap(),
                    message: Message::from_str(
                        "72c7278c8337a0480aa343dae2e6e6e1aee6c7b3df7d88f150a21c82f2b373ac",
                    )
                    .unwrap(),
                },
                TreeNode::ConcealedNode {
                    depth: 2,
                    hash: MerkleNode::from_str(
                        "d42b5b6f1d6cc564fea2258e5147f4dd07735fac5aafa4a8394feb75ed8e366d",
                    )
                    .unwrap(),
                },
                TreeNode::ConcealedNode {
                    depth: 1,
                    hash: MerkleNode::from_str(
                        "5009030a186d268e698e184cf9e32607951ab81c6e3b42ecaf6ccf73a5ca0f2e",
                    )
                    .unwrap(),
                },
            ],
            entropy: None,
        };

        block1.merge_reveal(block2).unwrap();

        assert_eq!(block1, expected);
    }
}

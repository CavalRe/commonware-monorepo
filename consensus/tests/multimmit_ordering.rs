//! Ordering proofs with real quorum signatures and producer ancestry.
use commonware_codec::{Decode, Encode};
use commonware_consensus::{
    Epochable,
    multimmit::{
        config::Protocol,
        mocks::Committee,
        ordering::{Error, Limits, Verifier},
        scheme::bls12381_threshold::Scheme,
        types::{
            Anchor, ChainProposal, DigestedLeader, Extension, LeaderBlock, Lqc, Position,
            TipRecord, TransactionBlockHeader, VoteBody, genesis_history,
        },
    },
    types::{Height, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    ed25519::PublicKey as EdPublic,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;

const fn limits() -> Limits {
    Limits {
        histories: 16,
        headers: 128,
        outputs: 128,
        steps: 2048,
    }
}

fn proofs<V: Variant>(n: u32) {
    let committee = Committee::<V>::builder(19, n).build();
    let protocol = committee.config.clone();
    let genesis = protocol.genesis();
    let record =
        TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec()).unwrap();
    let headers = genesis
        .tips()
        .iter()
        .map(|tip| {
            TransactionBlockHeader::new(
                protocol.epoch(),
                tip.chain(),
                Height::new(1),
                tip.digest(),
                Sha256::hash(&[b"body", &tip.chain().get().to_be_bytes()]),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        genesis.vqc(),
        record.commitment::<Sha256>(),
        genesis
            .tips()
            .iter()
            .zip(&headers)
            .map(|(tip, header)| {
                ChainProposal::new(
                    tip.chain(),
                    Anchor::Tip(*tip),
                    vec![header.body_digest()],
                    protocol.codec_config().pipeline_depth(),
                )
                .unwrap()
            })
            .collect(),
        protocol.codec_config(),
    )
    .unwrap();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(1); headers.len()],
        vec![Extension::empty(); headers.len()],
        protocol.codec_config(),
    )
    .unwrap();
    let votes = committee
        .signers
        .iter()
        .take(protocol.codec_config().view_quorum())
        .map(|signer| signer.sign_vote(body.clone()).unwrap())
        .collect::<Vec<_>>();
    let certificate = committee
        .verifier
        .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
        .unwrap();
    let new = || {
        Verifier::<Sha256, EdPublic, V>::new(protocol.clone(), committee.verifier.clone(), limits())
            .unwrap()
    };
    let mut verifier = new();
    let initial = verifier.history();
    let mut rng = test_rng();
    // Missing history, missing headers, changed body, and wrong epoch all fail atomically.
    assert_eq!(
        verifier.verify(&mut rng, &certificate, &[], &headers, &Sequential),
        Err(Error::History)
    );
    assert_eq!(
        verifier.verify(
            &mut rng,
            &certificate,
            std::slice::from_ref(&record),
            &[],
            &Sequential
        ),
        Err(Error::Ancestry)
    );
    let mut changed = headers.clone();
    let h = &changed[0];
    changed[0] = TransactionBlockHeader::new(
        protocol.epoch(),
        h.chain(),
        h.height(),
        h.parent(),
        Sha256::hash(&[b"tampered"]),
    )
    .unwrap();
    assert_eq!(
        verifier.verify(
            &mut rng,
            &certificate,
            std::slice::from_ref(&record),
            &changed,
            &Sequential
        ),
        Err(Error::Ancestry)
    );
    assert_eq!(verifier.history(), initial);
    assert_eq!(verifier.emitted(), genesis.tips());
    let mut bytes = certificate.encode().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    if let Ok(tampered) = Lqc::<V, _>::decode_cfg(bytes, &protocol.codec_config()) {
        assert_eq!(
            verifier.verify(
                &mut rng,
                &tampered,
                std::slice::from_ref(&record),
                &headers,
                &Sequential
            ),
            Err(Error::Certificate)
        );
    }
    assert_eq!(verifier.history(), initial);
    // The same protocol with unrelated ordinary and threshold keys cannot pass a proof.
    let wrong_keys = Committee::<V>::builder(20, n)
        .namespace(protocol.namespace())
        .build();
    let wrong_scheme = Scheme::certificate_verifier(
        protocol.parameters(),
        wrong_keys.roster,
        *wrong_keys.da.public(),
        *wrong_keys.nullification.public(),
    )
    .unwrap();
    let mut wrong =
        Verifier::<Sha256, EdPublic, V>::new(protocol.clone(), wrong_scheme, limits()).unwrap();
    assert_eq!(
        wrong.verify(
            &mut rng,
            &certificate,
            std::slice::from_ref(&record),
            &headers,
            &Sequential
        ),
        Err(Error::Certificate)
    );
    let expected = headers
        .iter()
        .map(|h| h.block_ref::<Sha256>())
        .collect::<Vec<_>>();
    assert_eq!(
        verifier
            .verify(
                &mut rng,
                &certificate,
                std::slice::from_ref(&record),
                &headers,
                &Sequential
            )
            .unwrap(),
        expected
    );
    assert!(
        verifier
            .verify(&mut rng, &certificate, &[], &headers, &Sequential)
            .unwrap()
            .is_empty()
    );
    // A subsequent view opens the prior history and advances exactly one height per chain.
    let next_record = TipRecord::at_tips(record.commitment::<Sha256>(), expected.clone()).unwrap();
    let next_headers = expected
        .iter()
        .map(|tip| {
            TransactionBlockHeader::new(
                protocol.epoch(),
                tip.chain(),
                Height::new(2),
                tip.digest(),
                Sha256::hash(&[b"next body", &tip.chain().get().to_be_bytes()]),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(2)),
        genesis.vqc(),
        next_record.commitment::<Sha256>(),
        expected
            .iter()
            .zip(&next_headers)
            .map(|(tip, header)| {
                ChainProposal::new(
                    tip.chain(),
                    Anchor::Tip(*tip),
                    vec![header.body_digest()],
                    protocol.codec_config().pipeline_depth(),
                )
                .unwrap()
            })
            .collect(),
        protocol.codec_config(),
    )
    .unwrap();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(1); expected.len()],
        vec![Extension::empty(); expected.len()],
        protocol.codec_config(),
    )
    .unwrap();
    let votes = committee
        .signers
        .iter()
        .take(protocol.codec_config().view_quorum())
        .map(|s| s.sign_vote(body.clone()).unwrap())
        .collect::<Vec<_>>();
    let next_certificate = committee
        .verifier
        .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
        .unwrap();
    assert_eq!(
        verifier.verify(
            &mut rng,
            &next_certificate,
            std::slice::from_ref(&next_record),
            &[],
            &Sequential
        ),
        Err(Error::Ancestry)
    );
    assert_eq!(verifier.emitted(), expected);
    assert_eq!(
        verifier
            .verify(
                &mut rng,
                &next_certificate,
                &[next_record],
                &next_headers,
                &Sequential
            )
            .unwrap(),
        next_headers
            .iter()
            .map(|h| h.block_ref::<Sha256>())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        verifier.verify(&mut rng, &certificate, &[], &headers, &Sequential),
        Err(Error::View)
    );
    // Resource failures cannot partially commit a history or frontier.
    let mut bounds = limits();
    bounds.outputs = 0;
    let mut bounded =
        Verifier::<Sha256, EdPublic, V>::new(protocol.clone(), committee.verifier.clone(), bounds)
            .unwrap();
    assert_eq!(
        bounded.verify(
            &mut rng,
            &certificate,
            std::slice::from_ref(&record),
            &headers,
            &Sequential
        ),
        Err(Error::Limit)
    );
    assert_eq!(bounded.history(), initial);
    assert_eq!(bounded.emitted(), genesis.tips());
    bounds.outputs = 128;
    bounds.steps = 0;
    let mut bounded =
        Verifier::<Sha256, EdPublic, V>::new(protocol.clone(), committee.verifier.clone(), bounds)
            .unwrap();
    assert_eq!(
        bounded.verify(
            &mut rng,
            &certificate,
            std::slice::from_ref(&record),
            &headers,
            &Sequential
        ),
        Err(Error::Limit)
    );
    assert_eq!(bounded.history(), initial);
    // Another genesis cannot use the same otherwise-valid committee proof.
    let other = commonware_consensus::multimmit::types::EpochGenesis::new(
        genesis.epoch(),
        Sha256::hash(&[b"other genesis"]),
        genesis.vqc(),
        genesis.lqc(),
        genesis.tips().to_vec(),
    )
    .unwrap();
    let other_protocol = Protocol::from_parameters(protocol.parameters().clone(), other).unwrap();
    let mut other =
        Verifier::<Sha256, EdPublic, V>::new(other_protocol, committee.verifier.clone(), limits())
            .unwrap();
    assert_eq!(
        other.verify(&mut rng, &certificate, &[record], &headers, &Sequential),
        Err(Error::History)
    );
}

#[test]
fn single_validator_order() {
    proofs::<MinPk>(1);
}
#[test]
fn six_validator_order_both_variants() {
    proofs::<MinPk>(6);
    proofs::<MinSig>(6);
}

#[test]
fn history_catchup_uses_both_ordering_passes() {
    let committee = Committee::<MinPk>::builder(31, 6).build();
    let protocol = &committee.config;
    let genesis = protocol.genesis();
    let base =
        TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec()).unwrap();
    let mut headers = Vec::new();
    let mut tips = genesis.tips().to_vec();
    for (chain, count) in [(0usize, 2u64), (1, 1)] {
        for height in 1..=count {
            let header = TransactionBlockHeader::new(
                protocol.epoch(),
                tips[chain].chain(),
                Height::new(height),
                tips[chain].digest(),
                Sha256::hash(&[b"payload", &height.to_be_bytes(), &[chain as u8]]),
            )
            .unwrap();
            tips[chain] = header.block_ref::<Sha256>();
            headers.push(header);
        }
    }
    let history = TipRecord::new(
        base.commitment::<Sha256>(),
        tips.clone(),
        vec![
            Height::new(1),
            Height::new(1),
            Height::zero(),
            Height::zero(),
            Height::zero(),
            Height::zero(),
        ],
    )
    .unwrap();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(3)),
        genesis.vqc(),
        history.commitment::<Sha256>(),
        tips.iter()
            .map(|tip| {
                ChainProposal::new(
                    tip.chain(),
                    Anchor::Tip(*tip),
                    vec![],
                    protocol.codec_config().pipeline_depth(),
                )
                .unwrap()
            })
            .collect(),
        protocol.codec_config(),
    )
    .unwrap();
    let body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(0); tips.len()],
        vec![Extension::empty(); tips.len()],
        protocol.codec_config(),
    )
    .unwrap();
    let votes = committee
        .signers
        .iter()
        .take(protocol.codec_config().view_quorum())
        .map(|s| s.sign_vote(body.clone()).unwrap())
        .collect::<Vec<_>>();
    let certificate = committee
        .verifier
        .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
        .unwrap();
    let mut verifier =
        Verifier::<Sha256, EdPublic, MinPk>::new(protocol.clone(), committee.verifier, limits())
            .unwrap();
    let initial = verifier.history();
    let mut rng = test_rng();
    assert_eq!(
        verifier.verify(
            &mut rng,
            &certificate,
            &[history.clone(), base.clone()],
            &headers,
            &Sequential
        ),
        Err(Error::History)
    );
    assert_eq!(verifier.history(), initial);
    assert_eq!(
        verifier
            .verify(
                &mut rng,
                &certificate,
                &[base, history],
                &headers,
                &Sequential
            )
            .unwrap(),
        vec![
            headers[0].block_ref::<Sha256>(),
            headers[2].block_ref::<Sha256>(),
            headers[1].block_ref::<Sha256>()
        ]
    );
    assert_eq!(verifier.emitted(), tips);
}

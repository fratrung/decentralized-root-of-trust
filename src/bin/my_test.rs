use decentralized_root_of_trust::snark_verifier_node::PQSNARKVerifierModule;
use decentralized_root_of_trust::status_list::{StatusList, hash_any, status_list_root_fe};
use decentralized_root_of_trust::{committee::Committee, snark_prover_node::PQSNARKProverModule};
use lean_multisig::{
    XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen, xmss_sign, xmss_verify,
};
use rand::RngExt;

struct SimpleNodeProver {
    prover_snark_module: PQSNARKProverModule,
}

impl SimpleNodeProver {
    pub fn new() -> Self {
        SimpleNodeProver {
            prover_snark_module: PQSNARKProverModule::init_prover(),
        }
    }
}

fn main() {
    const N_COMMITTEE_MEMBERS: u32 = 200;
    const SLOT: u32 = 42;

    const KEY_SLOTS: u32 = 64;
    const T: u32 = 150;
    let mut rng = rand::rng();
    let mut committe_members: Vec<(XmssSecretKey, XmssPublicKey)> = Vec::new();

    for _ in 0..N_COMMITTEE_MEMBERS {
        let seed = rng.random();
        let (sk, pk) = match xmss_key_gen(seed, SLOT, SLOT + KEY_SLOTS, false) {
            Ok((sk, pk)) => (sk, pk),
            Err(e) => {
                println!("Error: {:#?}", e);
                return;
            }
        };
        committe_members.push((sk, pk));
    }

    let members: Vec<XmssPublicKey> = committe_members.iter().map(|(_, pk)| pk.clone()).collect();
    let committee = Committee::new(members, 15);
    println!(
        "Committee of {} members, with threshold of {}",
        N_COMMITTEE_MEMBERS,
        committee.threshold()
    );

    println!("Choosing the prover: ");
    let idx = rng.random_range(0..committe_members.len());
    println!("Members number {} selected as a Aggregator", idx);

    let data: [u8; 32] = hash_any(rng.random::<[u8; 32]>());
    let mut list: Vec<[u8; 32]> = Vec::new();
    list.push(data);
    let version: u32 = 1;

    let message = status_list_root_fe(&list, version);

    println!("Making Signatures");
    let mut raws_signatures: Vec<(XmssPublicKey, XmssSignature)> = Vec::with_capacity(T as usize);
    let mut idx_signer = 0;
    for signer in committe_members {
        if idx_signer >= T {
            break;
        }
        println!("{} Sign", idx_signer);

        raws_signatures.push((
            signer.1.clone(),
            xmss_sign(&mut rng, &signer.0, &message, SLOT).expect("signing failed"),
        ));
        idx_signer += 1;
    }

    println!("Status List signed with {} signature", T);

    println!("Test Verifica firma aggregata");
    let mut verified_signature = 0;
    for s in raws_signatures.iter() {
        let _ = match xmss_verify(&s.0, &message, &s.1, SLOT) {
            Ok(()) => verified_signature += 1,
            Err(e) => {
                println!("Error: {:#?}", e);
            }
        };
    }

    println!("{} Verified Signature", verified_signature);

    println!("Setup Prover");
    let prover_node = SimpleNodeProver::new();

    println!("Making proof...");

    let snark_proof =
        prover_node
            .prover_snark_module
            .make_proof(raws_signatures, &list, SLOT, version, 2);

    println!("PQ SNARK Proof generated");
    let status_list = StatusList::new(
        decentralized_root_of_trust::status_list::Algorithms::WotsXmss,
        list,
        version,
        snark_proof,
    );

    println!("\nTest Verifier");
    println!("Setup Verifier");

    let verifier = PQSNARKVerifierModule::new(committee.clone(), version);

    let success = verifier.verify(&status_list);
    if success {
        println!("Prova verificata con successo!");
    } else {
        println!("Errore nella verifica della prova");
    }

    println!("Seconda verifica, senza setup");
    let success2 = verifier.verify(&status_list);
    if success2 {
        println!("Prova verificata con successo!");
    } else {
        println!("Errore nella verifica della prova");
    }
}

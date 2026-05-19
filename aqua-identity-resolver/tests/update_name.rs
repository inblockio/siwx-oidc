use std::sync::Arc;

use aqua_identity_resolver::{AquaIdentityResolver, InMemoryClaimStore};
use aqua_rs_sdk::{
    primitives::RevisionLink,
    schema::{
        templates::NameClaim,
        template::BuiltInTemplate,
        AquaTreeWrapper, SigningCredentials,
    },
    Aquafier,
};

#[tokio::test]
async fn update_agent_a_name() {
    let aquafier = Aquafier::new();

    let nc = NameClaim {
        signer_did: "did:key:z6MkmwP9dLN3tEMA7LJfQjtFKppERcfy4Rvn4fWGjBHWrruk".into(),
        given_name: "Alpha".into(),
        family_name: "Agent".into(),
        middle_name: None,
        name_prefix: None,
        name_suffix: None,
        nickname: None,
        preferred_username: Some("AlphaAgent".into()),
        valid_from: None,
        valid_until: None,
    };

    let payload = serde_json::to_value(&nc).unwrap();
    let template_hash = RevisionLink::from_bytes(NameClaim::TEMPLATE_LINK);

    let mut tree = aquafier
        .create_object(template_hash, None, payload, None)
        .unwrap();

    let privkey: Vec<u8> = (0..32)
        .map(|i| {
            let s = "d9688a626d93db3401b15e6326b26bbae8e646eaa42840c2f75514cabc267841";
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()
        })
        .collect();
    let creds = SigningCredentials::Did { did_key: privkey };

    let wrapper = AquaTreeWrapper::new(tree.clone(), None, None);
    let sign_result = aquafier
        .sign_aqua_tree(wrapper, &creds, None, None)
        .await
        .unwrap();
    tree = sign_result.aqua_tree;

    // Save the tree JSON for inspection
    let tree_json = serde_json::to_string_pretty(&tree).unwrap();
    std::fs::write("test-data/agent-a-updated.aqua.json", &tree_json).unwrap();
    println!("Saved updated tree to test-data/agent-a-updated.aqua.json");

    // Now run the full ingest pipeline
    let store = Arc::new(InMemoryClaimStore::new());
    let resolver = AquaIdentityResolver::with_store(store);

    let claims = resolver.ingest(tree).await.unwrap();
    assert!(!claims.is_empty(), "should extract at least one claim");

    let profile = resolver
        .resolve("did:key:z6MkmwP9dLN3tEMA7LJfQjtFKppERcfy4Rvn4fWGjBHWrruk")
        .await
        .unwrap()
        .expect("profile should exist");

    println!("Display name: {:?}", profile.display_name);
    println!("Claims: {}", profile.claims.len());

    // preferred_username takes priority
    assert_eq!(profile.display_name.as_deref(), Some("AlphaAgent"));
}

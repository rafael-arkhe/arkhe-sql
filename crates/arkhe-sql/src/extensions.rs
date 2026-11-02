//! Arkhe file extensions specification, categorization, and validation.
//!
//! Organizes file formats across Arkhe layers: Identity & Content, Manifests & Models,
//! Receipts & Evidence, Network & Discovery, Inference & Execution, Verification & Fraud,
//! Economy & Governance, Chain Integration (CAL), and Build/Tests/Supply Chain.
//!
//! Follows fail-closed security rules for prohibited (e.g. unencrypted `.pem`, production `.env`,
//! MMR `.bak`, dump with payload `.dump`) and restricted extensions (e.g. `.dll`, `.exe`, `.so`, `.dylib`, `.tmp`).

use std::path::Path;

/// Functional layers in the Arkhe architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArkheFileCategory {
    IdentityAndContent,
    ManifestsAndModels,
    ReceiptsAndEvidence,
    NetworkAndDiscovery,
    InferenceAndExecution,
    VerificationAndFraud,
    EconomyAndGovernance,
    ChainIntegration,
    BuildAndSupplyChain,
}

/// Requirement status for a file extension in the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequirementStatus {
    Mandatory,
    Optional,
    Recommended,
}

/// Policy status for file extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionPolicy {
    Allowed,
    Restricted,
    Prohibited,
}

/// Specification definition for a recognized Arkhe extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkheExtensionSpec {
    pub extension: &'static str,
    pub example_filename: &'static str,
    pub description: &'static str,
    pub category: ArkheFileCategory,
    pub requirement: RequirementStatus,
    pub policy: ExtensionPolicy,
}

/// Prohibited or restricted rule description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRule {
    pub pattern: &'static str,
    pub policy: ExtensionPolicy,
    pub reason: &'static str,
}

/// All recognized normative Arkhe file extension specifications.
pub static NORMATIVE_EXTENSIONS: &[ArkheExtensionSpec] = &[
    // 1. Identity & Content
    ArkheExtensionSpec {
        extension: ".cid",
        example_filename: "model.cid",
        description: "Representação textual de CIDv1/BLAKE3",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".multihash",
        example_filename: "digest.multihash",
        description: "Hash autodescritivo",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".pub",
        example_filename: "publisher.pub",
        description: "Chave pública ML-DSA-65 ou Ed25519",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".sig",
        example_filename: "manifest.sig",
        description: "Assinatura destacada",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".cert",
        example_filename: "device.cert",
        description: "Certificado / atualização de identidade",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".crl",
        example_filename: "revocation.crl",
        description: "Revogação de chaves/identidades",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Recommended,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".keystore",
        example_filename: "node.keystore",
        description: "Contêiner criptografado de chaves locais",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".seed",
        example_filename: "node.seed",
        description: "Material de identidade criptografado (nunca plaintext)",
        category: ArkheFileCategory::IdentityAndContent,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    // 2. Manifests & Models
    ArkheExtensionSpec {
        extension: ".arkmanifest",
        example_filename: "model.arkmanifest",
        description: "Manifesto canônico CBOR do modelo",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".arkmanifest.sig",
        example_filename: "model.arkmanifest.sig",
        description: "Assinatura ML-DSA do publisher",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".gguf",
        example_filename: "model.gguf",
        description: "Modelo local de referência",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".gguf.part",
        example_filename: "model.gguf.part0001",
        description: "Chunk de peso",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".gguf.index",
        example_filename: "model.gguf.index",
        description: "Índice de chunks / CIDs",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Recommended,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".quant",
        example_filename: "nvfp4.quant",
        description: "Perfil de quantização",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".lineage",
        example_filename: "training.lineage",
        description: "Cadeia de checkpoints de treinamento",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".eval",
        example_filename: "evaluation.eval",
        description: "Registro de avaliação por checkpoint",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".dataset",
        example_filename: "cohort.dataset",
        description: "Descritor de coorte / dataset",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".tokenizer",
        example_filename: "tokenizer.json",
        description: "Tokenizador do modelo",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".vocab",
        example_filename: "vocab.txt",
        description: "Vocabulário legado",
        category: ArkheFileCategory::ManifestsAndModels,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    // 3. Receipts & Evidence
    ArkheExtensionSpec {
        extension: ".afir",
        example_filename: "fragment.afir",
        description: "Recibo AFiR binário de 384 bytes",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".afir.json",
        example_filename: "fragment.afir.json",
        description: "Representação JCS para debug/interop",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".afirtree",
        example_filename: "session.afirtree",
        description: "Árvore Merkle de recibos MoE",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".wer",
        example_filename: "session.wer",
        description: "MobileWER / registro testemunhal",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".mmr",
        example_filename: "device.mmr",
        description: "Estado / peaks da Merkle Mountain Range",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".mmrproof",
        example_filename: "inclusion.mmrproof",
        description: "Prova de inclusão",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".consistency",
        example_filename: "history.consistency",
        description: "Prova de consistência entre roots",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".checkpoint",
        example_filename: "device.checkpoint",
        description: "Checkpoint híbrido ML-DSA + Ed25519",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".attest",
        example_filename: "boot.attest",
        description: "Blob de Verified Boot / KeyMint",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".arkbundle",
        example_filename: "audit.arkbundle",
        description: "Bundle offline completo (OfflineVerificationBundle)",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".wasm",
        example_filename: "arkverify.wasm",
        description: "Verificador offline",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    // 4. Network & Discovery
    ArkheExtensionSpec {
        extension: ".peers",
        example_filename: "peers.dat",
        description: "PeerBook: endereços, buckets, tried/new",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".peerledger",
        example_filename: "service.peerledger",
        description: "Serviço, receipts, latência, disponibilidade",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".seeds",
        example_filename: "seeds.toml",
        description: "Seeds constitucionais e política de rotação",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".dhtcache",
        example_filename: "dht.cache",
        description: "Cache de lookup/announce",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".announce",
        example_filename: "chunk.announce",
        description: "Anúncio de chunk com token",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".gossip",
        example_filename: "topic.gossip",
        description: "Configuração de tópicos GossipSub",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".netpolicy",
        example_filename: "network.netpolicy",
        description: "Limites, classes de conexão, bandwidth",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".pcap",
        example_filename: "debug.pcap",
        description: "Captura de rede apenas em diagnóstico",
        category: ArkheFileCategory::NetworkAndDiscovery,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    // 5. Inference & Execution
    ArkheExtensionSpec {
        extension: ".policy",
        example_filename: "inference.policy",
        description: "Política declarada da inferência",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".policy.sig",
        example_filename: "inference.policy.sig",
        description: "Assinatura da política",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".request",
        example_filename: "inference.request",
        description: "Pedido canônico / política-scoped",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".response",
        example_filename: "inference.response",
        description: "Resposta + referência ao recibo",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".session",
        example_filename: "inference.session",
        description: "Sessão com nonce, política e recibos",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".router",
        example_filename: "moe.router",
        description: "Decisão de roteamento MoE",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".expertmap",
        example_filename: "moe.expertmap",
        description: "Mapa de experts / shards",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".kv",
        example_filename: "kvcache.bin",
        description: "Cache de atenção local (nunca evidência)",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".gpu",
        example_filename: "gpu.profile",
        description: "Capacidade, backend e limits",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".onnx",
        example_filename: "model.onnx",
        description: "Modelo interoperável alternativo",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".safetensors",
        example_filename: "model.safetensors",
        description: "Formato alternativo de pesos",
        category: ArkheFileCategory::InferenceAndExecution,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    // 6. Verification & Fraud
    ArkheExtensionSpec {
        extension: ".fraudproof",
        example_filename: "receipt.fraudproof",
        description: "Prova de recibo inválido / fraudulento",
        category: ArkheFileCategory::VerificationAndFraud,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".reexec",
        example_filename: "reexecution.reexec",
        description: "Resultado de re-execução amostral",
        category: ArkheFileCategory::VerificationAndFraud,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".zkproof",
        example_filename: "fragment.zkproof",
        description: "Prova ZKML de amostra de alto valor",
        category: ArkheFileCategory::VerificationAndFraud,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".teequote",
        example_filename: "attestation.teequote",
        description: "Quote TEE como acelerador",
        category: ArkheFileCategory::VerificationAndFraud,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".verdict",
        example_filename: "adjudication.verdict",
        description: "Decisão assinada de disputa",
        category: ArkheFileCategory::VerificationAndFraud,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".slash",
        example_filename: "slashing.slash",
        description: "Ordem de slashing vinculada a prova",
        category: ArkheFileCategory::VerificationAndFraud,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".golden",
        example_filename: "vectors.golden",
        description: "Vetores de teste canônicos",
        category: ArkheFileCategory::VerificationAndFraud,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    // 7. Economy & Governance
    ArkheExtensionSpec {
        extension: ".constitution",
        example_filename: "arkhe.constitution",
        description: "Constituição content-addressed",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".constitution.sig",
        example_filename: "arkhe.constitution.sig",
        description: "Assinaturas de quorum",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".proposal",
        example_filename: "upgrade.proposal",
        description: "Proposta de upgrade/mudança",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".vote",
        example_filename: "quorum.vote",
        description: "Voto assinado do quorum",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".canon",
        example_filename: "canonification.canon",
        description: "Ata de canonificação humana",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".emission",
        example_filename: "emission.schedule",
        description: "Parâmetros de burn-and-mint",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".reward",
        example_filename: "poi.reward",
        description: "Recompensa vinculada a receipt root",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".stake",
        example_filename: "validator.stake",
        description: "Bond / estado de stake",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".epoch",
        example_filename: "roles.epoch",
        description: "Conjuntos disjuntos worker / validator",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".gini",
        example_filename: "emission.gini",
        description: "Métrica publicada de distribuição",
        category: ArkheFileCategory::EconomyAndGovernance,
        requirement: RequirementStatus::Recommended,
        policy: ExtensionPolicy::Allowed,
    },
    // 8. Chain Integration (CAL)
    ArkheExtensionSpec {
        extension: ".anchor",
        example_filename: "checkpoint.anchor",
        description: "Ancoragem de root em chain",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".ibc",
        example_filename: "cal.ibc",
        description: "Configuração / adapters IBC",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".ccip",
        example_filename: "cal.ccip",
        description: "Adapter Chainlink CCIP",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".layerzero",
        example_filename: "cal.layerzero",
        description: "Adapter LayerZero",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".abi",
        example_filename: "ISettlement.abi",
        description: "Interface de contrato",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".sol",
        example_filename: "ArkheSettlement.sol",
        description: "Contrato EVM",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".move",
        example_filename: "arkhe.move",
        description: "Contrato Move / Sui",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".tx",
        example_filename: "anchor.tx",
        description: "Transação de ancoragem",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".receiptroot",
        example_filename: "settlement.receiptroot",
        description: "Root usado no settlement",
        category: ArkheFileCategory::ChainIntegration,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    // 9. Build, Tests & Supply Chain
    ArkheExtensionSpec {
        extension: ".toml",
        example_filename: "arkhe.toml",
        description: "Configuração Rust / nó",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".rs",
        example_filename: "lib.rs",
        description: "Código Rust do núcleo",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".ts",
        example_filename: "index.ts",
        description: "SDK TypeScript",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".cs",
        example_filename: "Arkhe.cs",
        description: "Implementação C#, se adotada",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".csproj",
        example_filename: "Arkhe.csproj",
        description: "Projeto C#",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".wat",
        example_filename: "arkverify.wat",
        description: "Representação textual WASM",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".json",
        example_filename: "package.json",
        description: "Configuração SDK / JCS",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".lock",
        example_filename: "Cargo.lock",
        description: "Pinning de dependências",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".sbom",
        example_filename: "release.sbom",
        description: "Inventário de componentes",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".provenance",
        example_filename: "build.provenance",
        description: "Proveniência SLSA da build",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".sha256",
        example_filename: "artifact.sha256",
        description: "Hash de artefatos",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".sigstore",
        example_filename: "artifact.sigstore",
        description: "Assinatura / proveniência de release",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Recommended,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".log",
        example_filename: "node.log",
        description: "Log operacional",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Optional,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".trace",
        example_filename: "consensus.trace",
        description: "Rastro de consenso / testnet",
        category: ArkheFileCategory::BuildAndSupplyChain,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
    ArkheExtensionSpec {
        extension: ".cbor",
        example_filename: "data.cbor",
        description: "Dados canônicos de protocolo",
        category: ArkheFileCategory::ReceiptsAndEvidence,
        requirement: RequirementStatus::Mandatory,
        policy: ExtensionPolicy::Allowed,
    },
];

/// Prohibited or restricted rules according to the Arkhe specification.
pub static SECURITY_RULES: &[SecurityRule] = &[
    SecurityRule {
        pattern: ".dll",
        policy: ExtensionPolicy::Restricted,
        reason: "Binário nativo; só com hash, assinatura e proveniência",
    },
    SecurityRule {
        pattern: ".exe",
        policy: ExtensionPolicy::Restricted,
        reason: "Distribuição, não formato de protocolo",
    },
    SecurityRule {
        pattern: ".so",
        policy: ExtensionPolicy::Restricted,
        reason: "Binário nativo; só com hash, assinatura e proveniência",
    },
    SecurityRule {
        pattern: ".dylib",
        policy: ExtensionPolicy::Restricted,
        reason: "Binário nativo; só com hash, assinatura e proveniência",
    },
    SecurityRule {
        pattern: ".pem",
        policy: ExtensionPolicy::Prohibited,
        reason: "Chaves privadas não devem ficar em texto claro",
    },
    SecurityRule {
        pattern: ".env",
        policy: ExtensionPolicy::Prohibited,
        reason: "Segredos não devem viver em arquivo simples em produção",
    },
    SecurityRule {
        pattern: ".bak",
        policy: ExtensionPolicy::Prohibited,
        reason: "Pode criar histórico paralelo e quebrar append-only",
    },
    SecurityRule {
        pattern: ".tmp",
        policy: ExtensionPolicy::Restricted,
        reason: "Deve ser atomicamente renomeado ou descartado",
    },
    SecurityRule {
        pattern: ".dump",
        policy: ExtensionPolicy::Prohibited,
        reason: "Pode vazar prompts/saídas com payload",
    },
];

/// Validation error when verifying filenames or file policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileValidationError {
    Prohibited {
        pattern: &'static str,
        reason: &'static str,
    },
    Restricted {
        pattern: &'static str,
        reason: &'static str,
    },
    UnknownExtension(String),
}

impl std::fmt::Display for FileValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prohibited { pattern, reason } => {
                write!(f, "Prohibited file policy for '{pattern}': {reason}")
            }
            Self::Restricted { pattern, reason } => {
                write!(f, "Restricted file policy for '{pattern}': {reason}")
            }
            Self::UnknownExtension(ext) => {
                write!(f, "Unknown or unapproved extension '{ext}'")
            }
        }
    }
}

impl std::error::Error for FileValidationError {}

/// Checks if a filename or path violates security policies (prohibited or restricted).
///
/// Follows fail-closed semantics:
/// - Rejects prohibited files with an error.
/// - Identifies restricted files which require explicit verification (hash/provenance).
pub fn check_security_policy<P: AsRef<Path>>(path: P) -> Result<(), FileValidationError> {
    let path_str = path.as_ref().to_string_lossy();
    let file_name = path
        .as_ref()
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();

    for rule in SECURITY_RULES {
        let matches = if rule.pattern.starts_with('.') && !rule.pattern[1..].contains('.') {
            file_name.ends_with(rule.pattern) || file_name == rule.pattern[1..]
        } else {
            file_name.contains(rule.pattern) || path_str.contains(rule.pattern)
        };

        if matches {
            match rule.policy {
                ExtensionPolicy::Prohibited => {
                    return Err(FileValidationError::Prohibited {
                        pattern: rule.pattern,
                        reason: rule.reason,
                    });
                }
                ExtensionPolicy::Restricted => {
                    return Err(FileValidationError::Restricted {
                        pattern: rule.pattern,
                        reason: rule.reason,
                    });
                }
                ExtensionPolicy::Allowed => {}
            }
        }
    }

    Ok(())
}

/// Matches a filename against normative Arkhe file extension specifications.
///
/// Supports multi-dot extensions (such as `.arkmanifest.sig`, `.afir.json`, `.gguf.part`).
pub fn find_normative_spec<P: AsRef<Path>>(path: P) -> Option<&'static ArkheExtensionSpec> {
    let file_name = path.as_ref().file_name()?.to_str()?;

    // Check longer matching extensions first (e.g. .arkmanifest.sig before .sig)
    let mut matching_specs: Vec<&'static ArkheExtensionSpec> = NORMATIVE_EXTENSIONS
        .iter()
        .filter(|spec| {
            if spec.extension.ends_with(".part") {
                file_name.contains(".gguf.part")
            } else {
                file_name.ends_with(spec.extension)
            }
        })
        .collect();

    matching_specs.sort_by_key(|spec| std::cmp::Reverse(spec.extension.len()));
    matching_specs.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normative_extension_lookup() {
        let spec_afir = find_normative_spec("fragment.afir").expect("should find .afir");
        assert_eq!(spec_afir.extension, ".afir");
        assert_eq!(spec_afir.category, ArkheFileCategory::ReceiptsAndEvidence);
        assert_eq!(spec_afir.requirement, RequirementStatus::Mandatory);

        let spec_cbor = find_normative_spec("evidence.cbor").expect("should find .cbor");
        assert_eq!(spec_cbor.extension, ".cbor");

        let spec_checkpoint =
            find_normative_spec("device.checkpoint").expect("should find .checkpoint");
        assert_eq!(
            spec_checkpoint.category,
            ArkheFileCategory::ReceiptsAndEvidence
        );

        let spec_mmr = find_normative_spec("data.mmr").expect("should find .mmr");
        assert_eq!(spec_mmr.category, ArkheFileCategory::ReceiptsAndEvidence);

        let spec_wasm = find_normative_spec("arkverify.wasm").expect("should find .wasm");
        assert_eq!(spec_wasm.requirement, RequirementStatus::Mandatory);

        let spec_constitution =
            find_normative_spec("arkhe.constitution").expect("should find .constitution");
        assert_eq!(
            spec_constitution.category,
            ArkheFileCategory::EconomyAndGovernance
        );
    }

    #[test]
    fn test_multi_dot_extension_precedence() {
        let spec_sig =
            find_normative_spec("model.arkmanifest.sig").expect("should match longest extension");
        assert_eq!(spec_sig.extension, ".arkmanifest.sig");

        let spec_manifest =
            find_normative_spec("model.arkmanifest").expect("should match manifest");
        assert_eq!(spec_manifest.extension, ".arkmanifest");

        let spec_afir_json =
            find_normative_spec("receipt.afir.json").expect("should match .afir.json");
        assert_eq!(spec_afir_json.extension, ".afir.json");

        let spec_part =
            find_normative_spec("weights.gguf.part0001").expect("should match gguf.part");
        assert_eq!(spec_part.extension, ".gguf.part");

        let spec_const_sig =
            find_normative_spec("arkhe.constitution.sig").expect("should match .constitution.sig");
        assert_eq!(spec_const_sig.extension, ".constitution.sig");
    }

    #[test]
    fn test_security_policy_rejection_prohibited() {
        // Plaintext PEM private key
        assert!(matches!(
            check_security_policy("private_key.pem"),
            Err(FileValidationError::Prohibited {
                pattern: ".pem",
                ..
            })
        ));

        // Production env file
        assert!(matches!(
            check_security_policy("/etc/arkhe/.env"),
            Err(FileValidationError::Prohibited {
                pattern: ".env",
                ..
            })
        ));

        // MMR / checkpoint backup violating append-only
        assert!(matches!(
            check_security_policy("checkpoint.bak"),
            Err(FileValidationError::Prohibited {
                pattern: ".bak",
                ..
            })
        ));

        // Memory or payload dump leaking prompts
        assert!(matches!(
            check_security_policy("payload.dump"),
            Err(FileValidationError::Prohibited {
                pattern: ".dump",
                ..
            })
        ));
    }

    #[test]
    fn test_security_policy_restricted() {
        // Native binaries
        assert!(matches!(
            check_security_policy("plugin.dll"),
            Err(FileValidationError::Restricted {
                pattern: ".dll",
                ..
            })
        ));

        assert!(matches!(
            check_security_policy("worker.exe"),
            Err(FileValidationError::Restricted {
                pattern: ".exe",
                ..
            })
        ));

        assert!(matches!(
            check_security_policy("libcustom.so"),
            Err(FileValidationError::Restricted { pattern: ".so", .. })
        ));

        assert!(matches!(
            check_security_policy("driver.dylib"),
            Err(FileValidationError::Restricted {
                pattern: ".dylib",
                ..
            })
        ));

        // Receipt temp files
        assert!(matches!(
            check_security_policy("receipt.tmp"),
            Err(FileValidationError::Restricted {
                pattern: ".tmp",
                ..
            })
        ));
    }

    #[test]
    fn test_allowed_files_pass_policy() {
        assert!(check_security_policy("fragment.afir").is_ok());
        assert!(check_security_policy("checkpoint.mmr").is_ok());
        assert!(check_security_policy("model.arkmanifest").is_ok());
        assert!(check_security_policy("arkverify.wasm").is_ok());
    }
}

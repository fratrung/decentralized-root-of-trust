# Security Review: decentralized-root-of-trust-main

## Scope

Revisione statica repository-wide del crate Rust, della demo di rete, della persistenza, dei formati wire, degli script e della configurazione Docker.

- Scan mode: repository
- Target kind: directory_snapshot
- Target ID: sha256:486947fe4c78ce55de6f8d5a43f4f19fb924afbe48ca112bf5d1b406397451ae
- Revision: 6d9c5c32624bb479724b9e974f1940aa35c2be00
- Snapshot digest: codex-security-snapshot/v1:sha256:486947fe4c78ce55de6f8d5a43f4f19fb924afbe48ca112bf5d1b406397451ae
- Inventory strategy: directory
- Included paths: .
- Excluded paths: none
- Runtime or test status: Analisi statica completata; test dinamici non eseguiti perché cargo/rustc non sono installati nell'ambiente.
- Artifacts reviewed: src/, demo/src/, demo/docker/, tests/, Cargo.toml, demo/Cargo.toml, README.md, AGENTS.md
- Scan context: Leggiti bene questa repository e dimmi se ci sono problemi da verificare e validare

Limitations and exclusions:
- Nessun toolchain Rust disponibile per compilazione o test.
- Nessun database advisory offline disponibile per validare CVE delle dipendenze.
- Il commit leanVM pinning è stato verificato nella configurazione, ma il codice della dipendenza esterna non è incluso nello snapshot.
- Excluded docs/architecture.{png,svg}: Artefatti visuali dell'architettura, senza logica eseguibile.
- Excluded external leanVM source: La dipendenza è pin-nata ma il suo sorgente non fa parte dello snapshot allegato.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 11 |
| Severity mix | high: 1, medium: 6, low: 4 |
| Confidence mix | high: 11 |
| Coverage | partial |
| Validation mode | Source-backed validation con audit indipendente e due investigazioni focalizzate. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Il sistema autorizza aggiornamenti di una status/revocation list tramite un comitato t-of-N con firme XMSS, pubblicate in forma raw o aggregate in una prova SNARK. I record e la rete/DHT sono non fidati; l'anchor, gli slot XMSS e lo stato anti-rollback devono restare integri.

### Assets

- Chiavi private XMSS e unicità key-slot-message
- Semantica t-of-N su membri crittograficamente distinti
- Integrità append-only della status list
- Anchor del comitato e stato high-water anti-rollback
- Disponibilità di signer, holder e prover SNARK

### Trust Boundaries

- Byte SSZ/prove provenienti da peer o DHT verso decoder e verificatori
- Volume storage condiviso verso la logica di firma della demo
- Connessioni TCP non autenticate verso signer e holder
- Volume committee condiviso verso il bootstrap dell'anchor
- File locali persistenti verso contatore XMSS e high-water mark

### Attacker Capabilities

- Pubblicare o sostituire record nel canale DHT/storage della demo
- Connettersi alla rete bridge Docker come peer/container malevolo
- Compromettere meno di t membri senza dover ottenere un quorum
- Fornire record validi ma obsoleti o input molto grandi

### Security Objectives

- Solo t membri distinti possono autorizzare un aggiornamento
- Uno slot XMSS non viene mai riutilizzato per messaggi diversi
- Ogni nuovo stato estende un predecessore autenticato
- La freshness avanza solo dopo verifica e non regredisce
- Input non fidati consumano risorse limitate

### Assumptions

- In produzione l'anchor è autenticato fuori banda e immutabile salvo rotazione autorizzata.
- La directory privata di stato di un signer non è scrivibile da peer non privilegiati.
- Le proprietà crittografiche del commit leanVM pinning sono corrette.
- I listener della demo non sono pubblicati sulle interfacce host dalla configurazione Compose fornita.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [I signer trasformano un predecessore non autenticato in uno stato realmente firmato](#finding-1) | high | high | inline below |
| [I secret deterministici dei membri sono pubblicati nei file Compose](#finding-2) | medium | high | inline below |
| [Qualunque peer della rete demo può richiedere firme e issuance](#finding-3) | medium | high | inline below |
| [Chiavi duplicate nell'anchor collassano il quorum raw](#finding-4) | medium | high | inline below |
| [L'ultimo slot XMSS può essere riemesso dopo restart](#finding-5) | medium | high | inline below |
| [Record DHT e candidati di verifica non hanno budget di risorse](#finding-6) | medium | high | inline below |
| [L'anchor del holder proviene da un volume scrivibile da tutti i container](#finding-7) | medium | high | inline below |
| [Thread per connessione e timeout di 900 secondi consentono resource exhaustion](#finding-8) | low | high | inline below |
| [La persistenza high-water è fail-open e non serializzata tra processi](#finding-9) | low | high | inline below |
| [Un filename con versione alta sopprime tutti gli aggiornamenti validi](#finding-10) | low | high | inline below |
| [I tempfile prevedibili nel volume condiviso seguono symlink](#finding-11) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] I signer trasformano un predecessore non autenticato in uno stato realmente firmato

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Il flusso da latest_record a decode_list, extends_published e sign_at è diretto e non contiene alcuna chiamata ai verificatori raw o SNARK. |
| Category | improper-input-validation |
| CWE | CWE-345 |
| Affected lines | demo/src/storage.rs:154-180, demo/src/bin/signer.rs:272-313, demo/src/bin/signer.rs:337-366, demo/src/bin/signer.rs:218-247 |

#### Summary

Un writer del DHT/storage può sostituire il record corrente con un SSZ decodificabile ma non autorizzato; i membri ne verificano solo la forma, poi firmano un'estensione che incorpora lo stato scelto dall'attaccante.

#### Root Cause

La logica di transizione confonde un record sintatticamente valido con un predecessore autorizzato.

**Selezione del record solo per filename** — `demo/src/storage.rs:176-180`

Il record viene letto integralmente ma non autenticato.

```rust
published_records().into_iter().find_map(|(v, p)| std::fs::read(p).ok().map(|b| (v, b)))
```

**Il signer estrae lista/versione con from_bytes** — `demo/src/bin/signer.rs:307-313`

from_bytes valida l'SSZ esterno, non quorum/prova/anchor.

```rust
Mode::Raw => StatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned())),
Mode::Snark => SnarkStatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned()))
```

#### Validation

Il successore firmato è valido crittograficamente, quindi la verifica del holder non può più distinguere la porzione di stato inizialmente iniettata.

Validation method: Tracciamento statico indipendente e confronto con i contratti di StatusList::from_bytes, SnarkStatusList::from_bytes e i verificatori.

- **Status:** confirmed

Assertions:
- Lo storage è documentato come scrivibile da soggetti non fidati.
- StatusList::new ammette record raw con zero firme e SnarkStatusList::new ammette proof bytes arbitrari.
- L'estensione successiva raggiunge un quorum reale.

Counterevidence and remaining uncertainty:
- Il record iniettato originale viene rifiutato dal holder; ciò non protegge il successore firmato dagli honest signer.

Limitations:
- Nessun PoC dinamico eseguito per assenza del toolchain Rust.

#### Dataflow

I byte controllati dall'attaccante diventano la base della lista che il quorum firma.

- **Source:** Volume storage/DHT

- **Sink:** SignerNode::sign_at

- **Outcome:** Rollback o sostituzione della status list autenticata

Transformations:
- filename ordering
- SSZ decode
- append di una nuova entry
- firma t-of-N

**Selezione del record solo per filename** — `demo/src/storage.rs:176-180`

Il record viene letto integralmente ma non autenticato.

```rust
published_records().into_iter().find_map(|(v, p)| std::fs::read(p).ok().map(|b| (v, b)))
```

**Il signer estrae lista/versione con from_bytes** — `demo/src/bin/signer.rs:307-313`

from_bytes valida l'SSZ esterno, non quorum/prova/anchor.

```rust
Mode::Raw => StatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned())),
Mode::Snark => SnarkStatusList::from_bytes(bytes).map(|r| (r.version(), r.list_cloned()))
```

#### Reachability

Il modello della demo concede esplicitamente write access allo storage condiviso.

- **Attacker:** Writer DHT/storage malevolo

- **Entry point:** status-\*.ssz

- **Sink:** Quorum di firme raw o proof SNARK

- **Outcome:** Stato scelto dall'attaccante reso autorevole

Preconditions:
- Possibilità di sostituire o pubblicare il record selezionato come latest

#### Severity

**High** — L'attaccante previsto dal modello può rimuovere revoche o inserire stato arbitrario e farlo autenticare da un quorum onesto.

Scende se il volume storage è affidabile e non rappresenta un DHT non fidato; sale se il percorso è esposto a writer remoti reali.

Impact assessment:
- **Level:** high
- **Rationale:** Può riabilitare credenziali revocate o registrare entry arbitrarie.

Likelihood assessment:
- **Level:** high
- **Rationale:** La capacità di scrivere nel canale di pubblicazione è una premessa esplicita della demo.

#### Remediation

Ogni membro deve mantenere o ricostruire il più recente predecessore pienamente verificato sotto l'anchor e la freshness locale; la proposta deve impegnarsi sul digest del predecessore autenticato. Se la verifica SNARK è troppo costosa per ogni signer, introdurre un commitment/transizione autenticata dedicata, non usare un decode strutturale come autorizzazione.

Tests:
- Inserire un predecessore SSZ decodificabile ma senza quorum e verificare che nessun signer consumi lo slot.
- Sostituire il latest con una lista che rimuove una revoca e verificare che una nuova issuance fallisca.

<a id="finding-2"></a>

### [2] I secret deterministici dei membri sono pubblicati nei file Compose

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | La derivazione SHA3 e l'uso di xmss_key_gen_from_seed sono espliciti. |
| Category | hardcoded-credentials |
| CWE | CWE-798, CWE-321 |
| Affected lines | demo/docker/compose.raw.yml:41-206, demo/docker/compose.snark.yml:41-206, demo/src/storage.rs:111-131, demo/src/bin/signer.rs:96-102 |

#### Summary

Tutti i MEMBER_SECRET sono inclusi nel repository; combinandoli con il run-id condiviso si possono rigenerare deterministicamente tutte le chiavi private XMSS della demo.

#### Root Cause

Materiale segreto a lungo termine è trattato come configurazione pubblica della demo.

#### Validation

Repository + run-id sono sufficienti a ricreare tutte le keypair della demo.

Validation method: Tracciamento statico dei valori Compose fino alla key generation deterministica.

- **Status:** confirmed

Counterevidence and remaining uncertainty:
- Il run-id casuale ruota le chiavi tra run, ma non fornisce segretezza a chi può leggerlo.

#### Dataflow

The canonical finding records the affected path at demo/docker/compose.raw.yml:41-206, demo/docker/compose.snark.yml:41-206, demo/src/storage.rs:111-131, demo/src/bin/signer.rs:96-102, but no expanded source-to-sink narrative was recorded.

#### Reachability

Ogni container membro vede il run-id e il repository rivela tutti i secret.

- **Attacker:** Container membro compromesso o volume reader

- **Entry point:** run-id

- **Sink:** xmss_key_gen_from_seed

- **Outcome:** Compromissione completa del comitato

#### Severity

**Medium** — Compromette l'intero quorum ma richiede leggere il run-id dal volume condiviso; l'impatto è confinato alla demo fornita.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** complete committee forgery

**Likelihood assessment:** medium

#### Remediation

Generare secret indipendenti ad alta entropia fuori dal repository, iniettarli con Docker secrets/KMS e limitarne la visibilità a un solo membro. Considerare compromesse tutte le chiavi derivate dai valori committati.

<a id="finding-3"></a>

### [3] Qualunque peer della rete demo può richiedere firme e issuance

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Il peer address viene solo loggato e nessun controllo precede sign_at o l'intero round di issuance. |
| Category | missing-authorization |
| CWE | CWE-306, CWE-862 |
| Affected lines | demo/src/bin/signer.rs:145-196, demo/src/bin/signer.rs:198-247, demo/src/bin/signer.rs:316-406 |

#### Summary

I messaggi MSG_PROPOSAL e MSG_VC_REQUEST sono dispatchati senza autenticazione o policy; un peer può far firmare entry arbitrarie, consumare round XMSS e innescare prove SNARK costose.

#### Root Cause

Validità strutturale di una proposta è usata come sostituto dell'autorizzazione del proponente e del contenuto.

#### Validation

Un singolo peer può ottenere un quorum onesto su una nuova entry senza possedere t chiavi.

Validation method: Tracciamento TCP accept -\> recv -\> dispatch -\> sign_at/on_credential_request.

- **Status:** confirmed

#### Dataflow

The canonical finding records the affected path at demo/src/bin/signer.rs:145-196, demo/src/bin/signer.rs:198-247, demo/src/bin/signer.rs:316-406, but no expanded source-to-sink narrative was recorded.

#### Reachability

I listener bindano 0.0.0.0 sulla rete bridge; non sono pubblicati sull'host.

- **Attacker:** Peer/container sulla rete demo

- **Entry point:** TCP 9000

- **Sink:** SignerNode::sign_at e PQSNARKProverModule::make_proof

- **Outcome:** Aggiornamenti non autorizzati o esaurimento slot

#### Severity

**Medium** — L'impatto viola il t-of-N amministrativo, ma la configurazione fornita limita la reachability alla rete bridge Docker.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** unauthorized committee-backed status updates

**Likelihood assessment:** medium

#### Remediation

Usare mutua autenticazione, richieste firmate e replay-protected, autorizzare sia il requester sia l'esatta transizione canonica e applicare rate/quota prima di reserve_at o setup/prove SNARK.

<a id="finding-4"></a>

### [4] Chiavi duplicate nell'anchor collassano il quorum raw

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Le verifiche sono per indice e non esiste controllo di unicità delle key canoniche. |
| Category | improper-authentication |
| CWE | CWE-287 |
| Affected lines | src/protocol/committee.rs:49-59, src/protocol/committee.rs:148-163, src/node/raw_verifier.rs:91-118 |

#### Summary

Committee::new e from_bytes accettano la stessa public key in più indici; una singola firma può essere copiata in più seat del bitmap e contare t volte nel path raw.

#### Root Cause

L'invariante di unicità dei membri non è applicato dal tipo Committee.

#### Validation

Il path SNARK deduplica le public key; il bypass rompe specificamente l'equivalenza del path raw.

Validation method: Confronto costruttori Committee, bitmap distinctness e xmss_verify per index.

- **Status:** confirmed

#### Dataflow

The canonical finding records the affected path at src/protocol/committee.rs:49-59, src/protocol/committee.rs:148-163, src/node/raw_verifier.rs:91-118, but no expanded source-to-sink narrative was recorded.

#### Reachability

L'API pubblica e la deserializzazione accettano anchor duplicati.

- **Attacker:** Provisioner/bootstrap malevolo o errore di configurazione

- **Entry point:** Committee::new/from_bytes

- **Sink:** VerifierNode::verify_status_list

- **Outcome:** Threshold collapse

#### Severity

**Medium** — Riduce un t-of-N a una sola chiave, ma richiede anchor malformato/malevolo o provisioning compromesso.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** single-key authorization

**Likelihood assessment:** medium

#### Remediation

Rifiutare duplicate canonical public-key encodings in Committee::new e Committee::from_bytes; aggiungere un test con la stessa key in t posizioni e la stessa signature clonata.

<a id="finding-5"></a>

### [5] L'ultimo slot XMSS può essere riemesso dopo restart

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | saturating_add, persist e open mostrano direttamente la perdita del flag terminale. |
| Category | incorrect-calculation |
| CWE | CWE-682 |
| Affected lines | src/state/slot_counter.rs:256-280, src/state/slot_counter.rs:315-340, src/state/slot_counter.rs:360-387 |

#### Summary

Con slot_end == u32::MAX, lo stato persistito non può rappresentare one-past-end: exhausted resta solo in memoria e AtomicSlotCounter::open lo reimposta a false.

#### Root Cause

Il formato persistente non rappresenta lo stato terminale del dominio u32.

#### Validation

Il file rimane su u32::MAX e il reopen riabilita quello slot.

Validation method: Analisi aritmetica e del formato persistente; confronto con il test esistente che copre solo lo stesso processo.

- **Status:** confirmed

Counterevidence and remaining uncertainty:
- I parametri attuali della demo terminano ben prima di u32::MAX.

Limitations:
- Test dinamico non eseguito per assenza cargo.

#### Dataflow

The canonical finding records the affected path at src/state/slot_counter.rs:256-280, src/state/slot_counter.rs:315-340, src/state/slot_counter.rs:360-387, but no expanded source-to-sink narrative was recorded.

#### Reachability

La configurazione è documentata come legale dal tipo; il demo corrente non la usa.

- **Attacker:** Requester che può raggiungere l'ultimo slot e provocare restart

- **Entry point:** AtomicSlotCounter::reserve/reserve_at

- **Sink:** xmss_sign

- **Outcome:** Possibile compromissione della chiave

#### Severity

**Medium** — Il riuso può compromettere la key XMSS, ma richiede una finestra che termina a u32::MAX e un restart dopo l'ultimo slot.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** XMSS key compromise

**Likelihood assessment:** low-to-medium

#### Remediation

Persistire un flag exhausted esplicito o next_free come u64/versioned record; ricostruire e validare lo stato in open. Aggiungere restart test dopo reserve e reserve_at di u32::MAX.

<a id="finding-6"></a>

### [6] Record DHT e candidati di verifica non hanno budget di risorse

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Il frame TCP è limitato a 8 MiB, mentre std::fs::read e le API pubbliche non hanno equivalenti limiti. |
| Category | resource-exhaustion |
| CWE | CWE-400, CWE-770 |
| Affected lines | src/protocol/status_list.rs:62-83, src/node/snark_verifier.rs:126-137, demo/src/storage.rs:176-180 |

#### Summary

Le Vec SSZ, le letture da storage e la selezione SNARK non impongono limiti su byte, entry, proof o numero di candidati, consentendo OOM o verifiche costose ripetute.

#### Root Cause

I limiti di trasporto non sono parte del contratto dei decoder, dello storage o della selezione candidati.

#### Validation

Input validi grandi o molti candidati possono consumare risorse senza soglia applicativa.

Validation method: Analisi di Vec SSZ, std::fs::read e ciclo select_freshest_above.

- **Status:** confirmed

#### Dataflow

The canonical finding records the affected path at src/protocol/status_list.rs:62-83, src/node/snark_verifier.rs:126-137, demo/src/storage.rs:176-180, but no expanded source-to-sink narrative was recorded.

#### Reachability

Lo storage è il sostituto DHT non fidato e le API della libreria accettano slice/candidate arbitrari.

- **Attacker:** Peer DHT/storage

- **Entry point:** from_bytes/select_freshest_above/latest_record

- **Sink:** allocazioni, Poseidon fold, xmss_verify, SNARK verify

- **Outcome:** Denial of service

#### Severity

**Medium** — Un source DHT non fidato può rendere indisponibile il verificatore, ma l'impatto è disponibilità e dipende dall'integrazione/volume.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** availability loss

**Likelihood assessment:** high

#### Remediation

Applicare un limite prima della lettura/decodifica, cap su entry/signature/proof/candidate count e un budget totale per lookup/verifica; usare streaming per liste grandi dove possibile.

<a id="finding-7"></a>

### [7] L'anchor del holder proviene da un volume scrivibile da tutti i container

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | I mount Compose sono read-write e non esiste pin/digest/firma esterna dell'anchor. |
| Category | improper-certificate-validation |
| CWE | CWE-345 |
| Affected lines | demo/docker/compose.raw.yml:13-24, demo/docker/compose.snark.yml:13-24, demo/src/storage.rs:105-109, demo/src/bin/holder.rs:64-73 |

#### Summary

Il volume committee è montato read-write su signer, holder e tool; dopo un restart un container malevolo può sostituire anchor.bin e far ripartire vuota la freshness sotto un comitato controllato.

#### Root Cause

Il canale di provisioning dell'anchor non è separato dai participant non fidati.

#### Validation

Un nuovo processo holder tratta il contenuto corrente del volume come trust root senza autenticazione esterna.

Validation method: Analisi dei mount Compose e del percorso wait_for_committee -\> Committee::from_bytes -\> Node::build.

- **Status:** confirmed

Counterevidence and remaining uncertainty:
- Il holder residente non ricarica l'anchor durante la stessa vita del processo.

#### Dataflow

The canonical finding records the affected path at demo/docker/compose.raw.yml:13-24, demo/docker/compose.snark.yml:13-24, demo/src/storage.rs:105-109, demo/src/bin/holder.rs:64-73, but no expanded source-to-sink narrative was recorded.

#### Reachability

Tutti i servizi ereditano il mount read-write del volume committee.

- **Attacker:** Container partecipante compromesso

- **Entry point:** /shared/committee/anchor.bin

- **Sink:** RawNode/SnarkNode

- **Outcome:** Root of trust sostituito

#### Severity

**Medium** — Sostituzione totale del root of trust, ma richiede compromissione di un container con accesso al volume e un restart del holder.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** complete trust-anchor replacement

**Likelihood assessment:** medium

#### Remediation

Autenticare o incorporare l'anchor fuori banda, montarlo read-only nei servizi runtime e riservare la scrittura a un bootstrap one-shot fidato. La rotazione deve essere autorizzata dal vecchio comitato e non dedotta da un semplice cambio file.

<a id="finding-8"></a>

### [8] Thread per connessione e timeout di 900 secondi consentono resource exhaustion

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Spawn, timeout, read_exact e configurazione stack sono tutti visibili nel sorgente. |
| Category | resource-exhaustion |
| CWE | CWE-400, CWE-770 |
| Affected lines | demo/src/bin/signer.rs:145-183, demo/src/config.rs:119-127, demo/src/bin/holder.rs:217-282, .cargo/config.toml:1-4 |

#### Summary

Ogni connessione al signer crea un thread non limitato prima di leggere il frame; RUST_MIN_STACK è 512 MiB e il timeout inbound predefinito è 900 secondi. Il holder processa inoltre una connessione alla volta.

#### Root Cause

Non esistono limiti di concorrenza, queue o deadline brevi prima dell'autenticazione.

#### Validation

MAX_FRAME limita il singolo buffer ma non numero di thread/socket né coda dietro il round mutex.

Validation method: Analisi del ciclo listener e delle configurazioni runtime.

- **Status:** confirmed

#### Dataflow

The canonical finding records the affected path at demo/src/bin/signer.rs:145-183, demo/src/config.rs:119-127, demo/src/bin/holder.rs:217-282, .cargo/config.toml:1-4, but no expanded source-to-sink narrative was recorded.

#### Reachability

Raggiungibile dai container sulla rete drot-demo-net.

- **Attacker:** Peer di rete adiacente

- **Entry point:** TCP 9000/9100

- **Sink:** thread/file descriptor/address space

- **Outcome:** Denial of service

#### Severity

**Low** — DoS facile per un peer adiacente, ma i listener non sono pubblicati sull'host dalla Compose fornita.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** availability loss

**Likelihood assessment:** medium

#### Remediation

Usare worker pool/async bounded, semaforo e rate limit per principal/IP, header/body/total deadline brevi e write timeout; isolare lo stack grande alle sole thread del prover.

<a id="finding-9"></a>

### [9] La persistenza high-water è fail-open e non serializzata tra processi

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Il comportamento è esplicito nel codice e documentato come fail-open; nessun lock è presente. |
| Category | improper-check-for-unusual-condition |
| CWE | CWE-754, CWE-362 |
| Affected lines | src/state/freshness.rs:41-56, src/state/freshness.rs:64-75, src/state/freshness.rs:92-113 |

#### Summary

Errori/corruzione vengono trattati come mark vuoto e un persist fallito restituisce comunque Accepted; due istanze sullo stesso path possono inoltre sovrascrivere un valore più nuovo con uno più vecchio.

#### Root Cause

Il compare-and-persist non è una transazione fallibile e monotona condivisa.

#### Validation

Dopo restart può essere accettato un record vecchio ancora crittograficamente valido.

Validation method: Analisi del caricamento, della gestione errori e dell'assenza di file lock.

- **Status:** confirmed

Counterevidence and remaining uncertainty:
- Nel processo singolo della demo, con I/O corretto, la verifica precede l'avanzamento e il mark è monotono.

#### Dataflow

The canonical finding records the affected path at src/state/freshness.rs:41-56, src/state/freshness.rs:64-75, src/state/freshness.rs:92-113, but no expanded source-to-sink narrative was recorded.

#### Reachability

Richiede guasto storage o più processi/istanze che condividono il path.

- **Attacker:** Peer che offre record stale dopo perdita del mark

- **Entry point:** HighWaterMark::load/try_advance

- **Sink:** Outcome::Accepted

- **Outcome:** Rollback

#### Severity

**Low** — Può riaprire rollback con impatto di autorizzazione, ma richiede errore storage, restart o deployment concorrente locale non usato dalla demo standard.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** stale authorization accepted

**Likelihood assessment:** low

#### Remediation

Restituire Result da load/try_advance, rifiutare l'accettazione se il persist fallisce, distinguere prima inizializzazione da stato corrotto, e usare lock esclusivo con read-compare-write del valore durabile.

<a id="finding-10"></a>

### [10] Un filename con versione alta sopprime tutti gli aggiornamenti validi

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | La scelta one-record e il mancato fallback sono espliciti. |
| Category | improper-input-validation |
| CWE | CWE-345 |
| Affected lines | demo/src/storage.rs:140-180, demo/src/bin/holder.rs:310-329 |

#### Summary

latest_record restituisce un solo file ordinato dal nome; il holder usa accept invece di accept_best e non prova candidati validi più bassi quando quello più alto è falso.

#### Root Cause

Una versione dichiarata non autenticata decide l'unico candidato verificato.

#### Validation

Il controllo corretto esiste nella libreria ma non viene usato dalla demo.

Validation method: Confronto del transport demo con RawNode::accept_best e SnarkNode::accept_best già disponibili.

- **Status:** confirmed

#### Dataflow

The canonical finding records the affected path at demo/src/storage.rs:140-180, demo/src/bin/holder.rs:310-329, but no expanded source-to-sink narrative was recorded.

#### Reachability

Un writer dello storage può creare nomi status-\*.ssz.

- **Attacker:** Writer storage/DHT

- **Entry point:** record filename

- **Sink:** holder run_round

- **Outcome:** Soppressione degli update validi

#### Severity

**Low** — DoS persistente limitato al canale storage della demo; non modifica l'high-water né produce accettazione errata.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** persistent denial of service

**Likelihood assessment:** high

#### Remediation

Caricare un insieme limitato di candidati e passarlo a accept_best/select_freshest_above; usare la versione solo per ordinare tentativi e continuare dopo un fallimento.

<a id="finding-11"></a>

### [11] I tempfile prevedibili nel volume condiviso seguono symlink

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | File::create segue symlink e i runtime container non cambiano USER. |
| Category | symlink-following |
| CWE | CWE-59 |
| Affected lines | demo/src/storage.rs:61-76, demo/docker/Dockerfile:16-36, demo/docker/compose.raw.yml:19-24 |

#### Summary

write_atomic usa un nome .tmp prevedibile e File::create in directory scrivibili da peer; un container può predisporre un symlink assoluto verso un file privato del victim container, eseguito come root.

#### Root Cause

L'atomic rename è implementato assumendo una directory fidata, mentre la directory è un confine ostile condiviso.

#### Validation

Il symlink viene seguito durante create prima che rename sposti la directory entry.

Validation method: Analisi delle primitive POSIX usate e dei mount/container user.

- **Status:** confirmed

#### Dataflow

The canonical finding records the affected path at demo/src/storage.rs:61-76, demo/docker/Dockerfile:16-36, demo/docker/compose.raw.yml:19-24, but no expanded source-to-sink narrative was recorded.

#### Reachability

I container condividono storage/committee RW e girano come root.

- **Attacker:** Container malevolo con write sul volume

- **Entry point:** \*.tmp symlink

- **Sink:** File::create

- **Outcome:** Overwrite cross-volume

#### Severity

**Low** — Cross-volume overwrite reale ma confinato a container malevoli con write sul volume e con contenuto generato dal victim, non byte completamente arbitrari.

Additional runtime or deployment evidence could raise or lower this severity.

**Impact assessment:** private state corruption

**Likelihood assessment:** low

#### Remediation

Creare tempfile unici con create_new e no-follow/openat2, verificare regular file/owner, usare directory-fd-relative APIs, eseguire come utente non root e separare i mount con least privilege.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Verifica raw e SNARK | Quorum e identità dei membri | Reported | Binding lista/versione/slot e verifica delle prove risultano solidi per anchor con chiavi uniche; è riportato il caso duplicate-key. |
| Persistenza slot XMSS | Stateful signatures | Reported | Burn-before-sign, fsync e lock sono robusti nei casi ordinari; il terminal slot u32::MAX non sopravvive al reopen. |
| High-water anti-rollback | Rollback | Reported | Verifica prima dell'avanzamento corretta; persistenza fail-open e assenza di serializzazione cross-process richiedono correzione. |
| DHT e storage condiviso | Stato non fidato e disponibilità | Reported | Il predecessore non autenticato può essere riciclato in uno stato realmente firmato; mancano limiti e fallback sui candidati. |
| Listener e protocollo TCP della demo | Autorizzazione e resource exhaustion | Reported | Endpoint di firma/issuance privi di autenticazione e concorrenza non limitata. |
| Bootstrap e provisioning anchor | Root of trust | Reported | Anchor e seed della demo non soddisfano un confine di fiducia contro container malevoli. |
| Formati SSZ e canonicalità | Parsing | No issue found | Nessuna ambiguità di encoding o bypass di binding confermato; i problemi residui sono limiti di risorsa su input validi grandi. |
| Credential JSON/JCS | Semantic binding | No issue found | Il fingerprint usa i byte ricevuti; nessun path è derivato dal subject. Manca invece l'autorizzazione dell'issuance, riportata altrove. |
| Manifest e lockfile dipendenze | Supply chain | Needs follow-up | Pin leanVM verificato; advisories correnti non validati per assenza di database offline. |

## Open Questions And Follow Up

- L'anchor di produzione sarà autenticato e immutabile fuori banda?
  - Follow-up prompt: Definire provisioning e rotazione del comitato prima di usare la demo come architettura reale.
- Il deployment deve tollerare snapshot rollback dello stato privato dei signer?
  - Follow-up prompt: Se sì, serve storage monotono/rollback-resistant oltre all'atomicità POSIX.
- cargo e rustc non sono disponibili nell'ambiente di esecuzione.
  - Follow-up prompt: Review deferred unit dynamic-rust-validation and close its stated proof gap. Paths: src/, demo/src/, tests/. Surfaces: surface_protocol_verification, surface_xmss_state, surface_demo_storage, surface_demo_network.
- Nessun database advisory autorevole offline disponibile.
  - Follow-up prompt: Review deferred unit dependency-advisories and close its stated proof gap. Paths: Cargo.lock, demo/Cargo.lock. Surfaces: surface_dependencies.

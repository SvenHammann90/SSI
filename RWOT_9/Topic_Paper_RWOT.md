# Formal protocol verification for SSI 

## Introduction

The SSI ecosystem has many components that interact with another in complex ways. DIDs and DID resolution, edge agents and cloud agents interacting in DKMS and DIDComm, Verifiable Credentials that can be verified using different methods (traditional signatures or zero-knowledge), and more.

Even when best practices are followed during design and specification of such systems, security problems can still occur through unforeseen interactions. Even very simple protocols have been believed secure for a long time and found insecure only after tool-assisted formal analysis [1]. Traditionally, formal analysis has often been applied to already established standards and protocols; it has only recently been incorporated more into design processes, e.g., for TLS 1.3. [2].

While the SSI concepts are not security protocols in the traditional sense, many interactions closely resemble traditional security protocols, and thus can be modeled similarly. Especially for the SSI specifications that are still in progress, this is a great opportunity to incorporate formal verification into the design process. This not only helps find potential problems, but the modeling process itself helps getting a more precise understanding of security requirements. 

In this topic paper, we give a brief background on protocol verification, present some initial ideas on how to apply verification in the SSI space, and outline open questions.

## Background on protocol verification

Protocol verification models different agents and the messages they can send over a network. In particular, *symbolic* protocol verification in the *Dolev-Yao network attacker model* [3] assumes that the attacker controls the network, can read, send, and modify messages, but cannot break cryptography (i.e., cryptography is assumed to be perfect). The goal is to detect *logical* errors in the protocol design that can lead to attacks on desired security properties (such as the secrecy and integrity of messages).

In the state-of-the-art protocol verification tool Tamarin [4], the system of communicating agents is modeled as follows. The system state is a multiset of facts, which can be changed by multiset rewriting rules. These rules model agents sending and receiving messages. For example, [Agent_State_1()] -- [SendMessage(msg)]->[Agent_State_2(), Out(msg)] models that an agent in State_1 sends a message "msg" out into the network (modeled by Out(msg)), and ends up in State_2. The rule is annotated by a so-called action fact "SendMessage(msg)". The action facts of executed rules are recorded in a *trace*. 

A *security property* holds for a system if it holds for all traces the system could produce. For example, we could formalize that the adversary should never learn a certain message (secrecy property), or that two agents should always agree that they are talking to each other and on the message content (agreement/authentication properties).

## Applications to SSI

We outline some security-critical parts of the SSI ecosystem for which we believe protocol verification methods to be promising. We seek to understand which security properties are relevant for each part, and what levels of abstraction is appropriate for modeling each part of the system. We believe that just precisely modeling required security properties can already yield important insights.

### Agent-to-Agent Communication (DIDComm)

As a first step, we provided models of increasing complexity for DIDComm, agent-to-agent communication using peer DIDs. The basic security properties DIDComm aims to provide is *secrecy* (only the intended receiver can learn the content of the message), and in the case of authCrypt, *authentication/integrity* (the message received is what the sender sent). For these properties, only the innermost encryption with the receiver's public key is relevant. The encryptions between hops during the message routing is instead relevant for *privacy*. Thus, for security analysis, we abstracted away the routing (the Dolev-Yao attacker model overapproximates that one or more agents on the path might be compromised).

#### Model 1: Agents know each other's public keys

The first model (*didcomm_basic*) assumes the agent's already know each other's public keys, and one agent sends an authCrypt-encrypted message to the other. This simple model illustrates how we model authCrypt and the security properties.

##### AuthCrypt Model

In the symbolic model, we abstractly model a cryptographic primitive using equations that model its properties. For example, for standard symmetric encryption, decrypt(encrypt(message, key), key) = message. For asymmetric encryption (e.g., anonCrypt), a_decrypt(a_encrypt(message, public_key_of(secret_key)), secret_key) = message. That is, public_key_of maps a secret key to its corresponding public key. Similarly, we model authCrypt as follows:

auth_decrypt(
auth_encrypt(message, sender_secret_key, public_key_of(receiver_secret_key)), public_key_of(sender_secret_key), receiver_secret_key) = message. 

This models that the message is only successfully decrypted if it comes from the expected sender. However, to explicitly model whether encryption is successful or not, we require an additional function that evaluates to true for messages that can be decrypted.

auth_verify(
auth_encrypt(message, sender_secret_key, public_key_of(receiver_secret_key)), public_key_of(sender_secret_key), receiver_secret_key) = true. 

##### Security properties

We successfully verified the following properties in our model, where A and B are agents that already know each other's public key.

- (Secrecy) Whenever B receives a message msg and B believes that msg comes from A, the adversary cannot know or learn msg.
- (Non-injective agreement [6]) Whenever B receives a message msg and B believes that msg comes from A, then A has previously sent msg to B.

#### Model 2: Agents perform DIDExchange to exchange peer DIDs

In the second model (*didcomm_peer_did_exchange*), we assume that the agents do not have any previously shared information, and perform the DIDExchange [7] protocol over an insecure channel to exchange peer DIDs [8]. The invitee B then sends a message using authCrypt to the inviter A.

Unsurprisingly, this protocol does not provide any security guarantees; the exchange was performed over an insecure channel, so neither A nor B has any reason to believe that they are actually talking to the other party. There are different ways to achieve guarantees:

- The exchange could be performed over a secure channel. However, assuming a pre-existing secure channel between A and B defeats the purpose of setting up such a channel in the first place. Nevertheless, it could be useful to extend some sort of short-lived secure channel.
- Offline verification of the exchanged DIDs is performed by the users controlling A and B. This is feasible in settings where the users are, e.g., in the same room, perform the exchange, and then check the displayed DIDs on each other's agents. We model this scenario in Model 3.
- Verifiable credentials are exchanged. In this method, the security properties can only hold with respect to some trust assumptions. For example, if there exists an issuer of verifiable credentials that is trusted by both users, who, e.g., provides a verified e-mail address. 

#### Model 3: DIDExchange + Offline Verification

In the third model (*didcomm_did_exchange_with_offline_ver*), we assume that the agents display the DIDs of each connection. The users then check whether their agents display the same DIDs for the connection, and only proceed with sending the payload authCrypt message (for which we would like the security properties to hold) if they match.

In this model, Tamarin still finds an attack on the security properties. We next describe the attack in our model, and then discuss whether this reflects a real problem.

**Attack in our model.** Recall that the model is an attacker who controls the network. 

1. The attacker sends an invitation to B. B generates a peer-DID (didB) and key-pair, and sends didB and the DID Doc containing its public key (pkB) to the attacker.
2. A sends an invitation to B. The attacker intercepts this invitation, and instead replies to A with an exchange request using didB, but the DID Doc contains the attacker's public key (pkATK1). [Note: At this point, A could notice that something is off because didB was not generated using the DID document with pkATK inside. However, such a check is not specified.]
3. A now generates its own peer-DID (didA) and key-pair and sends didA and the DID Doc containing its public key (pkA) encrypted with pkATK1. A believes to be talking to B, but is actually sending this to the attacker. At this point, in A's view, it has set up a connection with B using didA and didB.
4. The attacker (who can decrypt A's message, which was encrypted with pkATK1) now sends a modified DID Doc to B, which contains didA, but another public key controlled by the attacker, pkATK2. 
5. B receives this DID Doc, and now, in B's view, it has set up a connection with A using didA and didB.
6. Both agents will display that they have set up a connection between didA and didB. Everything looks fine to their users unless they actually compare the public keys.

**Attack Discussion.** This attack shows that the following guarantee described in [9] does not currently follow from the specification:

"DIDs are associated with at least one key pair at the moment of creation.

This prevents a category of man-in-the-middle attacks where an attacker could rotate a DID's keys at the outset of a relationship, unbeknownst to peers."

As a possible solution, the inviter must verify that the DID was generated using the generation algorithm using the stored version of the received DID Doc as input. We explore this solution in the next model.

#### Model 4: Fixed DIDExchange + Offline Verification

This model implements the fix described above: A verifies for any exchange request whether the DID was generated according to the algorithm, and only accepts the exchange request if this is the case.

In this fixed version, the security properties could be proven.

For readers interested in the details, the Tamarin models are available in the folder *DID_Tamarin*.

### Thoughts on further topics

We briefly touch on some ideas about other topics, for which we have not yet done formal modeling.

#### Verifiable Credentials and Public DIDs

To model verifiable credentials and issuers, the following points must be addressed:

- Credential issuers usually have a public DID registered on a ledger. To model this, we must also introduce a public DID method and its CRUD operations [5].
- Verification of verifiable credentials are not necessarily simple signature verification, but may involve zero-knowledge proofs. Verifiable credentials are also issued with respect to a link secret, which is also not yet modeled.

#### Decentralized Key Management (DKMS)

In our simple model described above, each DID subject controlled just a single agent with a single key-pair. This allowed us to identify a DID subject with a unique agent. However, this does not appropriately model reality, where agents not only have multiple agents controlling different keys, but authorization policies grant different rights to different agents. Thus, the model should be extended to model a DID subject, such as a person, separate from their agents, and consider a more fine-grained key distribution. 

Furthermore, recovery and revocation policies and protocols (e.g., social recovery) give rise to new security properties. Note that these properties are relative to the trust assumptions made by the user. For example, when a 2-out-of-3 secret sharing is set up, the trust assumption is that at most one of the user's trustees is compromised. When a trust assumption is violated, then compromise could occur without there being a protocol flaw.

## References

[1] [https://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol](https://en.wikipedia.org/wiki/Needham–Schroeder_protocol)

[2] Cremers, Cas, et al. "A comprehensive symbolic analysis of TLS 1.3." *Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security*. ACM, 2017.

[3] [https://en.wikipedia.org/wiki/Dolev%E2%80%93Yao_model](https://en.wikipedia.org/wiki/Dolev–Yao_model)

[4] https://tamarin-prover.github.io/

[5] https://w3c-ccg.github.io/did-spec/#did-operations

[6] Lowe, Gavin. "A hierarchy of authentication specifications." *Proceedings 10th Computer Security Foundations Workshop*. IEEE, 1997.

[7] https://github.com/hyperledger/aries-rfcs/blob/master/features/0023-did-exchange/README.md

[8] https://dhh1128.github.io/peer-did-method-spec/index.html

[9] https://dhh1128.github.io/peer-did-method-spec/index.html#guarantees
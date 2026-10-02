# Implemented protocol and exact assumptions

## 1. Status

This release implements the simplified, no-handover schedule, not v0.5's paired
polynomials or proactive resharing. It is a new C implementation, not a port of the
old Arduino diagnostic. The host validation suite was executed before delivery;
Raspberry Pi measurements must be generated on the user's Pi. No host timing is
presented as Raspberry Pi timing.

The simulator has N meter processes and one parent process containing the ESP,
router and trusted experimental harness. There are no separate DAs or EST actor:
selected meters do aggregation. This is a controlled single-host experiment with
separate process address spaces and actual local socket communication, not a
physical distributed network or hardened isolation against the host administrator.

The scheduler dispatches work sequentially. This avoids nondeterministic protocol
ordering but does not model concurrent all-to-all transmission or network delay.

## 2. Notation and units

| Symbol | Meaning |
|---|---|
| N | Number of meters, 2..64 |
| c | Committee size, k <= c <= N |
| k | Reconstruction threshold, 2 <= k <= c |
| b | Zero-based billing period |
| r | Global zero-based reporting round |
| C_b | Ordered selection of c distinct meter IDs |
| T_b | Consecutive configured reporting rounds in billing period b |
| p | 2048-bit safe prime, RFC3526 group14 |
| q | (p-1)/2, prime-order scalar field modulus |
| R_(i,r) | Integer interval energy, mWh |
| t_r | Nonnegative integer tariff, microCAD per Wh |
| rho_(i,b) | 32-byte commit-reveal contribution, unrelated to commitment blind |
| z_(i,r) | Random commitment blind, also coefficient a_1 |

Polynomial arithmetic is modulo q. Commitments are elements of the subgroup of
order q modulo p. Using p as both the scalar field and multiplicative group order
would be incorrect; they are kept separate here.

Bill unit: (mWh)*(microCAD/Wh) = nanoCAD. For example 1000 mWh at 100 microCAD/Wh
costs 100000 nanoCAD = 0.0001 CAD. Values used for the validation oracle are bounded
and checked for uint64 overflow. Cryptographic sums are field elements; supported
input bounds keep honest totals far below q.

## 3. Selection and schedule

The trusted harness announces the schedule and distributes a static authenticated
public-key registry. The ESP does not privately pick the committee.

1. At period b, each meter obtains fresh 32-byte rho from OpenSSL RAND_priv_bytes.
2. Meter i commits to SHA256(encode32(b)||encode32(i)||rho_(i,b)).
3. Every meter sends its commitment to every other actor, including ESP. Local
   self-deliveries are implemented as authenticated messages but not counted as
   remote network messages.
4. Only after every commitment has been distributed do meters reveal rho. Each
   recipient checks it against the stored commitment.
5. Each actor independently computes

   seed_b = SHA256(encode32(b)||rho_(1,b)||...||rho_(N,b)).

6. score_(b,j) = SHA256(seed_b||encode32(j)). Actors take the c smallest scores.
   Ties retain increasing ID order. This is a deterministic, recomputable selection.
7. The same committee handles all reporting rounds of T_b. A newly selected
   committee starts zero billing accumulators only after this period closes.

There is one common accepted transcript in this honest-scheduler experiment.
**All N reveals are required**. There is no subset-of-reveals fallback, consensus,
Byzantine broadcast or withholding recovery. Thus this build does not silently
choose among missing-reveal subsets, but an abort/retry policy could itself create
bias and is not implemented. Recomputability and benign-run frequency counts do
not prove adversarial bias resistance.

Repeated membership is allowed. Selection events are not the same as an observed
membership change. Metadata carries meter IDs; rotation is not identity unlinkability.

## 4. A reporting round

Meter i creates one fresh degree-at-most-(k-1) polynomial:

F_(i,r)(x) = R_(i,r) + z_(i,r) x + sum_(d=2)^(k-1) a_(i,d,r) x^d mod q.

All nonconstant coefficients are sampled independently and uniformly with
rejection sampling. The synthetic reading seed never seeds cryptographic randomness.

It computes:

C_(i,r) = g^(R_(i,r)) h^(z_(i,r)) mod p,

s_(i->j,r) = F_(i,r)(j) mod q, for each j in C_b.

Coordinates are the **actual meter IDs**, nonzero and distinct. A committee is
fixed within the period, so an accumulator always combines evaluations at the
same x. There are no persistent-slot handovers to mismatched meter IDs.

The commitment is delivered to every actor on authenticated channels. Shares go
only to the selected recipients (including a local delivery if a meter is selected).
The ESP receives the reading commitment, not the customer's individual share.
Receivers check message context, AEAD authentication, replay counter, scalar/group
encoding and expected sender. This is **not per-share algebraic verification**:
there are no coefficient commitments proving each F(j) is well formed.

Each selected member j adds:

S_(j,r) = sum_i s_(i->j,r) mod q,

A_(i,j,b) <- A_(i,j,b) + t_r s_(i->j,r) mod q.

S is reset every round. A is separate for every customer and continues for the
whole period. A member records missing inputs rather than silently treating them
as a complete zero contribution. No new protocol recovers missing data.

The ESP independently maintains commitments:

SCR_r = product_i C_(i,r) mod p,

BCR_(i,b) <- BCR_(i,b) C_(i,r)^(t_r) mod p.

The latter starts at 1. The ESP uses authenticated readings' commitments received
directly from their originating meters, not an aggregator-provided replacement.

## 5. Spatial reconstruction (every round)

Each committee member sends its S_(j,r) and coverage flag to ESP using an encrypted,
authenticated report. ESP selects the first k available authorized committee members
in the deterministic committee order. In the implemented normal schedule all c report.

For those coordinates, it constructs Lagrange basis polynomials:

L_j(x) = product_(m != j) (x-x_m)/(x_j-x_m) mod q.

ESP obtains both coefficients of the aggregate polynomial:

M_r = sum_j S_(j,r) L_j(0) mod q,

beta_(1,r) = sum_j S_(j,r) [x]L_j(x) mod q.

The notation [x] means the coefficient of x, not evaluation at x=1.
It checks g^(M_r) h^(beta_(1,r)) = SCR_r mod p.

An accepted spatial output requires k reports, declared complete coverage,
all expected authenticated commitments, and a matching commitment. The plaintext
oracle comparison is an extra test-harness assertion, not part of ESP's protocol
acceptance rule.

Only the selected k reports enter interpolation. A bad unused report is not
promised to be detected. This implementation does not search all subsets to recover
from bad shares, prove every high-degree coefficient, or identify which member is bad.

## 6. Customer billing (period closure)

Each committee member sends one accumulated A_(i,j,b) per customer to ESP. For
customer i, ESP uses the same interpolation to recover:

Bill_(i,b) = sum_(r in T_b) t_r R_(i,r) mod q,

Z_(i,b) = sum_(r in T_b) t_r z_(i,r) mod q.

It verifies g^(Bill_(i,b)) h^(Z_(i,b)) = BCR_(i,b) mod p, together with coverage and
report checks. This is individual billing, not the tariff applied to a group total.
An honest selected member never reconstructs individual readings during accumulation.

Only after period closure is the next committee selected. The old committee never
transfers unfinished state to it. For this sequential experiment finalization does
not overlap the next period. No state sharing/refreshing or proactive-security claim
is present.

## 7. Numeric example (plain arithmetic illustration)

Suppose two customers have interval energies (1000,2000) mWh in round 0 and
(2000,3000) mWh in round 1. Tariffs are 100 then 200 microCAD/Wh.

- Spatial round 0: 3000 mWh, independent of tariff.
- Spatial round 1: 5000 mWh, independent of tariff.
- Customer 1: 100*1000 + 200*2000 = 500000 nanoCAD.
- Customer 2: 100*2000 + 200*3000 = 800000 nanoCAD.

For k=2, illustrative customer-1 polynomials could be F_0(x)=1000+7x and
F_1(x)=2000+9x. At coordinates 1 and 3, the weighted accumulated shares are
100*1007+200*2009=502500 and 100*1021+200*2027=507500. Interpolation recovers
constant 500000 and first coefficient 2500 (=100*7+200*9). Neither committee
member computes the 500000 bill alone. Small blind values here explain arithmetic;
the implementation samples full-field random blinds.

## 8. Communication implementation

- Trusted, one-run X25519 public keys are provisioned before the experiment.
- Each endpoint derives pairwise secrets using X25519 and HKDF-SHA256.
- HKDF salt is a fresh public 32-byte run ID; info contains a protocol label and
  ordered source/destination IDs. Opposite directions use different keys.
- Data packets use AES-256-GCM, 16-byte tag, 12-byte nonce = sender ID (32 bits)
  followed by a monotonically increasing per-recipient counter (64 bits).
- The 32-byte header is authenticated as associated data: type, sender, recipient,
  billing period, reporting round, customer/item ID, and counter.
- Scalars and group elements use fixed-width 256-byte big-endian encoding. Integers
  in the wire header use explicit big-endian encoding, independent of C padding.
- Public commitments/reveals are also carried on these channels. They are available
  to all participants, but there is no third-party transferable digital signature.
- Keys are fresh each run. There is no certificate issuance, revocation, online PKI,
  per-round key renegotiation or forward-secure erasure claim.
- The socket router forwards encrypted meter-to-meter packets without decrypting
  them. Unix SOCK_SEQPACKET preserves frame boundaries. Simulator control frames
  use host-local C layout and are not claimed to be an interoperable network protocol.

The host creates keys as trusted experimental provisioning and owns all processes.
Other actors' private key arrays are cleansed after initialization in each process;
this is not isolation against a privileged host or a proof that every allocator
copy is erased. Logs omit secret shares, private keys and blind values.

Bootstrap public-key distribution is outside recorded protocol traffic. Receive
counters reject replay; they do not implement loss recovery. Missing/altered shares
produce incomplete/rejected outputs as described below. A dead actor or a 120-second
command timeout aborts the experiment, preserves logs and creates failure.txt.

## 9. Fault scenarios implemented

| Scenario | Injection | Expected behavior |
|---|---|---|
| none | Honest path | Spatial totals and customer bills agree with oracle |
| tamper | Flip ciphertext byte of meter 1's first share at configured round | AEAD rejects; affected coverage remains incomplete |
| replay | Redeliver that same valid packet | Counter rejects duplicate; no double accumulation |
| bad-share | Meter 1 adds 1 to share sent to first selected member, before valid encryption | Aggregate commitment check fails when used for reconstruction; bill normally fails if its tariff contribution is nonzero |
| bad-aggregate | First selected member adds 1 to its spatial report | Spatial check fails; independent billing state is unchanged |
| drop-share | Router drops meter 1's first committee share | Coverage is incomplete for that round and affected period bill |

The first selected member belongs to the reconstruction subset in these tests.
These are specific reproducible faults, not exhaustive malicious-behavior tests or
a proof of security against an adaptive colluding adversary. Zero tariffs and
particular cancellation patterns can leave some aggregates unchanged. Neither an
aggregate commitment nor a coverage flag proves physical reading truthfulness.

## 10. Stop semantics

SIGINT/Ctrl+C, SIGTERM and SIGHUP set a stop flag in the parent. Children ignore
terminal SIGINT and await the parent's explicit shutdown commands. `q`+Enter has
the same effect. The currently scheduled round finishes, which can take time.
Then already accumulated period-prefix shares may be reported as a **partial** bill.
Normal round limits, duration limits and input-file exhaustion use the same
finalization. There is never a transfer to an incoming committee on stop.

This adds an experimental truncated-period release; it is not an authorized
production policy for the ESP to query arbitrary prefix bills. It must be disclosed
when reporting results. A single-reading partial bill can expose its reading through
division by the known tariff. For normal full-period results, run an exact multiple
of billing-rounds and do not mix partial outputs into completed-bill statistics.

Repeated Ctrl+C does not bypass finalization. SIGKILL, power loss or a fatal internal
check may prevent final summary generation. checkpoint.json and flushed CSVs are
recovery evidence, not a resumable cryptographic checkpoint.

## 11. Security limits of the retained single-polynomial construction

This section is essential, not an implementation claim to have fixed the paper's
cryptography. The code preserves the requested construction and does not silently
substitute paired sharing polynomials or proactive resharing.

**Individual properties cannot simply be combined into a privacy theorem.** A
Pedersen commitment alone is perfectly hiding, and ordinary Shamir shares alone
have threshold secrecy. Here the same random value appears as both the commitment
blind and a polynomial coefficient. The adversary sees their joint distribution.

For k=2, one share y=R+z*x gives z=(y-R)/x. For a candidate reading m, an observer
with y and C can check:

C ?= g^m h^((y-m)/x).

This can test a bounded reading dictionary without solving a discrete logarithm.
For k-1 shares at higher thresholds, fixing a candidate constant determines the
remaining coefficients, so the candidate first coefficient can be checked against
C in the same way (subject to any degenerate coordinate relations). The implemented
small synthetic reading domain is not a defense. Thus this release **does not claim
that any k-1 colluding members learn nothing from shares plus commitments**.

Other boundaries:

- Final commitment verification checks the reconstructed constant and first
  coefficient, not every coefficient or every individual share. A change leaving
  those two coefficients unchanged need not be detected.
- A passing check does not identify malicious members or prove all contributed
  physically accurate readings. Source meters are trusted for measurement truth.
- Static trusted public keys, an honest schedule/ESP and reliable transcript delivery
  are explicit assumptions. The simulator is not a Byzantine-consensus protocol.
- Exact totals and final bills intentionally reveal aggregate information. There
  is no differential privacy, identity unlinkability, or protection against all
  inferences using external information.
- The single host and synthetic generation seed are known to the validation harness.
  It can compute the plaintext oracle. This is a test fixture, not a privacy adversary.
- A 2048-bit group corrects neither the above joint-view issue nor protocol omissions;
  it merely specifies a concrete arithmetic parameter. This build is classical, not PQ.
- No active-memory side-channel guarantee, perfect erasure proof or proactive
  corruption protection is made. Selected members retain a customer's period state.

Changing the privacy construction is a separate research decision for the handover
paper, not a hidden change in this simplified experiment.

## 12. Code map

- src/crypto.c: fixed group, random scalars, commitments, both-coefficient Lagrange
  reconstruction, X25519/HKDF and AES-GCM.
- src/main.c: actor state machine, process router, selection, schedule, accumulation,
  output checking, control signals, metrics and fault injection.
- run.py: optional interactive launcher.
- summarize.py: descriptive summary of actual output files.
- tests/: independent arithmetic checks and complete subprocess tests.

Primary implementation references:
- https://www.rfc-editor.org/rfc/rfc3526 (group14)
- https://docs.openssl.org/3.0/man7/EVP_PKEY-X25519/
- https://docs.openssl.org/3.0/man3/EVP_PKEY_CTX_set_hkdf_md/
- https://docs.openssl.org/3.0/man3/EVP_EncryptInit/
- https://gmplib.org/manual/Integer-Exponentiation

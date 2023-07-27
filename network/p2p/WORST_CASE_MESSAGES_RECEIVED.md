# Worst case number of messages received per slot and per epoch

# Duties

Each duty has a certain probability of to be assigned to a validator. Since we want to estimate the worst case scenario, we will consider that these duties will be assigned. Let's recall the maximum number of validators per duty.


| Duty | Maximum Number of Duties per slot | Maximum Number of Duties per epoch
| --- | --- | --- |
Attestation | $min(N/32,64\times 2048)$ | N
Attestation Aggregation | $64\times 16 = 1024$ | $64\times 2048 \times 32 = 32768$
Proposal | 1 | 32
Sync Committee | 512 | $512 \times 32 = 16384$
Sync Committee Aggregator | $16 \times 4 = 64$ |  $16 \times 4 \times 32 = 2048$

Total maximum number of duties per slot: $min(N/32,64\times 2048) + 1024 + 1 + 512 + 64$  
Total maximum number of duties per epoch: $N + 32768 + 32 + 16384 + 2048$

Let's consider the total number of validators in the blockchain, $N$, to be 691463 (value on 27th of July of 2023).

Total maximum number of duties per slot: 23210

Total maximum number of duties per epoch: 742695

## Restraining to the ssv network

Suppose we have $V$ validators in ssv network. The above table becomes:

| Duty | Maximum Number of Duties per slot | Maximum Number of Duties per epoch
| --- | --- | --- |
Attestation | $min(min(N/32,64\times 2048),V)$ | $V$
Attestation Aggregation | $min(V,64\times 16) = min(V,1024)$ | $min(V,64\times 2048 \times 32) = min(V,32768)$
Proposal | 1 | $min(V,32)$
Sync Committee | $min(V,512)$ | $min(V,512 \times 32) = min(V,16384)$
Sync Committee Aggregator | $min(V,16 \times 4) = min(V,64)$ |  $min(V,16 \times 4 \times 32) = min(V,2048)$

# Number of messages per duty

Suppose a validator is decentralized by $C$ operators.

For a duty $d$ with pre-consensus (proposal & aggregators), the maximum number of messages is:
$$MaxPossibleMessages(d,C) = C \text{ (pre-consensus)} + CONS(C) \text { (consensus)} + C\times(f+1) \text{ (decided)} + C\text{ (post-consensus)}$$

where $CONS(C)$ is the number of maximum consensus messages given $C$ operators and $f$ is the maximum number of faults ($\lfloor\frac{C-1}{3}\rfloor$).

## Number of consensus messages
The number of consensus message is a bit tricky.

To consider the worst case scenario, with more messages being broadcasted in the network, we should consider that, every round, each node receives the maximum number of messages it can before reaching consensus and then proceeds to Round-Change.

The number of rounds, nonetheless, is determined by the maximum possible duration of each duty which is summarized below:

| Duty | Maximum duration period in slots | Maximum number of rounds |
| --- | --- | --- |
Attestation |  32 | 12 |
Attestation Aggregation | 32 | 12 |
Proposal | 1 | 6 |
Sync Committee | 1 | 6 |
Sync Committee Aggregation | 1 | 6 |

In a successful round, the maximum possible number of messages is: $SuccessfulRound(C) = 1 \text{ (proposal)} + C \text{ (prepares)} + f \text{ (round-changes)} + C \text{ (commits)}$

In a failed round, the maximum possible number of messages is: $FailedRound(C) = 1 \text{ (proposal)} + C \text{ (prepares)} + Quorum(C) - 1 \text{ (commits)} + C \text{ (round-changes)}$

Note: $Quorum(C)$ is the quorum value considering $C$ nodes, which corresponds to $\lfloor\frac{C+f}{2}\rfloor + 1$.

Note: if, in a successful round, we received more than $f$ Round-Changes, then the node would set its *ProposalValue* to *nil* and would no longer decide for that round.

An important detail, here, is: failed round produces more messages than successful ones. However, if every round fails, then no decided messages or post-consensus messages would be valid.

For the worst case scenario, to maximize the number of messages, the best approach would be to consider only the last round as successful. This is because, even though we lack $Quorum(C)$ messages in the successful round relatively to the unsuccessful round, decided and post-consensus messages counts up to $C\times(f+1) + C$.

---

Thus, for a duty $d$ with pre-consensus, the maximum number of messages is:
$$MaxPossibleMessages(d,C) = C \text{ (pre-consensus)} + FailedRound(C)\times(MaxPossibleRounds(d) - 1) + SuccessfulRound(C) \text { (consensus)} + C\times(f+1) \text{ (decided)} + C\text{ (post-consensus)}$$

For a duty without pre-consensus, $MaxPossibleMessages(d,C)$ is the same except by the pre-consensus messages.

## Number messages per duty in a single slot

Note, however, that this is the maximum number of messages for a duty during the duty lifetime. If we were to consider a slot, this number should be shortned for duties that live longer that a slot.

For such duties, since the slot has 12 seconds, which corresponds to 6 QBFT rounds, the case for the maximum number of messages within a slot is if we have 5 failed round and 1 successful one. Thus
$$MaxPossibleMessagesInOneSlot(d,C) = C \text{ (pre-consensus)} + FailedRound(C)\times(5) + SuccessfulRound(C) \text { (consensus)} + C\times(f+1) \text{ (decided)} + C\text{ (post-consensus)}$$



# Total number of messages per slot & epoch

Letting $D$ be the set of duties, the total number os messages per epoch is simply
$$\sum_{d\in D} MaxPossibleDutiesPerEpoch(d) * MaxPossibleMessages(d,C)$$

and the total number of messages per slot is
$$\sum_{d\in D} MaxPossibleDutiesPerSlot(d) * MaxPossibleMessagesInOneSlot(d,C)$$


# Expected number of messages on worst case performance for all duties

The above formula produces the result in a worst case scenario. For example:
- it encompass the case in which all validators of the SSV network are assigned to attest in the same slot (if the number of validators is less than $64\times 2048$).
- all Ethereum sync committee member for a certain epoch, proposers and aggregators are also in the SSV network.
- all duties are performed in the worst possible case (producing the highest number of messages possible in each round).

This is far from reality though gives us an upper bound. To have a more realistic approach do the duties, we could consider the maximum probability of a validator being assigned to each duty. This is presented below.

| Duty | Maximum probability for slot |
| --- | --- |
Attestation | $1/32 = 0.03125$ |
Attestation Aggregation |$1/32 \times \frac{C(15,128)}{C(16,128)} = 0.00001728$
Proposal | $1/N = 0.0000014462$
Sync Committee | $C(511,N) / C(512,N) = 2.83\times 10^{-9}$
Sync Committee Aggregation | $C(511,N) / C(512,N) \times \frac{C(15,128)}{C(16,128)} = 1.564\times 10^{-12}$

Thus, being $V$ the set of SSV validators, the expected number of messages considering
- the probability of each validator to be assigned for the above duties in a slot
- each duty performing the worst possible

is

$$\sum_{v\in V} \sum_{d\in D} P(d) \times MaxPossibleMessagesInOneSlot(d,C)$$

## Maximum number of messages per second

For every situation above, if we would like to count the maximum possible number of messages per second, then we should consider that all pre-consenus, consensus, decided and post-consensus messages occur within one second. I.e., for each duty, the amount would be:
$$C \text{ (pre-consensus)} + SuccessfulRound(C) \text { (consensus)} + C\times(f+1) \text{ (decided)} + C\text{ (post-consensus)}$$
# dex1-demo

Dex1 is an orderbook dex on Nervos CKB designed using [Cobuild Protocol](https://talk.nervos.org/t/ckb-transaction-cobuild-protocol-overview/7702). See [here](https://talk.nervos.org/t/an-orderbook-dex-design-using-cobuild-otx/8089) for a brief inspiration.

This repository contains a full setup to get dex1 running on CKB. However, it should be noted that all code included in this repository is for demo / prototype purpose now, it is not yet ready for production usage.

# Data Structure

An order in dex1, is represented as a Cobuild OTX:

```yaml
inputs:
  input 0:
    capacity: 1000 CKB
    lock: Alice
    type: USDC UDT type script
    data: <2000 USDC>
outputs:
witnesses:
  witness 0: WitnessLayout format, OTX variant
    seals:
      0: SealPair format
        script_hash: Alice's script hash
        seal: <Signature for Alice>
    input_cells: 1
    output_cells: 0
    cell_deps: 0
    header_deps: 0
    message: Message format
      Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant
              bid_token: <USDC UDT type script hash>
              bid_amount: <2000 USDC>
              ask_token: <DAI UDT type script hash>
              ask_amount: <2050 DAI>
              recipient: <Alice's script hash>
              claimed_ckbytes: <1000 CKB>
```

The above OTX expresses an order that is asking(buying) for 2050 DAI, while bidding(selling) 2000 USDC. It sets aside 1000 CKBytes, named `claimed ckbytes` to build the output cell containing the payment in DAI.

Note that the number of input cells and output cells does not matter, only the different of CKBytes and bid tokens between the input cells and the output cells matter. The following is also a valid OTX order:

```yaml
inputs:
  input 0:
    capacity: 1000 CKB
    lock: Alice
    type: USDC UDT type script
    data: <1500 USDC>
  input 1:
    capacity: 2000 CKB
    lock: Alice
    type: USDC UDT type script
    data: <1000 USDC>
  input 2:
    capacity: 3000 CKB
    lock: Alice
    type: <EMPTY>
    data: <EMPTY>
  input 3:
    capacity: 4000 CKB
    lock: Alice
    type: <EMPTY>
    data: <EMPTY>
outputs:
  output 0:
    capacity: 500 CKB
    lock: Alice
    type: USDC UDT type script
    data: <200 USDC>
  output 1:
    capacity: 8000 CKB
    lock: Alice
    type: USDC UDT type script
    data: <300 USDC>
  output 2:
    capacity: 500 CKB
    lock: Alice
    type: <EMPTY>
    data: <EMPTY>
witnesses:
  witness 0: WitnessLayout format, OTX variant
    seals:
      0: SealPair format
        script_hash: Alice's script hash
        seal: <Signature for Alice>
    input_cells: 4
    output_cells: 3
    cell_deps: 0
    header_deps: 0
    message: Message format
      Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant
              bid_token: <USDC UDT type script hash>
              bid_amount: <2000 USDC>
              ask_token: <DAI UDT type script hash>
              ask_amount: <2050 DAI>
              recipient: <Alice's script hash>
              claimed_ckbytes: <1000 CKB>
```

OTX processors collect orders in the form of OTXs, and assembled matched ones into CKB transaction. The following is one of the possible CKB transaction:

```yaml
inputs:
  input 0(otx #a):
    capacity: 1000 CKB
    lock: Alice
    type: USDC UDT type script
    data: <2000 USDC>
  input 1(otx #b):
    capacity: 200 CKB
    lock: Bob
    type: DAI UDT type script
    data: <8000 DAI>
  input 2(otx #b):
    capacity: 4343 CKB
    lock: Bob
    type: <EMPTY>
    data: <EMPTY>
  input 3(dex1 entity cell):
    capacity: 166 CKB
    lock: <always success>
    type: <dex1 entity script>
    data: <dex1 entity data>
  input 4(fee cell):
    capacity: 3000.12 CKB
    lock: OTX Processor
    type: <EMPTY>
    data: <EMPTY>
outputs:
  output 0(otx #b):
    capacity: 200 CKB
    lock: Bob
    type: DAI UDT type script
    data: <5950 DAI>
  output 1(otx #b):
    capacity: 4143 CKB
    lock: Bob
    type: <EMPTY>
    data: <EMPTY>
  output 2(dex1 entity cell):
    capacity: 166 CKB
    lock: <always success>
    type: <dex1 entity script>
    data: <dex1 entity data>
  output 3(payment cell for otx #a):
    capacity: 1000 CKB
    lock: Alice
    type: DAI UDT type script
    data: <2050 DAI>
  output 4(payment cell for otx #b):
    capacity: 200 CKB
    lock: Bob
    type: USDC UDT type script
    data: <2000 USDC>
  output 5(fee cell):
    capacity: 3000.11 CKB
    lock: OTX Processor
    type: <EMPTY>
    data: <EMPTY>
witnesses:
  witness 0: <EMPTY>
  witness 1: <EMPTY>
  witness 2: <EMPTY>
  witness 3: <EMPTY>
  witness 5: WitnessArgs format
    lock: <Signature for fee cell>
  witness 5: <EMPTY>
  witness 6: WitnessLayout format, SighashAll variant
  witness 7: WitnessLayout format, OtxStart variant
    start_input_cell: 0
    start_output_cell: 0
    start_cell_deps: 0
    start_header_deps: 0
  witness 8(otx #a): WitnessLayout format, OTX variant
    seals:
      0: SealPair format
        script_hash: Alice's script hash
        seal: <Signature for Alice>
    input_cells: 1
    output_cells: 0
    cell_deps: 0
    header_deps: 0
    message: Message format
      Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant
              bid_token: <USDC UDT type script hash>
              bid_amount: <2000 USDC>
              ask_token: <DAI UDT type script hash>
              ask_amount: <2050 DAI>
              recipient: <Alice's script hash>
              claimed_ckbytes: <1000 CKB>
  witness 9(otx #b): WitnessLayout format, OTX variant
    seals:
      0: SealPair format
        script_hash: Bob's script hash
        seal: <Signature for Bob>
    input_cells: 2
    output_cells: 2
    cell_deps: 0
    header_deps: 0
    message: Message format
      Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant
              bid_token: <DAI UDT type script hash>
              bid_amount: <2050 DAI>
              ask_token: <USDC UDT type script hash>
              ask_amount: <2000 USDC>
              recipient: <Bob's script hash>
              claimed_ckbytes: <200 CKB>
```

Notice that OTX processor create payment cells for each order. Dex1 entity script will validate the presence of payment cell for each of the OTX on chain.

It is a convention that all CKB transactions generated by dex1, organize cells in the following order:

* All OTXs come at the very first
* The dex1 entity input / output cells are appended next
* Payment cells follow dex1 entity output cell, in the same order as OTXs
* The OTX processor might add additional cell to pay for CKB fees, and to seal the whole transaction against tampering

The above case is a perfect match, where each side buys exact the same amount tokens the other side is selling. But in some cases(or actually in most cases), orders from both side won't match perfectly. There will be one order that can only be partially fulfilled. Dex1 introduces `freestanding cells` to solve this issue:

```yaml
inputs:
  input 0(otx #a):
    capacity: 1000 CKB
    lock: Alice
    type: USDC UDT type script
    data: <2000 USDC>
  input 1(otx #b):
    capacity: 200 CKB
    lock: Bob
    type: DAI UDT type script
    data: <8000 DAI>
  input 2(otx #b):
    capacity: 4343 CKB
    lock: Bob
    type: <EMPTY>
    data: <EMPTY>
  input 3(dex1 entity cell):
    capacity: 166 CKB
    lock: <always success>
    type: <dex1 entity script>
    data: <dex1 entity data>
  input 4(fee cell):
    capacity: 3000.12 CKB
    lock: OTX processor
    type: <EMPTY>
    data: <EMPTY>
outputs:
  output 0(otx #b):
    capacity: 200 CKB
    lock: Bob
    type: DAI UDT type script
    data: <6950 DAI>
  output 1(otx #b):
    capacity: 4143 CKB
    lock: Bob
    type: <EMPTY>
    data: <EMPTY>
  output 2(dex1 entity cell):
    capacity: 166 CKB
    lock: <always success>
    type: <dex1 entity script>
    data: <dex1 entity data>
  output 3(freestanding cell for otx #a):
    capacity: 800 CKB
    lock:
      code_hash: <dex1 entity script>
      args: <dex1 entity cell type id> <Alice's script hash> <New Order A's hash>
    type: USDC UDT type script
    data: <1000 USDC>
  output 4(payment cell for otx #a):
    capacity: 200 CKB
    lock: Alice
    type: DAI UDT type script
    data: <1050 DAI>
  output 5(payment cell for otx #b):
    capacity: 200 CKB
    lock: Bob
    type: USDC UDT type script
    data: <1000 USDC>
  output 6(fee cell):
    capacity: 3000.11 CKB
    lock: OTX processor
    type: <EMPTY>
    data: <EMPTY>
witnesses:
  witness 0: <EMPTY>
  witness 1: <EMPTY>
  witness 2: <EMPTY>
  witness 3: <EMPTY>
  witness 5: WitnessArgs format
    lock: <Signature for fee cell>
  witness 5: <EMPTY>
  witness 6: <EMPTY>
  witness 7: WitnessLayout format, SighashAll variant
  witness 8: WitnessLayout format, OtxStart variant
    start_input_cell: 0
    start_output_cell: 0
    start_cell_deps: 0
    start_header_deps: 0
  witness 9(otx #a): WitnessLayout format, OTX variant
    seals:
      0: SealPair format
        script_hash: Alice's script hash
        seal: <Signature for Alice>
    input_cells: 1
    output_cells: 0
    cell_deps: 0
    header_deps: 0
    message: Message format
      Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant
              bid_token: <USDC UDT type script hash>
              bid_amount: <2000 USDC>
              ask_token: <DAI UDT type script hash>
              ask_amount: <2050 DAI>
              recipient: <Alice's script hash>
              claimed_ckbytes: <1000 CKB>
  witness 10(otx #b): WitnessLayout format, OTX variant
    seals:
      0: SealPair format
        script_hash: Bob's script hash
        seal: <Signature for Bob>
    input_cells: 2
    output_cells: 2
    cell_deps: 0
    header_deps: 0
    message: Message format
      Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant
              bid_token: <DAI UDT type script hash>
              bid_amount: <1050 DAI>
              ask_token: <USDC UDT type script hash>
              ask_amount: <1000 USDC>
              recipient: <Bob's script hash>
              claimed_ckbytes: <200 CKB>
```

A hidden `New Order A` will also be created and stored off-chain:

```
bid_token: <USDC UDT type script hash>
bid_amount: <1000 USDC>
ask_token: <DAI UDT type script hash>
ask_amount: <1000 DAI>
recipient: <Alice's script hash>
claimed_ckbytes: <800 CKB>
```

Only `New Order A`'s hash will be stored on-chain(in the lock args of freestanding cell, or output #3 in the above example).

In this example, Alice's order (asking 2050 DAI for 2000 USDC) is only partially filled, Alice gets 1050 DAI in exchange for 1000 USDC from Bob's order. Dex1's OTX processor continues with the following action:

* A `New Order A` is created asking for 1000 DAI for 1000 USDC.
* A `freestanding cell`(output #3 in the above example) is created with reference to `New Order A`

The created `freestanding cell` can be unlocked in 2 ways:

1. Alice can unlock this cell, claim the CKBytes and included tokens back
2. The OTX processor will consider `freestanding cell` as orders just like OTX, and will use it in future order matching. For example, a later CKB transaction can continue to consume the above `freestanding cell`:

```yaml
inputs:
  input 0(otx #c):
    capacity: 200 CKB
    lock: Charlie
    type: DAI UDT type script
    data: <1100 DAI>
  input 1(otx #c):
    capacity: 7777 CKB
    lock: Charlie
    type: <EMPTY>
    data: <EMPTY>
  input 2(dex1 entity cell):
    capacity: 166 CKB
    lock: <always success>
    type: <dex1 entity script>
    data: <dex1 entity data>
  input 3(freestanding cell created above):
    capacity: 800 CKB
    lock:
      code_hash: <dex1 entity script>
      args: <dex1 entity cell type id> <Alice's script hash> <New Order A's hash>
    type: USDC UDT type script
    data: <1000 USDC>
  input 4(fee cell):
    capacity: 3000.11 CKB
    lock: OTX processor
    type: <EMPTY>
    data: <EMPTY>
outputs:
  output 0(otx #c):
    capacity: 200 CKB
    lock: Bob
    type: DAI UDT type script
    data: <100 DAI>
  output 1(otx #c):
    capacity: 7577 CKB
    lock: Charlie
    type: <EMPTY>
    data: <EMPTY>
  output 2(dex1 entity cell):
    capacity: 166 CKB
    lock: <always success>
    type: <dex1 entity script>
    data: <dex1 entity data>
  output 5(payment cell for otx #c):
    capacity: 200 CKB
    lock: Charlie
    type: USDC UDT type script
    data: <1000 USDC>
  output 5(payment cell for freestanding order):
    capacity: 800 CKB
    lock: Alice
    type: DAI UDT type script
    data: <1000 DAI>
  output 6(fee cell):
    capacity: 3000.10 CKB
    lock: OTX processor
    type: <EMPTY>
    data: <EMPTY>
witnesses:
  witness 0: <EMPTY>
  witness 1: <EMPTY>
  witness 2: <EMPTY>
  witness 3: <EMPTY>
  witness 5: WitnessArgs format
    lock: <Signature for fee cell>
  witness 5: <EMPTY>
  witness 6: <EMPTY>
  witness 7: WitnessLayout format, SighashAll variant
    message: Message format
      actions:
        Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant(New Order A)
              bid_token: <USDC UDT type script hash>
              bid_amount: <1000 USDC>
              ask_token: <DAI UDT type script hash>
              ask_amount: <1000 DAI>
              recipient: <Alice's script hash>
              claimed_ckbytes: <800 CKB>
  witness 8: WitnessLayout format, OtxStart variant
    start_input_cell: 0
    start_output_cell: 0
    start_cell_deps: 0
    start_header_deps: 0
  witness 10(otx #c): WitnessLayout format, OTX variant
    seals:
      0: SealPair format
        script_hash: Alice's script hash
        seal: <Signature for Charlie>
    input_cells: 2
    output_cells: 2
    cell_deps: 0
    header_deps: 0
    message: Message format
      Action 0:
        script_hash: <dex1 entity script hash>
        script_info_hash: <dex1 dapp info hash>
        data: Dex1Action format
          orders:
            0: Order format, LimitOrder variant
              bid_token: <DAI UDT type script hash>
              bid_amount: <1000 DAI>
              ask_token: <USDC UDT type script hash>
              ask_amount: <1000 USDC>
              recipient: <Charlie's script hash>
              claimed_ckbytes: <200 CKB>
```

In this new transaction, a freestanding cell is just treated as a normal OTX providing an order. The `New Order A` is inserted into Cobuild Action data of the dex1 entity script, and will be validated by the dex1 entity script to be the right order data. When this transaction is accepted, Alice's original order asking 2050 DAI for 2000 USDC, will then be completely fulfilled.

In terms of cell organization, freestanding cells add 2 rules:

* All consumed freestanding cells will immediately follow the dex1 entity input cell
* Payment cells for OTXs come first, payment cells for freestanding cells come later

Some might notice that due to CKBytes requirements, not all freestanding cells can be processed correctly, and this is totally expected behavior. A order's creator is in charge of deciding if his / her order can be partially fulfilled, and how many times it can be partiall fulfilled(more partial fulfillments would require more CKBytes).

# Code Structure

This repository contains a series of components required by a full dex1 setup:

* `schemas/dex1.mol`: molecule definitions of dex1 related data structures
* `dex-contracts/contracts/dex1`: the on-chain script for validating required dex logics on chain
* `offchain-modules/crates/dex1-assembler`: the actual open transaction assembler of dex1. This is the part that contains real dex1 logic, and should require a separate implementation for each individual cobuild OTX app. It contains 2 important constructs:
    + `Dex1`: the actual open transaction assembler. This struct is designed in a pure functional way, so the included, highly sophisticated logic could be easily tested. The structure of `Dex1` is highly inspired from Google's original [MapReduce](https://static.googleusercontent.com/media/research.google.com/en//archive/mapreduce-osdi04.pdf) prrogramming model: a `map` function parses and performs initial validation on open transactions from different users, valid ones are then **emitted**; a `reduce` function then aggregates multiple emitted open transactions, and assembles the CKB transaction as needed. A separate `postprocess` function is added due to OTX's property, but the general workflow still resembles a lot like the old MapReduce design. Personally I see a lot of similarites in the workflow of processing OTX, and MapReduce.
    + `Dex1Env`: a bridge between `Dex1` and a CKB node, it handles most of the boilerplates such as querying relavant cells, resolving inputs, signing transactions, etc. `Dev1Env` is splitted so `Dex1` can remain functional as it is now.
* `offchain-modules/crates/otx-traits`: Common trait definition. It is envisioned that all OTX apps would implement the common traits defined here, so we can abstract invididual apps via the traits defined here.
* `offchain-modules/crates/dex1-processor`: a driver to keep dex1 OTX assembler running. In fact, most of the code here are agnostic to invididual app logics. The processor merely manages OTXs and TXs, monitor all OutPoints for potential double spending(which is also the key for cancelling/updating OTXs), and keep the OTX assembler running. I personally do believe that in the future, a mature Cobuild OTX app structure can have one OTX processor running a series of independent OTX assemblers, each having different app logic. The processor merely deals with the common tasks that every OTX assembler would need.
* `offchain-modules/crates/dex1-helper`: a helper tool to make lifes easier testing and tinkering with dex1.

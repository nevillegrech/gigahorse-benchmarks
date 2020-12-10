# Gigahorse benchmarks

A collection of smart contracts in source and binary format, labelled with respective vulnerabilities.

Some of the contracts in this dataset have been derived from smartbugs, which in turn have been publically available and hence retain their original licences.

This benchmark repo is organized as follows:
| Path | Description |
| --- | --- |
| [invulnerable-bytecode](https://github.com/nevillegrech/gigahorse-benchmarks/tree/master/invulnerable-bytecode) | Contains a collection of popular compiled contract without known vulnerabilities |
| [vulnerable-bytecode](https://github.com/nevillegrech/gigahorse-benchmarks/tree/master/vulnerable-bytecode) | Contains a collection of compiled contracts with labelled vulnerabilities |
| [vulnerable-source](https://github.com/nevillegrech/gigahorse-benchmarks/tree/master/vulnerable-source) | Contains a collection of sources of contracts with labelled vulnerabilities |
| [labels.json](https://github.com/nevillegrech/gigahorse-benchmarks/tree/master/labels.json) | Machine-readable labels for all vulnerable contracts |


## Description

The naming conventions in the directories vulnerable-bytecode / vulnerable-source  are organized according to the [DASP taxonomy](https://dasp.co). Each class of vulnerability may include:

* Brief description of the vulnerability
* Attack scenarios to exploit the vulnerability
* Methods of mitigation
* Examples of real world exploitation

## More information about vulnerabilities

| Vulnerability | Description | Level |
| --- | --- | -- |
| [Reentrancy](reentrancy.md) | Reentrant function calls make a contract to behave in an unexpected way | Solidity |
| [Access Control](access_control.md) | Failure to use function modifiers or use of tx.origin | Solidity |
| [Arithmetic](arithmetic.md) | Integer over/underflows | Solidity |
| [Unchecked Low Level Calls](unchecked_low_level_calls.md) | call(), callcode(), delegatecall() or send() fails and it is not checked | Solidity |
| [Denial Of Service](denial_of_service.md) | The contract is overwhelmed with time-consuming computations | Solidity |
| [Bad Randomness](bad_randomness.md) | Malicious miner biases the outcome | Blockchain |
| [Front Running](front_running.md) | Two dependent transactions that invoke the same contract are included in one block | Blockchain |
| [Time Manipulation](time_manipulation.md) | The timestamp of the block is manipulated by the miner | Blockchain |
| [Short Addresses](short_addresses.md) | EVM itself accepts incorrectly padded arguments | EVM |

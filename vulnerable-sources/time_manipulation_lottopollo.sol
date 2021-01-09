/*
 * @source: https://github.com/seresistvanandras/EthBench/blob/master/Benchmark/Simple/timestampdependent.sol
 * @author: -
 * @vulnerable_at_lines: 13,27
 */

pragma solidity ^0.4.0;
contract lottopollo {
  address leader;
  uint    timestamp;
  function payOut(uint rand) internal {
    // <yes> <report> TIME MANIPULATION
    if ( rand > 0 && rand - timestamp > 24 hours ) {
      bool res1 = msg.sender.send( msg.value );
      require(res1);

      if ( this.balance > 0 ) {
        bool res2 = leader.send( this.balance );
        require(res2);
      }
    }
    else if ( msg.value >= 1 ether ) {
      leader = msg.sender;
      timestamp = rand;
    }
  }
  function randomGen() constant returns (uint randomNumber) {
      // <yes> <report> TIME MANIPULATION
      return block.timestamp;   
  }

  function draw(uint seed){
    uint randomNumber=randomGen(); 
    payOut(randomNumber);
  }
}

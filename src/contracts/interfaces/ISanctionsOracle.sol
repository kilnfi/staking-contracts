pragma solidity >=0.8.10;

interface ISanctionsOracle {
    function isSanctioned(address account) external returns (bool); 
}

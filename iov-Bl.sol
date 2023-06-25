pragma solidity ^0.4.25;

contract VehicleAuthentication {

  struct Vehicle {
    address owner;  
    bytes32 vin;
  }

  mapping (address => Vehicle) public vehicles;

  function registerVehicle(bytes32 _vin) public {
    vehicles[msg.sender] = Vehicle(msg.sender, _vin);  
  }

  function verifySignature(address _sender, bytes32 _dataHash, bytes signature) public view returns (bool) {
    bytes32 ethSignedMessageHash = keccak256(
      abi.encodePacked("\x19Ethereum Signed Message:\n32", _dataHash)
    );

    return _sender == ecrecover(ethSignedMessageHash, signature);  
  }

  function shareData(bytes32 _vin, bytes32 _dataHash, bytes signature) public {
    // Verify sender vehicle's signature    
    require(verifySignature(msg.sender, _dataHash, signature));

    // Get receiver vehicle from VIN
   Vehicle memory receiver = vehicles[_vin];
   require(receiver.owner != 0x0);  // Check vehicle exists

   // Emit data sharing event with sender and receiver
   DataShared(msg.sender, receiver.owner, _dataHash);    
}

}

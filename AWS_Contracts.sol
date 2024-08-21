// SPDX-License-Identifier: MIT
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

pragma solidity ^0.8.0;

// Manufacturer smart contract
contract ManufacturingCertification {
    // Define the structure to hold manufacturer details
    struct Manufacturer {
        string name;
        address manufacturerAddress;
        bool isApproved;
    }

    // Define the structure to hold compliance information
    struct ComplianceInformation {
        string awsId;
        bool isCompliant;
    }

    // Define certification status options
    enum CertificationStatus { NotCertified, Certified, NonCompliant }

    // Variables to store the certification status and compliance info
    CertificationStatus public certStatus;
    ComplianceInformation public complianceInfo;

    // Event declarations
    event AWSCertifiedSuccessfully(string awsId);
    event AWSCertificationFailed(string awsId);
    event UnauthorizedManufacturer(address manufacturerAddress);

    // Mapping to store registered manufacturers
    mapping(address => Manufacturer) public manufacturers;

    // Modifier to check if the manufacturer is approved
    modifier onlyApprovedManufacturer(address _manufacturerAddress) {
        require(manufacturers[_manufacturerAddress].isApproved, "Unauthorized Manufacturer");
        _;
    }

    // Function to register a manufacturer
    function registerManufacturer(string memory _name, address _manufacturerAddress) public {
        manufacturers[_manufacturerAddress] = Manufacturer({
            name: _name,
            manufacturerAddress: _manufacturerAddress,
            isApproved: true
        });
    }

    // Function to certify AWS
    function certifyAWS(address _manufacturerAddress, string memory _awsId, bool _isCompliant) 
        public 
        onlyApprovedManufacturer(_manufacturerAddress) 
    {
        // Set compliance information
        complianceInfo = ComplianceInformation({
            awsId: _awsId,
            isCompliant: _isCompliant
        });

        // Certification process
        if (_isCompliant) {
            certStatus = CertificationStatus.Certified;
            emit AWSCertifiedSuccessfully(_awsId);
        } else {
            certStatus = CertificationStatus.NonCompliant;
            emit AWSCertificationFailed(_awsId);
        }
    }

    // Function to reject unauthorized manufacturer
    function rejectCertification(address _manufacturerAddress) internal {
        emit UnauthorizedManufacturer(_manufacturerAddress);
    }
}

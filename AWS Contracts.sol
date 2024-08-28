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

// Ownership smart contract
contract OwnershipTransfer {
    // Define the structure to hold AWS details
    struct AWS {
        string awsId;
        address currentOwner;
    }

    // Define the structure to hold transfer conditions
    struct TransferConditions {
        bool regulatoryCompliant;
        string additionalConditions;
    }

    // Enum to represent the status of the transfer
    enum TransferStatus { NotTransferred, Transferred, FailedNonCompliant, FailedInvalidOwner }

    // Event declarations
    event OwnershipTransferSuccessful(string awsId, address indexed previousOwner, address indexed newOwner, string transferDate);
    event OwnershipTransferFailedNonCompliant(string awsId);
    event OwnershipTransferFailedInvalidOwner(string awsId);

    // Mapping to store AWS details
    mapping(string => AWS) public awsRegistry;

    // Function to register AWS
    function registerAWS(string memory _awsId, address _owner) public {
        awsRegistry[_awsId] = AWS({
            awsId: _awsId,
            currentOwner: _owner
        });
    }

    // Function to transfer ownership
    function transferOwnership(
        string memory _awsId,
        address _newOwner,
        string memory _transferDate,
        TransferConditions memory _transferConditions
    ) public returns (TransferStatus) {
        AWS storage aws = awsRegistry[_awsId];

        // Check if the sender is the current owner
        if (msg.sender == aws.currentOwner) {
            // Check if the transfer conditions meet regulatory compliance
            if (_transferConditions.regulatoryCompliant) {
                // Record the transfer details on the blockchain
                address previousOwner = aws.currentOwner;
                aws.currentOwner = _newOwner;

                emit OwnershipTransferSuccessful(_awsId, previousOwner, _newOwner, _transferDate);
                return TransferStatus.Transferred;
            } else {
                emit OwnershipTransferFailedNonCompliant(_awsId);
                return TransferStatus.FailedNonCompliant;
            }
        } else {
            emit OwnershipTransferFailedInvalidOwner(_awsId);
            return TransferStatus.FailedInvalidOwner;
        }
    }
}

// Deployment authorization smart contract
contract DeploymentAuthorization {
    // Define the structure to hold AWS details
    struct AWS {
        string awsId;
        string deploymentDetails;
    }

    // Define the structure to hold deployment conditions
    struct DeploymentConditions {
        bool regulatoryCompliant;
        bool governmentApproved;
    }

    // Enum to represent the status of the authorization
    enum AuthorizationStatus { NotRequested, Authorized, Denied, Rejected }

    // Event declarations
    event DeploymentAuthorizedSuccessfully(string awsId, string deploymentDetails);
    event DeploymentAuthorizationDenied(string awsId);
    event DeploymentAuthorizationRequestRejected(string awsId);

    // Mapping to store AWS details
    mapping(string => AWS) public awsRegistry;

    // Function to register AWS
    function registerAWS(string memory _awsId, string memory _deploymentDetails) public {
        awsRegistry[_awsId] = AWS({
            awsId: _awsId,
            deploymentDetails: _deploymentDetails
        });
    }

    // Function to authorize deployment
    function authorizeDeployment(
        string memory _awsId,
        DeploymentConditions memory _deploymentConditions,
        string memory _deploymentDetails
    ) public returns (AuthorizationStatus) {
        AWS storage aws = awsRegistry[_awsId];

        // Check if the Military Operator (MO) requests deployment authorization
        if (msg.sender != address(0)) {
            // Check if deployment conditions are compliant with government and regulatory standards
            if (_deploymentConditions.regulatoryCompliant && _deploymentConditions.governmentApproved) {
                // Record the deployment details and authorization status on the blockchain
                aws.deploymentDetails = _deploymentDetails;
                emit DeploymentAuthorizedSuccessfully(_awsId, _deploymentDetails);
                return AuthorizationStatus.Authorized;
            } else {
                emit DeploymentAuthorizationDenied(_awsId);
                return AuthorizationStatus.Denied;
            }
        } else {
            emit DeploymentAuthorizationRequestRejected(_awsId);
            return AuthorizationStatus.Rejected;
        }
    }
}

// Usage tracking smart contract
contract UsageTracking {
    // Define the structure to hold AWS usage details
    struct UsageLog {
        string awsId;
        string location;
        uint256 time;
        address operator;
        string actionDetails;
        bool compliant;
    }

    // Event declarations
    event UsageTrackedSuccessfully(string awsId, string location, uint256 time, address operator, string actionDetails);
    event UsageNonCompliant(string awsId, string location, uint256 time, address operator, string actionDetails);
    event NoDeploymentDetected(string awsId);

    // Mapping to store AWS usage logs
    mapping(string => UsageLog) public usageLogs;

    // Function to track usage of AWS
    function trackUsage(
        string memory _awsId,
        string memory _location,
        uint256 _time,
        address _operator,
        string memory _actionDetails,
        bool _deploymentStatus,
        bool _usageCompliant
    ) public {
        // Check if the AWS is deployed
        if (_deploymentStatus) {
            // Record usage details and compliance status
            UsageLog memory newLog = UsageLog({
                awsId: _awsId,
                location: _location,
                time: _time,
                operator: _operator,
                actionDetails: _actionDetails,
                compliant: _usageCompliant
            });
            
            // Store the usage log on the blockchain
            usageLogs[_awsId] = newLog;

            // Emit events based on compliance status
            if (_usageCompliant) {
                emit UsageTrackedSuccessfully(_awsId, _location, _time, _operator, _actionDetails);
            } else {
                emit UsageNonCompliant(_awsId, _location, _time, _operator, _actionDetails);
            }
        } else {
            // Emit event if AWS is not deployed
            emit NoDeploymentDetected(_awsId);
        }
    }
}

// Audit and compliance smart contract
contract AuditAndCompliance {
    using SafeMath for uint256; // Use SafeMath for uint256

    // Define the structure to hold compliance report details
    struct ComplianceReport {
        string awsId;
        bool compliant;
        string[] issues;
    }

    // Event declarations
    event ComplianceVerified(string awsId);
    event ComplianceFailed(string awsId, string[] issues);
    event AuditReportGenerated(string awsId, bool compliant, string[] issues);

    // Mapping to store compliance reports for each AWS
    mapping(string => ComplianceReport) public complianceReports;

    // Function to conduct an audit and generate a compliance report
    function conductAudit(
        string memory _awsId,
        string[] memory _logs,
        string[] memory _standards
    ) public {
        // Initialize an array to store identified issues
        string[] memory identifiedIssues;
        bool compliant = true;

        // Verify logs against compliance standards
        for (uint256 i = 0; i < _logs.length; i = i.add(1)) {
            require(i < _logs.length, "Index out of bounds");

            if (keccak256(abi.encodePacked(_logs[i])) != keccak256(abi.encodePacked(_standards[i]))) {
                compliant = false;
                identifiedIssues = append(identifiedIssues, _logs[i]);
            }
        }

        // Create and record the compliance report
        ComplianceReport memory report;
        report.awsId = _awsId;
        report.compliant = compliant;

        if (compliant) {
            emit ComplianceVerified(_awsId);
        } else {
            report.issues = identifiedIssues;
            emit ComplianceFailed(_awsId, identifiedIssues);
        }

        complianceReports[_awsId] = report;
    }

    // Function to generate an audit report based on the compliance report
    function generateAuditReport(string memory _awsId) public {
        // Retrieve the compliance report for the given AWS ID
        ComplianceReport memory report = complianceReports[_awsId];

        // Generate and store the audit report on the blockchain

        emit AuditReportGenerated(report.awsId, report.compliant, report.issues);
    }

    // Append issues to the array
    function append(string[] memory array, string memory item) internal pure returns (string[] memory) {
        string[] memory newArray = new string[](array.length.add(1));
        for (uint i = 0; i < array.length; i = i.add(1)) {
            require(i < array.length, "Index out of bounds");
            newArray[i] = array[i];
        }
        newArray[array.length] = item;
        return newArray;
    }
}

// Incident reporting smart contract
contract IncidentReporting {
    // Define the structure to hold incident details and resolution status
    struct Incident {
        string incidentId;
        string details;
        address reportedBy;
        string resStatus;
    }

    // Mapping to store incidents by their ID
    mapping(string => Incident) public incidents;

    // Event declarations
    event IncidentReported(string incidentId, string resStatus);
    event IncidentResolved(string incidentId, string resStatus);
    event IncidentReportRejected(string incidentId, string reason);

    // Function to report an incident
    function reportIncident(string memory _incidentId, string memory _details, address _reportedBy) public {
        // Check if the incident ID is valid (not empty and not already used)
        require(bytes(_incidentId).length > 0, "Invalid incident ID");
        require(bytes(incidents[_incidentId].incidentId).length == 0, "Incident ID already exists");

        // Log the incident on the blockchain
        incidents[_incidentId] = Incident({
            incidentId: _incidentId,
            details: _details,
            reportedBy: _reportedBy,
            resStatus: "Under Investigation"
        });

        // Notify regulatory body and inspectors for investigation
        emit IncidentReported(_incidentId, "Under Investigation");
    }

    // Function to resolve an incident
    function resolveIncident(string memory _incidentId, bool _resolved) public {
        // Check if the incident exists
        require(bytes(incidents[_incidentId].incidentId).length > 0, "Incident not found");

        if (_resolved) {
            // Update resolution status
            incidents[_incidentId].resStatus = "Resolved";
            emit IncidentResolved(_incidentId, "Resolved");
        } else {
            // Keep the status as "Under Investigation"
            emit IncidentReported(_incidentId, "Ongoing Investigation");
        }
    }

    // Function to reject an invalid incident report
    function rejectIncident(string memory _incidentId, string memory _reason) internal {
        emit IncidentReportRejected(_incidentId, _reason);
    }
}

// Disposal smart contract
contract DisposalSmartContract {

    enum DisposalStatus { Pending, Approved, Rejected, Compliant, NonCompliant, Completed }


    // Define the structure to hold disposal details
    struct DisposalRequest {
        uint256 id;
        address militaryOperator;
        address manufacturer;
        address government;
        address regulatoryBody;
        address auditor;
        DisposalStatus status;
        string approvalLog;
        string auditLog;
    }

    mapping(uint256 => DisposalRequest) public disposalRequests;

    event DisposalInitiated(uint256 indexed id, address indexed militaryOperator);
    event DisposalApproved(uint256 indexed id, address indexed government);
    event DisposalRejected(uint256 indexed id, address indexed government);
    event DisposalAudited(uint256 indexed id, DisposalStatus status, address indexed auditor);
    event DisposalFinalized(uint256 indexed id, address indexed manufacturer);

    modifier onlyMilitaryOperator(uint256 id) {
        require(msg.sender == disposalRequests[id].militaryOperator, "Not authorized: Military Operator");
        _;
    }

    modifier onlyGovernment(uint256 id) {
        require(msg.sender == disposalRequests[id].government, "Not authorized: Government");
        _;
    }

    modifier onlyAuditor(uint256 id) {
        require(msg.sender == disposalRequests[id].auditor, "Not authorized: Auditor");
        _;
    }

    modifier onlyManufacturer(uint256 id) {
        require(msg.sender == disposalRequests[id].manufacturer, "Not authorized: Manufacturer");
        _;
    }
    // Initiate the disposal request
    function initiateDisposal(uint256 id) public {
        DisposalRequest storage request = disposalRequests[id];
        request.militaryOperator = msg.sender;
        request.status = DisposalStatus.Pending;
        emit DisposalInitiated(id, msg.sender);
    }

    // Disposal approve function
    function approveDisposal(uint256 id) public onlyGovernment(id) {
        DisposalRequest storage request = disposalRequests[id];
        if (request.status == DisposalStatus.Pending) {
            request.status = DisposalStatus.Approved;
            request.approvalLog = "Disposal approved by Government.";
            emit DisposalApproved(id, msg.sender);
        } else {
            request.status = DisposalStatus.Rejected;
            request.approvalLog = "Disposal rejected by Government.";
            emit DisposalRejected(id, msg.sender);
        }
    }

    // Update audit details
    function conductAudit(uint256 id, bool compliant) public onlyAuditor(id) {
        DisposalRequest storage request = disposalRequests[id];
        if (request.status == DisposalStatus.Approved) {
            // Check the complaint status
            if (isCompliant) {
                request.status = DisposalStatus.Compliant;
                request.auditLog = "Disposal process is compliant.";
                emit DisposalAudited(id, DisposalStatus.Compliant, msg.sender);
            } else {
                request.status = DisposalStatus.NonCompliant;
                request.auditLog = "Disposal process is non-compliant.";
                emit DisposalAudited(id, DisposalStatus.NonCompliant, msg.sender);
            }
        }
    }
    // Finalize the disposal
    function finalizeDisposal(uint256 id) public onlyManufacturer(id) {
        DisposalRequest storage request = disposalRequests[id];
        require(request.status == DisposalStatus.Compliant, "Cannot finalize: Non-compliant or unapproved disposal.");
        request.status = DisposalStatus.Completed;
        emit DisposalFinalized(id, msg.sender);
    }
}


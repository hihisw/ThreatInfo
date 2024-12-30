// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title ThreatInfo - Threat Report Management Contract with Enhanced Features
/// @notice Manages threat reports with whitelisting and role-based controls
contract ThreatInfo {
    uint8 private constant MIN_THREAT_LEVEL = 1;
    uint8 private constant MAX_THREAT_LEVEL = 3;

    address public immutable owner;

    struct Threat {
        address reporter;
        string description;
        uint8 level;
        uint32 timestamp;
        bool isDeleted;
    }

    mapping(address => bool) public whitelist;
    mapping(address => bool) public auditors;
    mapping(uint256 => Threat) public threats;
    mapping(address => uint32) public userLastReportTime;
    mapping(address => uint16) public userReportCountInWindow;

    uint256 public threatCount;
    uint32 public reportWindow;
    uint16 public maxReportsPerWindow;

    event ThreatReported(uint256 indexed threatId, address indexed reporter, uint8 level, uint32 timestamp);
    event ThreatUpdated(uint256 indexed threatId, string newDescription, uint8 newLevel);
    event ThreatDeleted(uint256 indexed threatId);
    event WhitelistUpdated(address indexed account, bool status);
    event AuditorUpdated(address indexed account, bool status);
    event WindowConfigUpdated(uint32 newWindow, uint16 newMaxReports);

    error NotOwner();
    error NotWhitelisted(address reporter);
    error ExceededMaxReportsPerWindow(address reporter);
    error InvalidThreatLevel(uint8 level);
    error EmptyDescription();
    error InvalidWindowConfig();
    error NotAuthorized();

    constructor(uint16 _maxReportsPerWindow, uint32 _reportWindow) {
        if (_reportWindow == 0 || _maxReportsPerWindow == 0) revert InvalidWindowConfig();

        owner = msg.sender;
        maxReportsPerWindow = _maxReportsPerWindow;
        reportWindow = _reportWindow;
        whitelist[msg.sender] = true;

        emit WhitelistUpdated(msg.sender, true);
        emit WindowConfigUpdated(_reportWindow, _maxReportsPerWindow);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyAuditor() {
        if (!auditors[msg.sender]) revert NotAuthorized();
        _;
    }

    function updateWhitelist(address _address, bool _status) external onlyOwner {
        whitelist[_address] = _status;
        emit WhitelistUpdated(_address, _status);
    }

    function updateAuditor(address _address, bool _status) external onlyOwner {
        auditors[_address] = _status;
        emit AuditorUpdated(_address, _status);
    }

    function reportThreat(string calldata _description, uint8 _level) external {
        if (!whitelist[msg.sender]) revert NotWhitelisted(msg.sender);
        if (_level < MIN_THREAT_LEVEL || _level > MAX_THREAT_LEVEL) revert InvalidThreatLevel(_level);
        if (bytes(_description).length == 0) revert EmptyDescription();

        uint32 currentTime = uint32(block.timestamp);
        uint32 lastReportTime = userLastReportTime[msg.sender];

        if (currentTime - lastReportTime > reportWindow) {
            userReportCountInWindow[msg.sender] = 0;
        }

        if (userReportCountInWindow[msg.sender] >= maxReportsPerWindow) {
            revert ExceededMaxReportsPerWindow(msg.sender);
        }

        unchecked {
            userReportCountInWindow[msg.sender]++;
        }

        userLastReportTime[msg.sender] = currentTime;

        uint256 newThreatId = threatCount;
        threats[newThreatId] = Threat({
            reporter: msg.sender,
            description: _description,
            level: _level,
            timestamp: currentTime,
            isDeleted: false
        });

        emit ThreatReported(newThreatId, msg.sender, _level, currentTime);

        unchecked {
            threatCount++;
        }
    }

    function updateThreat(uint256 _threatId, string calldata _description, uint8 _level) external {
        Threat storage threat = threats[_threatId];
        if (msg.sender != threat.reporter) revert NotAuthorized();
        if (threat.isDeleted) revert("Threat already deleted");
        if (_level < MIN_THREAT_LEVEL || _level > MAX_THREAT_LEVEL) revert InvalidThreatLevel(_level);
        if (bytes(_description).length == 0) revert EmptyDescription();

        threat.description = _description;
        threat.level = _level;

        emit ThreatUpdated(_threatId, _description, _level);
    }

    function deleteThreat(uint256 _threatId) external {
        Threat storage threat = threats[_threatId];
        if (msg.sender != threat.reporter && msg.sender != owner) revert NotAuthorized();
        if (threat.isDeleted) revert("Threat already deleted");

        threat.isDeleted = true;
        emit ThreatDeleted(_threatId);
    }

    function getThreats(uint256 start, uint256 count) external view returns (Threat[] memory) {
        uint256 end = start + count;
        if (end > threatCount) end = threatCount;
        Threat[] memory result = new Threat[](end - start);
        for (uint256 i = start; i < end; i++) {
            result[i - start] = threats[i];
        }
        return result;
    }

    function updateReportWindow(uint32 _newWindow) external onlyOwner {
        if (_newWindow == 0) revert InvalidWindowConfig();
        reportWindow = _newWindow;
        emit WindowConfigUpdated(_newWindow, maxReportsPerWindow);
    }

    function updateMaxReportsPerWindow(uint16 _newMaxReports) external onlyOwner {
        if (_newMaxReports == 0) revert InvalidWindowConfig();
        maxReportsPerWindow = _newMaxReports;
        emit WindowConfigUpdated(reportWindow, _newMaxReports);
    }

    function markThreatResolved(uint256 _threatId) external onlyAuditor {
        Threat storage threat = threats[_threatId];
        if (threat.isDeleted) revert("Threat already deleted");

        threat.isDeleted = true;
        emit ThreatDeleted(_threatId);
    }
}

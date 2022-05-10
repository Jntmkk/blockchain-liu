pragma solidity >=0.8.0;

contract Cert {
    enum CertStatus {
        Issued,
        Uploaded,
        Cancelled
    }
    struct CertInfo {
        address owner;
        address issuer;
        bytes32 root;
        CertStatus state;
    }

    struct CaInfo {
        string pk;
        string describe;
        bool isValide;
    }
    //变量定义
    //合约管理者地址
    address[] Mannager;
    //CA发布的证书(ca地址=>(证书id=>接受者地址))
    mapping(address => bytes32[]) public caIssued;
    //接受者收到的证书(接受者地址=>证书id=>ca地址)
    mapping(address => bytes32[]) public userReceived;
    // 证书状态
    mapping(bytes32 => CertInfo) certs;
    //上链证书密文
    mapping(bytes32 => string) public loadedCert;
    //上链证书哈希
    mapping(bytes32 => bytes32) public certHash;
    //已注册的Ca地址
    mapping(address => CaInfo) public registeredCa;
    // 上链服务列表
    mapping(bytes32 => uint256) uploadTask;
    //更新服务列表
    mapping(bytes32 => uint256) updateTask;

    //事件定义
    event issueEvent(
        address from,
        bytes32[] certid,
        address[] receiver,
        bytes32 root
    );
    event revokeEvent(address owner, bytes32 certid);
    event uploadEvent(bytes32 certid);
    event updateEvent(bytes32 certid);
    event requestUploadEvent(address owner, bytes32 certid);
    event requestUpdateEvent(address owner, bytes32 certid);
    event caRegisterEvent(address ca);
    event caAuthEvent(address, string pk);
    event downloadEvent(address owner, bytes32 certid, string cert);

    //访问控制
    modifier certIssued(bytes32 certid) {
        require(certs[certid].state == CertStatus.Issued, "not expected stage");
        _;
    }

    modifier certUpload(bytes32 certid) {
        require(
            certs[certid].state == CertStatus.Uploaded,
            "not expected stage"
        );
        _;
    }

    constructor(address[] memory _mannagers) public {
        Mannager = _mannagers;
    }

    //合约函数
    //发布证书：将证书id和证书发布者以及证书所有者进行绑定，并将merkle的根哈希记录到区块链中
    function issueCertificates(
        bytes32[] calldata certid,
        address[] calldata receiver,
        bytes32 _root
    ) public {
        require(registeredCa[msg.sender].isValide, "CA has no authority");
        uint256 certid_nums = certid.length;
        uint256 user_nums = receiver.length;
        require(
            certid_nums == user_nums,
            "cert number is not equal to receiver number"
        );
        for (uint256 i = 0; i < certid_nums; i++) {
            bytes32 Certid = certid[i];
            address _owner = receiver[i];
            caIssued[msg.sender].push(Certid);
            userReceived[_owner].push(Certid);
            certs[Certid] = CertInfo({
                owner: _owner,
                issuer: msg.sender,
                root: _root,
                state: CertStatus.Issued
            });
        }
        emit issueEvent(msg.sender, certid, receiver, _root);
    }

    //ca撤销证书
    function revokeCertificates(bytes32 certid) public {
        require(
            msg.sender == certs[certid].issuer,
            "CA has no auth for the cert"
        );
        CertStatus state = certs[certid].state;
        if (state == CertStatus.Issued || state == CertStatus.Uploaded) {
            certs[certid].state = CertStatus.Cancelled;
        }
        emit revokeEvent(certs[certid].issuer, certid);
    }

    //ca注册
    function caRegister(string calldata info, string calldata _pk) public {
        require(!registeredCa[msg.sender].isValide, "Ca has already register");
        registeredCa[msg.sender] = CaInfo({
            pk: _pk,
            describe: info,
            isValide: false
        });
        emit caRegisterEvent(msg.sender);
    }

    //ca授权
    function caAuth(address ca) public {
        require(!registeredCa[msg.sender].isValide, "Ca has already register");
        registeredCa[ca].isValide = true;
        emit caAuthEvent(msg.sender, registeredCa[ca].pk);
    }

    //数字证书上链请求
    function requestForUpload(bytes32 certid) public {
        CertInfo storage info = certs[certid];
        require(
            (info.owner == msg.sender && info.state == CertStatus.Issued),
            "the user has no auth"
        );
        uploadTask[certid] = 1;
        emit requestUploadEvent(msg.sender, certid);
    }

    //数字证书更新请求
    function requestForUpdate(bytes32 certid) public {
        CertInfo storage info = certs[certid];
        require(
            (info.owner == msg.sender && info.state == CertStatus.Uploaded),
            "the user has no auth"
        );
        updateTask[certid] = 1;
        emit requestUpdateEvent(msg.sender, certid);
    }

    //数字证书上链
    function uploadCertificate(
        bytes32 certid,
        string calldata context,
        bytes32 digest
    ) public {
        require(uploadTask[certid] == 1, "uploadCert wrong");
        uploadTask[certid] = 0;
        loadedCert[certid] = context;
        certHash[certid] = digest;
        emit uploadEvent(certid);
    }

    //数字证书更新
    function updateCertificate(
        bytes32 certid,
        string calldata context,
        bytes32 digest
    ) public {
        require(updateTask[certid] == 1, "uploadCert wrong");
        updateTask[certid] = 0;
        loadedCert[certid] = context;
        certHash[certid] = digest;
        emit updateEvent(certid);
    }

    //链上证书密文查询与下载
    function downloadCertificate(bytes32 certid) public {
        require(
            certs[certid].owner == msg.sender &&
                certs[certid].state == CertStatus.Uploaded,
            "uploadCert wrong"
        );
        emit downloadEvent(msg.sender, certid, loadedCert[certid]);
    }
}

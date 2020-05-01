## Distro

macOS 10.15.4


## GSSAPI Impl

Kerberos 5 release 1.7-prerelease (Heimdal)


## Connection Info:

Connecting to host using FQDN with an invalid SPN `http@test`. Using explicit creds with the oid NTLM. Cannot seem to
get credentials for the SPNEGO OID.


## Notes

* This fails to authenticate with a Windows host with an invalid token error
* The error in the security event log is

```
An account failed to log on.

Subject:
	Security ID:		NULL SID
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		NULL SID
	Account Name:		vagrant-domain
	Account Domain:		DOMAIN.LOCAL

Failure Information:
	Failure Reason:		An Error occured during Logon.
	Status:			0x80090308   # SEC_E_INVALID_TOKEN
	Sub Status:		0x0

Process Information:
	Caller Process ID:	0x0
	Caller Process Name:	-

Network Information:
	Workstation Name:	JBOREAN-OSX
	Source Network Address:	-
	Source Port:		-

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon request fails. It is generated on the computer where access was attempted.

The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).

The Process Information fields indicate which account and process on the system requested the logon.

The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The authentication information fields provide detailed information about this specific logon request.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
```

* Will need to check a few things but IIRC the NTProofStr and MIC were actually calculated correctly
* Even if the user was `vagrant-domain@DOMAIN` or `DOMAIN\vagrant-domain` it will fail with the same error


## Tokens

```yaml
MessageType: NtlmNegotiate (1)
Signature: "NTLMSSP\0"
Data:
  NegotiateFlagsRaw: 1653080581
  NegotiateFlags:
  - NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)
  - NTLMSSP_NEGOTIATE_128 (536870912)
  - NTLMSSP_NEGOTIATE_VERSION (33554432)
  - NTLMSSP_NEGOTIATE_TARGET_INFO (8388608)
  - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)
  - NTLMSSP_NEGOTIATE_NTLM (512)
  - NTLMSSP_REQUEST_TARGET (4)
  - NTLMSSP_NEGOTIATE_UNICODE (1)
  DomainName:
  Workstation:
  Version:
    Major: 6
    Minor: 1
    Build: 7600
    NTLMRevision: 0
RawData: 4E544C4D535350000100000005028862000000000000000000000000000000000601B01D0F000000
```

```yaml
MessageType: NtlmChallenge (2)
Signature: "NTLMSSP\0"
Data:
  NegotiateFlagsRaw: 1653146117
  NegotiateFlags:
  - NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)
  - NTLMSSP_NEGOTIATE_128 (536870912)
  - NTLMSSP_NEGOTIATE_VERSION (33554432)
  - NTLMSSP_NEGOTIATE_TARGET_INFO (8388608)
  - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)
  - NTLMSSP_TARGET_TYPE_DOMAIN (65536)
  - NTLMSSP_NEGOTIATE_NTLM (512)
  - NTLMSSP_REQUEST_TARGET (4)
  - NTLMSSP_NEGOTIATE_UNICODE (1)
  TargetName: DOMAIN
  ServerChallenge: 4A16FA1A20160E80
  Reserved: '0000000000000000'
  TargetInfo:
  - AvId: MSV_AV_NB_DOMAIN_NAME (2)
    Value: DOMAIN
  - AvId: MSV_AV_NB_COMPUTER_NAME (1)
    Value: SERVER2019
  - AvId: MSV_AV_DNS_DOMAIN_NAME (4)
    Value: domain.local
  - AvId: MSV_AV_DNS_COMPUTER_NAME (3)
    Value: SERVER2019.domain.local
  - AvId: MSV_AV_DNS_TREE_NAME (5)
    Value: domain.local
  - AvId: MSV_AV_TIMESTAMP (7)
    Value: '2020-04-30T19:04:55.627728'
  - AvId: MSV_AV_EOL (0)
    Value:
  Version:
    Major: 10
    Minor: 0
    Build: 17763
    NTLMRevision: 15
RawData: 4E544C4D53535000020000000C000C0038000000050289624A16FA1A20160E800000000000000000A200A200440000000A0063450000000F44004F004D00410049004E0002000C0044004F004D00410049004E000100140053004500520056004500520032003000310039000400180064006F006D00610069006E002E006C006F00630061006C0003002E0053004500520056004500520032003000310039002E0064006F006D00610069006E002E006C006F00630061006C000500180064006F006D00610069006E002E006C006F00630061006C00070008001DEE5F3C221FD60100000000
```

```yaml
MessageType: NtlmAuthenticate (3)
Signature: "NTLMSSP\0"
Data:
  NegotiateFlagsRaw: 1653080581
  NegotiateFlags:
  - NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)
  - NTLMSSP_NEGOTIATE_128 (536870912)
  - NTLMSSP_NEGOTIATE_VERSION (33554432)
  - NTLMSSP_NEGOTIATE_TARGET_INFO (8388608)
  - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)
  - NTLMSSP_NEGOTIATE_NTLM (512)
  - NTLMSSP_REQUEST_TARGET (4)
  - NTLMSSP_NEGOTIATE_UNICODE (1)
  LmChallengeResponse:
    ResponseType: LMv1
    LMProofStr:
    - '000000000000000000000000000000000000000000000000'
  NtChallengeResponse:
    ResponseType: NTLMv2
    NTProofStr:
    - B225C3CCD6D6AD526A4624A2342B319E
    ClientChallenge:
      RespType: 1
      HiRespType: 1
      Reserved1: 0
      Reserved2: 0
      TimeStamp: '2020-04-30T19:05:57'
      ChallengeFromClient: 3442FEE968D48AE3
      Reserved3: 0
      AvPairs:
      - AvId: MSV_AV_NB_COMPUTER_NAME (1)
        Value: SERVER2019
      - AvId: MSV_AV_NB_DOMAIN_NAME (2)
        Value: DOMAIN
      - AvId: MSV_AV_DNS_COMPUTER_NAME (3)
        Value: SERVER2019.domain.local
      - AvId: MSV_AV_DNS_DOMAIN_NAME (4)
        Value: domain.local
      - AvId: MSV_AV_DNS_TREE_NAME (5)
        Value: domain.local
      - AvId: MSV_AV_FLAGS (6)
        Value:
        - MIC_PROVIDED (2)
      - AvId: MSV_AV_TIMESTAMP (7)
        Value: '2020-04-30T19:04:55.627728'
      - AvId: MSV_AV_TARGET_NAME (9)
        Value: http/test
      - AvId: MSV_AV_CHANNEL_BINDINGS (10)
        Value: '00000000000000000000000000000000'
      - AvId: MSV_AV_EOL (0)
        Value:
      Reserved4: 0
  DomainName: DOMAIN.LOCAL
  UserName: vagrant-domain
  Workstation: JBOREAN-OSX
  EncryptedRandomSessionKey: 1DE89553B73834ABDFE761A306A00E0C
  Version:
    Major: 6
    Minor: 1
    Build: 7600
    NTLMRevision: 0
  MIC: 79DFC3EE99849A8EB6B02FF50A2C4847
  SessionKey: Failed to derive
RawData: 4E544C4D535350000300000018001800A200000004010401BA00000018001800580000001C001C0070000000160016008C00000010001000BE010000050288620601B01D0F00000079DFC3EE99849A8EB6B02FF50A2C484744004F004D00410049004E002E004C004F00430041004C00760061006700720061006E0074002D0064006F006D00610069006E004A0042004F005200450041004E002D004F0053005800000000000000000000000000000000000000000000000000B225C3CCD6D6AD526A4624A2342B319E01010000000000008098F460221FD6013442FEE968D48AE30000000001001400530045005200560045005200320030003100390002000C0044004F004D00410049004E0003002E0053004500520056004500520032003000310039002E0064006F006D00610069006E002E006C006F00630061006C000400180064006F006D00610069006E002E006C006F00630061006C000500180064006F006D00610069006E002E006C006F00630061006C000600040002000000070008001DEE5F3C221FD6010900120068007400740070002F0074006500730074000A0010000000000000000000000000000000000000000000000000001DE89553B73834ABDFE761A306A00E0C
```
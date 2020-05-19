## Distro

Centos 8


## GSSAPI Impl

heimdal 7.7.0


## Connection Info:

Connecting to host using FQDN with an invalid. Using cached credentials from `NTLM_USER_FILE` with the NTLM OID.


## Notes

* The `DomainName` field is UTF-16 encoded when it should be OEM encoded, not critical but it is a bug
* The offset for `DomainName` is also incorrect, it's 8 bytes off due to it missing the length of the Workstation fields
* I haven't tested getting the session key or encryption yet but definitely should look into it
* The NT challenge response is an NTLMv1 message with extended session security. It also includes the LM challenge response which is not good
* Even if I could get it working with explicit credentials I don't think I should due to the weakness of the NT proof string
* Looking at the code it looks like it should be possible but for some reason it's not using NTLM v2 messages


## Tokens

```yaml
MessageType: NtlmNegotiate (1)
Signature: "NTLMSSP\0"
Data:
  NegotiateFlags:
    raw: 1074303489
    flags:
    - NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)
    - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)
    - NTLMSSP_NEGOTIATE_ALWAYS_SIGN (32768)
    - NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED (4096)
    - NTLMSSP_NEGOTIATE_NTLM (512)
    - NTLMSSP_NEGOTIATE_UNICODE (1)
  DomainNameFields:
    Len: 8
    MaxLen: 8
    BufferOffset: 24
  WorkstationFields:
    Len: 0
    MaxLen: 0
    BufferOffset: 0
  Version:
  Payload:
    DomainName: "\0\0\0\0\0\0\0\0"
    Workstation:
RawData: 4E544C4D535350000100000001920840080008001800000000000000000000005400450053005400
```

```yaml
MessageType: NtlmChallenge (2)
Signature: "NTLMSSP\0"
Data:
  TargetNameFields:
    Len: 12
    MaxLen: 12
    BufferOffset: 56
  NegotiateFlags:
    raw: 1116307973
    flags:
    - NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)
    - NTLMSSP_NEGOTIATE_VERSION (33554432)
    - NTLMSSP_NEGOTIATE_TARGET_INFO (8388608)
    - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)
    - NTLMSSP_TARGET_TYPE_DOMAIN (65536)
    - NTLMSSP_NEGOTIATE_ALWAYS_SIGN (32768)
    - NTLMSSP_NEGOTIATE_NTLM (512)
    - NTLMSSP_REQUEST_TARGET (4)
    - NTLMSSP_NEGOTIATE_UNICODE (1)
  ServerChallenge: 3124420FFA4EAC70
  Reserved: '0000000000000000'
  TargetInfoFields:
    Len: 138
    MaxLen: 138
    BufferOffset: 68
  Version:
    Major: 10
    Minor: 0
    Build: 14393
    Reserved: '000000'
    NTLMRevision: 15
  Payload:
    TargetName: DOMAIN
    TargetInfo:
    - AvId: MSV_AV_NB_DOMAIN_NAME (2)
      Value: DOMAIN
    - AvId: MSV_AV_NB_COMPUTER_NAME (1)
      Value: DC01
    - AvId: MSV_AV_DNS_DOMAIN_NAME (4)
      Value: domain.local
    - AvId: MSV_AV_DNS_COMPUTER_NAME (3)
      Value: DC01.domain.local
    - AvId: MSV_AV_DNS_TREE_NAME (5)
      Value: domain.local
    - AvId: MSV_AV_TIMESTAMP (7)
      Value: '2020-04-30T05:18:12.2734597Z'
    - AvId: MSV_AV_EOL (0)
      Value:
RawData: 4E544C4D53535000020000000C000C0038000000058289423124420FFA4EAC7000000000000000008A008A00440000000A0039380000000F44004F004D00410049004E0002000C0044004F004D00410049004E000100080044004300300031000400180064006F006D00610069006E002E006C006F00630061006C000300220044004300300031002E0064006F006D00610069006E002E006C006F00630061006C000500180064006F006D00610069006E002E006C006F00630061006C000700080005BC78BEAE1ED60100000000
```

```yaml
MessageType: NtlmAuthenticate (3)
Signature: "NTLMSSP\0"
Data:
  LmChallengeResponseFields:
    Len: 24
    MaxLen: 24
    BufferOffset: 134
  NtChallengeResponseFields:
    Len: 24
    MaxLen: 24
    BufferOffset: 158
  DomainNameFields:
    Len: 12
    MaxLen: 12
    BufferOffset: 72
  UserNameFields:
    Len: 28
    MaxLen: 28
    BufferOffset: 84
  WorkstationFields:
    Len: 22
    MaxLen: 22
    BufferOffset: 112
  EncryptedRandomSessionKeyFields:
    Len: 16
    MaxLen: 16
    BufferOffset: 182
  NegotiateFlags:
    raw: 1116307973
    flags:
    - NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)
    - NTLMSSP_NEGOTIATE_VERSION (33554432)
    - NTLMSSP_NEGOTIATE_TARGET_INFO (8388608)
    - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)
    - NTLMSSP_TARGET_TYPE_DOMAIN (65536)
    - NTLMSSP_NEGOTIATE_ALWAYS_SIGN (32768)
    - NTLMSSP_NEGOTIATE_NTLM (512)
    - NTLMSSP_REQUEST_TARGET (4)
    - NTLMSSP_NEGOTIATE_UNICODE (1)
  Version:
    Major: 6
    Minor: 1
    Build: 7600
    Reserved: 0F0000
    NTLMRevision: 0
  MIC:
  Payload:
    LmChallengeResponse:
      ResponseType: LMv1
      LMProofStr: F60C80F30CC7F7A100000000000000000000000000000000
    NtChallengeResponse:
      ResponseType: NTLMv1
      NTProofStr: 0E32499AF8302C49FF7614C2211CE6F3E82B61E32B445D33
    DomainName: DOMAIN
    UserName: vagrant-domain
    Workstation: workstation
    EncryptedRandomSessionKey: 42E2F5AC55AB4F867790D51D902973E0
  SessionKey: Failed to derive
RawData: 4E544C4D53535000030000001800180086000000180018009E0000000C000C00480000001C001C0054000000160016007000000010001000B6000000058289420601B01D0F00000044004F004D00410049004E00760061006700720061006E0074002D0064006F006D00610069006E0077006F0072006B00730074006100740069006F006E00F60C80F30CC7F7A1000000000000000000000000000000000E32499AF8302C49FF7614C2211CE6F3E82B61E32B445D3342E2F5AC55AB4F867790D51D902973E0
```
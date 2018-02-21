from enum import Enum, unique
from struct import pack, unpack


# EAP codes
# http://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-1

@unique
class EAPCode(Enum):
    EAP_REQUEST  = 1
    EAP_RESPONE  = 2
    EAP_SUCCESS  = 3
    EAP_FAILURE  = 4
    EAP_INITIATE = 5
    EAP_FINISH   = 6


# EAP methods types
# http://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-4

@unique
class EAPType(Enum):
    IDENTITY                                     = 1
    NOTIFICATION                                 = 2
    LEGACY_NAK                                   = 3
    MD5_CHALLENGE                                = 4
    EAP_OTP                                      = 5
    EAP_GTC                                      = 6
    RSA_PUBLIC_KEY_AUTHENTICATION                = 9
    DSS_UNILATERAL                               = 10
    KEA                                          = 11
    KEA_VALIDATE                                 = 12
    EAP_TLS                                      = 13
    AXENT_DEFENDER_TOKEN                         = 14
    RSA_SECURITY_SECURID_EAP                     = 15
    ARCOT_SYSTEMS_EAP                            = 16
    EAP_CISCO_WIRELESS                           = 17
    EAP_SIM                                      = 18
    SRP_SHA1                                     = 19
    EAP_TTLS                                     = 21
    REMOTE_ACCESS_SERVICE                        = 22
    EAP_AKA_AUTHENTICATION                       = 23
    EAP_3COM_WIRELESS                            = 24
    PEAP                                         = 25
    MS_EAP_AUTHENTICATION                        = 26
    MUTUAL_AUTHENTICATION_KEY_EXCHANGE           = 27
    CRYPTOCARD                                   = 28
    EAP_MSCHAP_V2                                = 29
    DYNAMID                                      = 30
    ROB_EAP                                      = 31
    PROTECTED_ONE_TIME_PASSWORD                  = 32
    MS_AUTHENTICATION_TLV                        = 33
    SENTRINET                                    = 34
    EAP_ACTIONTEC_WIRELESS                       = 35
    COGENT_SYSTEMS_BIOMETRICS_AUTHENTICATION_EAP = 36
    AIRFORTRESS_EAP                              = 37
    EAP_HTTP_DIGEST                              = 38
    SECURESUITE_EAP                              = 39
    DEVICECONNECT_EAP                            = 40
    EAP_SPEKE                                    = 41
    EAP_MOBAC                                    = 42
    EAP_FAST                                     = 43
    ZONELABS_EAP                                 = 44
    EAP_LINK                                     = 45
    EAP_PAX                                      = 46
    EAP_PSK                                      = 47
    EAP_SAKE                                     = 48
    EAP_IKEV2                                    = 49
    EAP_AKA                                      = 50
    EAP_GPSK                                     = 51
    EAP_PWD                                      = 52
    EAP_EKE_VERSION_1                            = 53
    EAP_METHOD_TYPE_FOR_PT_EAP                   = 54
    TEAP                                         = 55
    EXPANDED_TYPE                                = 254
    EXPERIMENTAL                                 = 255


class EAPPacket():
    @staticmethod
    def Parse(packet_raw):
        ret = {
            "packet_raw": packet_raw,
            "parsed": True
        }
        
        if len(packet_raw) < 4:
            ret["parsed"] = False
            return
        
        ret["eap_code"] = unpack('B', packet_raw[0])[0]
        ret["eap_id"]   = unpack('B', packet_raw[1])[0]
        ret["length"]   = len(packet_raw)
        ret["real_length"] = unpack('>H', packet_raw[2:4])[0]
        
        if len(packet_raw) >= 5:
            ret["eap_type"] = unpack('B', packet_raw[4])[0]
        else:
            ret["eap_type"] = None

        ret["body"] = packet_raw[6:]

        return ret

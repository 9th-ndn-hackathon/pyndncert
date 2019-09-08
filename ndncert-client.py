import sys, time, json
from base64 import b64decode, b64encode

from pyndn import Name
from pyndn import Blob
from pyndn import Face
from pyndn import Interest
from pyndn.util.common import Common
from pyndn.security.verification_helpers import VerificationHelpers
from pyndn.security.v2 import CertificateV2
from pyndn.security import KeyChain
from pyndn.security.signing_info import SigningInfo
from pyndn.validity_period import ValidityPeriod
from pyndn.meta_info import ContentType
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
from pyndn.encoding.tlv_0_2_wire_format import Tlv0_2WireFormat

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
#from cryptography.fernet import Fernet  # Uses AES CBC w/ 128 bit key, PKCS7 padding

from Crypto import Random
from Crypto.Cipher import AES

class ECDHState():
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.derived_key = None

    def getBase64PubKey(self):
        pub_key = self.private_key.public_key()
        return b64encode(pub_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)).decode("utf-8")

class ClientModule():
    def __init__(self, caPrefix):
        self.ecdh = ECDHState()
        self.face = Face()
        self.keyChain = KeyChain()
        self.key = None
        self.caPrefix = caPrefix
        self.anchor = CertificateV2()
        self.anchor.wireDecode(Blob(b64decode("Bv0DgQc7CANuZG4IA2VkdQgHbWVtcGhpcwgIYWdhd2FuZGUIA0tFWQgIo6cuGT4GVKEIAk5BCAn9AAABbQxT3hEUCRgBAhkEADbugBX9ASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDII1sLOE7cCQVTKoGjeM5o/mxWqhMx0siLHJ81Ee/eUCNAMxA0w1oxAoTGQ8HbNP3vShZfvMJ/11Jiqus2wAWlNjRWvQShNv5MueU8kYtOGTbiqr/I1EpSRQ2aJX3s49CoskoWMzf6knK4ELleH3/EBUPGJK0cpHHdFOjwlzO3Y3Rtc/DhHVTVsBWvPS1wKgnzBFO36k73gAQJi4bOc0ggPPcK3UfVzpz8XTe+IcS2N9jew+kDqoZaL+HHz26PIAwQvXQFXPhE6y/nH/4yes24DlK3u+vHTQHXRKcLNSpYvmS6KrHvt2t01Fk0hXxeFkbh4XaE73eXB9AzNw+AccovAgMBAAEW/QEHGwEBHCQHIggDbmRuCANlZHUIB21lbXBoaXMIA0tFWQgI9bIQPIJIGTf9AP0m/QD+DzIwMTkwOTA2VDE1MjQ0Nf0A/w8yMDIwMDkwNlQxNTI0NDX9AQKw/QIAD/0CAQdhZHZpc29y/QICAP0CACH9AgEFZW1haWz9AgIUYWdhd2FuZGVAbWVtcGhpcy5lZHX9AgAf/QIBCGZ1bGxuYW1l/QICD0FzaGxlc2ggR2F3YW5kZf0CAA39AgEFZ3JvdXD9AgIA/QIAD/0CAQdob21ldXJs/QICAP0CAC39AgEMb3JnYW5pemF0aW9u/QICGVRoZSBVbml2ZXJzaXR5IG9mIE1lbXBoaXMX/QEAMZ4XLBqFjABr/k58Gq6GrNfaDMb+NLyJYF5X2mDwKnUgp1is83eg/90LqO8AVGYdyirKfr23HP4565iJXhOmFgRbP+faN++0oUTXdUSvDm43Rp+OCHr9uGPPYjUjUeNhrD7Fxfq5m3EHNMxQqnVJOODpVrF3D0EYJ4Q4IETmxrSmuDpH9I92fs7rU/51aNAZbU7DewPmcq/IrY4RO5G9pfYR+gu/gyO/L8gN39EhBbsOYWOh3EYOdAJlSktP1evL/5yRdQq7bVLyG6dZSsYQ1x4XDJ9epUesZ+TbCK/lXfRrmFG9uk8TI/rZNAYfUiQifnsNvRu34PcyELiFJ/h2xA==")))
        self.identityName = ""
        self.status = None
        self.requestId = None
        self.challenges = None

    def sendProbeInterest(self):
        probeInterest = Interest(Name(self.caPrefix).append("CA").append("_PROBE"))

        probeInterest.setMustBeFresh(True)
        probeInterest.setCanBePrefix(False)

        probeInterest.setApplicationParameters(json.dumps({"email": "agawande@memphis.edu"}, indent=4))
        probeInterest.appendParametersDigestToName()

        print("Expressing interest: {}".format(probeInterest.getName()))
        self.face.expressInterest(probeInterest, self.onProbeData, self.onTimeout)

    def onProbeData(self, interest, data):
        """ Content:
          {
              "email": "agawande@memphis.edu",
              "UID": "",
              "name: "\/ndn\/edu\/memphis\/agawande\/6046888920342781294"
          }
          1) Verify signature
          2) Extract name component from the json to use as identity
        """
        if not VerificationHelpers.verifyDataSignature(data, self.anchor):
            print("Cannot verify signature from: {}".format(self.caPrefix))
        else:
            print("Successfully verified data with hard-coded certificate")

        try:
            self.identityName = Name(json.loads(data.getContent().__str__())['name'])
            if self.identityName == "":
                print("Name received from server is empty")
                sys.exit(0)
        except Exception as e:
            print(e)

        print("Got namespace {} from server".format(self.identityName))
        self.generateKeyAndSendNewInterest(data)

    def generateKeyAndSendNewInterest(self, probeTokenData):
        """
        """
        pib = self.keyChain.getPib()
        try:
            identity = pib.getIdentity(self.identityName)
            self.key = self.keyChain.createKey(identity)
        except Exception as e:
            identity = self.keyChain.createIdentityV2(self.identityName)
            self.key = identity.getDefaultKey()

        cert = CertificateV2()
        cert.setName(Name(self.key.getName()).append("cert-request").appendVersion(int(time.time())))
        cert.getMetaInfo().setType(ContentType.KEY)
        cert.getMetaInfo().setFreshnessPeriod(24 * 3600)
        cert.setContent(self.key.getPublicKey());

        signingInfo = SigningInfo(self.key)
        now = Common.getNowMilliseconds()
        signingInfo.setValidityPeriod(ValidityPeriod(now, now + 24 * 3600 * 1000.0))
        self.keyChain.sign(cert, signingInfo)
        #cert = self.keyChain.selfSign(self.key) # Does not work because validity period is greater than certserver default

        interestName = Name(self.caPrefix).append("CA").append("_NEW")
        newInterest = Interest(interestName)
        newInterest.setMustBeFresh(True)
        newInterest.setCanBePrefix(False)

        ecdhPub = "{}\n".format(self.ecdh.getBase64PubKey())
        ecdhCertReq = "{}\n".format(b64encode(cert.wireEncode().toBytes()).decode('utf-8'))
        probeToken = "{}\n".format(b64encode(probeTokenData.wireEncode().toBytes()).decode('utf-8'))

        jsonDump = json.dumps({"ecdh-pub": ecdhPub, "cert-request": ecdhCertReq, "probe-token": probeToken}, indent=4)
        print(jsonDump)
        newInterest.setApplicationParameters(jsonDump)
        newInterest.appendParametersDigestToName()

        self.keyChain.sign(newInterest, SigningInfo(self.key))

        print(newInterest.getName())

        self.face.expressInterest(newInterest, self.onNewData, self.onTimeout)

    def onNewData(self, interest, data):
        """
        !! Again \n in public key??
        Got data:  {
            "ecdh-pub": "Aqxofe3QdsAfgbtS8TMxv31oudNKoSV307ci5gNXm88h\n",
            "salt": "12935684137560555161",
            "request-id": "14275252044236690531",
            "status": "0",
            "challenges": [
                {
                    "challenge-id": "Email"
                }
            ]
        }
        1. Verify data
        2. Derive shared secret
        """
        content = data.getContent()
        print("Got data: ", content)
        if not VerificationHelpers.verifyDataSignature(data, self.anchor):
            print("Cannot verify signature from: {}".format(self.caPrefix))
        else:
            print("Successfully verified data with hard-coded certificate")

        contentJson = json.loads(content.__str__())
        peerKeyBase64 = contentJson['ecdh-pub']
        self.status = contentJson['status']
        self.requestId = contentJson['request-id']
        self.challenges = contentJson['challenges']

        print(peerKeyBase64)

        serverPubKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64decode(peerKeyBase64))

        shared_key = self.ecdh.private_key.exchange(ec.ECDH(), serverPubKey)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=contentJson['salt'].encode(),
                           info=b'handshake data', backend=default_backend()).derive(shared_key)

        self.ecdh.derived_key = derived_key
        print(shared_key)
        for t in shared_key:
            print(t)

        challengeInterestName = Name(self.caPrefix).append("CA").append("_CHALLENGE").append(self.requestId)
        challengeInterest = Interest(challengeInterestName)
        challengeInterest.setMustBeFresh(True)
        challengeInterest.setCanBePrefix(False)

        # Encrypt the interest parameters
        challengeJson = json.dumps({"selected-challenge": "Email", "email": "agawande@memphis.edu"}, indent=4)
        raw = self.pad(challengeJson, 16)
        print("raw", raw)
        iv = Random.new().read(AES.block_size)
        #cipher = AES.new(self.ecdh.derived_key, AES.MODE_CBC, iv)
        cipher = AES.new(shared_key, AES.MODE_CBC, iv)
        print(iv)
        xx = cipher.encrypt(raw)

        print(cipher.decrypt(xx))

        print("Printing iv:")
        for t in iv:
            print(t)

        encoder = TlvEncoder(256)
        saveLength = len(encoder)
        encoder.writeBlobTlv(632, iv)
        encoder.writeBlobTlv(630, cipher.encrypt(raw))
        #encoder.writeTypeAndLength(36, len(encoder) - saveLength)

        challengeInterest.setApplicationParameters(Blob(encoder.getOutput()))
        challengeInterest.appendParametersDigestToName()

        self.keyChain.sign(challengeInterest, SigningInfo(self.key))

        with open('foobar.tlv', 'wb') as f:
        	f.write(challengeInterest.wireEncode().buf())
        self.face.expressInterest(challengeInterest, self.onChallengeData, self.onTimeout)

    def onChallengeData(self, interest, data):
        print("Got data: ", data)

    def pad(self, s, blocksize):
        return s + (blocksize - len(s) % blocksize) * ' '

    def onTimeout(self, interest):
        print("Got timeout for interest: {}".format(interest.getName()))

    def start(self):
        while True:
            self.face.processEvents()
            # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
            time.sleep(0.01)

if __name__ == '__main__':
    CA_PREFIX = "/ndn/edu/memphis/agawande/"

    #ecdh = ECDHState()
    #print(ecdh.getBase64PubKey())

    client = ClientModule(CA_PREFIX)
    client.sendProbeInterest()
    client.start()

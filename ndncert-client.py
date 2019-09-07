import sys, time, json

from pyndn import Name
from pyndn import Blob
from pyndn import Face
from pyndn import Interest
from pyndn.security.verification_helpers import VerificationHelpers
from pyndn.security.v2 import CertificateV2
from base64 import b64decode

class ClientModule():
    def __init__(self, caPrefix):
        self.face = Face()
        self.caPrefix = caPrefix
        self.anchor = CertificateV2()
        self.anchor.wireDecode(Blob(b64decode("Bv0DgQc7CANuZG4IA2VkdQgHbWVtcGhpcwgIYWdhd2FuZGUIA0tFWQgIo6cuGT4GVKEIAk5BCAn9AAABbQxT3hEUCRgBAhkEADbugBX9ASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDII1sLOE7cCQVTKoGjeM5o/mxWqhMx0siLHJ81Ee/eUCNAMxA0w1oxAoTGQ8HbNP3vShZfvMJ/11Jiqus2wAWlNjRWvQShNv5MueU8kYtOGTbiqr/I1EpSRQ2aJX3s49CoskoWMzf6knK4ELleH3/EBUPGJK0cpHHdFOjwlzO3Y3Rtc/DhHVTVsBWvPS1wKgnzBFO36k73gAQJi4bOc0ggPPcK3UfVzpz8XTe+IcS2N9jew+kDqoZaL+HHz26PIAwQvXQFXPhE6y/nH/4yes24DlK3u+vHTQHXRKcLNSpYvmS6KrHvt2t01Fk0hXxeFkbh4XaE73eXB9AzNw+AccovAgMBAAEW/QEHGwEBHCQHIggDbmRuCANlZHUIB21lbXBoaXMIA0tFWQgI9bIQPIJIGTf9AP0m/QD+DzIwMTkwOTA2VDE1MjQ0Nf0A/w8yMDIwMDkwNlQxNTI0NDX9AQKw/QIAD/0CAQdhZHZpc29y/QICAP0CACH9AgEFZW1haWz9AgIUYWdhd2FuZGVAbWVtcGhpcy5lZHX9AgAf/QIBCGZ1bGxuYW1l/QICD0FzaGxlc2ggR2F3YW5kZf0CAA39AgEFZ3JvdXD9AgIA/QIAD/0CAQdob21ldXJs/QICAP0CAC39AgEMb3JnYW5pemF0aW9u/QICGVRoZSBVbml2ZXJzaXR5IG9mIE1lbXBoaXMX/QEAMZ4XLBqFjABr/k58Gq6GrNfaDMb+NLyJYF5X2mDwKnUgp1is83eg/90LqO8AVGYdyirKfr23HP4565iJXhOmFgRbP+faN++0oUTXdUSvDm43Rp+OCHr9uGPPYjUjUeNhrD7Fxfq5m3EHNMxQqnVJOODpVrF3D0EYJ4Q4IETmxrSmuDpH9I92fs7rU/51aNAZbU7DewPmcq/IrY4RO5G9pfYR+gu/gyO/L8gN39EhBbsOYWOh3EYOdAJlSktP1evL/5yRdQq7bVLyG6dZSsYQ1x4XDJ9epUesZ+TbCK/lXfRrmFG9uk8TI/rZNAYfUiQifnsNvRu34PcyELiFJ/h2xA==")))
        self.identityName = ""

    def sendProbeInterest(self):
        probeInterest = Interest(Name(self.caPrefix).append("CA").append("_PROBE"))

        probeInterest.setMustBeFresh(True)
        probeInterest.setCanBePrefix(False)

        probeInterest.setApplicationParameters(json.dumps({"email": "agawande@memphis.edu"}, indent=4))
        probeInterest.appendParametersDigestToName()

        print("Expressing interest: {}".format(probeInterest.getName()))
        self.face.expressInterest(probeInterest, self.onProbeData, self.onProbeTimeout)

    def onProbeData(self, interest, data):
        """ Content:
          {
              "email": "agawande@memphis.edu",
              "UID": "",
              "name: "\/ndn\/edu\/memphis\/agawande\/6046888920342781294"
          }
          1) Verify signature
          2) Extract name component from the json
        """
        if not VerificationHelpers.verifyDataSignature(data, self.anchor):
            print("Cannot verify signature from: {}".format(self.caPrefix))
        else:
            print("Successfully verified data with hard-coded certificate")

        try:
            self.identityName = json.loads(data.getContent().__str__())['name'].split("/")[-1]
            if self.identityName == "":
                print("Name received from server is empty")
        except Exception as e:
            print(e)

        print("Got namespace {} from server".format(self.identityName))

    def onProbeTimeout(self, interest):
        print("Got timeout", interest)

    def start(self):
        while True:
            self.face.processEvents()
            # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
            time.sleep(0.01)

if __name__ == '__main__':
    CA_PREFIX = "/ndn/edu/memphis/agawande/"

    client = ClientModule(CA_PREFIX)
    client.sendProbeInterest()
    client.start()

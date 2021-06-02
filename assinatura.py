import sys
import docopt

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random

def generate_keys():
   random_generator = Random.new().read
   key = RSA.generate(2048, random_generator)
   return (key.exportKey(), key.publickey().exportKey())

def generate_hash(data):
   return SHA256.new(data).digest()

def generate_signature(hash, key):
   return key.sign(hash, '')

def verify_signature(hash, public_key, signature):
   return public_key.verify(hash, signature)

if __name__ == "__main__":

   args = docopt.docopt(__doc__)

   if args["keys"]:

      private, public = generate_keys()
      keys = private + "\n\n" + public
      print(keys.strip())

   elif args["public"]:

      with open(args["<keyfilename>"], "r") as keyfile:
         public_key = keyfile.read().split("\n\n")[1]
      print(public_key.strip())

   elif args["sign"]:

      with open(args["<filename>"], "rb") as signedfile:
         hash = generate_hash(signedfile.read())

      with open(args["<keyfilename>"], "r") as keyfile:
         private_key = RSA.importKey(keyfile.read().split("\n\n")[0].strip())

      print(generate_signature(hash, private_key)[0])

   elif args["check"]:

      with open(args["<filename>"], "rb") as signedfile:
         hash = generate_hash(signedfile.read())

      with open(args["<keyfilename>"], "r") as keyfile:
         public_key = RSA.importKey(keyfile.read().split("\n\n")[1].strip())

      with open(args["<signaturefilename>"], "r") as signaturefile:
         signature = long(signaturefile.read())

      if verify_signature(hash, public_key, (signature,)):
         sys.exit("valid signature :)")
      else:
         sys.exit("invalid signature! :(")
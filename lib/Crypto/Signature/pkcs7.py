# Python of PKCS#7 v1.5.  Currently only certain parts of
# PKCS#7 are implemented, especially the enveloped-data content type.
#
# Copyright (c) 2013 ENDOH takanao <djmchl@gmail.com>
#
# Currently this implementation only supports ContentType of either
# EnvelopedData or EncryptedData on root level.  The top level elements may
# contain only a ContentInfo of ContentType Data, i.e. plain data.  Further
# nesting is not (yet) supported.

#import aes
#import asn1
#import pkcs7asn1
#import pki
#import random
#import util

class PKCS7(object):
  def messageFromPem(self, pem):
    """
    Converts a PKCS#7 message from PEM format.

    @param pem the PEM-formatted PKCS#7 message.

    @return the PKCS#7 message.
    """
    der = pki.pemToDer(pem)
    obj = asn1.fromDer(der)
    return self.messageFromAsn1(obj)

  def messageToPem(self, msg, maxline=None):
    """
    Converts a PKCS#7 message to PEM format.

    @param msg The PKCS#7 message object
    @param maxline The maximum characters per line, defaults to 64.

    @return The PEM-formatted PKCS#7 message.
    """
    if maxline is None:
      maxline = 64
    out = asn1.toDer(msg.toAsn1())
    out = util.encode64(out.getBytes(), maxline)
    return "-----BEGIN PKCS7-----\r\n{0}\r\n-----END PKCS7-----".format(out)

  def messageFromAsn1(self, obj):
    """
    Converts a PKCS#7 message from an ASN.1 object.

    @param obj the ASN.1 representation of a ContentInfo.

    @return the PKCS#7 message.
    """
    # validate root level ContentInfo and capture data
    capture = dict()
    try:
      asn1.validate(obj, self.asn1.contentInfoValidator, capture)
    except:
      raise Exception("Cannot read PKCS#7 message. ASN.1 object is not an PKCS#7 ContentInfo.")
    contentType = asn1.derToOid(capture.contentType)
    if contentType == pki.oids.envelopedData:
      msg = self.createEnvelopedData()
    elif contentType == pki.oids.encryptedData:
      msg = self.createEncryptedData()
    else
      raise Exception("Cannot read PKCS#7 message. ContentType with OID {0} is not (yet) supported.".format(contentType))
    msg.fromAsn1(capture.content.value[0])
    return msg

  def _recipientInfoFromAsn1(self, obj):
    """
    Converts a single RecipientInfo from an ASN.1 object.

    @param obj The ASN.1 representation of a RecipientInfo.

    @return The recipientInfo object.
    """
    # Validate EnvelopedData content block and capture data.
    capture = {}
    try:
      asn1.validate(obj, self.asn1.recipientInfoValidator, capture)
    except:
      raise Exception("Cannot read PKCS#7 message. ASN.1 object is not an PKCS#7 EnvelopedData.")
    return dict(
      version = capture.version.charCodeAt(0),
      issuer = pki.RDNAttributesAsArray(capture.issuer),
      serialNumber = util.createBuffer(capture.serial).toHex(),
      encContent = dict(
        algorithm = asn1.derToOid(capture.encAlgorithm),
        parameter = capture.encParameter.value,
        content = capture.encKey,
        ),
      )

  def _recipientInfoToAsn1(self, obj):
    """
    Converts a single recipientInfo object to an ASN.1 object.

    @param obj The recipientInfo object.

    @return The ASN.1 representation of a RecipientInfo.
    """
    return asn1.create(asn1.Class.UNIVERSAL,
                       asn1.Type.SEQUENCE,
                       True,
                       [
                        # Version
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, False, chr(obj.version)),
                        # IssuerAndSerialNumber
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, True, [
                          # Name
                          pki.distinguishedNameToAsn1(dict(attributes=obj.issuer)),
                          # Serial
                          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, False, util.hexToBytes(obj.serialNumber)),
                        ]),
                        # KeyEncryptionAlgorithmIdentifier
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, True, [
                          # Algorithm
                          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, False, asn1.oidToDer(obj.encContent.algorithm).getBytes()),
                          # Parameter, force NULL, only RSA supported for now.
                          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, False, "")
                        ]),
                        # EncryptedKey
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, False, obj.encContent.content)
                      ],
                     )
  def _recipientInfosFromAsn1(self, objArr):
    """
    Map a set of RecipientInfo ASN.1 objects to recipientInfo objects.

    @param objArr Array of ASN.1 representations RecipientInfo (i.e. SET OF).

    @return array of recipientInfo objects.
    """
    return (self._recipientInfoFromAsn1(i) for i in objArr)

  def _recipientInfosToAsn1(self, recipientsArr):
    """
    Map an array of recipientInfo objects to ASN.1 objects.

    @param recipientsArr Array of recipientInfo objects.

    @return Array of ASN.1 representations RecipientInfo.
    """
    return (self._recipientInfoToAsn1(i) for i in recipientsArr)

  def _encContentToAsn1(self, ec):
    """
    Map messages encrypted content to ASN.1 objects.

    @param ec The encContent object of the message.

    @return ASN.1 representation of the encContent object (SEQUENCE).
    """
    return [
      # ContentType, always Data for the moment
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, False, asn1.oidToDer(pki.oids.data).getBytes()),
      # ContentEncryptionAlgorithmIdentifier
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, True, [
        # Algorithm
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, False, asn1.oidToDer(ec.algorithm).getBytes()),
        # Parameters (IV)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, False, ec.parameter.getBytes()),
      ]),
      # [0] EncryptedContent
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, True, [
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, False, ec.content.getBytes()),
      ]),
    ]

  def _fromAsn1(self, msg, obj, validator):
    """
    Reads the "common part" of an PKCS#7 content block (in ASN.1 format)

    This function reads the "common part" of the PKCS#7 content blocks
    EncryptedData and EnvelopedData, i.e. version number and symmetrically
    encrypted content block.

    The result of the ASN.1 validate and capture process is returned
    to allow the caller to extract further data, e.g. the list of recipients
    in case of a EnvelopedData object.

    @param msg The PKCS#7 object to read the data to
    @param obj The ASN.1 representation of the content block
    @param validator The ASN.1 structure validator object to use
    @return Map with values captured by validator object
    """
    capture = {}
    try:
      asn1.validate(obj, validator, capture)
    except:
      raise Exception("Cannot read PKCS#7 message. ASN.1 object is not an PKCS#7 EnvelopedData.")
    # Check contentType, so far we only support (raw) Data.
    contentType = asn1.derToOid(capture.contentType)
    if contentType != pki.oids.data:
      raise Exception("Unsupported PKCS#7 message. Only contentType Data supported within EnvelopedData.")
    content = ""
    if isinstance(capture.encContent.constructor, list):
      for i in capture.encContent:
        if i.type != asn1.Type.OCTETSTRING:
          raise Exception("Malformed PKCS#7 message, expecting encrypted " + "content constructed of only OCTET STRING objects.")
        content += i.value
    else
      content = capture.encContent
    msg.version = ord(capture.version[0])
    msg.encContent = dict(
      algorithm = asn1.derToOid(capture.encAlgorithm),
      parameter = util.createBuffer(capture.encParameter.value),
      content = util.createBuffer(content),
    )
    return capture

  def _decryptContent(self, msg):
    """
    Decrypt the symmetrically encrypted content block of the PKCS#7 message.

    Decryption is skipped in case the PKCS#7 message object already has a
    (decrypted) content attribute.  The algorithm, key and cipher parameters
    (probably the iv) are taken from the encContent attribute of the message
    object.

    @param The PKCS#7 message object.
    """
    if msg.encContent.key is None:
      raise Exception("Symmetric key not available.")
    if msg.content is None:
      if msg.encContent.algorithm in [pki.oids["aes128-CBC"], pki.oids["aes192-CBC"], pki.oids["aes256-CBC"]]:
        ciph = aes.createDecryptionCipher(msg.encContent.key)
      elif msg.encContent.algorithm == pki.oids["des-EDE3-CBC"]:
        ciph = des.createDecryptionCipher(msg.encContent.key)
      else
        raise Exception("Unsupported symmetric cipher, OID {0}".format(msg.encContent.algorithm))
      ciph.start(msg.encContent.parameter)
      ciph.update(msg.encContent.content)
      if not ciph.finish():
        raise Exception("Symmetric decryption failed.")
      msg.content = ciph.output

  def createEncryptedData(self):
    """
    Creates an empty PKCS#7 message of type EncryptedData.

    @return the message.
    """

    class msg(object):
      type = pki.oids.encryptedData
      version = 0
      encContent = dict(
        algorithm = pki.oids["aes256-CBC"],
      )

      def __init__(self, p7):
        self.p7 = p7

      def fromAsn1(self, obj):
        """
        Reads an EncryptedData content block (in ASN.1 format)

        @param obj The ASN.1 representation of the EncryptedData content block
        """
        # Validate EncryptedData content block and capture data.
        self.p7._fromAsn1(msg, obj, self.p7.asn1.encryptedDataValidator)

      def decrypt(self, key):
        """
        Decrypt encrypted content

        @param key The (symmetric) key as a byte buffer
        """
        if key is not None:
          self.encContent.key = key
        self.p7._decryptContent(msg)

    return msg(self)

  def createEnvelopedData(self):
    """
    Creates an empty PKCS#7 message of type EnvelopedData.

    @return the message.
    """
    class msg(object):
      type = pki.oids.envelopedData
      version = 0
      recipients = list()
      encContent = dict(
        algorithm = pki.oids["aes256-CBC"],
      )

      def __init__(self, p7):
        self.p7 = p7

      def fromAsn1(self, obj):
        """
        Reads an EnvelopedData content block (in ASN.1 format)

        @param obj The ASN.1 representation of the EnvelopedData content block
        """
        # Validate EnvelopedData content block and capture data.
        capture = self.p7._fromAsn1(msg, obj, self.p7.asn1.envelopedDataValidator)
        self.recipients = self.p7._recipientInfosFromAsn1(capture.recipientInfos.value)

      def toAsn1(self):
        return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, True, [
          # ContentInfo
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, False, asn1.oidToDer(self.type).getBytes()),
          # ContentType
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, True, [
            # [0] EnvelopedData
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, True, [
              # Version
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, False, chr(self.version)),
              # RecipientInfos
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, True, self.p7._recipientInfosToAsn1(self.recipients)),
              # EncryptedContentInfo
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, True, self.p7._encContentToAsn1(self.encContent))
            ])
          ])
        ]

      def findRecipient(self, cert):
        """
        Find recipient by X.509 certificate's subject.

        @param cert The certificate for which's subject to look for.

        @return The recipient object
        """
        sAttr = cert.subject.attributes
        for r in self.recipients:
          rAttr = r.issuer
          if r.serialNumber != cert.serialNumber:
            continue
          if len(rAttr) != len(sAttr):
            continue
          match = True
          for j in xrange(len(sAttr)):
            if rAttr[j].type != sAttr[j].type or rAttr[j].value != sAttr[j].value
              match = False
              break
          if match:
            return r

      def decrypt(self, recipient, privKey):
        """
        Decrypt enveloped content

        @param recipient The recipient object related to the private key
        @param privKey The (RSA) private key object
        """
        if self.encContent.key is None and recipient is not None and privKey is not None:
          if recipient.encContent.algorithm == pki.oids.rsaEncryption:
            key = privKey.decrypt(recipient.encContent.content)
            self.encContent.key = util.createBuffer(key)
          else
            raise Exception("Unsupported asymmetric cipher, OID {0}".format(recipient.encContent.algorithm))
        self.p7._decryptContent(self)

      def addRecipient(self, cert):
        """
        Add (another) entity to list of recipients.

        @param cert The certificate of the entity to add.
        """
        self.recipients.append(dict(
          version = 0,
          issuer = cert.subject.attributes,
          serialNumber = cert.serialNumber,
          encContent = dict(
            # We simply assume rsaEncryption here, since forge.pki only
            # supports RSA so far.  If the PKI module supports other
            # ciphers one day, we need to modify this one as well.
            algorithm = pki.oids.rsaEncryption,
            key = cert.publicKey,
          ),
        ))

      def encrypt(self, key, cipher):
        """
        Encrypt enveloped content.

        This function supports two optional arguments, cipher and key, which
        can be used to influence symmetric encryption.  Unless cipher is
        provided, the cipher specified in encContent.algorithm is used
        (defaults to AES-256-CBC).  If no key is provided, encContent.key
        is (re-)used.  If that one's not set, a random key will be generated
        automatically.

        @param [key] The key to be used for symmetric encryption.
        @param [cipher] The OID of the symmetric cipher to use.
        """
        # Part 1: Symmetric encryption
        if self.encContent.content is None:
          cipher = cipher or self.encContent.algorithm
          key = key or self.encContent.key
          if cipher == pki.oids["aes128-CBC"]:
            keyLen = 16
            ivLen = 16
            ciphFn = forge.aes.createEncryptionCipher
          elif cipher == pki.oids["aes192-CBC"]:
            keyLen = 24
            ivLen = 16
            ciphFn = aes.createEncryptionCipher
          elif cipher == pki.oids["aes256-CBC"]
            keyLen = 32
            ivLen = 16
            ciphFn = aes.createEncryptionCipher
          elif cipher == pki.oids["des-EDE3-CBC"]:
            keyLen = 24
            ivLen = 8
            ciphFn = des.createEncryptionCipher
          else
            raise Exception("Unsupported symmetric cipher, OID {0}".format(cipher))
          if key is None:
            key = util.createBuffer(random.getBytes(keyLen))
          else:
            if len(key) != keyLen:
              raise Exception("Symmetric key has wrong length, got {0} bytes, expected {1}".format(len(key), keyLen))

          # Keep a copy of the key & IV in the object, so the caller can
          # use it for whatever reason.
          self.encContent.algorithm = cipher
          self.encContent.key = key
          self.encContent.parameter = util.createBuffer(random.getBytes(ivLen))
          ciph = ciphFn(key)
          ciph.start(self.encContent.parameter.copy())
          ciph.update(self.content)

          # The finish function does PKCS#7 padding by default, therefore
          # no action required by us.
          if not ciph.finish():
            raise Exception("Symmetric encryption failed.")
          self.encContent.content = ciph.output

        # Part 2: asymmetric encryption for each recipient
        for recipient in self.recipients:
          if recipient.encContent.content is not None: # Nothing to do, encryption already done.
            continue
          if recipient.encContent.algorithm == pki.oids.rsaEncryption:
            recipient.encContent.content = recipient.encContent.key.encrypt(self.encContent.key.data)
          else
            raise Exception("Unsupported asymmetric cipher, OID {0}".format(recipient.encContent.algorithm))

    return msg(self)

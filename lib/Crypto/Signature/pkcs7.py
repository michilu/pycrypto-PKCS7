###
Javascript implementation of PKCS#7 v1.5.  Currently only certain parts of
PKCS#7 are implemented, especially the enveloped-data content type.

@author Stefan Siegl

Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>

Currently this implementation only supports ContentType of either
EnvelopedData or EncryptedData on root level.  The top level elements may
contain only a ContentInfo of ContentType Data, i.e. plain data.  Further
nesting is not (yet) supported.

The Forge validators for PKCS #7's ASN.1 structures are available from
a seperate file pkcs7asn1.js, since those are referenced from other
PKCS standards like PKCS #12.
###
(->

  # define forge
  forge = {}
  if typeof (window) isnt "undefined"
    forge = window.forge = window.forge or {}

  # define node.js module
  else if typeof (module) isnt "undefined" and module.exports
    forge =
      aes: require("./aes")
      asn1: require("./asn1")
      des: require("./des")
      pkcs7:
        asn1: require("./pkcs7asn1")

      pki: require("./pki")
      random: require("./random")
      util: require("./util")

    module.exports = forge.pkcs7

  # shortcut for ASN.1 API
  asn1 = forge.asn1

  # shortcut for PKCS#7 API
  p7 = forge.pkcs7 = forge.pkcs7 or {}

  ###
  Converts a PKCS#7 message from PEM format.

  @param pem the PEM-formatted PKCS#7 message.

  @return the PKCS#7 message.
  ###
  p7.messageFromPem = (pem) ->
    der = forge.pki.pemToDer(pem)
    obj = asn1.fromDer(der)
    p7.messageFromAsn1 obj


  ###
  Converts a PKCS#7 message to PEM format.

  @param msg The PKCS#7 message object
  @param maxline The maximum characters per line, defaults to 64.

  @return The PEM-formatted PKCS#7 message.
  ###
  p7.messageToPem = (msg, maxline) ->
    out = asn1.toDer(msg.toAsn1())
    out = forge.util.encode64(out.getBytes(), maxline or 64)
    "-----BEGIN PKCS7-----\r\n" + out + "\r\n-----END PKCS7-----"


  ###
  Converts a PKCS#7 message from an ASN.1 object.

  @param obj the ASN.1 representation of a ContentInfo.

  @return the PKCS#7 message.
  ###
  p7.messageFromAsn1 = (obj) ->

    # validate root level ContentInfo and capture data
    capture = {}
    errors = []
    unless asn1.validate(obj, p7.asn1.contentInfoValidator, capture, errors)
      throw
        message: "Cannot read PKCS#7 message. " + "ASN.1 object is not an PKCS#7 ContentInfo."
        errors: errors
    contentType = asn1.derToOid(capture.contentType)
    msg = undefined
    switch contentType
      when forge.pki.oids.envelopedData
        msg = p7.createEnvelopedData()
      when forge.pki.oids.encryptedData
        msg = p7.createEncryptedData()
      else
        throw message: "Cannot read PKCS#7 message. ContentType with OID " + contentType + " is not (yet) supported."
    msg.fromAsn1 capture.content.value[0]
    msg


  ###
  Converts a single RecipientInfo from an ASN.1 object.

  @param obj The ASN.1 representation of a RecipientInfo.

  @return The recipientInfo object.
  ###
  _recipientInfoFromAsn1 = (obj) ->

    # Validate EnvelopedData content block and capture data.
    capture = {}
    errors = []
    unless asn1.validate(obj, p7.asn1.recipientInfoValidator, capture, errors)
      throw
        message: "Cannot read PKCS#7 message. " + "ASN.1 object is not an PKCS#7 EnvelopedData."
        errors: errors
    version: capture.version.charCodeAt(0)
    issuer: forge.pki.RDNAttributesAsArray(capture.issuer)
    serialNumber: forge.util.createBuffer(capture.serial).toHex()
    encContent:
      algorithm: asn1.derToOid(capture.encAlgorithm)
      parameter: capture.encParameter.value
      content: capture.encKey


  ###
  Converts a single recipientInfo object to an ASN.1 object.

  @param obj The recipientInfo object.

  @return The ASN.1 representation of a RecipientInfo.
  ###
  _recipientInfoToAsn1 = (obj) ->

    # Version

    # IssuerAndSerialNumber

    # Name

    # Serial

    # KeyEncryptionAlgorithmIdentifier

    # Algorithm

    # Parameter, force NULL, only RSA supported for now.

    # EncryptedKey
    asn1.create asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, String.fromCharCode(obj.version)), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [forge.pki.distinguishedNameToAsn1(attributes: obj.issuer), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, forge.util.hexToBytes(obj.serialNumber))]), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(obj.encContent.algorithm).getBytes()), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, "")]), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, obj.encContent.content)]


  ###
  Map a set of RecipientInfo ASN.1 objects to recipientInfo objects.

  @param objArr Array of ASN.1 representations RecipientInfo (i.e. SET OF).

  @return array of recipientInfo objects.
  ###
  _recipientInfosFromAsn1 = (objArr) ->
    ret = []
    i = 0

    while i < objArr.length
      ret.push _recipientInfoFromAsn1(objArr[i])
      i++
    ret


  ###
  Map an array of recipientInfo objects to ASN.1 objects.

  @param recipientsArr Array of recipientInfo objects.

  @return Array of ASN.1 representations RecipientInfo.
  ###
  _recipientInfosToAsn1 = (recipientsArr) ->
    ret = []
    i = 0

    while i < recipientsArr.length
      ret.push _recipientInfoToAsn1(recipientsArr[i])
      i++
    ret


  ###
  Map messages encrypted content to ASN.1 objects.

  @param ec The encContent object of the message.

  @return ASN.1 representation of the encContent object (SEQUENCE).
  ###
  _encContentToAsn1 = (ec) ->

    # ContentType, always Data for the moment

    # ContentEncryptionAlgorithmIdentifier

    # Algorithm

    # Parameters (IV)

    # [0] EncryptedContent
    [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(forge.pki.oids.data).getBytes()), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(ec.algorithm).getBytes()), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, ec.parameter.getBytes())]), asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, ec.content.getBytes())])]


  ###
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
  ###
  _fromAsn1 = (msg, obj, validator) ->
    capture = {}
    errors = []
    unless asn1.validate(obj, validator, capture, errors)
      throw
        message: "Cannot read PKCS#7 message. " + "ASN.1 object is not an PKCS#7 EnvelopedData."
        errors: errors

    # Check contentType, so far we only support (raw) Data.
    contentType = asn1.derToOid(capture.contentType)
    throw message: "Unsupported PKCS#7 message. " + "Only contentType Data supported within EnvelopedData."  if contentType isnt forge.pki.oids.data
    content = ""
    if capture.encContent.constructor is Array
      i = 0

      while i < capture.encContent.length
        throw message: "Malformed PKCS#7 message, expecting encrypted " + "content constructed of only OCTET STRING objects."  if capture.encContent[i].type isnt asn1.Type.OCTETSTRING
        content += capture.encContent[i].value
        i++
    else
      content = capture.encContent
    msg.version = capture.version.charCodeAt(0)
    msg.encContent =
      algorithm: asn1.derToOid(capture.encAlgorithm)
      parameter: forge.util.createBuffer(capture.encParameter.value)
      content: forge.util.createBuffer(content)

    capture


  ###
  Decrypt the symmetrically encrypted content block of the PKCS#7 message.

  Decryption is skipped in case the PKCS#7 message object already has a
  (decrypted) content attribute.  The algorithm, key and cipher parameters
  (probably the iv) are taken from the encContent attribute of the message
  object.

  @param The PKCS#7 message object.
  ###
  _decryptContent = (msg) ->
    throw message: "Symmetric key not available."  if msg.encContent.key is `undefined`
    if msg.content is `undefined`
      ciph = undefined
      switch msg.encContent.algorithm
        when forge.pki.oids["aes128-CBC"], forge.pki.oids["aes192-CBC"]
      , forge.pki.oids["aes256-CBC"]
          ciph = forge.aes.createDecryptionCipher(msg.encContent.key)
        when forge.pki.oids["des-EDE3-CBC"]
          ciph = forge.des.createDecryptionCipher(msg.encContent.key)
        else
          throw message: "Unsupported symmetric cipher, " + "OID " + msg.encContent.algorithm
      ciph.start msg.encContent.parameter
      ciph.update msg.encContent.content
      throw message: "Symmetric decryption failed."  unless ciph.finish()
      msg.content = ciph.output


  ###
  Creates an empty PKCS#7 message of type EncryptedData.

  @return the message.
  ###
  p7.createEncryptedData = ->
    msg = null
    msg =
      type: forge.pki.oids.encryptedData
      version: 0
      encContent:
        algorithm: forge.pki.oids["aes256-CBC"]


      ###
      Reads an EncryptedData content block (in ASN.1 format)

      @param obj The ASN.1 representation of the EncryptedData content block
      ###
      fromAsn1: (obj) ->

        # Validate EncryptedData content block and capture data.
        _fromAsn1 msg, obj, p7.asn1.encryptedDataValidator


      ###
      Decrypt encrypted content

      @param key The (symmetric) key as a byte buffer
      ###
      decrypt: (key) ->
        msg.encContent.key = key  if key isnt `undefined`
        _decryptContent msg

    msg


  ###
  Creates an empty PKCS#7 message of type EnvelopedData.

  @return the message.
  ###
  p7.createEnvelopedData = ->
    msg = null
    msg =
      type: forge.pki.oids.envelopedData
      version: 0
      recipients: []
      encContent:
        algorithm: forge.pki.oids["aes256-CBC"]


      ###
      Reads an EnvelopedData content block (in ASN.1 format)

      @param obj The ASN.1 representation of the EnvelopedData content block
      ###
      fromAsn1: (obj) ->

        # Validate EnvelopedData content block and capture data.
        capture = _fromAsn1(msg, obj, p7.asn1.envelopedDataValidator)
        msg.recipients = _recipientInfosFromAsn1(capture.recipientInfos.value)

      toAsn1: ->

        # ContentInfo

        # ContentType

        # [0] EnvelopedData

        # Version

        # RecipientInfos

        # EncryptedContentInfo
        asn1.create asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(msg.type).getBytes()), asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, String.fromCharCode(msg.version)), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, _recipientInfosToAsn1(msg.recipients)), asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, _encContentToAsn1(msg.encContent))])])]


      ###
      Find recipient by X.509 certificate's subject.

      @param cert The certificate for which's subject to look for.

      @return The recipient object
      ###
      findRecipient: (cert) ->
        sAttr = cert.subject.attributes
        i = 0

        while i < msg.recipients.length
          r = msg.recipients[i]
          rAttr = r.issuer
          continue  if r.serialNumber isnt cert.serialNumber
          continue  if rAttr.length isnt sAttr.length
          match = true
          j = 0

          while j < sAttr.length
            if rAttr[j].type isnt sAttr[j].type or rAttr[j].value isnt sAttr[j].value
              match = false
              break
            j++
          return r  if match
          i++


      ###
      Decrypt enveloped content

      @param recipient The recipient object related to the private key
      @param privKey The (RSA) private key object
      ###
      decrypt: (recipient, privKey) ->
        if msg.encContent.key is `undefined` and recipient isnt `undefined` and privKey isnt `undefined`
          switch recipient.encContent.algorithm
            when forge.pki.oids.rsaEncryption
              key = privKey.decrypt(recipient.encContent.content)
              msg.encContent.key = forge.util.createBuffer(key)
            else
              throw message: "Unsupported asymmetric cipher, " + "OID " + recipient.encContent.algorithm
        _decryptContent msg


      ###
      Add (another) entity to list of recipients.

      @param cert The certificate of the entity to add.
      ###
      addRecipient: (cert) ->
        msg.recipients.push
          version: 0
          issuer: cert.subject.attributes
          serialNumber: cert.serialNumber
          encContent:

            # We simply assume rsaEncryption here, since forge.pki only
            # supports RSA so far.  If the PKI module supports other
            # ciphers one day, we need to modify this one as well.
            algorithm: forge.pki.oids.rsaEncryption
            key: cert.publicKey



      ###
      Encrypt enveloped content.

      This function supports two optional arguments, cipher and key, which
      can be used to influence symmetric encryption.  Unless cipher is
      provided, the cipher specified in encContent.algorithm is used
      (defaults to AES-256-CBC).  If no key is provided, encContent.key
      is (re-)used.  If that one's not set, a random key will be generated
      automatically.

      @param [key] The key to be used for symmetric encryption.
      @param [cipher] The OID of the symmetric cipher to use.
      ###
      encrypt: (key, cipher) ->

        # Part 1: Symmetric encryption
        if msg.encContent.content is `undefined`
          cipher = cipher or msg.encContent.algorithm
          key = key or msg.encContent.key
          keyLen = undefined
          ivLen = undefined
          ciphFn = undefined
          switch cipher
            when forge.pki.oids["aes128-CBC"]
              keyLen = 16
              ivLen = 16
              ciphFn = forge.aes.createEncryptionCipher
            when forge.pki.oids["aes192-CBC"]
              keyLen = 24
              ivLen = 16
              ciphFn = forge.aes.createEncryptionCipher
            when forge.pki.oids["aes256-CBC"]
              keyLen = 32
              ivLen = 16
              ciphFn = forge.aes.createEncryptionCipher
            when forge.pki.oids["des-EDE3-CBC"]
              keyLen = 24
              ivLen = 8
              ciphFn = forge.des.createEncryptionCipher
            else
              throw message: "Unsupported symmetric cipher, OID " + cipher
          if key is `undefined`
            key = forge.util.createBuffer(forge.random.getBytes(keyLen))
          else throw message: "Symmetric key has wrong length, " + "got " + key.length() + " bytes, expected " + keyLen  unless key.length() is keyLen

          # Keep a copy of the key & IV in the object, so the caller can
          # use it for whatever reason.
          msg.encContent.algorithm = cipher
          msg.encContent.key = key
          msg.encContent.parameter = forge.util.createBuffer(forge.random.getBytes(ivLen))
          ciph = ciphFn(key)
          ciph.start msg.encContent.parameter.copy()
          ciph.update msg.content

          # The finish function does PKCS#7 padding by default, therefore
          # no action required by us.
          throw message: "Symmetric encryption failed."  unless ciph.finish()
          msg.encContent.content = ciph.output

        # Part 2: asymmetric encryption for each recipient
        i = 0

        while i < msg.recipients.length
          recipient = msg.recipients[i]
          continue  if recipient.encContent.content isnt `undefined` # Nothing to do, encryption already done.
          switch recipient.encContent.algorithm
            when forge.pki.oids.rsaEncryption
              recipient.encContent.content = recipient.encContent.key.encrypt(msg.encContent.key.data)
            else
              throw message: "Unsupported asymmetric cipher, OID " + recipient.encContent.algorithm
          i++

    msg
)()

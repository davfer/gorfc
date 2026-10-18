package rfc7519

const (
	// ClaimIss represents the "iss" claim.
	// Description: Issuer
	// Reference: [RFC7519, Section 4.1.1]
	ClaimIss = "iss"

	// ClaimSub represents the "sub" claim.
	// Description: Subject
	// Reference: [RFC7519, Section 4.1.2]
	ClaimSub = "sub"

	// ClaimAud represents the "aud" claim.
	// Description: Audience
	// Reference: [RFC7519, Section 4.1.3]
	ClaimAud = "aud"

	// ClaimExp represents the "exp" claim.
	// Description: Expiration Time
	// Reference: [RFC7519, Section 4.1.4]
	ClaimExp = "exp"

	// ClaimNbf represents the "nbf" claim.
	// Description: Not Before
	// Reference: [RFC7519, Section 4.1.5]
	ClaimNbf = "nbf"

	// ClaimIat represents the "iat" claim.
	// Description: Issued At
	// Reference: [RFC7519, Section 4.1.6]
	ClaimIat = "iat"

	// ClaimJti represents the "jti" claim.
	// Description: JWT ID
	// Reference: [RFC7519, Section 4.1.7]
	ClaimJti = "jti"

	// ClaimName represents the "name" claim.
	// Description: Full name
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimName = "name"

	// ClaimGivenName represents the "given_name" claim.
	// Description: Given name(s) or first name(s)
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimGivenName = "given_name"

	// ClaimFamilyName represents the "family_name" claim.
	// Description: Surname(s) or last name(s)
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimFamilyName = "family_name"

	// ClaimMiddleName represents the "middle_name" claim.
	// Description: Middle name(s)
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimMiddleName = "middle_name"

	// ClaimNickname represents the "nickname" claim.
	// Description: Casual name
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimNickname = "nickname"

	// ClaimPreferredUsername represents the "preferred_username" claim.
	// Description: Shorthand name by which the End-User wishes to be referred to
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimPreferredUsername = "preferred_username"

	// ClaimProfile represents the "profile" claim.
	// Description: Profile page URL
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimProfile = "profile"

	// ClaimPicture represents the "picture" claim.
	// Description: Profile picture URL
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimPicture = "picture"

	// ClaimWebsite represents the "website" claim.
	// Description: Web page or blog URL
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimWebsite = "website"

	// ClaimEmail represents the "email" claim.
	// Description: Preferred e-mail address
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimEmail = "email"

	// ClaimEmailVerified represents the "email_verified" claim.
	// Description: True if the e-mail address has been verified; otherwise false
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimEmailVerified = "email_verified"

	// ClaimGender represents the "gender" claim.
	// Description: Gender
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimGender = "gender"

	// ClaimBirthdate represents the "birthdate" claim.
	// Description: Birthday
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimBirthdate = "birthdate"

	// ClaimZoneinfo represents the "zoneinfo" claim.
	// Description: Time zone
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimZoneinfo = "zoneinfo"

	// ClaimLocale represents the "locale" claim.
	// Description: Locale
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimLocale = "locale"

	// ClaimPhoneNumber represents the "phone_number" claim.
	// Description: Preferred telephone number
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimPhoneNumber = "phone_number"

	// ClaimPhoneNumberVerified represents the "phone_number_verified" claim.
	// Description: True if the phone number has been verified; otherwise false
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimPhoneNumberVerified = "phone_number_verified"

	// ClaimAddress represents the "address" claim.
	// Description: Preferred postal address
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimAddress = "address"

	// ClaimUpdatedAt represents the "updated_at" claim.
	// Description: Time the information was last updated
	// Reference: [OpenID Connect Core 1.0, Section 5.1]
	ClaimUpdatedAt = "updated_at"

	// ClaimAzp represents the "azp" claim.
	// Description: Authorized party - the party to which the ID Token was issued
	// Reference: [OpenID Connect Core 1.0, Section 2]
	ClaimAzp = "azp"

	// ClaimNonce represents the "nonce" claim.
	//nolint:lll
	// Description: Value used to associate a Client session with an ID Token (MAY also be used for nonce values in other applications of JWTs)
	// Reference: [OpenID Connect Core 1.0, Section 2][RFC9449]
	ClaimNonce = "nonce"

	// ClaimAuthTime represents the "auth_time" claim.
	// Description: Time when the authentication occurred
	// Reference: [OpenID Connect Core 1.0, Section 2]
	ClaimAuthTime = "auth_time"

	// ClaimAtHash represents the "at_hash" claim.
	// Description: Access Token hash value
	// Reference: [OpenID Connect Core 1.0, Section 2]
	ClaimAtHash = "at_hash"

	// ClaimCHash represents the "c_hash" claim.
	// Description: Code hash value
	// Reference: [OpenID Connect Core 1.0, Section 3.3.2.11]
	ClaimCHash = "c_hash"

	// ClaimAcr represents the "acr" claim.
	// Description: Authentication Context Class Reference
	// Reference: [OpenID Connect Core 1.0, Section 2]
	ClaimAcr = "acr"

	// ClaimAmr represents the "amr" claim.
	// Description: Authentication Methods References
	// Reference: [OpenID Connect Core 1.0, Section 2]
	ClaimAmr = "amr"

	// ClaimSubJwk represents the "sub_jwk" claim.
	// Description: Public key used to check the signature of an ID Token
	// Reference: [OpenID Connect Core 1.0, Section 7.4]
	ClaimSubJwk = "sub_jwk"

	// ClaimCnf represents the "cnf" claim.
	// Description: Confirmation
	// Reference: [RFC7800, Section 3.1]
	ClaimCnf = "cnf"

	// ClaimSipFromTag represents the "sip_from_tag" claim.
	// Description: SIP From tag header field parameter value
	// Reference: [RFC8055][RFC3261]
	ClaimSipFromTag = "sip_from_tag"

	// ClaimSipDate represents the "sip_date" claim.
	// Description: SIP Date header field value
	// Reference: [RFC8055][RFC3261]
	ClaimSipDate = "sip_date"

	// ClaimSipCallid represents the "sip_callid" claim.
	// Description: SIP Call-Id header field value
	// Reference: [RFC8055][RFC3261]
	ClaimSipCallid = "sip_callid"

	// ClaimSipCseqNum represents the "sip_cseq_num" claim.
	// Description: SIP CSeq numeric header field parameter value
	// Reference: [RFC8055][RFC3261]
	ClaimSipCseqNum = "sip_cseq_num"

	// ClaimSipViaBranch represents the "sip_via_branch" claim.
	// Description: SIP Via branch header field parameter value
	// Reference: [RFC8055][RFC3261]
	ClaimSipViaBranch = "sip_via_branch"

	// ClaimOrig represents the "orig" claim.
	// Description: Originating Identity String
	// Reference: [RFC8225, Section 5.2.1]
	ClaimOrig = "orig"

	// ClaimDest represents the "dest" claim.
	// Description: Destination Identity String
	// Reference: [RFC8225, Section 5.2.1]
	ClaimDest = "dest"

	// ClaimMky represents the "mky" claim.
	// Description: Media Key Fingerprint String
	// Reference: [RFC8225, Section 5.2.2]
	ClaimMky = "mky"

	// ClaimEvents represents the "events" claim.
	// Description: Security Events
	// Reference: [RFC8417, Section 2.2]
	ClaimEvents = "events"

	// ClaimToe represents the "toe" claim.
	// Description: Time of Event
	// Reference: [RFC8417, Section 2.2]
	ClaimToe = "toe"

	// ClaimTxn represents the "txn" claim.
	// Description: Transaction Identifier
	// Reference: [RFC8417, Section 2.2]
	ClaimTxn = "txn"

	// ClaimRph represents the "rph" claim.
	// Description: Resource Priority Header Authorization
	// Reference: [RFC8443, Section 3]
	ClaimRph = "rph"

	// ClaimSid represents the "sid" claim.
	// Description: Session ID
	// Reference: [OpenID Connect Front-Channel Logout 1.0, Section 3]
	ClaimSid = "sid"

	// ClaimVot represents the "vot" claim.
	// Description: Vector of Trust value
	// Reference: [RFC8485]
	ClaimVot = "vot"

	// ClaimVtm represents the "vtm" claim.
	// Description: Vector of Trust trustmark URL
	// Reference: [RFC8485]
	ClaimVtm = "vtm"

	// ClaimAttest represents the "attest" claim.
	// Description: Attestation level as defined in SHAKEN framework
	// Reference: [RFC8588]
	ClaimAttest = "attest"

	// ClaimOrigid represents the "origid" claim.
	// Description: Originating Identifier as defined in SHAKEN framework
	// Reference: [RFC8588]
	ClaimOrigid = "origid"

	// ClaimAct represents the "act" claim.
	// Description: Actor
	// Reference: [RFC8693, Section 4.1]
	ClaimAct = "act"

	// ClaimScope represents the "scope" claim.
	// Description: Scope Values
	// Reference: [RFC8693, Section 4.2]
	ClaimScope = "scope"

	// ClaimClientId represents the "client_id" claim.
	// Description: Client Identifier
	// Reference: [RFC8693, Section 4.3]
	ClaimClientId = "client_id"

	// ClaimMayAct represents the "may_act" claim.
	// Description: Authorized Actor - the party that is authorized to become the actor
	// Reference: [RFC8693, Section 4.4]
	ClaimMayAct = "may_act"

	// ClaimJcard represents the "jcard" claim.
	// Description: jCard data
	// Reference: [RFC8688][RFC7095]
	ClaimJcard = "jcard"

	// ClaimAtUseNbr represents the "at_use_nbr" claim.
	// Description: Number of API requests for which the access token can be used
	// Reference: [ETSI GS NFV-SEC 022 V2.7.1]
	ClaimAtUseNbr = "at_use_nbr"

	// ClaimDiv represents the "div" claim.
	// Description: Diverted Target of a Call
	// Reference: [RFC8946]
	ClaimDiv = "div"

	// ClaimOpt represents the "opt" claim.
	// Description: Original PASSporT (in Full Form)
	// Reference: [RFC8946]
	ClaimOpt = "opt"

	// ClaimVc represents the "vc" claim.
	// Description: Verifiable Credential as specified in the W3C Recommendation
	//nolint:lll
	// Reference: [W3C Recommendation Verifiable Credentials Data Model 1.0 - Expressing verifiable information on the Web (19 November 2019), Section 6.3.1]
	ClaimVc = "vc"

	// ClaimVp represents the "vp" claim.
	// Description: Verifiable Presentation as specified in the W3C Recommendation
	//nolint:lll
	// Reference: [W3C Recommendation Verifiable Credentials Data Model 1.0 - Expressing verifiable information on the Web (19 November 2019), Section 6.3.1]
	ClaimVp = "vp"

	// ClaimSph represents the "sph" claim.
	// Description: SIP Priority header field
	// Reference: [RFC9027]
	ClaimSph = "sph"

	// ClaimAceProfile represents the "ace_profile" claim.
	// Description: The ACE profile a token is supposed to be used with.
	// Reference: [RFC9200, Section 5.10]
	ClaimAceProfile = "ace_profile"

	// ClaimCnonce represents the "cnonce" claim.
	//nolint:lll
	// Description: "client-nonce". A nonce previously provided to the AS by the RS via the client. Used to verify token freshness when the RS cannot synchronize its clock with the AS.
	// Reference: [RFC9200, Section 5.10]
	ClaimCnonce = "cnonce"

	// ClaimExi represents the "exi" claim.
	//nolint:lll
	// Description: "Expires in". Lifetime of the token in seconds from the time the RS first sees it. Used to implement a weaker from of token expiration for devices that cannot synchronize their internal clocks.
	// Reference: [RFC9200, Section 5.10.3]
	ClaimExi = "exi"

	// ClaimRoles represents the "roles" claim.
	// Description: Roles
	// Reference: [RFC7643, Section 4.1.2][RFC9068, Section 2.2.3.1]
	ClaimRoles = "roles"

	// ClaimGroups represents the "groups" claim.
	// Description: Groups
	// Reference: [RFC7643, Section 4.1.2][RFC9068, Section 2.2.3.1]
	ClaimGroups = "groups"

	// ClaimEntitlements represents the "entitlements" claim.
	// Description: Entitlements
	// Reference: [RFC7643, Section 4.1.2][RFC9068, Section 2.2.3.1]
	ClaimEntitlements = "entitlements"

	// ClaimTokenIntrospection represents the "token_introspection" claim.
	// Description: Token introspection response
	// Reference: [RFC9701, Section 5]
	ClaimTokenIntrospection = "token_introspection"

	// ClaimEatNonce represents the "eat_nonce" claim.
	// Description: Nonce
	// Reference: [RFC9711]
	ClaimEatNonce = "eat_nonce"

	// ClaimUeid represents the "ueid" claim.
	// Description: Universal Entity ID
	// Reference: [RFC9711]
	ClaimUeid = "ueid"

	// ClaimSueids represents the "sueids" claim.
	// Description: Semipermanent UEIDs
	// Reference: [RFC9711]
	ClaimSueids = "sueids"

	// ClaimOemid represents the "oemid" claim.
	// Description: Hardware OEM ID
	// Reference: [RFC9711]
	ClaimOemid = "oemid"

	// ClaimHwmodel represents the "hwmodel" claim.
	// Description: Model identifier for hardware
	// Reference: [RFC9711]
	ClaimHwmodel = "hwmodel"

	// ClaimHwversion represents the "hwversion" claim.
	// Description: Hardware Version Identifier
	// Reference: [RFC9711]
	ClaimHwversion = "hwversion"

	// ClaimOemboot represents the "oemboot" claim.
	// Description: Indicates whether the software booted was OEM authorized
	// Reference: [RFC9711]
	ClaimOemboot = "oemboot"

	// ClaimDbgstat represents the "dbgstat" claim.
	// Description: The status of debug facilities
	// Reference: [RFC9711]
	ClaimDbgstat = "dbgstat"

	// ClaimLocation represents the "location" claim.
	// Description: The geographic location
	// Reference: [RFC9711]
	ClaimLocation = "location"

	// ClaimEatProfile represents the "eat_profile" claim.
	// Description: The EAT profile followed
	// Reference: [RFC9711]
	ClaimEatProfile = "eat_profile"

	// ClaimSubmods represents the "submods" claim.
	// Description: The section containing submodules
	// Reference: [RFC9711]
	ClaimSubmods = "submods"

	// ClaimUptime represents the "uptime" claim.
	// Description: Uptime
	// Reference: [RFC9711]
	ClaimUptime = "uptime"

	// ClaimBootcount represents the "bootcount" claim.
	// Description: The number of times the entity or submodule has been booted
	// Reference: [RFC9711]
	ClaimBootcount = "bootcount"

	// ClaimBootseed represents the "bootseed" claim.
	// Description: Identifies a boot cycle
	// Reference: [RFC9711]
	ClaimBootseed = "bootseed"

	// ClaimDloas represents the "dloas" claim.
	// Description: Certifications received as Digital Letters of Approval
	// Reference: [RFC9711]
	ClaimDloas = "dloas"

	// ClaimSwname represents the "swname" claim.
	// Description: The name of the software running in the entity
	// Reference: [RFC9711]
	ClaimSwname = "swname"

	// ClaimSwversion represents the "swversion" claim.
	// Description: The version of software running in the entity
	// Reference: [RFC9711]
	ClaimSwversion = "swversion"

	// ClaimManifests represents the "manifests" claim.
	// Description: Manifests describing the software installed on the entity
	// Reference: [RFC9711]
	ClaimManifests = "manifests"

	// ClaimMeasurements represents the "measurements" claim.
	// Description: Measurements of the software, memory configuration, and such on the entity
	// Reference: [RFC9711]
	ClaimMeasurements = "measurements"

	// ClaimMeasres represents the "measres" claim.
	// Description: The results of comparing software measurements to reference values
	// Reference: [RFC9711]
	ClaimMeasres = "measres"

	// ClaimIntuse represents the "intuse" claim.
	// Description: The intended use of the EAT
	// Reference: [RFC9711]
	ClaimIntuse = "intuse"

	// ClaimCdniv represents the "cdniv" claim.
	// Description: CDNI Claim Set Version
	// Reference: [RFC9246, Section 2.1.8]
	ClaimCdniv = "cdniv"

	// ClaimCdnicrit represents the "cdnicrit" claim.
	// Description: CDNI Critical Claims Set
	// Reference: [RFC9246, Section 2.1.9]
	ClaimCdnicrit = "cdnicrit"

	// ClaimCdniip represents the "cdniip" claim.
	// Description: CDNI IP Address
	// Reference: [RFC9246, Section 2.1.10]
	ClaimCdniip = "cdniip"

	// ClaimCdniuc represents the "cdniuc" claim.
	// Description: CDNI URI Container
	// Reference: [RFC9246, Section 2.1.11]
	ClaimCdniuc = "cdniuc"

	// ClaimCdniets represents the "cdniets" claim.
	// Description: CDNI Expiration Time Setting for Signed Token Renewal
	// Reference: [RFC9246, Section 2.1.12]
	ClaimCdniets = "cdniets"

	// ClaimCdnistt represents the "cdnistt" claim.
	// Description: CDNI Signed Token Transport Method for Signed Token Renewal
	// Reference: [RFC9246, Section 2.1.13]
	ClaimCdnistt = "cdnistt"

	// ClaimCdnistd represents the "cdnistd" claim.
	// Description: CDNI Signed Token Depth
	// Reference: [RFC9246, Section 2.1.14]
	ClaimCdnistd = "cdnistd"

	// ClaimSigValClaims represents the "sig_val_claims" claim.
	// Description: Signature Validation Token
	// Reference: [RFC9321, Section 3.2.3]
	ClaimSigValClaims = "sig_val_claims"

	// ClaimAuthorizationDetails represents the "authorization_details" claim.
	//nolint:lll
	// Description: The claim authorization_details contains a JSON array of JSON objects representing the rights of the access token. Each JSON object contains the data to specify the authorization requirements for a certain type of resource.
	// Reference: [RFC9396, Section 9.1]
	ClaimAuthorizationDetails = "authorization_details"

	// ClaimVerifiedClaims represents the "verified_claims" claim.
	//nolint:lll
	// Description: A structured claim containing end-user claims and the details of how those end-user claims were assured.
	// Reference: [OpenID Identity Assurance Schema Definition 1.0, Section 5]
	ClaimVerifiedClaims = "verified_claims"

	// ClaimPlaceOfBirth represents the "place_of_birth" claim.
	//nolint:lll
	// Description: A structured claim representing the end-user's place of birth.
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimPlaceOfBirth = "place_of_birth"

	// ClaimNationalities represents the "nationalities" claim.
	// Description: String array representing the end-user's nationalities.
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimNationalities = "nationalities"

	// ClaimBirthFamilyName represents the "birth_family_name" claim.
	//nolint:lll
	// Description: Family name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the family name(s) later in life for any reason. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimBirthFamilyName = "birth_family_name"

	// ClaimBirthGivenName represents the "birth_given_name" claim.
	//nolint:lll
	// Description: Given name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the given name later in life for any reason. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimBirthGivenName = "birth_given_name"

	// ClaimBirthMiddleName represents the "birth_middle_name" claim.
	//nolint:lll
	// Description: Middle name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the middle name later in life for any reason. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimBirthMiddleName = "birth_middle_name"

	// ClaimSalutation represents the "salutation" claim.
	// Description: End-user's salutation, e.g., "Mr"
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimSalutation = "salutation"

	// ClaimTitle represents the "title" claim.
	// Description: End-user's title, e.g., "Dr"
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimTitle = "title"

	// ClaimMsisdn represents the "msisdn" claim.
	// Description: End-user's mobile phone number formatted according to ITU-T recommendation [E.164]
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimMsisdn = "msisdn"

	// ClaimAlsoKnownAs represents the "also_known_as" claim.
	//nolint:lll
	// Description: Stage name, religious name or any other type of alias/pseudonym with which a person is known in a specific context besides its legal name.
	// Reference: [OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4]
	ClaimAlsoKnownAs = "also_known_as"

	// ClaimHtm represents the "htm" claim.
	// Description: The HTTP method of the request
	// Reference: [RFC9449, Section 4.2]
	ClaimHtm = "htm"

	// ClaimHtu represents the "htu" claim.
	// Description: The HTTP URI of the request (without query and fragment parts)
	// Reference: [RFC9449, Section 4.2]
	ClaimHtu = "htu"

	// ClaimAth represents the "ath" claim.
	// Description: The base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value
	// Reference: [RFC9449, Section 4.2]
	ClaimAth = "ath"

	// ClaimAtc represents the "atc" claim.
	// Description: Authority Token Challenge
	// Reference: [RFC9447]
	ClaimAtc = "atc"

	// ClaimSubId represents the "sub_id" claim.
	// Description: Subject Identifier
	// Reference: [RFC9493, Section 4.1]
	ClaimSubId = "sub_id"

	// ClaimRcd represents the "rcd" claim.
	// Description: Rich Call Data Information
	// Reference: [RFC9795]
	ClaimRcd = "rcd"

	// ClaimRcdi represents the "rcdi" claim.
	// Description: Rich Call Data Integrity Information
	// Reference: [RFC9795]
	ClaimRcdi = "rcdi"

	// ClaimCrn represents the "crn" claim.
	// Description: Call Reason
	// Reference: [RFC9795]
	ClaimCrn = "crn"

	// ClaimMsgi represents the "msgi" claim.
	// Description: Message Integrity Information
	// Reference: [RFC9475]
	ClaimMsgi = "msgi"

	// ClaimClaimNames represents the "_claim_names" claim.
	// Description: JSON object whose member names are the Claim Names for the Aggregated and Distributed Claims
	// Reference: [OpenID Connect Core 1.0, Section 5.6.2]
	ClaimClaimNames = "_claim_names"

	// ClaimClaimSources represents the "_claim_sources" claim.
	// Description: JSON object whose member names are referenced by the member values of the _claim_names member
	// Reference: [OpenID Connect Core 1.0, Section 5.6.2]
	ClaimClaimSources = "_claim_sources"

	// ClaimRdapAllowedPurposes represents the "rdap_allowed_purposes" claim.
	//nolint:lll
	// Description: This claim describes the set of RDAP query purposes that are available to an identity that is presented for access to a protected RDAP resource.
	// Reference: [RFC9560, Section 3.1.5.1]
	ClaimRdapAllowedPurposes = "rdap_allowed_purposes"

	// ClaimRdapDntAllowed represents the "rdap_dnt_allowed" claim.
	//nolint:lll
	// Description: This claim contains a JSON boolean literal that describes a "do not track" request for server-side tracking, logging, or recording of an identity that is presented for access to a protected RDAP resource.
	// Reference: [RFC9560, Section 3.1.5.2]
	ClaimRdapDntAllowed = "rdap_dnt_allowed"

	// ClaimGeohash represents the "geohash" claim.
	// Description: Geohash String or Array
	// Reference: [Fast and Readable Geographical Hashing (CTA-5009)]
	ClaimGeohash = "geohash"

	// ClaimSd represents the "_sd" claim.
	// Description: Digests of Disclosures for object properties
	// Reference: [RFC9901, Section 4.2.4.1]
	ClaimSd = "_sd"

	// ClaimSdAlg represents the "_sd_alg" claim.
	// Description: Hash algorithm used to generate Disclosure digests and digest over presentation
	// Reference: [RFC9901, Section 4.1.1]
	ClaimSdAlg = "_sd_alg"

	// ClaimSdHash represents the "sd_hash" claim.
	// Description: Digest of the SD-JWT to which the KB-JWT is tied
	// Reference: [RFC9901, Section 4.3]
	ClaimSdHash = "sd_hash"

	// ClaimConsumerplmnid represents the "consumerPlmnId" claim.
	// Description: PLMN ID of the NF service consumer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimConsumerplmnid = "consumerPlmnId"

	// ClaimConsumersnpnid represents the "consumerSnpnId" claim.
	// Description: SNPN ID of the NF service consumer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimConsumersnpnid = "consumerSnpnId"

	// ClaimProducerplmnid represents the "producerPlmnId" claim.
	// Description: PLMN ID of the NF service producer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimProducerplmnid = "producerPlmnId"

	// ClaimProducersnpnid represents the "producerSnpnId" claim.
	// Description: SNPN ID of the NF service producer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimProducersnpnid = "producerSnpnId"

	// ClaimProducersnssailist represents the "producerSnssaiList" claim.
	// Description: list of S-NSSAIs of the NF service producer which are authorized for the NF service consumer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimProducersnssailist = "producerSnssaiList"

	// ClaimProducernsilist represents the "producerNsiList" claim.
	// Description: List of NSIs of the NF service producer which are authorized for the NF service consumer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimProducernsilist = "producerNsiList"

	// ClaimProducernfsetid represents the "producerNfSetId" claim.
	// Description: NF Set ID of the NF service producer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimProducernfsetid = "producerNfSetId"

	// ClaimProducernfservicesetid represents the "producerNfServiceSetId" claim.
	// Description: NF Service Set ID of the NF Service Producer
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimProducernfservicesetid = "producerNfServiceSetId"

	// ClaimSourcenfinstanceid represents the "sourceNfInstanceId" claim.
	// Description: NF Instance ID of the source NF
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimSourcenfinstanceid = "sourceNfInstanceId"

	// ClaimAnalyticsidlist represents the "analyticsIdList" claim.
	// Description: Analytics IDs
	// Reference: [3GPP TS 29.510, Clause 6.3.5.2.4]
	ClaimAnalyticsidlist = "analyticsIdList"

	// ClaimResownerid represents the "resOwnerId" claim.
	//nolint:lll
	// Description: Contains the identifier of the resource owner, e.g., GPSI as specified in clause 5.3.2 of [3GPP TS 29.571].
	// Reference: [3GPP TS 29.222, Clause 8.5.4.2.8]
	ClaimResownerid = "resOwnerId"

	// ClaimCmw represents the "cmw" claim.
	// Description: A RATS Conceptual Message Wrapper
	// Reference: [RFC-ietf-rats-msg-wrap-22, Sections 3.1, 3.3]
	ClaimCmw = "cmw"

	// ClaimJwks represents the "jwks" claim.
	// Description: JSON Web Key Set
	// Reference: [OpenID Federation 1.0, Section 13.1]
	ClaimJwks = "jwks"

	// ClaimMetadata represents the "metadata" claim.
	// Description: Metadata object
	// Reference: [OpenID Federation 1.0, Section 13.2]
	ClaimMetadata = "metadata"

	// ClaimConstraints represents the "constraints" claim.
	// Description: Constraints object
	// Reference: [OpenID Federation 1.0, Section 13.3]
	ClaimConstraints = "constraints"

	// ClaimCrit represents the "crit" claim.
	//nolint:lll
	// Description: List of Claims in this JWT defined by extensions to this kind of JWT that MUST be understood and processed
	// Reference: [OpenID Federation 1.0, Section 13.4]
	ClaimCrit = "crit"

	// ClaimRef represents the "ref" claim.
	// Description: Reference
	// Reference: [OpenID Federation 1.0, Section 13.5]
	ClaimRef = "ref"

	// ClaimDelegation represents the "delegation" claim.
	// Description: Delegation
	// Reference: [OpenID Federation 1.0, Section 13.6]
	ClaimDelegation = "delegation"

	// ClaimLogoUri represents the "logo_uri" claim.
	// Description: URI referencing a logo
	// Reference: [OpenID Federation 1.0, Section 13.7]
	ClaimLogoUri = "logo_uri"

	// ClaimAuthorityHints represents the "authority_hints" claim.
	// Description: Authority Hints
	// Reference: [OpenID Federation 1.0, Section 3.2]
	ClaimAuthorityHints = "authority_hints"

	// ClaimTrustAnchorHints represents the "trust_anchor_hints" claim.
	// Description: Trust Anchor Hints
	// Reference: [OpenID Federation 1.0, Section 3.2]
	ClaimTrustAnchorHints = "trust_anchor_hints"

	// ClaimTrustMarks represents the "trust_marks" claim.
	// Description: Trust Marks
	// Reference: [OpenID Federation 1.0, Section 3.2]
	ClaimTrustMarks = "trust_marks"

	// ClaimTrustMarkIssuers represents the "trust_mark_issuers" claim.
	// Description: Trust Mark Issuers
	// Reference: [OpenID Federation 1.0, Section 3.2]
	ClaimTrustMarkIssuers = "trust_mark_issuers"

	// ClaimTrustMarkOwners represents the "trust_mark_owners" claim.
	// Description: Trust Mark Owners
	// Reference: [OpenID Federation 1.0, Section 3.2]
	ClaimTrustMarkOwners = "trust_mark_owners"

	// ClaimMetadataPolicy represents the "metadata_policy" claim.
	// Description: Metadata Policy object
	// Reference: [OpenID Federation 1.0, Section 3.3]
	ClaimMetadataPolicy = "metadata_policy"

	// ClaimMetadataPolicyCrit represents the "metadata_policy_crit" claim.
	// Description: Critical Metadata Policy Operators
	// Reference: [OpenID Federation 1.0, Section 3.3]
	ClaimMetadataPolicyCrit = "metadata_policy_crit"

	// ClaimSourceEndpoint represents the "source_endpoint" claim.
	// Description: Source Endpoint URL
	// Reference: [OpenID Federation 1.0, Section 3.3]
	ClaimSourceEndpoint = "source_endpoint"

	// ClaimKeys represents the "keys" claim.
	// Description: Array of JWK values in a JWK Set
	// Reference: [OpenID Federation 1.0, Section 5.2.1]
	ClaimKeys = "keys"

	// ClaimTrustMarkType represents the "trust_mark_type" claim.
	// Description: Trust Mark Type Identifier
	// Reference: [OpenID Federation 1.0, Section 7.1]
	ClaimTrustMarkType = "trust_mark_type"

	// ClaimTrustChain represents the "trust_chain" claim.
	// Description: Trust Chain
	// Reference: [OpenID Federation 1.0, Section 8.3.2]
	ClaimTrustChain = "trust_chain"

	// ClaimTrustAnchor represents the "trust_anchor" claim.
	// Description: Trust Anchor ID
	// Reference: [OpenID Federation 1.0, Section 12.2.3]
	ClaimTrustAnchor = "trust_anchor"
)

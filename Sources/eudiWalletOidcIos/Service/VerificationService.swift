//
//  VerificationService.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
import CryptoKit
import PresentationExchangeSdkiOS
import SwiftCBOR
import OrderedCollections
import Security
import ASN1Decoder


public class VerificationService: NSObject, VerificationServiceProtocol {
    
    var keyHandler: SecureKeyProtocol
    
    // MARK: - A custom initialiser with dependency injection for encryption key generation handler
    ///
    /// - Parameters:
    ///   - keyhandler: A handler to encryption key generation class
    /// - Returns: An `VerificationService` object
    public required init(keyhandler: SecureKeyProtocol) {
        keyHandler = keyhandler
    }
    
    
    public func processOrSendAuthorizationResponse(
        did: String,
        presentationRequest: PresentationRequest?,
        credentialsList: [String]?,
        wua: String,
        pop: String) async -> WrappedVerificationResponse? {
            
            let params = await AuthorisationResponseHandler().prepareAuthorisationResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler) ?? [:]
            guard let redirectURL = presentationRequest?.redirectUri else {return nil}
            return await sendVPRequest(params: params, redirectURI: presentationRequest?.redirectUri ?? "", wua: wua, pop: pop)
        }
        
//    func createVPToken(presentationRequest: PresentationRequest?, format: String, credentialsList: [String]?, presentationDefinition :PresentationDefinitionModel?, did: String, header: String, payload: String) async -> (String, String) {
//            var vpToken: String = ""
//            var idToken: String = ""
//            if format == "mso_mdoc" {
//                vpToken = MDocVpTokenBuilder().build(credentials: credentialsList ?? [], presentationRequest: presentationRequest, did: did, index: <#Int#>) ?? ""
//            } else {
//                if presentationRequest?.responseType == "vp_token" {
//                    vpToken = await generateVPToken(header: header, payload: payload)
//                } else if presentationRequest?.responseType == "id_token" {
//                    idToken =  await generateJWTokenForIDtokenRequest(didKeyIdentifier: did, authorizationEndpoint: presentationRequest?.clientId ?? "", nonce: presentationRequest?.nonce ?? "")
//                }
//            }
//            return (vpToken, idToken)
//        }
    
    public func processAuthorisationRequest(data: String?) async -> (PresentationRequest?, EUDIError?) {
            guard let _ = data else { return (nil, nil) }
            
            if let code = data {
                let state = URL(string: code)?.queryParameters?["state"] ?? ""
                let nonce = URL(string: code)?.queryParameters?["nonce"] ?? ""
                let responseUri = URL(string: code)?.queryParameters?["response_uri"] ?? ""
                let redirectUri = URL(string: code)?.queryParameters?["redirect_uri"] ?? responseUri
                let clientID = URL(string: code)?.queryParameters?["client_id"] ?? ""
                let responseType = URL(string: code)?.queryParameters?["response_type"] ?? ""
                let scope = URL(string: code)?.queryParameters?["scope"] ?? ""
                let requestUri = URL(string: code)?.queryParameters?["request_uri"] ?? ""
                let responseMode = URL(string: code)?.queryParameters?["response_mode"] ?? ""
                var presentationDefinition = URL(string: code)?.queryParameters?["presentation_definition"] ?? ""
                var clientMetaData = URL(string: code)?.queryParameters?["client_metadata"] ?? ""
                var presentationDefinitionUri = URL(string: code)?.queryParameters?["presentation_definition_uri"] ?? ""
                var clientMetaDataUri = URL(string: code)?.queryParameters?["client_metadata_uri"] ?? ""
                var clientIDScheme = URL(string: code)?.queryParameters?["client_id_scheme"] ?? ""
                var request = URL(string: code)?.queryParameters?["request"] ?? ""
                
                if presentationDefinition != "" || presentationDefinitionUri != "" {
                    var presentationRequest =  PresentationRequest(state: state,
                                                                   clientId: clientID,
                                                                   redirectUri: redirectUri ?? responseUri,
                                                                   responseUri: responseUri,
                                                                   responseType: responseType,
                                                                   responseMode: responseMode,
                                                                   scope: scope,
                                                                   nonce: nonce,
                                                                   requestUri: requestUri,
                                                                   presentationDefinition: presentationDefinition,
                                                                   clientMetaData: clientMetaData,
                                                                   presentationDefinitionUri: presentationDefinitionUri, clientMetaDataUri: clientMetaDataUri, clientIDScheme: clientIDScheme, transactionData: [""], dcqlQuery: nil, request: request
                    )
                    if presentationDefinition == "" && presentationDefinitionUri != "" {
                        let presentationDefinitionFromUri = await resolvePresentationDefinitionFromURI(url: presentationDefinitionUri)
                        presentationRequest.presentationDefinition = presentationDefinitionFromUri
                    }
                    if clientMetaData == "" && clientMetaDataUri != "" {
                        let clientMetaDataFromUri = await resolveClientMetaDataFromURI(url: clientMetaDataUri)
                        presentationRequest.clientMetaData = clientMetaDataFromUri
                    }
                    return (presentationRequest, nil)
                    
                } else if requestUri != "" {
                    var request = URLRequest(url: URL(string: requestUri)!)
                    request.httpMethod = "GET"
                    
                    do {
                        let (data, response) = try await URLSession.shared.data(for: request)
                        if let res = response as? HTTPURLResponse, res.statusCode >= 400 {
                            let dataString = String(data: data, encoding: .utf8)
                            let errorMsg = ErrorHandler.processError(data: data, contentType: res.value(forHTTPHeaderField: "Content-Type"))
                            return(nil, errorMsg)
                        } else {
                        let jsonDecoder = JSONDecoder()
                        var model = try? jsonDecoder.decode(PresentationRequest.self, from: data)
                        if model == nil {
                            if let jwtString = String(data: data, encoding: .utf8) {
                                do {
                                    let segments = jwtString.split(separator: ".")
                                    if segments.count == 3 {
                                        guard let jsonPayload = try? jwtString.decodeJWT(jwtToken: jwtString) else { return (nil, nil) }
                                        guard let data = try? JSONSerialization.data(withJSONObject: jsonPayload, options: []) else { return (nil, nil) }
                                        var model = try jsonDecoder.decode(PresentationRequest.self, from: data)
                                        let requestData = model.request
                                        if model.request == nil {
                                            model.request = jwtString
                                        } else {
                                            model.request = requestData
                                        }
                                        do {
                                            let updatedModel = try await ClientIdSchemeRequestHandler().handle(jwtRequest: model.request, presentationRequest: model)
                                            return (updatedModel, nil)
                                        } catch  PresentationRequestError.requestValidationFailed {
                                            let error = EUDIError(from: ErrorResponse(message:"Request validation failed", code: nil))
                                            return (nil, error)
                                        }
                                       // model.request = model.request != nil ? model.request : jwtString
                                    }
                                } catch {
                                    debugPrint("Error:\(error)")
                                }
                            } else {
                                let error = EUDIError(from: ErrorResponse(message:"Invalid DID", code: nil))
                                debugPrint(error)
                                return (nil, error)
                            }
                        }
                        if model?.presentationDefinition == nil && model?.presentationDefinitionUri != "" {
                            let presentationDefinitionFromUri = await resolvePresentationDefinitionFromURI(url: model?.presentationDefinitionUri)
                            model?.presentationDefinition = presentationDefinitionFromUri
                        }
                        if model?.clientMetaData == nil && model?.clientMetaDataUri != "" {
                            let clientMetaDataFromUri = await resolveClientMetaDataFromURI(url: model?.clientMetaDataUri)
                            model?.clientMetaData = clientMetaDataFromUri
                        }
                        return (model, nil)
                    }
                    } catch {
                        let errorMsg = EUDIError(from: ErrorResponse(message: error.localizedDescription, code: nil))
                        debugPrint(error)
                        return (nil, errorMsg)
                        debugPrint("Error:\(error)")
                    }
                }
            }
            
            return (nil, nil)
        }
    
    func base64UrlToBase64(_ base64Url: String) -> String {
        var base64 = base64Url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        // Add padding if needed
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        
        return base64
    }
    
    func resolvePresentationDefinitionFromURI(url: String?) async -> String? {
        if let uri = URL(string: url ?? "") {
            var request = URLRequest(url: uri)
            request.httpMethod = "GET"
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                if let presentationDefinitionFromUri = String(data: data, encoding: .utf8) {
                    return presentationDefinitionFromUri
                } else {
                    debugPrint("Error: Could not resolve presentation_definition from URI")
                    return nil
                }
            } catch {
                debugPrint("Error while fetching presentation_definition from URI: \(error)")
                return nil
            }
        }
        return nil
    }
    
    func resolveClientMetaDataFromURI(url: String?) async -> String? {
        if let uri = URL(string: url ?? "") {
            var request = URLRequest(url: uri)
            request.httpMethod = "GET"
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                if let clientMetaDataFromUri = String(data: data, encoding: .utf8) {
                    return clientMetaDataFromUri
                } else {
                    debugPrint("Error: Could not resolve presentation_definition from URI")
                    return nil
                }
            } catch {
                debugPrint("Error while fetching presentation_definition from URI: \(error)")
                return nil
            }
        }
        return nil
    }
    
    
    
    private func generateJWTPayload(did: String, nonce: String, credentialsList: [String], state: String, clientID: String, transactionData: String? = nil) async -> String {
        var updatedCredentialList: [String] = []
        for item in credentialsList {
                var claims: [String: Any] = [:]
            if let transactionData = transactionData, !transactionData.isEmpty {
                claims["transaction_data_hashes"] = [self.generateHash(input: transactionData)]
                claims["transaction_data_hashes_alg"] = "sha-256"
            }
            claims["aud"] = clientID
            claims["nonce"] = nonce
            let split = item.split(separator: ".")
            var dict: [String: Any] = [:]
            if split.count > 1 {
                let jsonString = "\(split[1])".decodeBase64() ?? ""
                dict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) ?? [:]
            }
            var itemWithTilda: String? = nil
            if item.hasSuffix("~") {
                itemWithTilda = item
            } else {
                itemWithTilda = "\(item)~"
            }
            if let keyBindingJwt = await KeyBindingJwtService().generateKeyBindingJwt(issuerSignedJwt: itemWithTilda, claims: claims, keyHandler: keyHandler), let vct = dict["vct"] as? String, !vct.isEmpty{
                 var updatedCred = "\(itemWithTilda ?? "")\(keyBindingJwt)"
                updatedCredentialList.append(updatedCred)
            } else {
                updatedCredentialList.append(item)
            }
        }
        let uuid4 = UUID().uuidString
        let vp =
        ([
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "holder": did,
            "id": "urn:uuid:\(uuid4)",
            "type": [
                "VerifiablePresentation"
            ],
            "verifiableCredential": updatedCredentialList
        ] as [String : Any])
        
        let currentTime = Int(Date().timeIntervalSince1970)
        
        return ([
            "aud": clientID,
            "exp": currentTime + 3600,
            "iat": currentTime,
            "iss": "\(did)",
            "jti": "urn:uuid:\(uuid4)",
            "nbf": currentTime,
            "nonce": "\(nonce)",
            "sub": "\(did)",
            "vp": vp,
        ] as [String : Any]).toString() ?? ""
    }
    
    private func generateVPToken(header: String, payload: String) async -> String {
        let headerData = Data(header.utf8)
       
        let secureData = await keyHandler.generateSecureKey()
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return ""}
       
        return idToken
    }
    
    public func generateJWTokenForIDtokenRequest(
            didKeyIdentifier: String,
            authorizationEndpoint: String,
            nonce: String
           ) async -> String{
            // Generate JWT header
            let header =
            ([
                "typ": "JWT",
                "alg": "ES256",
                "kid": "\(didKeyIdentifier)#\(didKeyIdentifier.replacingOccurrences(of: "did:key:", with: ""))"
            ]).toString() ?? ""
            
            // Generate JWT payload
            let currentTime = Int(Date().timeIntervalSince1970)
            let payload =
            ([
                "iss": "\(didKeyIdentifier)",
                "sub": "\(didKeyIdentifier)",
                "aud": "\(authorizationEndpoint)",
                "exp": currentTime + 3600,
                "iat": currentTime,
                "nonce": "\(nonce)"
            ] as [String : Any]).toString() ?? ""
            
            // Create JWT token
            let headerData = Data(header.utf8)
            let payloadData = Data(payload.utf8)
            
            let secureData = await keyHandler.generateSecureKey()
                guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return ""}
            return idToken
        }
    
    func createParamsForSendVPRequest(token: [String], idToken: String, presentationSubmission: String, state: String, responseType: String) -> [String: Any]{
        var params: [String: Any] = [:]
        var vpToken: Any? = nil
        if token.count == 1 {
            vpToken = token[0]
        } else {
            vpToken = token
        }
        if responseType.contains("vp_token") && responseType.contains("id_token") {
            guard let vpToken = vpToken else { return [:]}
            params = ["vp_token": vpToken , "id_token": idToken ,"presentation_submission": presentationSubmission ?? "", "state": state]
        } else if responseType.contains("vp_token") {
            guard let vpToken = vpToken else { return [:]}
            params = ["vp_token": vpToken , "presentation_submission": presentationSubmission ?? "", "state": state]
        } else if responseType.contains("id_token") {
            params = ["id_token": idToken, "state": state]
        }
        return params
    }
    
    private func sendVPRequest(params: [String: Any], redirectURI: String, wua: String, pop: String) async -> WrappedVerificationResponse? {
        let postString = UIApplicationUtils.shared.getPostString(params: params)
        let paramsData = postString.data(using: .utf8)
        
        var request = URLRequest(url: URL(string: redirectURI)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(wua, forHTTPHeaderField: "OAuth-Client-Attestation")
        request.setValue(pop, forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
        request.httpBody = paramsData
        
        // Performing the token request
        var responseUrl = ""
        do {
            let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
            
            let (data, response) = try await session.data(for: request)
            
            
            let httpres = response as? HTTPURLResponse
            
            if httpres?.statusCode == 302 {
                if let location = httpres?.value(forHTTPHeaderField: "Location") {
                    responseUrl = location
                    let url = URL.init(string: location)
                    if let errorDescription = url?.queryParameters?["error_description"] as? String {
                        let error = errorDescription.replacingOccurrences(of: "+", with: " ").data(using: .utf8)
                        return WrappedVerificationResponse(data: nil, error: ErrorHandler.processError(data: error, contentType: httpres?.value(forHTTPHeaderField: "Content-Type")))
                    } else {
                        return WrappedVerificationResponse(data: responseUrl, error: nil)
                    }
                } else {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=1", error: nil)
                }
            } else if httpres?.statusCode == 200 || httpres?.statusCode == 204 {
                if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let redirectUri = jsonResponse["redirect_uri"] as? String {
                    return WrappedVerificationResponse(data: redirectUri, error: nil)
                } else {
                    return WrappedVerificationResponse(data: "https://www.example.com?code=1", error: nil)
                }
            } else if httpres?.statusCode ?? 400 >= 400 {
                return WrappedVerificationResponse(data: nil, error: ErrorHandler.processError(data: data, contentType: httpres?.value(forHTTPHeaderField: "Content-Type")))
            } else{
                guard let dataString = String(data: data, encoding: .utf8) else {
                    return WrappedVerificationResponse(data: "data", error: nil)
                }
                return WrappedVerificationResponse(data: dataString, error: nil)
            }
        } catch {
            debugPrint("JSON Serialization Error: \(error)")
            return nil
        }
    }
    
    
    public static func processPresentationDefinition(_ presentationDefinition: Any?) throws -> PresentationDefinitionModel {
        do {
            guard let presentationDefinition = presentationDefinition else {
                throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid presentation definition"])
            }
            
            if let presentationDefinition = presentationDefinition as? PresentationDefinitionModel {
                return presentationDefinition
            } else if let linkedTreeMap = presentationDefinition as? [AnyHashable: Any] {
                let jsonData = try JSONSerialization.data(withJSONObject: linkedTreeMap)
                let jsonString = String(data: jsonData, encoding: .utf8) ?? ""
                return try JSONDecoder().decode(PresentationDefinitionModel.self, from: jsonString.data(using: .utf8) ?? Data())
            } else if let jsonString = presentationDefinition as? String {
                let str = jsonString.replacingOccurrences(of: "+", with: "")
                let data = str.data(using: .utf8)
                let model = try JSONDecoder().decode(PresentationDefinitionModel.self, from: data!)
                return model
            } else {
                throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid presentation definition format"])
            }
        } catch {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Error processing presentation definition"])
        }
    }
    
    public func filterCredentials(credentialList: [String?], presentationDefinition: PresentationDefinitionModel) -> [[String]] {
        var response: [[String]] = []
        
        if let inputDescriptors = presentationDefinition.inputDescriptors {
            for inputDescriptor in inputDescriptors {
        var processedCredentials:[String] = []
                var tempCredentialList: [String?] = []
                var credentialFormat: String = ""
                if let format = presentationDefinition.format ?? inputDescriptor.format {
                    for (key, value) in format {
                        credentialFormat = key
                    }
                }
                if credentialFormat == "mso_mdoc" {
                    tempCredentialList = credentialList
                    processedCredentials = processCborCredentialToJsonString(credentialList: tempCredentialList)
                } else {
                    tempCredentialList = splitCredentialsBySdJWT(allCredentials: credentialList, isSdJwt: inputDescriptor.constraints?.limitDisclosure != nil)
                    
                    processedCredentials = processCredentialsToJsonString(credentialList: tempCredentialList)
                }
                
                let updatedDescriptor = updatePath(in: inputDescriptor)
                var filteredCredentialList: [String] = []
                
                let jsonEncoder = JSONEncoder()
                jsonEncoder.keyEncodingStrategy = .convertToSnakeCase
                guard let jsonData = try? jsonEncoder.encode(updatedDescriptor),
                      let dictionary = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
                    fatalError("Failed to convert Person to dictionary")
                }
                // Convert the dictionary to a string
                guard let inputDescriptorString = String(data: try! JSONSerialization.data(withJSONObject: dictionary, options: .withoutEscapingSlashes), encoding: .utf8) else {
                    fatalError("Failed to convert dictionary to string")
                }
                do {
                    let matchesString = try matchCredentials(inputDescriptorJson: inputDescriptorString, credentials: processedCredentials)
                    for item in matchesString {
                        filteredCredentialList.append(tempCredentialList[item.index] ?? "")
                    }
                    
                } catch {
                    print("error")
                }
                
                response.append(filteredCredentialList)
            }
        }
        
        return response
    }
    
    func splitCredentialsBySdJWT(allCredentials: [String?], isSdJwt: Bool) -> [String?] {
//        var filteredCredentials: [String?] = []
//        for item in allCredentials {
//            if isSdJwt == true,
//               item?.contains("~") == true {
//                filteredCredentials.append(item)
//            } else if isSdJwt == false,
//                      item?.contains("~") == false {
//                filteredCredentials.append(item)
//            }
//        }
        return allCredentials
    }
    
    func processCborCredentialToJsonString(credentialList: [String?]) -> [String] {
        var processedCredentials = [String]()
        for cred in credentialList {
            var cborItem = MDocVpTokenBuilder().convertCBORtoJson(credential: cred ?? "") ?? ""
            processedCredentials.append(cborItem)
        }
        return processedCredentials
    }
    
    
    func getDocTypeFromIssuerAuth(cborData: CBOR) -> String? {
        guard case let CBOR.array(elements) = cborData else {
            print("Expected CBOR array, but got something else.")
            return nil
        }
        var docType: String? = ""
        for element in elements {
            if case let CBOR.byteString(byteString) = element {
                if let nestedCBOR = try? CBOR.decode(byteString) {
                    if case let CBOR.tagged(tag, item) = nestedCBOR, tag.rawValue == 24 {
                        if case let CBOR.byteString(data) = item {
                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)) {
                                docType = MDocVpTokenBuilder().extractDocType(cborData: decodedInnerCBOR )
                            } else {
                                print("Failed to decode inner ByteString under Tag 24.")
                            }
                        }
                    }
                } else {
                    print("Could not decode ByteString as CBOR, inspecting data directly.")
                    print("ByteString data: \(byteString)")
                }
            } else {
                print("Element: \(element)")
            }
        }
        return docType ?? ""
    }
        
    func extractStatusListFromCBOR(cbor: CBOR) -> (Int?, String?) {
        guard case let CBOR.map(map) = cbor else {
            return (nil, nil)        }
        
        var StatusIndex: Int? = 0
        var StatusUri: String? = ""
        for (key, value) in map {
            if case let CBOR.utf8String(keyString) = key, keyString == "status" {
                if case let CBOR.map(map) = value {
                    for (key, value) in map {
                        if case let CBOR.map(map) = value  {
                            for (key, value) in map {
                                if case let CBOR.utf8String(keyString) = key, keyString == "idx" {
                                    if case let CBOR.unsignedInt(index) = value {
                                        StatusIndex = Int(index)
                                    } else {
                                        print("The value associated with 'docType' is not a string.")
                                    }
                                }
                                if case let CBOR.utf8String(keyString) = key, keyString == "uri" {
                                    if case let CBOR.utf8String(uri) = value {
                                        StatusUri = uri
                                    } else {
                                        print("The value associated with 'docType' is not a string.")
                                    }
                                }
                            }
                        } else {
                            print("The value associated with 'docType' is not a string.")
                        }
                    }
                } else {
                    print("The value associated with 'docType' is not a string.")
                }
            }
        }
        return (StatusIndex, StatusUri)
        
        print("docType not found in the CBOR map.")
    }
    
    func getStatusListItemsFromCbor(cborData: CBOR) -> (Int?, String?) {
        guard case let CBOR.array(elements) = cborData else {
            print("Expected CBOR array, but got something else.")
            return (nil, nil)
        }
        var index: Int? = 0
        var uri: String? = ""
        for element in elements {
            if case let CBOR.byteString(byteString) = element {
                if let nestedCBOR = try? CBOR.decode(byteString) {
                    if case let CBOR.tagged(tag, item) = nestedCBOR, tag.rawValue == 24 {
                        if case let CBOR.byteString(data) = item {
                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)) {
                                (index, uri) = extractStatusListFromCBOR(cbor: decodedInnerCBOR)
                            } else {
                                print("Failed to decode inner ByteString under Tag 24.")
                            }
                        }
                    }
                } else {
                    print("Could not decode ByteString as CBOR, inspecting data directly.")
                    print("ByteString data: \(byteString)")
                }
            } else {
                print("Element: \(element)")
            }
        }
        return (index, uri)
    }
        
    public func getFilteredCbor(credential: String, inputDescriptor: InputDescriptor?) -> CBOR? {
        var requestedParams: [String] = []
        var limitDisclosure: Bool = false
        if let fields = inputDescriptor?.constraints?.fields {
            print("printing inputDescriptor fields: \(fields)")
            for field in fields {
                let components = field.path?.first?.components(separatedBy: ["[", "]", "'"])
                let filteredComponents = components?.filter { !$0.isEmpty }
                if let identifier = filteredComponents?.last {
                    requestedParams.append(String(identifier))
                }
            }
        }
        print("printing requestedParams from cbor: \(requestedParams)")
        if inputDescriptor?.constraints?.limitDisclosure == nil {
            limitDisclosure = false
        } else {
            limitDisclosure = true
        }
        print("printing limitDisclosure from cbor: \(limitDisclosure)")
        if let data = Data(base64URLEncoded: credential) {
            do {
                let decodedCBOR = try CBOR.decode([UInt8](data))
                if let dictionary = decodedCBOR {
                    //if let nameSpacesValue = dictionary[CBOR.utf8String("nameSpaces")] {
                    if limitDisclosure {
                        return filterCBORWithRequestedParams(cborData: dictionary, requestedParams: requestedParams)
                        print("printing decoded cbor in limitDisclosure: \(filterCBORWithRequestedParams(cborData: dictionary, requestedParams: requestedParams))")
                    } else {
                        return dictionary
                    }
                    print("printing decoded cbor: \(dictionary)")
                    // }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
                return nil
            }
        } else {
            print("Invalid base64 URL encoded credential.")
            return nil
        }
        
        return nil
    }
    
    
    public func filterCBORWithRequestedParams(cborData: CBOR, requestedParams: [String]) -> CBOR? {
        guard case let CBOR.map(cborMap) = cborData else { return nil }
        
        var modifiedCBORMap = cborMap
        print("printing modifiedCBORMap cbor: \(modifiedCBORMap)")

        if let namespacesValue = modifiedCBORMap[CBOR.utf8String("nameSpaces")] {
            print("printing modifiedCBORMap nameSpaces: \(CBOR.map(modifiedCBORMap))")
            if let filteredNameSpaces = MDocVpTokenBuilder().filterNameSpaces(nameSpacesValue: namespacesValue, requestedParams: requestedParams) {
                modifiedCBORMap[CBOR.utf8String("nameSpaces")] = filteredNameSpaces
                print("printing modifiedCBORMap nameSpaces inside: \(filteredNameSpaces)")
            }
        }
        print("printing modifiedCBORMap return: \(CBOR.map(modifiedCBORMap))")
        return CBOR.map(modifiedCBORMap)
    }
    
    func convertCBORtoJson(credential: String) -> String? {
        if let data = Data(base64URLEncoded: credential) {
            do {
                let decodedCBOR = try CBOR.decode([UInt8](data))
                if let dictionary = decodedCBOR {
                    
                    if let nameSpacesValue = dictionary[CBOR.utf8String("nameSpaces")],
                       case let CBOR.map(nameSpaces) = nameSpacesValue {
                        
                        var resultDict: [String: [String: String]] = [:]
                        for (key, namespaceValue) in nameSpaces {
                            var valuesDict: [String: String] = [:]
                            if case let CBOR.array(orgValues) = namespaceValue {
                                for value in orgValues {
                                    if case let CBOR.tagged(tag, taggedValue) = value, tag.rawValue == 24 {
                                        if case let CBOR.byteString(byteString) = taggedValue {
                                            let data = Data(byteString)
                                            
                                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)),
                                               case let CBOR.map(decodedMap) = decodedInnerCBOR {
                                                if let identifier = decodedMap[CBOR.utf8String("elementIdentifier")],
                                                   let value = decodedMap[CBOR.utf8String("elementValue")],
                                                   case let CBOR.utf8String(identifierString) = identifier {
                                                    
                                                    valuesDict[identifierString] = cborToString(value)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            resultDict[cborToString(key)] = valuesDict
                        }
                        
                        // Convert the result dictionary to JSON
                        let jsonData = try JSONSerialization.data(withJSONObject: resultDict, options: .prettyPrinted)
                        let jsonString = String(data: jsonData, encoding: .utf8)
                        return jsonString?.replacingOccurrences(of: "\n", with: "")
                    } else {
                        print("Key 'nameSpaces' not found or not a valid map.")
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
            }
        }
        return nil
    }
    
    
    func cborToString(_ cbor: CBOR) -> String {
        switch cbor {
        case .utf8String(let stringValue):
            return stringValue
        case .unsignedInt(let uintValue):
            return String(uintValue)
        case .negativeInt(let intValue):
            return String(intValue)
        case .boolean(let boolValue):
            return String(boolValue)
        case .null:
            return "null"
        case .float(let floatValue):
            return String(floatValue)
        case .double(let doubleValue):
            return String(doubleValue)
        default:
            return "Unsupported CBOR type"
        }
    }
    
    
    func processCredentialsToJsonString(credentialList: [String?]) -> [String] {
        var processedCredentials = [String]()
        for cred in credentialList {
            guard let cred = cred else { continue }
            let split = cred.split(separator: ".")
            
            let jsonString: String
            if (cred.split(separator: "~").count) > 0 {
                jsonString = SDJWTService.shared.updateIssuerJwtWithDisclosures(credential: cred) ?? ""
            } else if split.count > 1,
                      let base64Data = Data(base64Encoded: String(split[1]), options: .ignoreUnknownCharacters),
                      let decodedString = String(data: base64Data, encoding: .utf8) {
                jsonString = decodedString
            } else {
                jsonString = ""
            }
            
            let json = try? JSONSerialization.jsonObject(with: Data(jsonString.utf8), options: []) as? [String: Any] ?? [:]
            
            var vcString = ""
            if let vc = json?["vc"] as? [String: Any] {
                vcString = vc.toString() ?? ""
            } else {
                vcString = jsonString
            }
            
            processedCredentials.append(vcString)
        }
        return processedCredentials
    }
    
    func generateHash(input: String) -> String? {
        guard let data = input.data(using: .utf8) else { return nil }
        
        let hash = Data(SHA256.hash(data: data))
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    func updatePath(in descriptor: InputDescriptor) -> InputDescriptor {
        var updatedDescriptor = descriptor
        guard var constraints = updatedDescriptor.constraints else { return updatedDescriptor }
        guard var fields = constraints.fields else { return updatedDescriptor }
        
        for j in 0..<fields.count {
            guard var pathList = fields[j].path else { continue }
            
            for k in 0..<pathList.count {
                let path = pathList[k]
                if path.contains("$.vc.") {
                    let newPath = path.replacingOccurrences(of: "$.vc.", with: "$.")
                    if !pathList.contains(newPath) {
                        pathList.append(newPath)
                    }
                }
            }
            fields[j].path = pathList
        }
        constraints.fields = fields
        updatedDescriptor.constraints = constraints
        
        return updatedDescriptor
    }
}
extension VerificationService: URLSessionDelegate, URLSessionTaskDelegate {
    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        // Stops the redirection, and returns (internally) the response body.
        completionHandler(nil)
    }
}

protocol CustomCborConvertible {
    func toCBOR() -> CBOR
}

public struct DeviceResponse :CustomCborConvertible{
    let version: String
    let documents: [Document]?
    let status: Int
    
    enum Keys: String {
        case version
        case documents
        case status
    }
    
    init(version: String? = nil, documents: [Document]? = nil, status: Int) {
        self.version = version ?? "1.0"
        self.documents = documents
        self.status = status
    }
    
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [:]
        dict["version"] = version
        dict["documents"] = documents
        dict["status"] = status
        return dict
    }
    
    func encodeToCBOR(_ dict: [String: Any]) -> CBOR? {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        
        for (key, value) in dict {
            let cborKey = CBOR.utf8String(key)
            
            // Handle different value types
            if let stringValue = value as? String {
                if stringValue == "NULL" {
                    cborMap[cborKey] = CBOR.null
                } else if stringValue.contains("ByteString") {
                    // Handle ByteString placeholder
                    cborMap[cborKey] = CBOR.byteString([0x01, 0x02, 0x03]) // Example ByteString, customize as needed
                } else {
                    cborMap[cborKey] = CBOR.utf8String(stringValue)
                }
            } else if let intValue = value as? Int {
                if intValue >= 0 {
                    cborMap[cborKey] = CBOR.unsignedInt(UInt64(intValue))
                } else {
                    cborMap[cborKey] = CBOR.negativeInt(UInt64(-1 - intValue))
                }
            } else if let floatValue = value as? Float {
                cborMap[cborKey] = CBOR.float(floatValue)
            } else if let doubleValue = value as? Double {
                cborMap[cborKey] = CBOR.double(doubleValue)
            } else if let boolValue = value as? Bool {
                cborMap[cborKey] = CBOR.boolean(boolValue)
            } else if let arrayValue = value as? [Any] {
                cborMap[cborKey] = encodeArrayToCBOR(arrayValue)
            } else if let dictValue = value as? [String: Any] {
                if let encodedDict = encodeToCBOR(dictValue) {
                    cborMap[cborKey] = encodedDict
                }
            } else if let cborValue = value as? SwiftCBOR.CBOR {
                // Handle CBOR types directly
                cborMap[cborKey] = cborValue
            } else if let customObject = value as? CustomCborConvertible {
                // Handle custom objects that conform to CustomCborConvertible
                cborMap[cborKey] = customObject.toCBOR()
            } else {
                print("Unsupported type for key: \(key)")
                return nil
            }
        }
        
        return CBOR.map(cborMap)
    }
    
    func encodeArrayToCBOR(_ array: [Any]) -> CBOR {
        var cborArray: [CBOR] = []
        
        for value in array {
            if let stringValue = value as? String {
                if stringValue == "NULL" {
                    cborArray.append(CBOR.null)
                } else if stringValue.contains("ByteString") {
                    cborArray.append(CBOR.byteString([0x01, 0x02, 0x03])) // Example ByteString
                } else {
                    cborArray.append(CBOR.utf8String(stringValue))
                }
            } else if let intValue = value as? Int {
                if intValue >= 0 {
                    cborArray.append(CBOR.unsignedInt(UInt64(intValue)))
                } else {
                    cborArray.append(CBOR.negativeInt(UInt64(-1 - intValue)))
                }
            } else if let floatValue = value as? Float {
                cborArray.append(CBOR.float(floatValue))
            } else if let boolValue = value as? Bool {
                cborArray.append(CBOR.boolean(boolValue))
            } else if let dictValue = value as? [String: Any], let encodedDict = encodeToCBOR(dictValue) {
                cborArray.append(encodedDict)
            } else if let subArray = value as? [Any] {
                cborArray.append(encodeArrayToCBOR(subArray))
            } else if let cborValue = value as? SwiftCBOR.CBOR {
                // Handle CBOR values directly
                cborArray.append(cborValue)
            } else if let customObject = value as? CustomCborConvertible {
                // Handle custom objects
                cborArray.append(customObject.toCBOR())
            } else {
                print("Unsupported type in array")
                return CBOR.null
            }
        }
        
        return CBOR.array(cborArray)
    }
    
    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[CBOR.utf8String("version")] = CBOR.utf8String(version)
        
        if let documents = documents {
            cborMap[CBOR.utf8String("documents")] = encodeArrayToCBOR(documents.map { $0.toCBOR() })
        }
        
        cborMap[CBOR.utf8String("status")] = CBOR.unsignedInt(UInt64(status))
        
        return CBOR.map(cborMap)
    }
}

public struct Document : CustomCborConvertible{
    
    let docType: String
    let issuerSigned: IssuerSigned
    let deviceSigned: DeviceSigned?
    
    enum Keys:String {
        case docType
        case issuerSigned
        case deviceSigned
    }
    
    init(docType: String, issuerSigned: IssuerSigned, deviceSigned: DeviceSigned? = nil) {
        self.docType = docType
        self.issuerSigned = issuerSigned
        self.deviceSigned = deviceSigned
    }
    
    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[CBOR.utf8String("docType")] = CBOR.utf8String(docType)
        
        cborMap[CBOR.utf8String("issuerSigned")] = issuerSigned.toCBOR()
        
        if let deviceSigned = deviceSigned {
            cborMap[CBOR.utf8String("deviceSigned")] = deviceSigned.toCBOR()
        }
        
        return CBOR.map(cborMap)
    }
}

// Model for IssuerSigned part
struct IssuerSigned : CustomCborConvertible{
    let nameSpaces: SwiftCBOR.CBOR // Using ByteString struct here
    let issuerAuth: SwiftCBOR.CBOR
    
    init(nameSpaces: SwiftCBOR.CBOR, issuerAuth: SwiftCBOR.CBOR) {
        self.nameSpaces = nameSpaces
        self.issuerAuth = issuerAuth
    }
    
    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[CBOR.utf8String("nameSpaces")] = nameSpaces
        cborMap[CBOR.utf8String("issuerAuth")] = issuerAuth
        
        return CBOR.map(cborMap)
    }
}

// Model for DeviceSigned part
struct DeviceSigned: Codable, CustomCborConvertible {
    let nameSpaces: String
    let deviceAuth: DeviceAuth
    
    func toCBOR() -> CBOR {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        cborMap[CBOR.utf8String("nameSpaces")] = CBOR.utf8String(nameSpaces)
        cborMap[CBOR.utf8String("deviceAuth")] = deviceAuth.toCBOR()
        
        return CBOR.map(cborMap)
    }
}

//struct IssuerAuth: Codable {
//    let byteString: ByteString?
//    let dictionary: [String: ByteString]?
//}

struct DeviceAuth: Codable, CustomCborConvertible {
    let deviceSignature: [DeviceSignature]
    
    func toCBOR() -> CBOR {
        var cborArray: [CBOR] = []
        for signature in deviceSignature {
            cborArray.append(signature.toCBOR())
        }
        return CBOR.array(cborArray)
    }
}

enum DeviceSignature: Codable, CustomCborConvertible {
    case byteString(String)
    case dictionary([String: String])
    case null
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let byteString = try? container.decode(String.self) {
            self = .byteString(byteString)
        } else if let dict = try? container.decode([String: String].self) {
            self = .dictionary(dict)
        } else if container.decodeNil() {
            self = .null
        } else {
            throw DecodingError.typeMismatch(DeviceSignature.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Type mismatch"))
        }
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .byteString(let byteString):
            try container.encode(byteString)
        case .dictionary(let dict):
            try container.encode(dict)
        case .null:
            try container.encodeNil()
        }
    }
    
    func toCBOR() -> CBOR {
        switch self {
        case .byteString(let byteString):
            return CBOR.byteString(Array(byteString.utf8))
        case .dictionary(let dict):
            var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
            for (key, value) in dict {
                cborMap[CBOR.utf8String(key)] = CBOR.utf8String(value)
            }
            return CBOR.map(cborMap)
        case .null:
            return CBOR.null
        }
    }
}


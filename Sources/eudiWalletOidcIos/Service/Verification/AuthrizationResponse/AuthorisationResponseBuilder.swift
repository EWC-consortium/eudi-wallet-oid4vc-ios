//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class AuthorisationResponseBuilder{
    
    
    static func buildResponse(
        credentialsList: [String]?,
        presentationRequest: PresentationRequest?,
        did: String, keyHandler: SecureKeyProtocol
    ) async -> [String: Any] {
        
        var params: [String: Any] = [:]
        
        if let dcql = presentationRequest?.dcqlQuery {
            //Fixme: handle DCQL response
            params = await DCQLAuthorisationResponseBuilder().build(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler)
            return params
        }else{
            let tokensAndPresentationSubmission = await createVPTokenAndPresentationSubmission(
                credentialsList: credentialsList,
                did: did,
                presentationRequest: presentationRequest, keyHandler: keyHandler
            )
            
            // Handle vp_token
            if presentationRequest?.responseType?.contains("vp_token") ?? false {
                // appending vp_token to params
                let token = tokensAndPresentationSubmission.0
                // Use single token if only one exists, else array
                let vpToken: Any = (token.count == 1) ? token[0] : token
                params["vp_token"] = vpToken
                
                // appending presentation_submission to params
                let presentationSubmission = tokensAndPresentationSubmission.1
                let encoder = JSONEncoder()
                encoder.keyEncodingStrategy = .convertToSnakeCase
                let data = try? encoder.encode(presentationSubmission)
                var json = [String: Any]()
                do {
                    let jsonObj = try JSONSerialization.jsonObject(with: data!, options: .mutableContainers)
                    json = jsonObj as! [String : Any]
                } catch let myJSONError {
                    debugPrint(myJSONError)
                }
                
                var resultDict: [String: Any]? = [:]
                for (key, value) in json {
                    if let valueData = value as? String {
                        resultDict?[key] = valueData
                    } else if let arrayValue = value as? [[String: Any]] {
                        let stringifiedArray = arrayValue.map { dict in
                            var stringDict: [String: String] = [:]
                            for (k, v) in dict {
                                stringDict[k] = "\(v)"
                            }
                            return stringDict
                        }
                        resultDict?[key] = stringifiedArray
                    }
                    else {
                        resultDict?[key] = value
                    }
                }
                
                params["presentation_submission"] = json.toString()
            }
            
            // Handle id_token
            if presentationRequest?.responseType?.contains("id_token") ?? false {
                let idToken = tokensAndPresentationSubmission.2
                params["id_token"] = idToken
            }
            
            // Always include state if available
            if let state = presentationRequest?.state {
                params["state"] = state
            }
            
            return params
        }
    }
    
    static func createVPTokenAndPresentationSubmission(credentialsList: [String]?, did: String, presentationRequest: PresentationRequest?, keyHandler: SecureKeyProtocol) async -> ([String], PresentationSubmissionModel?, String){
        // Fixme: set nonce when processing authorisation request itself
        let nonce = presentationRequest?.nonce ?? UUID().uuidString
        
        // processing presentation definition from presentation request
        var presentationDefinition :PresentationDefinitionModel? = nil
        do {
            presentationDefinition = try VerificationService.processPresentationDefinition(presentationRequest?.presentationDefinition)
        } catch {
            presentationDefinition = nil
        }
        
        // Temp variables
        var jwtList: [String] = []
        var vpTokenList: [String] = []
        var mdocList: [String] = []
        var firstJWTProcessedIndex: Int? = nil
        var mdocProcessedIndex: Int? = nil
        var idToken: String = ""
        var presentationSubmission: PresentationSubmissionModel? = nil
        
        // checking if credential list is empty or not, if empty return
        // Fixme: what if only id token needed ?
        guard let credentialsList = credentialsList else { return ([], nil, "")}
        
        // Checking if response type contains or request vp_token
        if let resType = presentationRequest?.responseType, resType.contains("vp_token") {
            for (index, item) in credentialsList.enumerated() {
                var claims: [String: Any] = [:]
                var credFormat: String? = ""
                if let format = presentationDefinition?.inputDescriptors?[index].format ??  presentationDefinition?.format {
                    for (key, _) in format {
                        credFormat = key
                    }
                }
                claims["aud"] = presentationRequest?.clientId ?? ""
                claims["nonce"] = nonce
                let split = item.split(separator: ".")
                var dict: [String: Any] = [:]
                if split.count > 1 {
                    let jsonString = "\(split[1])".decodeBase64() ?? ""
                    dict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString) ?? [:]
                }
                
                var transactionData: String? = nil
                if !(presentationRequest?.transactionData?.isEmpty ?? true) {
                    transactionData = presentationRequest?.transactionData?.first
                    if SDJWTVpTokenBuilder().checkTransactionDataWithMultipleInputDescriptors(inputDescriptor: presentationDefinition?.inputDescriptors?[index], transactionDataItem: transactionData) {
                        claims["transaction_data_hashes"] = [SDJWTVpTokenBuilder().generateHash(input: transactionData ?? "")]
                        claims["transaction_data_hashes_alg"] = "sha-256"
                    }
                }
                
                var itemWithTilda: String? = nil
                if item.hasSuffix("~") {
                    itemWithTilda = item
                } else {
                    itemWithTilda = "\(item)~"
                }
                
                if let keyBindingJwt = await KeyBindingJwtService().generateKeyBindingJwt(issuerSignedJwt: itemWithTilda, claims: claims, keyHandler: keyHandler), let vct = dict["vct"] as? String, !vct.isEmpty {
                    //Fixme: need to update the vp_token creation using SDJWTVpTokenBuilder
                    var updatedCred = "\(itemWithTilda ?? "")\(keyBindingJwt)"
                    vpTokenList.append(updatedCred)
                } else if credFormat == "mso_mdoc" {
                    mdocList.append(item)
                    if !vpTokenList.contains("MDOC") {
                        vpTokenList.append("MDOC")
                    }
                } else {
                    jwtList.append(item)
                    if !vpTokenList.contains("JWT") {
                        firstJWTProcessedIndex = vpTokenList.count
                        vpTokenList.append("JWT")
                    }
                }
            }
            
            // creating w3c jwt vp token
            var vpToken: String = await JWTVpTokenBuilder().build(credentials: jwtList, presentationRequest: presentationRequest, did: did, index: nil, keyHandler: keyHandler) ?? ""
            
            // creating mdoc vp token
            var mdocToken: String = ""
            if !mdocList.isEmpty {
                mdocToken = MDocVpTokenBuilder().build(credentials: credentialsList ?? [], presentationRequest: presentationRequest, did: did, index: nil, keyHandler: keyHandler) ?? ""
            }
            
            if let index = vpTokenList.firstIndex(of: "JWT") {
                vpTokenList[index] = vpToken ?? ""
            }
            
            if let index = vpTokenList.firstIndex(of: "MDOC") {
                mdocProcessedIndex = index
                vpTokenList[index] = mdocToken ?? ""
            }
            
            
            // Generating presentation submission
            // Fixme: need to move presentation submission creation to another class
            var descMap : [DescriptorMap] = []
            
            var credentialFormat: String = ""
            
            var format = ""
            var formatType: String? = ""
            var jwtIndex = 0
            var vpTokenIndex = 0
            var jwtListAdded: Bool = false
            if let inputDescriptors = presentationDefinition?.inputDescriptors {
                for index in 0..<inputDescriptors.count {
                    let item = inputDescriptors[index]
                    if var format2 = item.format ?? presentationDefinition?.format {
                        for (key, _) in format2 {
                            credentialFormat = key
                        }
                    }
                    
                    if credentialFormat == "vcsd-jwt" || credentialFormat == "vpsd-jwt"{
                        format = "vc+sd-jwt"
                    } else if credentialFormat == "dcsd-jwt" {
                        format = "dc+sd-jwt"
                    } else {
                        format = credentialFormat
                    }
                    let encodedFormat = format.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed.union(CharacterSet(charactersIn: "+")).subtracting(CharacterSet(charactersIn: "+")))?.replacingOccurrences(of: "+", with: "%2B")
                    var pathNested: DescriptorMap? = nil
                    if format ==  "vc+sd-jwt" || format == "dc+sd-jwt" {
                        pathNested = nil
                        if vpTokenList.count == 1 {
                            descMap.append(DescriptorMap(id: item.id ?? "", path: "$", format: format ?? "", pathNested: pathNested))
                        } else {
                            descMap.append(DescriptorMap(id: item.id ?? "", path: "$[\(vpTokenIndex)]", format: format ?? "", pathNested: pathNested))
                        }
                        vpTokenIndex += 1
                    } else if credentialFormat == "mso_mdoc" {
                        formatType = "mso_mdoc"
                        pathNested = nil
                        if vpTokenList.count == 1 {
                            descMap.append(DescriptorMap(id: item.id ?? "", path: "$", format: formatType ?? "", pathNested: pathNested))
                        } else {
                            descMap.append(DescriptorMap(id: item.id ?? "", path: "$[\(mdocProcessedIndex ?? 0)]", format: formatType ?? "", pathNested: pathNested))
                        }
                        vpTokenIndex += 1
                    } else {
                        var pathNestedValue: DescriptorMap? = nil
                        formatType = encodedFormat ?? "jwt_vp"
                        let credentialFormat = fetchFormat(presentationDefinition: presentationDefinition, index: index)
                        if vpTokenList.count == 1 {
                            pathNestedValue = DescriptorMap(id: item.id ?? "", path: "$.vp.verifiableCredential[\(jwtIndex)]", format: "jwt_vc", pathNested: nil)
                            descMap.append(DescriptorMap(id: item.id ?? "", path: "$", format: credentialFormat ?? "", pathNested: pathNestedValue))
                        } else {
                            pathNestedValue = DescriptorMap(id: item.id ?? "", path: "$[\(firstJWTProcessedIndex ?? 0)].vp.verifiableCredential[\(jwtIndex)]", format: "jwt_vc", pathNested: nil)
                            descMap.append(DescriptorMap(id: item.id ?? "", path: "$[\(firstJWTProcessedIndex ?? 0)]", format: formatType ?? "", pathNested: pathNestedValue))
                        }
                        if !(jwtListAdded) {
                            vpTokenIndex += 1
                            jwtListAdded = true
                        }
                        jwtIndex += 1
                    }
                }
            }
            presentationSubmission = PresentationSubmissionModel(id: UUID().uuidString, definitionID: presentationDefinition?.id ?? "", descriptorMap: descMap)
        }
        
        // Checking if response type contains or request vp_token
        if let resType = presentationRequest?.responseType, resType.contains("id_token") {
            idToken =  await generateJWTokenForIDtokenRequest(didKeyIdentifier: did, authorizationEndpoint: presentationRequest?.clientId ?? "", nonce: presentationRequest?.nonce ?? "", keyHandler: keyHandler)
        }
        
        return (vpTokenList, presentationSubmission, idToken)
    }
    
    static func generateJWTokenForIDtokenRequest(
            didKeyIdentifier: String,
            authorizationEndpoint: String,
            nonce: String, keyHandler: SecureKeyProtocol
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
    
    static func fetchFormat(presentationDefinition: PresentationDefinitionModel?, index: Int) -> String {
        var credentialFormat: String = ""
        var credentialFormatString: String = ""
        var inputDescriptorFromat: String = ""
        var presentationDefinitionFormat: String = ""
        if var format = presentationDefinition?.inputDescriptors?[index].format ?? presentationDefinition?.format {
            for (key, _) in format {
                credentialFormat = key
            }
        }
        if credentialFormat == "vcsd-jwt" || credentialFormat == "vpsd-jwt"{
            credentialFormatString = "vc+sd-jwt"
        } else if credentialFormat == "dcsd-jwt" {
            credentialFormatString = "dc+sd-jwt"
        } else {
            credentialFormatString = credentialFormat
        }
        
        guard let encodedFormat = credentialFormatString.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed.union(CharacterSet(charactersIn: "+")).subtracting(CharacterSet(charactersIn: "+")))?.replacingOccurrences(of: "+", with: "%2B") else { return ""}
        if var format = presentationDefinition?.inputDescriptors?[index].format  {
            for (key, _) in format {
                inputDescriptorFromat = key
            }
        }
        if var format = presentationDefinition?.format  {
            for (key, _) in format {
                presentationDefinitionFormat = key
            }
        }
        if inputDescriptorFromat.contains("jwt_vp") {
            return "jwt_vp"
        }
        if inputDescriptorFromat.contains("jwt_vp_json") {
            return "jwt_vp_json"
        }
        if presentationDefinitionFormat.contains("jwt_vp")  {
            return "jwt_vp"
        }
        if  presentationDefinitionFormat.contains("jwt_vp_json") {
            return "jwt_vp_json"
        }
        return encodedFormat
    }
}

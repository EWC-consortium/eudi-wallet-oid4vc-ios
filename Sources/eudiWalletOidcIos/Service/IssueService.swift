//
//  IssueService.swift
//
//
//  Created by Mumthasir mohammed on 07/03/24.
//

import Foundation
import CryptoKit
//import KeychainSwift
import CryptoSwift

public class IssueService: NSObject, IssueServiceProtocol {
    
    var session: URLSession?
    var keyHandler: SecureKeyProtocol!
    
    // MARK: - A custom initialiser with dependency injection for encryption key generation handler
    ///
    /// - Parameters:
    ///   - keyhandler: A handler to encryption key generation class
    /// - Returns: An `IssueService` object
    
    public init(keyHandler: SecureKeyProtocol) {
        super.init()
        session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        self.keyHandler = keyHandler
    }
    
    // MARK: - Retrieves credential issuer asynchronously based on the provided credential_offer / credential_offer_uri.
    ///
    /// - Parameters:
    ///   - credentialOffer: The string representation of the credential offer.
    /// - Returns: A `CredentialOffer` object if the resolution is successful; otherwise, `nil`.
    public func resolveCredentialOffer(credentialOffer credentialOfferString: String) async throws -> CredentialOffer? {
            let credentialOfferUrl = URL(string: credentialOfferString)
           let credentialOfferUri = credentialOfferUrl?.queryParameters?["credential_offer_uri"]
            
        if let credentialOfferUri = credentialOfferUri, !credentialOfferUri.isEmpty {
                var request = URLRequest(url: URL(string: credentialOfferUri ?? "")!)
                request.httpMethod = "GET"
                
                let (data, response) = try await URLSession.shared.data(for: request)
                
                do {
                    let httpRes = response as? HTTPURLResponse
                    if let res = httpRes?.statusCode, res >= 400 {
                        let errorData = String(data: data, encoding: .utf8)
                        if let eudiErrorData = ErrorHandler.processError(data: data) {
                            return CredentialOffer(fromError: eudiErrorData)
                        } else {
                            let error = EUDIError(from: ErrorResponse(message: errorData, code: nil))
                            return CredentialOffer(fromError: error)
                        }
                    } else {
                        guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                            return nil
                        }
                        let credentialOfferResponse = parseCredentialOfferResponseModel(jsonData: jsonObject, data: data)
                        return credentialOfferResponse
                    }
                }
            } else {
                guard let credentialOffer = credentialOfferUrl?.queryParameters?["credential_offer"] else { return nil }
                let jsonData = Data(credentialOffer.utf8)
                guard let jsonObject = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
                    return nil
                }
                if credentialOffer != "" {
                    let credentialOfferResponse = parseCredentialOfferResponseModel(jsonData: jsonObject, data: jsonData)
                    return credentialOfferResponse
                } else {
                    return nil
                }
            }
        return nil
    }
    
     func parseCredentialOfferResponseModel(jsonData: [String: Any], data: Data?) -> CredentialOffer? {
        let jsonDecoder = JSONDecoder()
        if jsonData["credentials"] != nil {
            if let data = data, let model = try? jsonDecoder.decode(CredentialOfferResponse.self, from: data) {
                if model.credentialIssuer == nil {
                    let error = EUDIError(from: ErrorResponse(message: "Invalid DID", code: nil))
                    return CredentialOffer(fromError: error)
                }
                return CredentialOffer(from: model)
            }
        } else if jsonData["credential_configuration_ids"] != nil {
            
            if let data = data, let modelV2 = try? jsonDecoder.decode(CredentialOfferV2.self, from: data) {
                if modelV2.credentialIssuer == nil {
                    let error = EUDIError(from: ErrorResponse(message: "Invalid DID", code: nil))
                    return CredentialOffer(fromError: error)
                }
                return CredentialOffer(from: modelV2)
            }
        }
        
        else {
            let error = EUDIError(from: ErrorResponse(message: "Invalid data format", code: nil))
            return CredentialOffer(fromError: error)
        }
    return nil
    }
    
    private func buildAuthorizationRequestV1(credentialOffer: CredentialOffer?, docType: String, format: String) -> String {
        var authorizationDetails =  if format == "mso_mdoc" {
            "[" + (([
                "format": format,
                "doctype": docType,
                "locations": [credentialOffer?.credentialIssuer ?? ""]
            ] as [String : Any]).toString() ?? "") + "]"
        } else if credentialOffer?.credentials?[0].trustFramework == nil {
            "[" + (([
                "type": "openid_credential",
                "format": format,
                "credential_definition": ["type":credentialOffer?.credentials?[0].types ?? []],
                "locations": [credentialOffer?.credentialIssuer ?? ""]
            ] as [String : Any]).toString() ?? "") + "]"
        } else {
            "[" + (([
                "type": "openid_credential",
                "format": format,
                "types": credentialOffer?.credentials?[0].types ?? [],
                "locations": [credentialOffer?.credentialIssuer ?? ""]
            ] as [String : Any]).toString() ?? "") + "]"
        }
        
        return authorizationDetails
    }
    
    func buildAuthorizationRequestV2(credentialOffer: CredentialOffer?, docType: String, format: String, issuerConfig: IssuerWellKnownConfiguration?) -> String {
            let credentialConfigID = credentialOffer?.credentials?.first?.types?.first ?? nil
            var authorizationDetails =  if format == "mso_mdoc" {
                "[" + (([
                    "type": "openid_credential",
                    "doctype": docType,
                    "credential_configuration_id": credentialConfigID,
                    "locations": [credentialOffer?.credentialIssuer ?? ""]
                    
                ] as [String : Any]).toString() ?? "") + "]"
            } else if format.contains("sd-jwt"){
                "[" + (([
                    "type": "openid_credential",
                    "format": format,
                    "vct": getTypesFromIssuerConfig(issuerConfig: issuerConfig, type: credentialConfigID)
                ] as [String : Any]).toString() ?? "") + "]"
            }
            else {
                "[" + (([
                    "type": "openid_credential",
                    "credential_configuration_id": credentialConfigID,
                    "credential_definition": ["type": getTypesFromIssuerConfig(issuerConfig: issuerConfig, type: credentialConfigID)]
                ] as [String : Any]).toString() ?? "") + "]"
            }
            
            return authorizationDetails
        }
    
    
    private func buildAuthorizationRequest(credentialOffer: CredentialOffer?, docType: String, format: String, issuerConfig: IssuerWellKnownConfiguration?) -> String {
        if credentialOffer?.version == "v1" {
            return buildAuthorizationRequestV1(credentialOffer: credentialOffer, docType: docType, format: format)
            
        } else {
            return buildAuthorizationRequestV2(credentialOffer: credentialOffer, docType: docType, format: format, issuerConfig: issuerConfig)
        }
    }
    
    // MARK: - To process the authorisation request, The authorisation request is to grant access to the credential endpoint.
    /// - Parameters:
    ///   - did - DID created for the issuance
    ///   - secureKey: A wrapper object containing the public and private encryption keys
    ///   - credentialOffer: The credential offer containing the necessary details for authorization.
    ///   - codeVerifier - to build the authorisation request
    ///   - authServer: The authorization server configuration.
    /// - Returns: code if successful; otherwise, nil.
    public func processAuthorisationRequest(did: String,
                                            credentialOffer: CredentialOffer,
                                            codeVerifier: String,
                                            authServer: AuthorisationServerWellKnownConfiguration, credentialFormat: String, docType: String, issuerConfig: IssuerWellKnownConfiguration?, redirectURI: String?) async -> WrappedResponse? {
        
        guard let authorizationEndpoint = authServer.authorizationEndpoint else { return WrappedResponse(data: nil, error: nil) }
        let redirectUri = redirectURI ?? "openid://callback"
        
        // Gather query parameters
        let responseType = "code"
        let scope = credentialFormat == "mso_mdoc" ? credentialFormat + "openid" : "openid"
        let state = UUID().uuidString
        let docType = credentialFormat == "mso_mdoc" ? docType : ""
        let authorizationDetails = buildAuthorizationRequest(credentialOffer: credentialOffer, docType: docType, format: credentialFormat, issuerConfig: issuerConfig)
        
        let nonce = UUID().uuidString
        let codeChallenge = CodeVerifierService.shared.generateCodeChallenge(codeVerifier: codeVerifier)
        let codeChallengeMethod = "S256"
        let clientMetadata = credentialFormat == "mso_mdoc" ? "" :
        ([
            "vp_formats_supported": [
                "jwt_vp": [ "alg": ["ES256"] ],
                "jwt_vc": [ "alg": ["ES256"] ]
            ],
            "response_types_supported": ["vp_token", "id_token"],
            "authorization_endpoint": "\(redirectUri)"
        ] as [String : Any]).toString()
        
        // Validate required parameters
        if responseType == "", did == "" {
            return WrappedResponse(data: nil, error: nil)
        }
        var authorizationURLComponents: URLComponents?
        if authServer.requirePushedAuthorizationRequests == true {
            let parEndpoint = authServer.pushedAuthorizationRequestEndpoint ?? ""
            var request = URLRequest(url: URL(string: parEndpoint)!)
            request.httpMethod = "POST"
            
            let bodyParameters = [
                "response_type": responseType,
                "client_id": did,
                "code_challenge": codeChallenge ?? "",
                "code_challenge_method": codeChallengeMethod,
                "redirect_uri": redirectUri,
                "authorization_details": authorizationDetails,
                "scope": scope,
                "state": state,
                "nonce": nonce,
                "client_metadata": clientMetadata ?? "",
                "issuer_state": credentialOffer.grants?.authorizationCode?.issuerState ?? ""
            ] as [String: Any]
            
            let postString = UIApplicationUtils.shared.getPostString(params: bodyParameters)
            let parameter = postString.replacingOccurrences(of: "+", with: "%2B")
            request.httpBody =  parameter.data(using: .utf8)
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            
            do {
                let (data, response) = try await session!.data(for: request)
                guard let authorization_response = String.init(data: data, encoding: .utf8) else { return WrappedResponse(data: nil, error: nil) }
                if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 || httpResponse.statusCode == 201 {
                    if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []),
                       let jsonDict = jsonResponse as? [String: Any],
                       let requestURI = jsonDict["request_uri"] as? String {
                        
                        authorizationURLComponents = URLComponents(string: authorizationEndpoint)
                        authorizationURLComponents?.queryItems = [
                            URLQueryItem(name: "client_id", value: did),
                            URLQueryItem(name: "request_uri", value: requestURI)
                        ]
                    }
                } else if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode >= 400 {
                    return WrappedResponse(data: nil, error: ErrorHandler.processError(data: data))
                }
                else {
                    debugPrint("Failed to get request_uri from the PAR response.")
                }
            } catch {
                debugPrint("Error in making PAR request: \(error.localizedDescription)")
            }
            
        } else {
            // Construct the authorization URL
            authorizationURLComponents = URLComponents(string: authorizationEndpoint)
            authorizationURLComponents?.queryItems = [
                URLQueryItem(name: "response_type", value: responseType),
                URLQueryItem(name: "scope", value: scope),
                URLQueryItem(name: "state", value: state),
                URLQueryItem(name: "client_id", value: did),
                URLQueryItem(name: "authorization_details", value: authorizationDetails),
                URLQueryItem(name: "redirect_uri", value: redirectUri),
                URLQueryItem(name: "nonce", value: nonce),
                URLQueryItem(name: "code_challenge", value: codeChallenge),
                URLQueryItem(name: "code_challenge_method", value: codeChallengeMethod),
                URLQueryItem(name: "client_metadata", value: clientMetadata),
                URLQueryItem(name: "issuer_state", value: credentialOffer.grants?.authorizationCode?.issuerState)
            ]
        }
        
        // Validate the constructed authorization URL
        guard let authorizationURL = authorizationURLComponents?.url else {
            debugPrint("Failed to construct the authorization URL.")
            return WrappedResponse(data: nil, error: nil)
        }
        debugPrint(authorizationURL)
        
        // Service call to get authorisation response
        var request = URLRequest(url: authorizationURL)
        request.httpMethod = "GET"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        var responseUrl = ""
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        do {
            // Try to fetch data from the URL session
//            if session == nil{
//                session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
//            }
            let (data, response) = try await session.data(for: request)
            
            let httpres = response as? HTTPURLResponse
            if httpres?.statusCode == 302, let location = httpres?.value(forHTTPHeaderField: "Location"){
                responseUrl = location
            } else if httpres?.statusCode ?? 0 >= 400 {
                return WrappedResponse(data: nil, error: ErrorHandler.processError(data: data))
            } else if httpres?.statusCode == 200, let contentType = httpres?.value(forHTTPHeaderField: "Content-Type"), contentType.contains("text/html") {
                responseUrl = authorizationURL.absoluteString
            } else{
                guard let authorization_response = String.init(data: data, encoding: .utf8) else { return nil }
                responseUrl = authorization_response
            }
            
        } catch {
            // If an error occurs, attempt to extract the failing URL from the error
            let nsError = error as NSError
            let response = nsError.userInfo["NSErrorFailingURLKey"]
            responseUrl = String(describing: response ?? "")
        }
        
        
        if responseUrl.contains("code=") ||
            responseUrl.contains("error=") ||
            responseUrl.contains("presentation_definition=") || responseUrl.contains("presentation_definition_uri=") ||
            (responseUrl.contains("request_uri=") && !responseUrl.contains("response_type=") && !responseUrl.contains("state=")){
            return WrappedResponse(data: responseUrl, error: nil)
        } else if let url = URL(string: responseUrl), let redirectUri = url.queryParameters?["redirect_uri"] , let responseType = url.queryParameters?["response_type"], responseType == "id_token" {
            let nonce = url.queryParameters?["nonce"]
            let state = url.queryParameters?["state"]
            let clientID = url.queryParameters?["client_id"]
            let uri = redirectUri.replacingOccurrences(of: "\n", with: "") ?? ""
            let code =  await processAuthorisationRequestUsingIdToken(
                did: did,
                authServerWellKnownConfig: authServer,
                redirectURI:  uri.trimmingCharacters(in: .whitespaces) ,
                nonce: nonce ?? "",
                state: state ?? "", clientID: clientID ?? "")
            return WrappedResponse(data: code, error: nil)
        } else if !responseUrl.hasPrefix(redirectURI ?? "") {
            return WrappedResponse(data: responseUrl, error: nil)
        } else {
            // if 'code' is not present
            let url = URL(string: responseUrl)
            let state = url?.queryParameters?["state"]
            let nonce = url?.queryParameters?["nonce"]
            let redirectUri = url?.queryParameters?["redirect_uri"]
            let uri = redirectUri?.replacingOccurrences(of: "\n", with: "") ?? ""
          let clientID = url?.queryParameters?["client_id"]
            let code =  await processAuthorisationRequestUsingIdToken(
                did: did,
                authServerWellKnownConfig: authServer,
                redirectURI:  uri.trimmingCharacters(in: .whitespaces) ,
                nonce: nonce ?? "",
                state: state ?? "", clientID: clientID ?? "")
            return WrappedResponse(data: code, error: nil)
        }
    }
    
    
    private func processAuthorisationRequestUsingIdToken(
        did: String,
        authServerWellKnownConfig: AuthorisationServerWellKnownConfiguration,
        redirectURI: String,
        nonce: String,
        state: String, clientID: String) async -> String? {
            
            // Retrieve the authorization endpoint from the server configuration.
            guard let authorizationEndpoint = authServerWellKnownConfig.authorizationEndpoint else { return nil }
            
            let header =
            ([
                "typ": "JWT",
                "alg": "ES256",
                "kid": "\(did)#\(did.replacingOccurrences(of: "did:key:", with: ""))"
            ]).toString() ?? ""
            
            // Generate JWT payload
            let currentTime = Int(Date().timeIntervalSince1970)
            let payload =
            ([
                "iss": "\(did)",
                "sub": "\(did)",
                "aud": "\(clientID ?? authorizationEndpoint)",
                "exp": currentTime + 3600,
                "iat": currentTime,
                "nonce": "\(nonce)"
            ] as [String : Any]).toString() ?? ""
            
            // Create JWT token
            let headerData = Data(header.utf8)
            
//            let keyHandler = SecureEnclaveHandler(organisationID: keyId)
            let secureData = await keyHandler.generateSecureKey()
            guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return nil}
            
            guard let urlComponents = URLComponents(string: redirectURI) else { return nil }
            
            // Create the URL with the added query parameters
            guard let url = urlComponents.url else { return nil }
            
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            
            let params = [
                "id_token" : idToken,
                "state" : state
            ] as [String: Any]
            
            
            let postString = UIApplicationUtils.shared.getPostString(params: params)
            request.httpBody = postString.data(using: .utf8)
            
            var responseUrl = ""
            
            do {
                if session == nil{
                    session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
                }
                let (data, response) = try await session!.data(for: request)
                let httpres = response as? HTTPURLResponse
                if httpres?.statusCode == 302, let location = httpres?.value(forHTTPHeaderField: "Location"){
                    responseUrl = location
                    return responseUrl
                } else{
                    let authorization_response = String.init(data: data, encoding: .utf8) ?? ""
                    
                    responseUrl = authorization_response
                }
                
                guard let authorisation_url = URL(string: responseUrl) else { return nil }
                if let components = URLComponents(url: authorisation_url, resolvingAgainstBaseURL: false),
                   let auth_code = components.queryItems?.first(where: { $0.name == "code" })?.value {
                    return responseUrl
                } else {
                    return nil
                }
            } catch {
                let nsError = error as NSError
                let response = nsError.userInfo["NSErrorFailingURLKey"]
                responseUrl = String(describing: response ?? "")
                return responseUrl
            }
        }
    
    // MARK: -  Processes the token request to obtain the access token.
    /** - Parameters
     - authServerWellKnownConfig: The well-known configuration of the authorization server.
     - code:  If the credential offer is pre authorised, then use the pre authorised code from the credential offer
     else use the code from the previous function - processAuthorisationRequest
     - did: The identifier for the DID key.
     - isPreAuthorisedCodeFlow: A boolean indicating if it's a pre-authorized code flow.
     - preAuthCode: The pre-authorization code for the token request.
     - userPin: The user's PIN, if required.
     
     - Returns: A `TokenResponse` object if the request is successful, otherwise `nil`.
     */
    public func processTokenRequest(
        did: String,
        tokenEndPoint: String?,
        code: String,
        codeVerifier: String,
        isPreAuthorisedCodeFlow: Bool = false,
        userPin: String?,
        version: String?,
        clientIdAssertion: String = "",
        wua: String,
        pop: String,
        redirectURI: String?) async -> TokenResponse? {
            
            if isPreAuthorisedCodeFlow {
                let tokenResponse =
                await getAccessTokenForPreAuthCredential(preAuthCode: code,
                                                         otpVal: userPin ?? "",
                                                         tokenEndpoint: tokenEndPoint ?? "",
                                                         version: version,
                                                         clientIdAssertion: clientIdAssertion,
                                                         wua: wua,
                                                         pop: pop)
                return tokenResponse
            } else {
                let codeVal = code.removingPercentEncoding ?? ""
                let tokenResponse =
                await getAccessToken(didKeyIdentifier: did,
                                     codeVerifier: codeVerifier,
                                     authCode: codeVal,
                                     tokenEndpoint: tokenEndPoint ?? "",
                                     clientIdAssertion: clientIdAssertion,
                                     wua: wua,
                                     pop: pop,
                                     redirectURI: redirectURI)
                return tokenResponse
            }
        }
    
    // MARK:  Processes a credential request to the specified credential endpoint.
    
    /** - Parameters
     - did: The identifier for the DID key.
     - secureKey: A wrapper object containing the public and private encryption keys
     - credentialOffer: The credential offer object containing offer details.
     - credentialEndpointUrlString: The URL string of the credential endpoint.
     - c_nonce: The nonce value for the credential request.
     - accessToken: The access token for authentication.
     
     - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.
     */
    public func processCredentialRequest(
        did: String,
        nonce: String,
        credentialOffer: CredentialOffer,
        issuerConfig: IssuerWellKnownConfiguration,
        accessToken: String,
        format: String) async -> CredentialResponse? {
            
            let jsonDecoder = JSONDecoder()
            guard let url = URL(string: issuerConfig.credentialEndpoint ?? "") else { return nil }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            
            guard let idToken = await ProofService.generateProof(nonce: nonce, credentialOffer: credentialOffer, issuerConfig: issuerConfig, did: did, keyHandler: keyHandler) else {return nil}
            
            let credentialTypes = getTypesFromCredentialOffer(credentialOffer: credentialOffer) ?? []
            let types = getTypesFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last ?? "")
            let formatT = getFormatFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last)
            let doctType = getDocTypeFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last)
            var params: [String: Any] = [:]
            if formatT == "mso_mdoc" {
                params = [
                    "doctype": doctType,
                    "format": formatT,
                    "proof": [
                        "proof_type": "jwt",
                        "jwt": idToken
                    ]
                ]
            } else {
                if types is String {
                    params = [
                        "vct": types ?? "",
                        "format": formatT ?? "jwt_vc",
                        "proof": [
                            "proof_type": "jwt",
                            "jwt": idToken
                        ]
                    ]
                }else{
                    params = [
                        "credential_definition": [
                            "type": types ?? []
                        ],
                        "format": formatT ?? "jwt_vc",
                        "proof": [
                            "proof_type": "jwt",
                            "jwt": idToken
                        ]
                    ]
                }
                if issuerConfig.credentialsSupported?.version == "v1" {
                    params = [
                        "types": credentialTypes,
                        "format": formatT ?? "jwt_vc",
                        "proof": [
                            "proof_type": "jwt",
                            "jwt": idToken
                        ]
                    ]
                } else {
                    
                    if let data = getTypesFromIssuerConfig(issuerConfig: issuerConfig, type: credentialTypes.last ?? "") {
                        if let dataArray = data as? [String] {
                            params = [
                                "credential_definition": [
                                    "type": dataArray ?? []
                                ],
                                "format": formatT ?? "jwt_vc",
                                "proof": [
                                    "proof_type": "jwt",
                                    "jwt": idToken
                                ]
                            ]
                        } else if let dataString = data as? String {
                            params = [
                                "vct": dataString,
                                "format": formatT ?? "jwt_vc",
                                "proof": [
                                    "proof_type": "jwt",
                                    "jwt": idToken
                                ]
                            ]
                        }
                    }
                }
            }
            
            // Create URL for the credential endpoint
            guard let url = URL(string: issuerConfig.credentialEndpoint ?? "") else { return nil }
            
            // Set up the request for the credential endpoint
            request = URLRequest(url: url)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            request.httpMethod = "POST"
            
            // Convert the parameters to JSON data and set it as the request body
            let requestBodyData = try? JSONSerialization.data(withJSONObject: params)
            request.httpBody =  requestBodyData
            
            // Perform the request and handle the response
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                let httpRes = response as? HTTPURLResponse
                if httpRes?.statusCode ?? 0 >= 400 {
                    let errorString = String(data: data, encoding: .utf8)
                    let error = EUDIError(from: ErrorResponse(message: errorString))
                    if let eudiErrorData = ErrorHandler.processError(data: data) {
                        return CredentialResponse(fromError: eudiErrorData)
                    } else {
                        return CredentialResponse(fromError: error)
                    }
                }
                guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else { return nil }
                if jsonObject["acceptance_token"] != nil {
                    let model = try jsonDecoder.decode(CredentialResponseV1.self, from: data)
                    return CredentialResponse(from: model)
                    
                } else if jsonObject["transaction_id"] != nil {
                    let modelV2 = try jsonDecoder.decode(CredentialResponseV2.self, from: data)
                    return CredentialResponse(from: modelV2)
                } else if jsonObject["acceptance_token"] == nil && jsonObject["transaction_id"] == nil {
                    let model = try jsonDecoder.decode(CredentialResponseV1.self, from: data)
                    return CredentialResponse(from: model)
                }
                else {
                    let error = EUDIError(from: ErrorResponse(message: "Invalid data format", code: nil))
                    return CredentialResponse(fromError: error)
                }
            } catch {
                debugPrint("Process credential request failed: \(error)")
                let nsError = error as NSError
                let errorCode = nsError.code
                let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
                return CredentialResponse(fromError: error)
            }
        }
    
    
    // MARK: - Processes a deferred credential request to obtain the credential response in deffered manner.
    
    /** - Parameters
     - acceptanceToken - token which we got from credential request
     - deferredCredentialEndPoint - end point to call the deferred credential
     **/
    //    - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.
    
    public func processDeferredCredentialRequest(
        acceptanceToken: String,
        deferredCredentialEndPoint: String, version: String?, accessToken: String?) async -> CredentialResponse? {
            
            let jsonDecoder = JSONDecoder()
            guard let url = URL(string: deferredCredentialEndPoint) else { return nil }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            
            if version == "v1" {
                request.setValue( "Bearer \(acceptanceToken)", forHTTPHeaderField: "Authorization")
                let params = "{}"
                let data = params.data(using: .utf8)
                request.httpBody = data
            } else if version == "v2" {
                var params: [String: Any] = [:]
                request.setValue( "Bearer \(accessToken ?? "")", forHTTPHeaderField: "Authorization")
                params = ["transaction_id": acceptanceToken ?? ""]
                let requestBodyData = try? JSONSerialization.data(withJSONObject: params)
                request.httpBody =  requestBodyData
            }
            
            
            // Perform the request and handle the response
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                    return nil
                }
                if jsonObject["acceptance_token"] != nil {
                    let model = try jsonDecoder.decode(CredentialResponseV1.self, from: data)
                    return CredentialResponse(from: model)
                    
                } else if jsonObject["transaction_id"] != nil {
                    let modelV2 = try jsonDecoder.decode(CredentialResponseV2.self, from: data)
                    return CredentialResponse(from: modelV2)
                } else if jsonObject["acceptance_token"] == nil && jsonObject["transaction_id"] == nil {
                    let model = try jsonDecoder.decode(CredentialResponseV1.self, from: data)
                    return CredentialResponse(from: model)
                }
                else {
                    let error = EUDIError(from: ErrorResponse(message: "Invalid data format", code: nil))
                    return CredentialResponse(fromError: error)
                }
            } catch {
                debugPrint("Process deferred credential request failed: \(error)")
                let nsError = error as NSError
                let errorCode = nsError.code
                let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
                return CredentialResponse(fromError: error)
            }
        }
    
    // MARK: - Private methods
    
    // Retrieves the access token for Pre-Authorised credential using the provided parameters.
    private func getAccessTokenForPreAuthCredential(
        preAuthCode: String,
        otpVal: String,
        tokenEndpoint: String?,
        version: String?,
        clientIdAssertion: String = "",
        wua: String,
        pop: String) async -> TokenResponse? {
            
            let jsonDecoder = JSONDecoder()
            let grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            
            // Constructing parameters for the token request
            var params: [String: Any] = [:]
            // Constructing parameters for the token request
            if version == "v1" {
                params = ["grant_type": grantType, "pre-authorized_code":preAuthCode, "user_pin": otpVal] as [String: Any]
            } else if version == "v2" {
                params = ["grant_type": grantType, "pre-authorized_code":preAuthCode, "tx_code": otpVal] as [String: Any]
            }
//            if !clientIdAssertion.isEmpty {
//                params["client_assertion"] = clientIdAssertion
//                params["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
//            }
            let postString = UIApplicationUtils.shared.getPostString(params: params)
            
            guard let urlString = tokenEndpoint, let url =  URL(string: urlString) else { return TokenResponse(error: EUDIError(from: ErrorResponse(message: "Invalid url")))}
            // Creating the request
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            request.setValue(wua, forHTTPHeaderField: "OAuth-Client-Attestation")
            request.setValue(pop, forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
            request.httpBody = postString.data(using: .utf8)
            
            // Performing the token request
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                let httpres = response as? HTTPURLResponse
                let dataString = String.init(data: data, encoding: .utf8)
                if let dataResponse = response as? HTTPURLResponse, dataResponse.statusCode >= 400, let errorData =  dataString {
                    let jsonData = errorData.data(using: .utf8)
                    ErrorHandler.processError(data: data)
                    return TokenResponse(error: ErrorHandler.processError(data: data))
                } else {
                    let dataResponse = response as? HTTPURLResponse
                    let lpid = dataResponse?.value(forHTTPHeaderField: "legal-pid-attestation")
                    let lpidPop = dataResponse?.value(forHTTPHeaderField: "legal-pid-attestation-pop")
                    var model = try jsonDecoder.decode(TokenResponse.self, from: data)
                    model.lpid = lpid
                    model.lpidPop = lpidPop
                    return model
                }
            } catch {
                debugPrint("Get access token for preauth credential failed: \(error)")
                let nsError = error as NSError
                let errorCode = nsError.code
                let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
                return TokenResponse(error: error)
            }
            
            return nil
        }
    
    // Retrieves the access token using the provided parameters.
    private func getAccessToken(
        didKeyIdentifier: String,
        codeVerifier: String,
        authCode: String,
        tokenEndpoint: String?,
        clientIdAssertion: String = "",
        wua: String,
        pop: String,
        redirectURI: String?) async -> TokenResponse? {
            
            let jsonDecoder = JSONDecoder()
            let grantType = "authorization_code"
            
            // Constructing parameters for the token request
            //let clientAssertion = !clientIdAssertion.isEmpty ? clientIdAssertion : nil
            var params: [String: Any] = [
                "grant_type": grantType,
                "code": authCode,
                "client_id": didKeyIdentifier,
                "code_verifier": codeVerifier,
                "redirect_uri": redirectURI ?? "openid://callback"
            ]
            
            if !clientIdAssertion.isEmpty {
                params["client_assertion"] = clientIdAssertion
                params["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            }
            let postString = UIApplicationUtils.shared.getPostString(params: params)
            
            // Creating the request
            guard let urlString = tokenEndpoint, let url =  URL(string: urlString) else { return TokenResponse(error: EUDIError(from: ErrorResponse(message: "Invalid url")))}
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            request.setValue(wua, forHTTPHeaderField: "OAuth-Client-Attestation")
            request.setValue(pop, forHTTPHeaderField: "OAuth-Client-Attestation-PoP")
            
            request.httpBody = postString.data(using: .utf8)
            
            // Performing the token request
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                let httpsResponse = response as? HTTPURLResponse
                if httpsResponse?.statusCode ?? 0 >= 400 {
                    let dataString = String(data: data, encoding: .utf8)
                    let error = EUDIError(from: ErrorResponse(message: dataString))
                    return TokenResponse(error: ErrorHandler.processError(data: data))
                } else {
                    var model = try jsonDecoder.decode(TokenResponse.self, from: data)
                    let lpid = httpsResponse?.value(forHTTPHeaderField: "legal-pid-attestation")
                    let lpidPop = httpsResponse?.value(forHTTPHeaderField: "legal-pid-attestation-pop")
                    model.lpid = lpid
                    model.lpidPop = lpidPop
                    return model
                }
            } catch {
                debugPrint("Get access token for preauth credential failed: \(error)")
                let nsError = error as NSError
                let errorCode = nsError.code
                let error = EUDIError(from: ErrorResponse(message:error.localizedDescription, code: errorCode))
                return TokenResponse(error: error)
            }
        }
    
    public func getFormatFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> String? {
        guard let issuerConfig = issuerConfig else { return nil }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            return credentialSupported.format
        } else {
            return "jwt_vc"
        }
    }
    
    public func isCredentialMetaDataAvailable(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Bool? {
        guard let issuerConfig = issuerConfig else { return nil }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            return true
        } else {
            return false
        }
    }
    
    
    public func getTypesFromCredentialOffer(credentialOffer: CredentialOffer?) -> [String]? {
        guard let credentialOffer = credentialOffer else { return nil }
        
        if let types = credentialOffer.credentials?[0].types {
            return types
        } else if credentialOffer.credentials?[0].format == "mso_mdoc", let doctype = credentialOffer.credentials?[0].doctype {
            return [doctype]
        } else {
            return nil
        }
    }
    
    public func getTypesFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Any? {
        guard let issuerConfig = issuerConfig else { return nil }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            if credentialSupported.format == "vc+sd-jwt" || credentialSupported.format == "dc+sd-jwt"{
                return credentialSupported.credentialDefinition?.vct ?? credentialSupported.vct
            } else {
                return credentialSupported.credentialDefinition?.type
            }
        } else {
            return nil
        }
    }
    
    public func getCryptoFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> [String]? {
        guard let issuerConfig = issuerConfig else { return nil }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            return credentialSupported.cryptographicSuitesSupported
        } else {
            return nil
        }
    }
    
    public func getCredentialDisplayFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Display? {
        guard let issuerConfig = issuerConfig else { return nil }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            return credentialSupported.display?[0] ?? nil
        } else {
            return nil
        }
    }
    
    public func getDocTypeFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> String? {
        guard let issuerConfig = issuerConfig else { return nil }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            return credentialSupported.docType ?? nil
        } else {
            return nil
        }
    }
}


extension IssueService: URLSessionDelegate, URLSessionTaskDelegate {
    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        // Stops the redirection, and returns (internally) the response body.
        completionHandler(nil)
    }
}


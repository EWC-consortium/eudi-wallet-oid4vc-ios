//
//  IssueServiceProtocol.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//
import Foundation
import CryptoKit
protocol IssueServiceProtocol {
    // Retrieves credential issuer asynchronously based on the provided credential_offer / credential_offer_uri.
    ///
    /// - Parameters:
    ///   - credentialOffer: The string representation of the credential offer.
    /// - Returns: A `CredentialOffer` object if the resolution is successful; otherwise, `nil`.
    func resolveCredentialOffer(credentialOffer: String) async throws -> CredentialOffer?
    
    
    // To process the authorisation request, The authorisation request is to grant access to the credential endpoint.
    /// - Parameters:
    ///   - did - DID created for the issuance
    ///   - secureKey: A wrapper object containing the public and private encryption keys
    ///   - credentialOffer: The credential offer containing the necessary details for authorization.
    ///   - authServer: The authorization server configuration.
    ///   - codeVerifier - to build the authorisation request
    /// - Returns: code if successful; otherwise, nil.
    func processAuthorisationRequest(did: String, credentialOffer: CredentialOffer, codeVerifier: String, authServer: AuthorisationServerWellKnownConfiguration, credentialFormat: String, docType: String, issuerConfig: IssuerWellKnownConfiguration?, redirectURI: String?) async -> WrappedResponse?
    
    // Processes the token request to obtain the access token.
    /** - Parameters
     - authServerWellKnownConfig: The well-known configuration of the authorization server.
     - code:  If the credential offer is pre authorised, then use the pre authorised code from the credential offer
     else use the code from the previous function - processAuthorisationRequest
     - did: The identifier for the DID key.
     - codeverifier:
     - isPreAuthorisedCodeFlow: A boolean indicating if it's a pre-authorized code flow.
     - preAuthCode: The pre-authorization code for the token request.
     - userPin: The user's PIN, if required.
     
     - Returns: A `TokenResponse` object if the request is successful, otherwise `nil`.
     */
    func processTokenRequest(did: String, tokenEndPoint: String?, code: String, codeVerifier: String, isPreAuthorisedCodeFlow: Bool, userPin: String?, version: String?,  clientIdAssertion: String, wua: String, pop: String, redirectURI: String?) async -> TokenResponse?
    
    
    // Processes a credential request to the specified credential endpoint.
    
    /** - Parameters
     - did: The identifier for the DID key.
     - secureKey: A wrapper object containing the public and private encryption keys
     - credentialOffer: The credential offer object containing offer details.
     - credentialEndpointUrlString: The URL string of the credential endpoint.
     - c_nonce: The nonce value for the credential request.
     - accessToken: The access token for authentication.
     - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.
     */
    func processCredentialRequest(did: String, nonce: String, credentialOffer: CredentialOffer, issuerConfig: IssuerWellKnownConfiguration, accessToken: String, format: String, credentialTypes: [String], tokenResponse: TokenResponse?, authDetails: AuthorizationDetails?) async -> CredentialResponse?
    
    // Processes a deferred credential request to obtain the credential response in deffered manner.
    /** - Parameters
     - acceptanceToken - token which we got from credential request
     - deferredCredentialEndPoint - end point to call the deferred credential
     **/
    //    - Returns: A `CredentialResponse` object if the request is successful, otherwise `nil`.
    func processDeferredCredentialRequest(acceptanceToken: String, deferredCredentialEndPoint: String, version: String?, accessToken: String?) async -> CredentialResponse?
    
    func getFormatFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?) -> String?
    
    func isCredentialMetaDataAvailable(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Bool?
    
    func getTypesFromCredentialOffer(credentialOffer: CredentialOffer?) -> [String]?
    func getTypesFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Any?
    
    func getCryptoFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> [String]?
    
    func getCredentialDisplayFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> Display?
    func getDocTypeFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> String?
    
}

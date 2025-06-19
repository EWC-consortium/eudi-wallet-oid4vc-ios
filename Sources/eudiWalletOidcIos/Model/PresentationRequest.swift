//
//  PresentationRequest.swift
//
//
//  Created by Mumthasir mohammed on 18/03/24.
//
import Foundation
public struct PresentationRequest: Codable {
    public var state, clientId, clientIDScheme,  redirectUri, responseType, responseMode, scope, nonce, requestUri: String?
    public var responseUri: String?
    public var presentationDefinition: String?
    public var clientMetaData: String?
    public var presentationDefinitionUri: String?
    public var clientMetaDataUri: String?
    public var transactionData: [String]?
    public var request: String?
    enum CodingKeys: String, CodingKey {
        case state = "state"
        case clientId = "client_id"
        case clientIDScheme = "client_id_scheme"
        case redirectUri = "redirect_uri"
        case responseUri = "response_uri"
        case responseType = "response_type"
        case responseMode = "response_mode"
        case scope = "scope"
        case nonce = "nonce"
        case requestUri = "request_uri"
        case presentationDefinition = "presentation_definition"
        case clientMetaData = "client_metadata"
        case presentationDefinitionUri = "presentation_definition_uri"
        case clientMetaDataUri = "client_metadata_uri"
        case transactionData = "transaction_data"
        case request = "request"
    }
    public init(state: String?, clientId: String?, redirectUri: String?, responseUri: String?, responseType: String?, responseMode: String?, scope: String?, nonce: String?, requestUri: String?, presentationDefinition: String?, clientMetaData:  String?, presentationDefinitionUri: String?, clientMetaDataUri: String?, clientIDScheme: String?, transactionData: [String], request: String?) {
        self.state = state
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.responseUri = responseUri
        self.responseType = responseType
        self.responseMode = responseMode
        self.scope = scope
        self.nonce = nonce
        self.requestUri = requestUri
        self.presentationDefinition = presentationDefinition
        self.clientMetaData = clientMetaData
        self.presentationDefinitionUri = presentationDefinitionUri
        self.clientMetaDataUri = clientMetaDataUri
        self.clientIDScheme = clientIDScheme
        self.transactionData = transactionData
        self.request = request
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decodeIfPresent(String.self, forKey: .state)
        clientId = try container.decodeIfPresent(String.self, forKey: .clientId)
        clientIDScheme = try container.decodeIfPresent(String.self, forKey: .clientIDScheme)
        redirectUri = try container.decodeIfPresent(String.self, forKey: .redirectUri)
        responseUri = try container.decodeIfPresent(String.self, forKey: .responseUri)
        responseType = try container.decodeIfPresent(String.self, forKey: .responseType)
        responseMode = try container.decodeIfPresent(String.self, forKey: .responseMode)
        scope = try container.decodeIfPresent(String.self, forKey: .scope)
        nonce = try container.decodeIfPresent(String.self, forKey: .nonce)
        requestUri = try container.decodeIfPresent(String.self, forKey: .requestUri)
        
        if let presentationDefinitionString = try? container.decode(String.self, forKey: .presentationDefinition) {
            presentationDefinition = presentationDefinitionString
        } else if let presentationDefinitionModel = try? container.decode(PresentationDefinitionModel.self, forKey: .presentationDefinition) {
            presentationDefinition = presentationDefinitionModel.toJSONString()
        } else {
            presentationDefinition = nil
        }
        if let clientMetaDataModel = try? container.decode(ClientMetaData.self, forKey: .clientMetaData) {
            clientMetaData = clientMetaDataModel.toJSONString()
        }
        presentationDefinitionUri = try container.decodeIfPresent(String.self, forKey: .presentationDefinitionUri)
        clientMetaDataUri = try container.decodeIfPresent(String.self, forKey: .clientMetaDataUri)
        transactionData = try container.decodeIfPresent([String].self, forKey: .transactionData)
        request = try container.decodeIfPresent(String.self, forKey: .request)
//        if let transactionDataModel = try? container.decode(TransactionData.self, forKey: .transactionData) {
//            transactionData = transactionDataModel.toJSONString()
//        }
    }
}
public struct ClientMetaData: Codable {
    public var clientName, coverUri, description, location, logoUri, legalPidAttestation, legalPidAttestationPop: String?
    enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case coverUri = "cover_uri"
        case description = "description"
        case location = "location"
        case logoUri = "logo_uri"
        case legalPidAttestation = "legal_pid_attestation"
        case legalPidAttestationPop = "legal_pid_attestation_pop"
    }
    public init(clientName: String?, coverUri: String?, description: String?, location: String?, logoUri: String?, legalPidAttestation: String?, legalPidAttestationPop: String?) {
        self.clientName = clientName
        self.coverUri = coverUri
        self.description = description
        self.location = location
        self.logoUri = logoUri
        self.legalPidAttestation = legalPidAttestation
        self.legalPidAttestationPop = legalPidAttestationPop
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        clientName = try container.decodeIfPresent(String.self, forKey: .clientName)
        coverUri = try container.decodeIfPresent(String.self, forKey: .coverUri)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        location = try container.decodeIfPresent(String.self, forKey: .location)
        logoUri = try container.decodeIfPresent(String.self, forKey: .logoUri)
        legalPidAttestation = try container.decodeIfPresent(String.self, forKey: .legalPidAttestation)
        legalPidAttestationPop = try container.decodeIfPresent(String.self, forKey: .legalPidAttestationPop)
    }
    
}
public struct TransactionData: Codable {
    public var type: String?
    public var credentialIDs: [String]?
    public var paymentData: PaymentData?
    enum CodingKeys: String, CodingKey {
        case type = "type"
        case credentialIDs = "credential_ids"
        case paymentData = "payment_data"
    }
    public init(type: String?, credentialIDs: [String]?, paymentData: PaymentData?) {
        self.type = type
        self.credentialIDs = credentialIDs
        self.paymentData = paymentData
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        type = try container.decodeIfPresent(String.self, forKey: .type)
        credentialIDs = try container.decodeIfPresent([String].self, forKey: .credentialIDs)
        paymentData = try container.decodeIfPresent(PaymentData.self, forKey: .paymentData)
    }
    
}
public struct PaymentData: Codable {
    public var payee: String?
    public var currencyAmount: CurrencyAmount?
    
    enum CodingKeys: String, CodingKey {
        case payee = "payee"
        case currencyAmount = "currency_amount"
    }
    public init(payee: String?, currencyAmount: CurrencyAmount?) {
        self.payee = payee
        self.currencyAmount = currencyAmount
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payee = try container.decodeIfPresent(String.self, forKey: .payee)
        currencyAmount = try container.decodeIfPresent(CurrencyAmount.self, forKey: .currencyAmount)
    }
}
public struct CurrencyAmount: Codable {
    public var currency: String?
    public var value: Double?
    
    enum CodingKeys: String, CodingKey {
        case currency = "currency"
        case value = "value"
    }
    public init(currency: String?, value: Double?) {
        self.currency = currency
        self.value = value
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        currency = try container.decodeIfPresent(String.self, forKey: .currency)
        if let valueDouble = try? container.decode(Double.self, forKey: .value) {
            value = valueDouble
        } else if let valueString = try? container.decode(String.self, forKey: .value) {
            value = Double(valueString)
        } else {
            value = nil
        }
    }
}

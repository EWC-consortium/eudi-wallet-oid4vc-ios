//
//  IssuerWellKnownConfiguration.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//
import Foundation
// MARK: - IssuerWellKnownConfiguration
public struct Display: Codable{
    public let name: String?
    public let location: String?
    public let locale: String?
    public let description: String?
    public var bgImage, logo, cover: DisplayCover?
    public var backgroundColor, textColor: String?
    
    init(from: DisplayResponse) {
        name = from.name
        location = from.location
        locale = from.locale
        description = from.description
        bgImage = from.bgImage == nil ? nil : DisplayCover(from: from.bgImage!)
        logo = from.logo == nil ? nil : DisplayCover(from: from.logo!)
        cover = from.cover == nil ? nil : DisplayCover(from: from.cover!)
        backgroundColor = from.backgroundColor
        textColor = from.textColor
    }
    
    public init(mName: String?, mLocation:String?, mLocale: String?, mDescription: String?, mCover: DisplayCover?, mLogo: DisplayCover?, mBackgroundColor: String?, mTextColor: String?) {
           name = mName
           location = mLocation
           locale = mLocale
           description = mDescription
           bgImage = mCover
           logo = mLogo
           backgroundColor = mBackgroundColor
           textColor = mTextColor
       }
}
public struct TrustFrameworkInIssuer {
    public let name: String?
    public let type: String?
    public let uri: String?
    public let display: Display?
    
    init(from: TrustFrameworkInIssuerResponse) {
        name = from.name
        type = from.type
        uri = from.uri
        display = from.display == nil ? nil : Display(from: from.display!)
    }
}
// MARK: - CredentialObj
public struct CredentialSupportedObject {
    
    public var dataSharing: [String : DataSharing]?
    // version is used to identify whether the CredentialSupportedObject is an array or another type
    public var version: String?
    
    init(from: [String:DataSharingResponse]) {
        
        dataSharing = from.mapValues({
            DataSharing(from: $0)
        })
        version = "v2"
        
    }
    init(from: [String:DataSharingResponseV2]) {
        
        dataSharing = from.mapValues({
            DataSharing(from: $0)
        })
        version = "v2"
        
    }
    
    init(from: [DataSharingOldFormatResponse]) {
        var ldataSharing = [String:DataSharing]()
        version = "v1"
        if from.count > 0{
            for item in from{
                let dataSharingVal = DataSharing(from: item)
                if dataSharingVal.format == "mso_mdoc" {
                    if let key = dataSharingVal.docType{
                        ldataSharing[key] = dataSharingVal
                    }
                }
                else if let key = dataSharingVal.types?.last{
                    ldataSharing[key] = dataSharingVal
                }
            }
            
            if ldataSharing.count > 0{
                dataSharing = ldataSharing
            }
        }
    }
}
public struct DisplayElement {
    public var name: String?
    public var locale: Locale?
    
    init(from: DisplayElementResponse) {
        name = from.name
        locale = from.locale
    }
}
public struct IssuerCredentialDefinition {
    public var type: [String]?
    public var vct: String?
    
    init(from: IssuerCredentialDefinitionResponse) {
        type = from.type
        vct = from.vct
    }
}
// MARK: - DataSharing
public struct DataSharing {
    public var format, scope: String?
    public var cryptographicBindingMethodsSupported, cryptographicSuitesSupported: [String]?
    public var display: [Display]?
    public var types: [String]?
    public var trustFramework: TrustFramework?
    public var credentialDefinition: IssuerCredentialDefinition?
    public var docType: String?
    public var vct: String?
    
    init(from: DataSharingResponse) {
        format = from.format
        scope = from.scope
        cryptographicBindingMethodsSupported = from.cryptographicBindingMethodsSupported
        cryptographicSuitesSupported = from.cryptographicSuitesSupported
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0) })
        }
        credentialDefinition = from.credentialDefinition == nil ? nil : IssuerCredentialDefinition(from: from.credentialDefinition!)
    docType = from.docType
    }
    init(from: DataSharingResponseV2) {
        format = from.format
        scope = from.scope
        cryptographicBindingMethodsSupported = from.cryptographicBindingMethodsSupported
        cryptographicSuitesSupported = from.cryptographicSuitesSupported
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0) })
        }
        credentialDefinition = from.credentialDefinition == nil ? nil : IssuerCredentialDefinition(from: from.credentialDefinition!)
        vct = from.vct
        docType = from.docType
    }
    
    init(from: DataSharingOldFormatResponse) {
        format = from.format
        types = from.types
    docType = from.docType
        trustFramework = from.trustFramework == nil ? nil : TrustFramework(from: from.trustFramework!)
        if let dataSharingDisplayList = from.display, dataSharingDisplayList.count > 0{
            display = dataSharingDisplayList.map({ Display(from: $0)})
        }
    }
}
// MARK: - CredentialsSupportedObjectDisplay
public struct CredentialsSupportedObjectDisplay {
    public var name, location, locale: String?
    public var cover, logo: DisplayCover?
    public var description: String?
}
// MARK: - Cover
public struct DisplayCover: Codable {
    public var uri: String?
    public var altText: String?
    public var url: String?
    
    init(from: DisplayCoverResponse) {
        uri = from.uri
        altText = from.altText
        url =  from.url
    }
    
    public init(mUrl: String?, mAltText: String?) {
        uri = mUrl
        altText = mAltText
        url = mUrl
    }
}
public struct IssuerWellKnownConfiguration {
    public let credentialIssuer: String?
    public let authorizationServer: String?
    public let credentialEndpoint: String?
    public let deferredCredentialEndpoint: String?
    public let display: [Display]?
    public let credentialsSupported: CredentialSupportedObject?
    public let error: EUDIError?
    public let notificationEndPoint: String?
    
    public init(from: IssuerWellKnownConfigurationResponse) {
        credentialIssuer = from.credentialIssuer
        authorizationServer = from.authorizationServer ?? from.authorizationServers?[0] ?? ""
        credentialEndpoint = from.credentialEndpoint
        deferredCredentialEndpoint = from.deferredCredentialEndpoint
        
        if let displayList = from.display as? [DisplayResponse]
        {
            display = displayList.map({ Display(from: $0) })
        } else{
            display = nil
        }
        
        if let credentialsSupportList = from.credentialsSupported as? [[String:DataSharingResponse]], let firstObj = credentialsSupportList.first{
            credentialsSupported = CredentialSupportedObject(from: firstObj)
        } else if let credentialsSupportListOldFormat = from.credentialsSupported as? [DataSharingOldFormatResponse]{
            credentialsSupported = CredentialSupportedObject(from: credentialsSupportListOldFormat)
        } else{
            credentialsSupported = nil
        }
        notificationEndPoint = from.notificationEndPoint
        error = nil
  
    }
public init(from: IssuerWellKnownConfigurationResponseV2) {
        credentialIssuer = from.credentialIssuer
        authorizationServer = from.authorizationServer ?? from.authorizationServers?[0] ?? ""
        credentialEndpoint = from.credentialEndpoint
        deferredCredentialEndpoint = from.deferredCredentialEndpoint
        
        if let displayList = from.display as? [DisplayResponse]
        {
            display = displayList.map({ Display(from: $0) })
        } else{
            display = nil
        }
        
        if let credentialsSupportList = from.credentialsSupported as? [[String:DataSharingResponseV2]], let firstObj = credentialsSupportList.first{
            credentialsSupported = CredentialSupportedObject(from: firstObj)
        } else if let credentialsSupportListOldFormat = from.credentialsSupported as? [DataSharingOldFormatResponse]{
            credentialsSupported = CredentialSupportedObject(from: credentialsSupportListOldFormat)
        } else{
            credentialsSupported = nil
        }
        
        error = nil
    notificationEndPoint = from.notificationEndPoint
    }
    
    public init(mCredentialIssuer: String?,
                mAuthorizationServer: String?,
                mCredentialEndpoint: String?,
                mDeferredCredentialEndpoint: String?,
                mDisplay: Display?) {
        credentialIssuer = nil
        authorizationServer = nil
        credentialEndpoint = nil
        deferredCredentialEndpoint = nil
        display = mDisplay != nil ? [mDisplay!] : nil
        credentialsSupported = nil
        error = nil
        notificationEndPoint = nil
    }
    
    init(from: EUDIError) {
        error = from
        credentialIssuer = nil
        authorizationServer = nil
        credentialEndpoint = nil
        deferredCredentialEndpoint = nil
        display = nil
        credentialsSupported = nil
        notificationEndPoint = nil
    }
}

//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class DCQLToPresentationExchange {
    
    func convertDCQLToPresentationExchange(dcql: String) -> PresentationDefinitionModel? {
        //Fix me: convert dcql to PresentationDefinitionModel
        return nil
    }
    
    func convertToOID4VP(dcql: DCQLQuery?) -> PresentationDefinitionModel? {
        let presentationDefinitionId = UUID().uuidString

        let inputDescriptors: [InputDescriptor] = dcql?.credentials.compactMap { credential in
            let descriptorId = credential.id

            // Claim fields
            let claimFields: [Field] = credential.claims.compactMap { claim in
                switch claim {
                case .namespacedClaim(let namespaced):
                    let path = "$['\(namespaced.namespace)']['\(namespaced.claimName)']"
                    return Field(path: [path], filter: nil)
                case .pathClaim(let pathClaim):
                    guard let last = pathClaim.path.last else { return nil }
                    let path = "$.\(last)"
                    return Field(path: [path], filter: nil)
                }
            }

            // Meta fields (vct filtering)
            var metaFields: [Field] = []
            if case .dcSDJWT(let meta) = credential.meta,
               let vctValue = meta.vctValues.first {
                let metaField = Field(
                    path: ["$.vct", "$.vc.vct"],
                    filter: Filter(
                        type: "string",
                        contains: nil,
                        const: vctValue,
                        pattern: nil
                    )
                )
                metaFields.append(metaField)
            }

            // Combined fields
            let allFields = claimFields + metaFields

            // Format
            let jwtVp = JwtVp(alg: ["ES256", "ES384"])
            let format: [String: JwtVp?] = [
                credential.format: jwtVp
            ]

            return InputDescriptor(
                id: descriptorId,
                name: nil,
                purpose: nil,
                constraints: Constraints(
                    limitDisclosure: "required",
                    fields: allFields
                ),
                format: format
            )
        } ?? []

        return PresentationDefinitionModel(
            id: presentationDefinitionId,
            name: nil,
            purpose: nil,
            format: nil, // Top-level format is optional and not used in original Kotlin
            inputDescriptors: inputDescriptors
        )
        
    }
    
    func convertPresentationDefinitionModelToString(_ model: PresentationDefinitionModel?) -> String? {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase // Optional: aligns with your `input_descriptors` key
        encoder.outputFormatting = .prettyPrinted
       // [.prettyPrinted, .sortedKeys]

        do {
            let jsonData = try encoder.encode(model)
            return String(data: jsonData, encoding: .utf8)
        } catch {
            print("Failed to encode PresentationDefinitionModel: \(error)")
            return nil
        }
    }
        
}

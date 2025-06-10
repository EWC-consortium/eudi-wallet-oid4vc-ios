//
//  File.swift
//
//
//  Created by oem on 05/07/24.
//

import Foundation

class ErrorHandler {
    
    static func processError(data: Data?) -> EUDIError? {
            // Convert Data to String for initial check
            guard let data = data, let dataString = String(data: data, encoding: .utf8) else {
                return EUDIError(from: ErrorResponse(message:"Unexpected error. Please try again.", code: -1))
            }

            // Attempt to parse the data string as a JSON object
            let jsonObject: [String: Any]?
            do {
                jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
            } catch {
                return EUDIError(from: ErrorResponse(message: dataString, code: -1))
            }

            // Determine the error response based on the content of the error message
            let errorResponse: EUDIError?
            if dataString.contains("Invalid Proof JWT: iss doesn't match the expected client_id") {
                errorResponse = EUDIError(from: ErrorResponse(message:"DID is invalid", code: 1))
            } else if let jsonObject = jsonObject {
                if let errorDescription = jsonObject["error_description"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:errorDescription, code: -1))
                } else if let errors = jsonObject["errors"] as? [[String: Any]],
                          let firstError = errors.first,
                          let message = firstError["message"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:message, code: -1))
                } else if let error = jsonObject["error"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:error, code: -1))
                } else if let error = jsonObject["detail"] as? String {
                    errorResponse = EUDIError(from: ErrorResponse(message:error, code: -1))
                } else if let error = jsonObject["detail"] as? [String: Any] {
                    let errorDetail = error["error_description"] as? String
                    errorResponse = EUDIError(from: ErrorResponse(message:errorDetail, code: -1))
                } else {
                    errorResponse = EUDIError(from: ErrorResponse(message:"Unexpected error. Please try again.", code: -1))
                }
            } else {
                errorResponse = EUDIError(from: ErrorResponse(message:"Unexpected error. Please try again.", code: -1))
            }
            return errorResponse
        }
}

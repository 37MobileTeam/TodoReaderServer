//
//  Data+decryptWithAES256CBC.swift
//  App
//
//  Created by lory on 2022/12/13.
//

import Foundation

extension String {
    func decryptWithAES256CBC(requestNonceStr: String, requestId: String, requestVersion: String?) throws -> String? {
        let xRequestId = requestId
        let xRequestNonceStr = requestNonceStr
        let cookies: String? = nil
        let authorization: String? = nil
        let base64Str = self
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           xRequestId: xRequestId,
                                           xRequestVersion: requestVersion, params: [String: AnyHashable]())
        guard let data = base64Str.data(using: .utf8) else {
            return ""
        }
        let aesKey = tool?.requestDecryptAesKey(xRequestNonceStr)
        let iv = tool?.requestDecryptIV(xRequestNonceStr)
        let plainData = try tool?.decrypt(data,
                                          aesKey: aesKey!,
                                          iv: iv!,
                                          cookie: cookies,
                                          authorization: authorization)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            return ""
        }
        print("Content-Length", plainText.count)
        print("Encrypt Body", plainText)
        return plainText
    }
    
    func encryptWithAES256CBC(requestNonceStr: String = "soC2GAr8jN2fsbry7890123456789012", responseNonceStr: String = "23456789012345678901234567890123", requestVersion: String?) throws -> String? {
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           requestNonceStr: requestNonceStr,
                                           responseNonceStr: responseNonceStr,
                                           requestVersion: requestVersion)
        let encryptPostString = try tool?.encrypt(response: self)
        print("Content-Length", encryptPostString?.count)
        print("Encrypt Body", encryptPostString)
        return encryptPostString
    }
    
    func decryptWithAES256CBC(requestNonceStr: String = "soC2GAr8jN2fsbry7890123456789012", responseNonceStr: String = "23456789012345678901234567890123", requestVersion: String?) throws -> String? {
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           requestNonceStr: requestNonceStr,
                                           responseNonceStr: responseNonceStr,
                                           requestVersion: requestVersion)
        let decryptPostString = try tool?.decrypt(response: self)
        print("Content-Length", decryptPostString?.count)
        print("Encrypt Body", decryptPostString)
        return decryptPostString
    }
}


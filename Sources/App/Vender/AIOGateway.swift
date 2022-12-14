//
//  AIOGateway.swift
//  PassionKit
//
//  Created by lory on 2022/10/21.
//  Copyright © 2022 sqsy. All rights reserved.
//

import Foundation
import CommonCrypto

/// All-in-One Gateway 统一网关
struct AIOGateway {
    let processID = String( ProcessInfo.processInfo.processIdentifier )
#if DEBUG
    var aesSalt = "1234567890123456" // 固定Key(16位)
#else
    var aesSalt = "1234567890123456" // TODO: 发版时替换正式的Key
#endif
    var request: URLRequest
    var millisecondTime: String { String( Int(Date().timeIntervalSince1970 * 1000)) }
    var ramdonString: String { UUID().uuidString.components(separatedBy: "-").dropFirst(3).joined(separator: "") }
    var xRequestId: String?
    var xResponseNonceStr: String?
    var params: [String: Any] = [:]
    
    let options = CCOptions(kCCOptionPKCS7Padding)

    var active = false
    var cryptoType: CryptoType = .plainText
    
    var xRequestNonceStr: String?
    
    private var requestId: String {
        "iOS-\(self.processID)-\(self.millisecondTime)-\(self.ramdonString)".md5()
    }

    init(_ type: CryptoType = .encryptAES256CBC,
         request: URLRequest = URLRequest(url: URL(string: "about://blank")!),
         xRequestId: String? = nil,
         params: [String: Any] = [:]) {
        self.active = true
        self.cryptoType = type
        self.request = request
        self.xRequestId = xRequestId ?? self.requestId
        self.params = params
    }
    
    func xRequestNonceStr(_ signStr: String) -> String {
        signStr.md5()
    }
    
    func requestAesKey(_ xRequestNonceStr: String) -> String {
        aesSalt + String(xRequestNonceStr.prefix(16))
    }
    
    func requestIV(_ xRequestNonceStr: String) -> String {
        String(xRequestNonceStr.suffix(16))
    }
    
    func responseAesKey(xRequestNonceStr: String, xResponseNonceStr: String) -> String {
        aesSalt + String(xRequestNonceStr.prefix(8)) + String(xResponseNonceStr.prefix(8))
    }
    
    func responseIV(_ xRequestNonceStr: String) -> String {
        String(xRequestNonceStr.prefix(24).suffix(16))
    }
}

extension AIOGateway {
    func encrypt(_ queryString: String) throws -> String? {
        if queryString.isEmpty {
            return nil
        }
        guard self.cryptoType == CryptoType.encryptAES256CBC else {
            return queryString
        }
        let nonceString = nonceString(self.params)
        let xRequestNonceStr = xRequestNonceStr(nonceString)
        let aesKey = requestAesKey(xRequestNonceStr)
        let iv = requestIV(xRequestNonceStr)
        if let data = try? AES(keyString: aesKey,
                               options: options).encrypt(queryString,
                                                         iv: iv) {
            return data.base64Url
        }
        return nil
    }
    
    func encrypt(_ parameters: [String: Any]) throws -> String? {
        if parameters.isEmpty {
            return ""
        }
        guard self.cryptoType == CryptoType.encryptAES256CBC else {
            return AIOGateway.postParam(parameters, separator: "&")
        }
        let nonceString = nonceString(parameters)
        let xRequestNonceStr = xRequestNonceStr(nonceString)
        let aesKey = requestAesKey(xRequestNonceStr)
        let iv = requestIV(xRequestNonceStr)
        if let data = try? AES(keyString: aesKey,
                               options: options).encrypt(AIOGateway.postParam(parameters, separator: "&"),
                                                         iv: iv) {
            return data.base64Url
        }
        return nil
    }

    func decrypt(_ data: Data, aesKey: String, iv: String, cookie: String? = nil, authorization: String? = nil) throws -> Data? {
        guard self.cryptoType == CryptoType.encryptAES256CBC else {
            return data
        }
        if let dataStr = String(data: data, encoding: .utf8),
            let str = try? AES(keyString: aesKey,
                               options: options).decrypt(dataStr.base64urlToBase64,
                                                         iv: iv) {
            return str.data(using: .utf8)
        }
        return Data()
    }
    
    func nonceString(_ parameters: [String: Any] = [:]) -> String {
        let httpMethod = self.request.httpMethod ?? ""
        var body = httpMethod + (getQuery() ?? "")
        if self.request.httpMethod?.uppercased() == "POST" {
            body += AIOGateway.postParam(parameters)
        }
        body += getCookie()
        body += getAuthorization()
        body += xRequestId ?? ""
        return body
    }
    
    private func getString(_ parameters: [String: Any]) -> String? {
        return self.request.url?.query
    }
    
    private func postString(_ parameters: [String: Any]) -> String? {
        let httpMethod = self.request.httpMethod ?? ""
        if httpMethod == "POST" {
            return AIOGateway.postParam(parameters)
        }
        return nil
    }
}

extension AIOGateway {
    
    func getQuery() -> String? {
        return self.request.url?.query
    }
    func getCookie() -> String {
        
        return self.request.allHTTPHeaderFields?["Cookie"] ?? ""
    }
    
    func getAuthorization() -> String {
        return self.request.allHTTPHeaderFields?["Authorization"] ?? ""
    }
}


extension AIOGateway {
    static func getParam(_ parameters: [String: Any], separator: String = "&") -> String {
        postParam(parameters, separator: separator)
    }

    static func postParam(_ parameters: [String: Any], separator: String = "&") -> String {
        let keys = parameters.keys.sorted()
        var body = [String]()
        for key in keys {
            var keyValue = key + "="
            if let value = parameters[key] {
                keyValue += (value as? String ?? "").urlEncodeString()
            }
            body.append(keyValue)
        }
        return body.joined(separator: separator)
    }
}

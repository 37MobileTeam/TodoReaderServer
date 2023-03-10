//
//  AIOGateway.swift
//  RedCrystal
//
//  Created by lory on 2022/10/21.
//  Copyright © 2022 sqsy. All rights reserved.
//

import Foundation
import CommonCrypto

/// All-in-One Gateway 统一网关
struct AIOGateway {
    private let processID = String( ProcessInfo.processInfo.processIdentifier )
    // TODO: (liwei) 待开启正式环境
//#if DEBUG
    private(set) var xRequestVersion: String = "" // 1为测试， 其他为正式
    private(set) var defaultAppSecret = "1234567890123456"
//#else
//    private(set) var xRequestVersion: String = "" // 1为测试， 其他为正式
//    private(set) var defaultAppSecret = "s" + "o" + "C" + "2" + "G" + "A" + "r" + "8" + "j" + "N" + "2" + "f" + "s" + "b" + "r" + "y"
//#endif
    private(set) static var appSecrets: [[String: Any]] = []
    private var request: URLRequest
    private var millisecondTime: String { String( Int(Date().timeIntervalSince1970 * 1000)) }
    var ramdonString: String { UUID().uuidString.components(separatedBy: "-").dropFirst(3).joined(separator: "") }
    private(set) var xRequestId: String?
    private var xRequestNonceStrWithResponse: String?
    private var xResponseNonceStr: String?
    private var params = [String: Any]()
    
    private let options = CCOptions(kCCOptionPKCS7Padding)

    private var active = false
    private var cryptoType: CryptoType = .plainText
    
    
    private var requestId: String {
        "iOS-\(self.processID)-\(self.millisecondTime)-\(self.ramdonString)".md5()
    }

    init(_ type: CryptoType = .encryptAES256CBC,
         request: URLRequest = URLRequest(url: URL(string: "about://blank")!),
         xRequestId: String? = nil,
         xRequestVersion: String?,
         params: [String: Any] = [:]) {
        self.active = true
        self.cryptoType = type
        self.request = request
        self.xRequestId = xRequestId ?? self.requestId
        self.params = params
        self.xRequestVersion = xRequestVersion ?? ""
    }
    
    func xRequestNonceStr(_ signStr: String) -> String {
        md5(signStr)
    }
    
    func requestAesKey(_ xRequestNonceStr: String) -> String {
        self.aesSalt() + String(xRequestNonceStr.prefix(16))
    }
    
    func requestIV(_ xRequestNonceStr: String) -> String {
        String(xRequestNonceStr.suffix(16))
    }
    
    func responseAesKey(xRequestNonceStr: String, xResponseNonceStr: String) -> String {
        self.aesSalt() + String(xRequestNonceStr.prefix(8)) + String(xResponseNonceStr.prefix(8))
    }
    
    func responseIV(_ xRequestNonceStr: String) -> String {
        String(xRequestNonceStr.prefix(24).suffix(16))
    }
    func aesSalt() -> String {
        var decodeStr: String?
        AIOGateway.appSecrets.forEach { appSecret in
            if let version = appSecret["X-Request-Version"] as? String, self.xRequestVersion == version {
                let key = appSecret["X-Request-AppKey"] as? String ?? ""
                let target = appSecret["X-Request-AppSecret"] as? String ?? ""
                let options = CCOptions(kCCOptionPKCS7Padding)
                let encryKey = String((key + String(repeating: "0", count: 16)).prefix(16))
                let iv = encryKey
                decodeStr = try? AES(keyString: encryKey, options: options).decrypt(target.base64urlToBase64, iv: iv)
            }
        }
        return decodeStr ?? defaultAppSecret // 固定Key(16位)
    }
    static func updateAppSecrets(_ newSecret: [String: Any]) {
        AIOGateway.appSecrets.removeAll { appSecret in
            if let version = appSecret["X-Request-Version"] as? String, let newVersion = newSecret["X-Request-Version"] as? String,
               version == newVersion {
                return true
            }
            return false
        }
        AIOGateway.appSecrets.append(newSecret)
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
extension AIOGateway {
    private func md5(_ str: String) -> String {
        let cStr = str.cString(using: String.Encoding.utf8)
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        CC_MD5(cStr!, (CC_LONG)(strlen(cStr!)), buffer)
        let md5String = NSMutableString()
        for index in 0 ..< 16 {
            md5String.appendFormat("%02x", buffer[index])
        }
        free(buffer)
        return md5String as String
    }
}

extension AIOGateway {
    init(_ type: CryptoType = .encryptAES256CBC, requestNonceStr: String, responseNonceStr: String, requestVersion: String?) {
        self.active = true
        self.cryptoType = type
        self.xRequestNonceStrWithResponse = requestNonceStr
        self.xResponseNonceStr = responseNonceStr
        self.xRequestVersion = requestVersion ?? ""
        self.params = [:]
        self.request = URLRequest(url: URL(string: "about://blank")!)
    }
    
    func encrypt(response: String) throws -> String? {
        if response.isEmpty {
            return response
        }
        guard self.cryptoType == CryptoType.encryptAES256CBC else {
            return response
        }
        guard let xRequestNonceStr = self.xRequestNonceStrWithResponse, let xResponseNonceStr = self.xResponseNonceStr else {
            return response
        }
        let aesKey = self.responseAesKey(xRequestNonceStr: xRequestNonceStr, xResponseNonceStr: xResponseNonceStr)
        let iv = responseIV(xResponseNonceStr)
        if let data = try? AES(keyString: aesKey,
                               options: options).encrypt(response,
                                                         iv: iv) {
            return data.base64Url
        }
        return nil
    }
    
    func decrypt(response: String) throws -> String {
        
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           xRequestId: xRequestId, xRequestVersion: xRequestVersion)
        guard let data = response.data(using: .utf8) else {
            return ""
        }
        
        guard let xRequestNonceStr = self.xRequestNonceStrWithResponse, let xResponseNonceStr = self.xResponseNonceStr else {
            return response
        }
        let aesKey = tool?.responseAesKey(xRequestNonceStr: xRequestNonceStr, xResponseNonceStr: xResponseNonceStr)
        let iv = tool?.responseIV(xResponseNonceStr)
        let plainData = try tool?.decrypt(data,
                                          aesKey: aesKey!,
                                          iv: iv!,
                                          cookie: nil,
                                          authorization: nil)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            return ""
        }
            
        return plainText
    }
    
    func requestDecryptAesKey(_ xRequestNonceStr: String) -> String {
        self.aesSalt() + String(xRequestNonceStr.prefix(16))
    }
    
    func requestDecryptIV(_ xRequestNonceStr: String) -> String {
        String(xRequestNonceStr.suffix(16))
    }
}

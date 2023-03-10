//
//  AIOGatewayController.swift
//  App
//
//  Created by lory on 2022/12/13.
//

import Vapor

struct AIOGatewayController: RouteCollection {
    
    init() {
        // 加载配置
        guard let data = try? Data(contentsOf: URL.init(fileURLWithPath: "./Resource/x_secure_key.json")),
              let jsonObject = try? JSONSerialization.jsonObject(with: data),
              let jsonObject = jsonObject as? [String: Any] else {
            return
        }
        AIOGateway.updateAppSecrets(jsonObject)
        guard let data = try? Data(contentsOf: URL.init(fileURLWithPath: "./Resource/x_secure_key_1.json")),
              let jsonObject1 = try? JSONSerialization.jsonObject(with: data),
              let jsonObject1 = jsonObject1 as? [String: Any] else {
            return
        }
        AIOGateway.updateAppSecrets(jsonObject1)
    }
    
    func boot(routes: RoutesBuilder) throws {
        let allInOneGateway = routes.grouped("gw")
        allInOneGateway.get(use: index)
    }

    func index(req: Request) throws -> EventLoopFuture<String> {
        return  req.eventLoop.submit {
            return "AllInOne Gateway works!"
        }
    }
    
    func decrypt(request req: Request) -> EventLoopFuture<String> {
        return  req.eventLoop.submit {
            guard let dict = req.url.query?.queryStringComponents() else {
                return ""
            }
            guard let requestNonceStr = dict["X-Request-Nonce-Str"] as? String, let xRequestId = dict["X-Request-Id"] as? String else {
                return ""
            }
            let plainJson = req.body.string
            let xRequestVersion = dict["X-Request-Version"] as? String
            let decryptStr = try? plainJson?.decryptWithAES256CBC(requestNonceStr: requestNonceStr,
                                                                  requestId: xRequestId,
                                                                  requestVersion: xRequestVersion)
            print(decryptStr, decryptStr?.count)
            return decryptStr ?? ""
        }
    }
    
    func encrypt(response req: Request) -> EventLoopFuture<String> {
        return  req.eventLoop.submit {
            guard let dict = req.url.query?.queryStringComponents() else {
                return ""
            }
            guard let requestNonceStr = dict["X-Request-Nonce-Str"] as? String, let responseNonceStr = dict["X-Response-Nonce-Str"] as? String else {
                return ""
            }
            let xRequestVersion = dict["X-Request-Version"] as? String
            let plainJson = req.body.string
            let encryptStr = try? plainJson?.encryptWithAES256CBC(requestNonceStr: requestNonceStr,
                                                                  responseNonceStr: responseNonceStr,
                                                                  requestVersion: xRequestVersion)
            print(encryptStr, encryptStr?.count)
            return encryptStr ?? ""
        }
    }
    
    func decrypt(response req: Request) -> EventLoopFuture<String> {
        return  req.eventLoop.submit {
            guard let dict = req.url.query?.queryStringComponents() else {
                return ""
            }
            guard let requestNonceStr = dict["X-Request-Nonce-Str"] as? String, let responseNonceStr = dict["X-Response-Nonce-Str"] as? String else {
                return ""
            }
            let xRequestVersion = dict["X-Request-Version"] as? String
            let plainJson = req.body.string
            let decryptStr = try? plainJson?.decryptWithAES256CBC(requestNonceStr: requestNonceStr,
                                                                  responseNonceStr: responseNonceStr,
                                                                  requestVersion: xRequestVersion)
            print(decryptStr, decryptStr?.count)
            return decryptStr ?? ""
        }
    }
}

//
//  AIOGatewayController.swift
//  App
//
//  Created by lory on 2022/12/13.
//

import Vapor

struct AIOGatewayController: RouteCollection {
    
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
            let decryptStr = try? plainJson?.decryptWithAES256CBC(requestNonceStr: requestNonceStr, requestId: xRequestId)
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
            let plainJson = req.body.string
            let encryptStr = try? plainJson?.encryptWithAES256CBC(requestNonceStr: requestNonceStr, responseNonceStr: responseNonceStr)
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
            let plainJson = req.body.string
            let decryptStr = try? plainJson?.decryptWithAES256CBC(requestNonceStr: requestNonceStr, responseNonceStr: responseNonceStr)
            print(decryptStr, decryptStr?.count)
            return decryptStr ?? ""
        }
    }
}

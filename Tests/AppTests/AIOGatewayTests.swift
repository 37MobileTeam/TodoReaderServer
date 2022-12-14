//
//  AIOGatewayTests.swift
//  PassionKitTests
//
//  Created by lory on 2022/10/21.
//  Copyright © 2022 sqsy. All rights reserved.
//
@testable import App
import XCTVapor

// swiftlint:disable line_length
final class AIOGatewayTests: XCTestCase {
//
//    override func setUpWithError() throws {
//        // Put setup code here. This method is called before the invocation of each test method in the class.
//    }
//
//    override func tearDownWithError() throws {
//        // Put teardown code here. This method is called after the invocation of each test method in the class.
//    }
    
    func testAIOGatewayRamdonString() throws {
        XCTAssertEqual(AIOGateway(params: [String: Any]()).ramdonString.count, 16, "长度只能是16位")
        for _ in 1...20 {
            XCTAssertNotEqual(AIOGateway(params: [String: Any]()).ramdonString,
                              AIOGateway(params: [String: Any]()).ramdonString)
        }
    }

    func testAIOGatewayXRequestId() throws {
        XCTAssertEqual(AIOGateway(params: [String: Any]()).xRequestId?.count, 32, "长度只能是32位")
        for _ in 1...20 {
            XCTAssertNotEqual(AIOGateway(params: [String: Any]()).xRequestId,
                              AIOGateway(params: [String: Any]()).xRequestId)
        }
    }
    
    func testAIOGatewayAesKey() throws {
        let tool = AIOGateway(params: [String: Any]())
    
        let xRequestNonceStr = "28971bba18f2d70a2002ee6868c90fbd"
        let xResponseNonceStr = "f9390ab2e0956cda9ea943ff2202afae"
        XCTAssertEqual(tool.requestAesKey(xRequestNonceStr).count, 32, "长度只能是16位")
        XCTAssertEqual(tool.responseAesKey(xRequestNonceStr: xRequestNonceStr, xResponseNonceStr: xResponseNonceStr).count, 32, "长度只能是16位")
    }
    
    func testAIOGatewayIV() throws {
        let tool = AIOGateway(params: [String: Any]())
        let xResponseNonceStr = "f9390ab2e0956cda9ea943ff2202afae"
        XCTAssertEqual(tool.requestIV(xResponseNonceStr).count, 16, "长度只能是16位")
        XCTAssertEqual(tool.responseIV(xResponseNonceStr).count, 16, "长度只能是16位")
    }
    
    func testAIOGatewayEncryptQueryToAESData() throws {
        var request = URLRequest(url: URL(string: "http://localhost/api/login?pid=1")!)
        request.httpMethod = "GET"
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           request: request,
                                           params: [String: AnyHashable]())
        let encryptQueryString = try tool?.encrypt(request.url?.query ?? "pid=1")
        XCTAssertNotNil(encryptQueryString, "加密失败")
        
        let nonceString = tool?.nonceString() ?? ""
        let xRequestNonceStr = tool?.xRequestNonceStr(nonceString)
        let aesKey = tool?.requestAesKey(xRequestNonceStr!)
        let iv = tool?.requestIV(xRequestNonceStr!)
        
        guard let encryptQueryData = encryptQueryString?.data(using: .utf8) else {
            XCTFail("无法解析 encryptQueryString"); return
        }
        let plainData = try tool?.decrypt(encryptQueryData,
                                          aesKey: aesKey!,
                                          iv: iv!,
                                          cookie: nil,
                                          authorization: nil)
        XCTAssertNotNil(plainData)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 plainText"); return
        }
        let expect = "pid=1"
        XCTAssertEqual(plainText, expect, "验证失败")
    }
    
    func testAIOGatewayEncryptPostToAESData() throws {
        var request = URLRequest(url: URL(string: "http://localhost/api/login")!)
        request.httpMethod = "POST"
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           request: request,
                                           params: ["version": "1.0", "gid": "10000", "refer": "0", "pid": "46"])
        let encryptPostString = try tool?.encrypt(["version": "1.0", "gid": "10000", "refer": "0", "pid": "46"])
        XCTAssertNotNil(encryptPostString, "加密失败")
        request.httpBody = encryptPostString?.data(using: .utf8)
        
        let nonceString = tool?.nonceString(["version": "1.0", "gid": "10000", "refer": "0", "pid": "46"]) ?? ""
        let xRequestNonceStr = tool?.xRequestNonceStr(nonceString)
        let aesKey = tool?.requestAesKey(xRequestNonceStr!)
        let iv = tool?.requestIV(xRequestNonceStr!)
        
        print("requestAesKey: " + aesKey!)
        print("requestIV: " + iv!)
        
        guard let encryptPostData = encryptPostString?.data(using: .utf8) else {
            XCTFail("无法解析 encryptPostString"); return
        }
        let plainData = try tool?.decrypt(encryptPostData,
                                          aesKey: aesKey!,
                                          iv: iv!,
                                          cookie: nil,
                                          authorization: nil)
        XCTAssertNotNil(plainData)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 plainData"); return
        }
        let expect = "gid=10000&pid=46&refer=0&version=1.0"
        XCTAssertEqual(plainText, expect, "验证失败")
    }
    
    func testAIOGatewayEncryptQueryAndPostToAESData() throws {
        var request = URLRequest(url: URL(string: "http://localhost/api/login?pid=1")!)
        request.httpMethod = "POST"
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           request: request,
                                           params: ["version": "1.0", "gid": "10000", "refer": "0", "pid": "46"])
        let encryptQueryString = try tool?.encrypt(request.url?.query ?? "pid=1")
        XCTAssertNotNil(encryptQueryString)
        let encryptPostString = try tool?.encrypt(["version": "1.0", "gid": "10000", "refer": "0", "pid": "46"])
        XCTAssertNotNil(encryptPostString)
        request.httpBody = encryptPostString?.data(using: .utf8)
    
        let nonceString = tool?.nonceString(["version": "1.0", "gid": "10000", "refer": "0", "pid": "46"]) ?? ""
        let xRequestNonceStr = tool?.xRequestNonceStr(nonceString)
        let aesKey = tool?.requestAesKey(xRequestNonceStr!)
        let iv = tool?.requestIV(xRequestNonceStr!)
        
        print("requestAesKey: " + aesKey!)
        print("requestIV: " + iv!)
        
        guard let encryptPostData = encryptPostString?.data(using: .utf8) else {
            XCTFail("无法解析 encryptPostString"); return
        }
        let plainData = try tool?.decrypt(encryptPostData,
                                          aesKey: aesKey!,
                                          iv: iv!,
                                          cookie: nil,
                                          authorization: nil)
        XCTAssertNotNil(plainData)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 encryptPostString"); return
        }
        XCTAssertEqual(plainText, "gid=10000&pid=46&refer=0&version=1.0", "验证失败")
        
        guard let encryptQueryData = encryptQueryString?.data(using: .utf8) else {
            XCTFail("无法解析 encryptQueryString"); return
        }
        
        let queryData = try tool?.decrypt(encryptQueryData,
                                      aesKey: aesKey!,
                                      iv: iv!,
                                      cookie: nil,
                                      authorization: nil)
        guard let queryData = queryData, let queryText = String(data: queryData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 encryptQueryData"); return
        }
        XCTAssertEqual(queryText, "pid=1", "验证失败")
    }
    
    func testAIOGatewayDecryptLocalAESData() throws {
        let xRequestId = "3420ab1bf68dd78069f2e6920ea48bcf"
        let xRequestNonceStr = "8ec25bf4ee9bda343e5277c4eac9e519"
        let xResponseNonceStr = "b40cf65318494b211e0dc413836247f0"
        let cookies: String? = nil
        let authorization: String? = nil
        let base64Str = "ReHgzyIP158zpR0FA3vUwi8AhgsVidYoIeRqASOTqE5Nc5MJQwI9tYM7Z9l8_fgDt-hr4IXLlZbfE0-03QSmG_PQMuofTcdsmDlHa8BZrucOqMybQOHePdOkVX97iCCAnJvil3SGBEZk3tkUmLVFC-YEIBf7KPD76iGyqvmzxEBz1Z9jICZ-8GPCiu0E0DvG8S3VN6eSUXSJkHz9pt5XCQHoc5NU5LtZy38Eqy_lWQtFnomZmnFJw08mV8Olmnpgr4TEEyJbk7VGeVXu8d_Mbcgv7v0dUh-2YfJnGPuV0LWpxAF7x9TCdW_-i0aaRwdu0PTamKSui1R9Tth0R3LeBhO9TZEEg9N1dPKdr3q-bK_fwnuo9Fg83Ca60iOStBn5TMkcAnAOGQqR2r1To6MK5feTv0aKooyRIlY7TL4Gy4nzTc7aeOiZ3PBqd7bR39c6kT8C7uZkxMpmZ6rB-UvadameWV-sZDjuAVlltnUuNe4flbsWpWOn8muZOEPM1R_0GeL8_G3fESUMCOlpB9FY-n4eoj0DKFlD16IEt34bQWLGWXpVIPokpadMx3r8fPtzamD3s1OiQmKf8Hewyc2olz7S0rbOGIEH22C4Up58p4imDX4aB2uPfmbMNSyCSWYfQovrlyPPlAnXzQbBd7W0wh6Uwn8DgH7rSe507qDxT01Zo2qp3ktfAHCIpmtEJV9UlvPFCv7u4f2dboizSOePo16V4r7BMNok_gbXm31UV8KrwfNqOYKJKTOCt6cutgIVDxh4vfDUF0rI4VWQLLjv_AiyzYlgtqTriGvCcxn4Pqymg_wfrCYt4Cn03UnZ5vIdEPor8SjyqU3Ea-zRhSQQfmzA_FXK7xhrLK3w3APQn3FPxKqU2Kso2fs5PBgrMMq0H-JtIvlpvgmBo-knizQqSwtYBr5QnvgSHZQFm4GkJGmGVa9PeVyuPbxqM9HPzc8JjbJK08BDsV_f21TwifiYS8qr5ALEPFJD0hhXXhdWfO0mrwj2Pvbqa755VgFh63Lg1vk_97vILWS36Q9_ZwNIiql02tlBF9O2sMMTTjnqESugJ0xJSKusihr6oDLdIzE1xOeyVhjn-qKtXsfvBciMw-3P2cm1n9rNF7B-6K7nxlFJkQy3w1f0VrLK7dgXOoi2QWxQ7WcZdE4EasMut4x366Pxqlz7m1L3s5DaN80OJD0JMEnSV7fga-AlDGLB6upbRii_uNNuluOCKNkyHlsiLdzo5eVIAShQ-x1ftawGnd9_ZdTnRD620FMSbMcr5HnssmuWlRl34o_IGomN7pGSSc_FakoMif34nYA0V0uOOai3fVddOuEDcgwEyu8V8ZWIlRZsk_rAwZVhtj9La1dZcAeE5tbJk-TJc_HZg-vFLTSBUrmpozg42z0g6bcyLqB6M-FOSMhAnJNxy2jiDUybypHu6G4mHvAXJ00OjSbGKB10XoCzQ348df6UyCgI6zfuAb1ci61JZJsR10rpfKxGW_m4jPtS5V3wjEdrmQhn6NmpzB1zK13a7G5O0Q03L-S8t-E9p6iZF4B5lCVh56wWHq5EFH9Y4t1zgYJeCpFkzLFYSojQOhdANCGyUBIpTJBKCRlgKGWAPe-AOnxa94My5Q"
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           xRequestId: xRequestId,
                                           params: [String: AnyHashable]())
        guard let data = base64Str.data(using: .utf8) else {
            XCTFail("无法解析 base64Str"); return
        }
        
        let aesKey = tool?.responseAesKey(xRequestNonceStr: xRequestNonceStr, xResponseNonceStr: xResponseNonceStr)
        let iv = tool?.responseIV(xResponseNonceStr)
        print("responseAesKey: " + aesKey!)
        print("responseIV: " + iv!)
        let plainData = try tool?.decrypt(data,
                                          aesKey: aesKey!,
                                          iv: iv!,
                                          cookie: cookies,
                                          authorization: authorization)
        XCTAssertNotNil(plainData)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 plainText"); return
        }
        let expect = """
{\"state\":1,\"msg\":\"成功\",\"data\":{\"code\":1,\"dev\":\"f800c672cbfbc30be53b835e74d309c5\",\"ph\":6,\"vptapi\":\"http://pvt-api.39ej7e.com/verify/ptoken/\",\"papi\":\"http://push-api.39ej7e.com/sdk/push/\",\"eapi\":\"http://m-api.39ej7e.com/sdk/enter/\",\"nurl\":\"\",\"turl\":\"\",\"lurl\":\"http://10.4.1.173:8000/xianXiaRun/?\",\"pInfo\":\"\",\"rlapi\":\"http://live-api.39ej7e.com/api/live-service/v1/go/sdk/radio/radio_channels\",\"rlcapi\":\"http://live-api.39ej7e.com/api/live-service/v1/go/sdk/radio/radio_channel\",\"pop_ups_active_api\":\"http://m-api.39ej7e.com/go/sdk/popups/active\",\"pop_ups_login_api\":\"http://m-api.39ej7e.com/go/sdk/popups/login\",\"pop_ups_enter_api\":\"http://m-api.39ej7e.com/go/sdk/popups/enter\",\"pop_ups_recharge_api\":\"http://m-api.39ej7e.com/go/sdk/popups/recharge\",\"ry\":1,\"de\":1,\"td\":1,\"uvs\":\"\",\"aliauthswitch\":0,\"videopos\":{},\"cnf\":{\"activeTipOn\":1,\"dlurl\":\"\",\"hasPhoneReg\":0,\"iscover\":\"\",\"lang\":\"\",\"logOn\":0,\"orientation\":0,\"skin\":0,\"touristOff\":0},\"anti_addiction\":{\"state\":0},\"sss\":{\"code\":1,\"hpid\":\"46\",\"pid\":\"1\",\"cid\":10010,\"papid\":null},\"u\":{\"uagreeUrl\":\"https://39ej7e.com/user-agreement/content/shell.html?gid=1000000\\u0026gwversion=4.0.8\\u0026pid=46\\u0026scut=1\",\"uagreeConfig\":{\"type\":3,\"version\":1007}}}}
"""
        XCTAssertEqual(plainText, expect, "解密异常")
    }
    
    func testAIOGatewayDecryptRemoteAESDataWhenInvalid() throws {
        let xRequestId = ""
        let xRequestNonceStr = ""
        let xResponseNonceStr = "b40cf65318494b211e0dc413836247f0"
        let cookies: String? = nil
        let authorization: String? = nil
        let base64Str = "ZHncbFIZvu1E9oTx9NCmflwdwDjTM2x8XtXFRPF9eVgQ714duh3qmoiPzGVWYO0wM2wh-IJkUInjowYonJrNDg"
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           xRequestId: xRequestId)
        guard let data = base64Str.data(using: .utf8) else {
            XCTFail("无法解析 base64Str"); return
        }
        
        let aesKey = tool?.responseAesKey(xRequestNonceStr: xRequestNonceStr, xResponseNonceStr: xResponseNonceStr)
        let iv = tool?.responseIV(xRequestNonceStr)
        print("responseAesKey: " + aesKey!)
        print("responseIV: " + iv!)
        let plainData = try tool?.decrypt(data,
                                          aesKey: aesKey!,
                                          iv: iv!,
                                          cookie: cookies,
                                          authorization: authorization)
        XCTAssertNotNil(plainData)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 plainText"); return
        }
        let expect = """
"""
        XCTAssertEqual(plainText, expect, "解密异常")
    }
    
    func testAIOGatewayDecryptSendingAESData() throws {
        let xRequestId = "9d978b1e8aea54544eb253e149011241"
        let xRequestNonceStr = "f65ab9715f81a46e0ff80ab69190a51d"
        let cookies: String? = nil
        let authorization: String? = nil
        let base64Str = "U0I1uh2MyBrWhWLo8_VYKGNgYvsb6MegFoPi7M0YOHQ"
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           xRequestId: xRequestId,
                                           params: [String: AnyHashable]())
        guard let data = base64Str.data(using: .utf8) else {
            XCTFail("无法解析 base64Str"); return
        }
        print("xRequestId: " + xRequestId)
        print("xRequestNonceStr: " + xRequestNonceStr)
        let aesKey = requestDecryptAesKey(xRequestNonceStr)
        let iv = requestDecryptIV(xRequestNonceStr)
        print("requestDecryptAesKey: " + aesKey)
        print("requestDecryptIV: " + iv)
        let plainData = try tool?.decrypt(data,
                                          aesKey: aesKey,
                                          iv: iv,
                                          cookie: cookies,
                                          authorization: authorization)
        XCTAssertNotNil(plainData)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 plainText"); return
        }
        XCTAssertNotEqual(plainText, "")
    }
    
    func testAIOGatewayDecryptSending2AESData() throws {
        let xRequestId = "9a77f016bf7f0609e6f07e1ec6c3f71b"
        let xRequestNonceStr = "512d8db8230a3dcdb7db8d81f735c385"
        let cookies: String? = nil
        let authorization: String? = nil
        let base64Str = "BW6dMcjOpvoWOG7ycmT3n9i0TnJQ_kibMLG4GUZjlHgKAlr5_lqeFRtjuYZ-pplLpDcbog2wK-7lYe2JXJjeerXgf1fOttqQFoyB5y1kM75-TZ1p-m0tsq63IKJTBh9EAY0KzNizS6gLyCxAHC1AlTFN9DeKUHWad0wZAE83kjSxgE8wfBGFgHYgSQBfAkygL3ilJ9vK6_Eh5Whz-RgVGC4sn27_xaVtXRhb9-TWgkVJQMogUKGE2EHFHL9h8GklqEh3xLiM3OWv1cXaVgI6EwcwokM9V3qNx53s95hs6iLaCIMdjThIPcH8RX1H9Qk775mi87SBeUwcuNZeHdjRLydfuh1NOoR2CKCN2fU8vi4LlAeBsfVJtaogU-t5AeMk-u83eN-FrBNlM6c5f33frcazWz-OVlf3_0o0aillupzijXCqgLnVJiqfR86LeNHCGu-bVLzG953J6ml-uIS8WukgbzONJj76d3jXnEROqV2cWY2E_zxmRGNs9lxHq826UV55b1rK3YwaIJD-ZqTyT1MUS6Drz9XejuAf1Nt3Is9sLZwczsLHoyGzeWoqpMqltsFtXCDyx0reBUMmL0XpZNJsIk3mWk13YMVxul9OVRKiz1kjTcM7bTJx4ncXJnKhgAU-geeViq2392fry4IRt7Lk74WJTPIiC5SAGPyzy4pTF_0eBw1PQgfrdMs1aJYOQyZuyDoVvzxkudkeu4XEMynOJ_XSf1h-f9a5x_AxZxcSw9HxYashjJbjbkFnHI_2Fiud1zAv4bljMr4JX6WTzXwE5srt2Qpd9m9g8DaQGnxlZ4-T9MG8JsrFyiWY3Z-IG40KXGXo4NXMbZ6igtkxOMonIRnMa66znfVlwLwmi3PzY9t9S1RZoNiIy3SLjH_X-mc0S58RXLLXjH-nzYXwOMz7g76oYrkDrBILpvG29YfkzxfkGj1w2wQYbfCXmsYvPbgYJlrumV1iTbpl_NN1KT2OG8e82Cw2fma_i4YmL8U5ZeeDwlJU750qdctX97TAgjGepSkTRMSmuH_jj7FgfdMCEyEznpi-jtcdwcnUyk2LLcLcFiSptJTODrmWjgVj8zjmztvzzu9R90SSP2hrvcwNfk-YRL2OZygxYRQRikdCGw0L_gVfJ2HpTPSORWcsgXYvMObyjsHFxVXdcdEiIBraY8vInUZiDQVOELKSvLHOd_bzuf9Rkk3BGTQL6Z-AEAPpKgG9ECfSARZgYCZkHxEvrRZ-PaTZOmNFEgToCitszoUUyc4277isZDwbAyy-p61gNXntrbBJ9tuc5UA6LJfhnaCVDeKT5a5xhyxlZzUvYRcg1dszqZ2za9-Q5n9d"
        let tool: AIOGateway? = AIOGateway(.encryptAES256CBC,
                                           xRequestId: xRequestId)
        guard let data = base64Str.data(using: .utf8) else {
            XCTFail("无法解析 base64Str"); return
        }
        
        let aesKey = requestDecryptAesKey(xRequestNonceStr)
        let iv = requestDecryptIV(xRequestNonceStr)
        print("requestDecryptAesKey: " + aesKey)
        print("requestDecryptIV: " + iv)
        let plainData = try tool?.decrypt(data,
                                          aesKey: aesKey,
                                          iv: iv,
                                          cookie: cookies,
                                          authorization: authorization)
        XCTAssertNotNil(plainData)
        guard let plainData = plainData, let plainText = String(data: plainData,
                                                                encoding: .utf8) else {
            XCTFail("无法解析 plainText"); return
        }
        XCTAssertNotEqual(plainText, "")
        print("plainText: \(plainText)")
    }
}

extension AIOGatewayTests {
    
    private func requestDecryptAesKey(_ xRequestNonceStr: String) -> String {
        "1234567890123456" + String(xRequestNonceStr.prefix(16))
    }
    
    private func requestDecryptIV(_ xRequestNonceStr: String) -> String {
        String(xRequestNonceStr.suffix(16))
    }
}

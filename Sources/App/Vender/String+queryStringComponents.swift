//
//  String+queryStringComponents.swift
//  App
//
//  Created by lory on 2022/12/13.
//

import Foundation

extension String {
    func queryStringComponents() -> [String: AnyObject] {

        var dict = [String: AnyObject]()

        // Check for query string
        if let query = self.split(separator: "?").last {

            // Loop through pairings (separated by &)
            for pair in query.components(separatedBy: "&") {

                // Pull key, val from from pair parts (separated by =) and set dict[key] = value
                let components = pair.components(separatedBy: "=")
                if (components.count > 1) {
                    dict[components[0]] = components[1] as AnyObject?
                }
            }

        }

        return dict
    }
}
